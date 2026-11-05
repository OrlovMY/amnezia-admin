package main

// Перенос на ЧИСТЫЙ сервер (PR 7а плана «перенос на чистый сервер»):
//
//	migrate -key <источник> -to-host <ip|имя> [-to-port 22] [-to-user root]
//	        [-to-hostkey SHA256:…] [-key-out <файл>] [-yes] [-apply]
//
// Решения владельца (05.11): цель задаётся адресом, ключа vpn:// у нового
// сервера нет; вход ключами ПК, не вышло — пароль (один раз, без эха, не
// сохраняется); ставится свежая закреплённая версия, если совместима; цель
// не чистая — в ЭТОМ PR отказ с причиной (снос — отдельно); новый vpn:// с
// паролем — только с согласия на экране; источник продолжает работать;
// ключ vpn:// и пароль не печатаются (ключ — только Reveal() в файл; на
// Linux/macOS права 0600, на Windows — права каталога).
//
// Поток: источник (-key) → ConnectNew цели (исход по ключам печатается) →
// CollectBackupCtx(источник) → ProvisionCheckFor (порты ИЗ КОПИИ) →
// PlanInstall → план (Verdict + Reason, Skipped целиком, оговорка
// NeedsMeasurement) → InstallPreview → [без -apply — стоп: ничего не
// записано] → подтверждение → Install → ReadyForRestore → runMigrate (тот же
// путь, что -to-key: автокопия цели, подтверждение адреса) → параметры с
// сервера → согласие на пароль в ключе → BuildAdminKey → VerifyAdminKey →
// файл 0600.
//
// Коды выхода — как у migrate: 0 — перенесено (или сухой прогон прошёл);
// 1 — не перенесено / нельзя (измерено); 2 — ошибка использования,
// подключения или не подтверждено; 4 — остановлено проверкой / неизвестно.
// Отличие от migrate -to-key: ошибка подключения к ЦЕЛИ здесь 2, а не 1 —
// как у provision-check: 1 занят измеренным «нельзя». Исход выдачи ключа
// код не меняет: главный результат — перенос (ревью PR #70, L2).
//
// Все вопросы (слой автокопии, согласие на пароль в ключе, установка с
// переносом, XRay) и известные заранее проверки (адрес выдачи — тем же
// путём, что CheckTarget) — ДО установки; runMigrate получает ответы в
// migrateFlags.pre и второй раз не спрашивает (ревью PR #70, H1).

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"amnezia-admin/core"
	"amnezia-admin/internal/version"
)

const (
	exitToHostNo      = 1
	exitToHostUsage   = 2
	exitToHostUnknown = exitRestoreStopped // 4
)

// toHostOpts — флаги режима -to-host.
type toHostOpts struct {
	srcKey, srcHostkey  string
	srcKeyFile          string // -key-file источника (для подсказки продолжения)
	host, port, user    string
	hostkey, keyOut     string
	knownHostsPath      string
	clientHost          string
	clientHostOK        bool
	mf                  migrateFlags
	authKeyDir, agentFS string // шов теста: каталог ключей ПК / сокет агента
	noAgent             bool
}

// Швы теста: каждое обращение к серверу или к диску вне конфигов.
var (
	toHostConnectNew = core.ConnectNew
	toHostCollect    = func(ctx context.Context, s *core.Session, now time.Time, p core.ProgressFunc) (*core.Backup, error) {
		return s.CollectBackupCtx(ctx, version.String(), now, net.LookupIP, p)
	}
	toHostProvCheck     = func(s *core.Session, b *core.Backup) core.ProvisionReport { return s.ProvisionCheckFor(b) }
	toHostInstall       = core.Install
	toHostMigrate       = runMigrate
	toHostKeyContainers = func(s *core.Session, names []string) ([]core.AdminKeyContainer, []string, error) {
		return s.AdminKeyContainersFromServer(names)
	}
	toHostVerify                 = core.VerifyAdminKey
	toHostResolve  core.Resolver = net.LookupIP
	toHostPassword               = readPasswordTTY
	// toHostKeyDir — каталог ключей по умолчанию (рядом с «Конфигурации»).
	toHostKeyDir = func() (string, error) {
		d, err := core.UserConfigsDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(filepath.Dir(d), "Ключи доступа"), nil
	}
)

// toHostClean — «сервер не чистый» в отчёте предпроверки: пункт о
// контейнерах Amnezia НЕ годится.
func toHostNotClean(r core.ProvisionReport) bool {
	for _, it := range r.Items {
		if it.State == core.ProvBad && strings.Contains(strings.ToLower(it.What), "контейнер") {
			return true
		}
	}
	return false
}

// printInstallPlan — план установки: по контейнеру Verdict() и Reason (не
// String() состояния), ревизия; не поставленные из копии — целиком;
// оговорка NeedsMeasurement — вместе с готовностью.
func printInstallPlan(w io.Writer, plan core.InstallPlan) {
	fmt.Fprintln(w, "План установки на новый сервер:")
	for _, it := range plan.Items {
		l := "  " + it.Container + ": " + it.Verdict()
		if it.Reason != "" {
			l += " — " + it.Reason
		}
		if it.Revision != "" {
			l += " [скрипты " + it.Revision + "]"
		}
		fmt.Fprintln(w, l)
	}
	for _, s := range plan.Skipped {
		fmt.Fprintln(w, "  Не ставится: "+s.Container+" — "+s.Reason)
	}
	switch {
	case !plan.Ready():
		fmt.Fprintln(w, "Готовность: НЕ готов — установка не начнётся.")
	case plan.NeedsMeasurement():
		fmt.Fprintln(w, "Готовность: готов по скриптам; совпадение с копией подтвердится только измерением после установки.")
	default:
		fmt.Fprintln(w, "Готовность: готов.")
	}
}

// planNotReadyCode — Mismatch где-либо — 1 (измерено «нельзя»), иначе 4.
func planNotReadyCode(plan core.InstallPlan) int {
	for _, it := range plan.Items {
		if it.Compat == core.CompatMismatch {
			return exitToHostNo
		}
	}
	return exitToHostUnknown
}

func askYes(in io.Reader, w io.Writer, q string) bool {
	fmt.Fprint(w, q)
	a := strings.ToLower(strings.TrimSpace(readLine(in)))
	return a == "y" || a == "yes"
}

// runMigrateToHost — режим -to-host.
func runMigrateToHost(ctx context.Context, in io.Reader, w, errOut io.Writer, isTTY bool, o toHostOpts, now time.Time) int {
	in = bufio.NewReader(in)
	host := strings.TrimSpace(o.host)
	switch {
	case strings.TrimSpace(o.srcKey) == "":
		fmt.Fprintln(errOut, "Не задан ключ источника: -key-file <файл>, -key vpn://... или переменная AMNEZIA_KEY")
		return exitToHostUsage
	case strings.HasPrefix(strings.ToLower(host), "vpn://"):
		// раньше общей проверки: «vpn://» содержит «:» и «/» (аудит AU-1, L4)
		fmt.Fprintln(errOut, "-to-host принимает адрес сервера, а не ключ vpn://. Для цели с ключом используйте -to-key-file (или -to-key).")
		return exitToHostUsage
	case host == "" || strings.ContainsAny(host, " /@:") && net.ParseIP(host) == nil:
		fmt.Fprintln(errOut, "-to-host: укажите IP или DNS-имя нового сервера (без пользователя и порта — они задаются -to-user и -to-port)")
		return exitToHostUsage
	}
	port, err := strconv.Atoi(strings.TrimSpace(o.port))
	if err != nil || port < 1 || port > 65535 {
		fmt.Fprintln(errOut, "-to-port: порт SSH 1…65535")
		return exitToHostUsage
	}
	user := strings.TrimSpace(o.user)
	if user == "" {
		fmt.Fprintln(errOut, "-to-user: не задан пользователь SSH")
		return exitToHostUsage
	}

	src, code := migrateConnect("источник", o.srcKey, o.srcHostkey, "-hostkey", o.knownHostsPath, in, w, errOut, isTTY)
	if code != 0 {
		return exitToHostUsage
	}
	defer src.Close()

	// --- вход на новый сервер ---
	// Пароль входа: буфер Secret затирается после вопроса о ключе. Копии,
	// которые делает SSH-библиотека (строка пароля) и ключ vpn:// (строка),
	// не затираются — так устроены строки Go (аудит AU-1, L3).
	var loginPw core.Secret
	defer func() { loginPw.Wipe() }()
	auth := core.AuthSource{KeyDir: o.authKeyDir, AgentSocket: o.agentFS, NoAgent: o.noAgent}
	if isTTY {
		auth.Password = func(keys core.KeyAttempt) ([]byte, error) {
			fmt.Fprintln(w, "Вход ключами ПК: "+keys.Reason()+".")
			b, err := toHostPassword(w, "Пароль "+user+"@"+host+" (не отображается; не сохраняется; "+pwCancelHint+"): ")
			if err != nil {
				return nil, err
			}
			if ctx.Err() != nil { // Ctrl+C пришёл во время ввода
				clear(b)
				return nil, core.ErrPasswordCancelled
			}
			loginPw = core.NewSecret(append([]byte(nil), b...))
			return b, nil
		}
	}
	pol := hostKeyPolicyForCLI(in, w, errOut, isTTY, o.hostkey, o.knownHostsPath)
	dst, att, err := toHostConnectNew(host, strconv.Itoa(port), user, auth, pol)
	if err != nil {
		var ae *core.AuthError
		if errors.As(err, &ae) {
			fmt.Fprintln(errOut, core.MaskText(ae.Error()))
			if !isTTY && !ae.PasswordTried {
				fmt.Fprintln(errOut, "Без терминала пароль не спрашивается: войти можно только ключами ПК (агент или ~/.ssh без парольной фразы).")
			}
		} else {
			fmt.Fprintln(errOut, "SSH (новый сервер):", core.MaskText(err.Error()))
			if errors.Is(err, core.ErrHostKeyUnknown) && !isTTY {
				fmt.Fprintln(errOut, "Без терминала подключение к новому серверу требует явного отпечатка: -to-hostkey SHA256:...")
			}
		}
		return exitToHostUsage
	}
	defer dst.Close()
	if att.Outcome == core.KeysAccepted {
		fmt.Fprintln(w, "Вход на новый сервер: по ключу ПК ("+att.Reason()+").")
	} else {
		fmt.Fprintln(w, "Вход на новый сервер: по паролю. Ключи ПК: "+att.Reason()+". Пароль не сохраняется.")
	}
	fmt.Fprintln(w, sideLine("Источник (только чтение)", src))
	fmt.Fprintln(w, sideLine("Новый сервер (сюда будет записано)", dst))
	if src.HostKeyFingerprint != "" && src.HostKeyFingerprint == dst.HostKeyFingerprint {
		fmt.Fprintln(w, "ПЕРЕЕЗД ОСТАНОВЛЕН: у источника и нового сервера один ключ хоста — это один и тот же сервер.")
		return exitToHostUnknown
	}
	if strings.TrimSpace(o.clientHost) != "" {
		if proceed, code, _ := applyClientHost(in, w, errOut, isTTY, o.clientHost, o.clientHostOK, src); !proceed {
			return code
		}
	}

	// --- копия источника в память ---
	progress := cliProgress(errOut, isTTY)
	b, err := toHostCollect(ctx, src, now, progress)
	endProgress(errOut, isTTY)
	if errors.Is(err, core.ErrCanceled) {
		fmt.Fprintln(w, "Отменено — на серверах ничего не изменено.")
		return exitToHostUsage
	}
	if err != nil {
		backupErr(errOut, "Источник не прочитан: ", err)
		return exitToHostNo
	}
	fmt.Fprintln(w, "Источник прочитан в память (на диск не записывается).")

	// --- предпроверка нового сервера с портами копии ---
	rep := toHostProvCheck(dst, b)
	fmt.Fprintln(w, "Предпроверка нового сервера (только чтение):")
	for _, it := range rep.Items {
		fmt.Fprintf(w, "  %s: %s — %s\n", it.What, it.State, it.Reason)
	}
	v := rep.Verdict()
	fmt.Fprintln(w, "Итог предпроверки: "+v.String()+".")
	switch v {
	case core.ProvVerdictNo:
		if toHostNotClean(rep) {
			fmt.Fprintln(w, "Новый сервер не чистый: на нём уже есть контейнеры Amnezia. Снос существующего (с подтверждением и копией) — отдельный шаг, в этой версии его нет. Если на сервере уже стоит Amnezia и у вас есть его ключ vpn:// — используйте migrate -to-key.")
		}
		fmt.Fprintln(w, "Ничего не изменено.")
		return exitToHostNo
	case core.ProvVerdictUnknown:
		fmt.Fprintln(w, "Часть пунктов узнать не удалось — это не «годится». Ничего не изменено.")
		return exitToHostUnknown
	}

	// --- план и перечень изменений ---
	plan := core.PlanInstall(b, nil)
	printInstallPlan(w, plan)
	if !plan.Ready() {
		fmt.Fprintln(w, "Ничего не изменено.")
		return planNotReadyCode(plan)
	}
	preview, err := core.InstallPreview(plan)
	if err != nil {
		backupErr(errOut, "Перечень изменений на хосте не составлен — установка не начнётся: ", err)
		return exitToHostUnknown
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Установка изменит на новом сервере:")
	printLines(w, preview)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Источник после переезда продолжит работать. Клиенты, подключённые по DNS-имени, перейдут на новый сервер после смены записи DNS.")
	if !o.mf.apply {
		fmt.Fprintln(w, "\nЭто сухой прогон: на серверах ничего не изменено, на диск ничего не записано. Чтобы выполнить — добавьте -apply.")
		return 0
	}
	// --- ВСЕ вопросы и известные заранее проверки — ДО установки (ревью
	// PR #70, H1): после Install остановка оставила бы на сервере
	// контейнеры без клиентов. ---
	// Адрес выдачи — тем же путём, что compat.NeedAddressConfirm в CheckTarget.
	needAddr, addrText := core.TargetAddressCheck(b, host, toHostResolve)
	if need, text := needAddr, addrText; need && !o.mf.addrOK {
		fmt.Fprintln(w, "Адрес: "+text)
		fmt.Fprintln(w, "ПЕРЕЕЗД ОСТАНОВЛЕН ДО УСТАНОВКИ: адрес выдачи другой или не проверен. Если клиенты подключаются по DNS-имени, после переезда переключите DNS; повторите с флагом -address-changes. Ничего не изменено.")
		return exitToHostUnknown
	}
	if !o.mf.yes && !isTTY {
		fmt.Fprintln(errOut, "Действие не выполнено: без терминала требуется флаг -yes (для скриптов). Ничего не изменено.")
		return exitToHostUsage
	}
	fmt.Fprintln(w, "Перед переносом клиентов программа сохранит на диск АВТОКОПИЮ НОВОГО СЕРВЕРА (его состояние до замены; источник на диск не пишется).")
	layer, warning, code := backupLayerChoice(in, w, errOut, isTTY, o.mf.pwFile, o.mf.noPw)
	if code != 0 {
		fmt.Fprintln(w, "Ничего не изменено.")
		return code
	}
	fmt.Fprintln(w, warning)
	// Согласие на пароль в ключе — только на экране; -yes его не даёт.
	var keyPw core.Secret
	defer func() { keyPw.Wipe() }()
	consent := false
	if !isTTY {
		fmt.Fprintln(w, "Ключ vpn:// нового сервера выдан не будет: в ключ кладётся пароль "+user+", и согласие на это даётся только на экране (терминал).")
	} else {
		fmt.Fprintln(w, "После переноса программа может выдать ключ vpn:// нового сервера (как «полный доступ» в приложении Amnezia). В нём будет пароль "+user+"@"+host+": кто получит ключ — получит root-доступ к серверу.")
		consent = askYes(in, w, "Положить пароль в ключ и выдать ключ после переноса? (y/n): ")
		switch {
		case !consent:
			fmt.Fprintln(w, "Ключ выдан не будет (нет согласия).")
		case loginPw.Len() > 0:
			keyPw = core.NewSecret(loginPw.Bytes())
		default:
			fmt.Fprintln(w, "Вход был по ключу ПК — пароля для ключа vpn:// у программы нет.")
			if keyPw = askKeyPassword(ctx, w, user, host); keyPw.Len() == 0 {
				consent = false
				fmt.Fprintln(w, "Пароль не введён — ключ выдан не будет.")
			}
		}
	}
	loginPw.Wipe() // пароль входа больше не нужен
	hasXRay := false
	for _, it := range plan.Items {
		hasXRay = hasXRay || it.Container == "amnezia-xray"
	}
	xrayNote := ""
	if hasXRay && !o.mf.skipXRay {
		xrayNote = " (XRay на новом сервере будет перезапущен)"
	}
	if !o.mf.yes && !askYes(in, w, "Поставить Amnezia на новый сервер и перенести на него клиентов источника"+xrayNote+"? (y/n): ") {
		fmt.Fprintln(w, "Отменено: ничего не записано.")
		return exitToHostUsage
	}

	// Маркер незавершённой операции — до первой записи на цель; снимается
	// только при измеренном итоге (аудит AU GUI-TO-HOST M1).
	var names0 []string
	for _, it := range plan.Items {
		names0 = append(names0, it.Container)
	}
	mk := core.OpMarker{Target: host, Started: now, Step: "установка Amnezia", Installed: names0, Tool: version.String()}
	if err := core.BeginOpMarker(mk); err != nil {
		if errors.Is(err, core.ErrOpMarkerPending) {
			backupErr(errOut, "Установка не начата: ", err)
		} else {
			backupErr(errOut, "Установка не начата (без маркера обрыв посреди установки остался бы без следа): ", err)
		}
		fmt.Fprintln(w, "Ничего не изменено.")
		return exitToHostNo
	}
	stopAwake, awake := core.KeepAwake()
	defer stopAwake()
	if awake {
		fmt.Fprintln(w, "Сон ПК запрещён до конца установки и переноса. Не закрывайте крышку ноутбука и не рвите сеть до итога.")
	} else {
		fmt.Fprintln(w, "Не усыпляйте ПК, не закрывайте крышку ноутбука и не рвите сеть до итога (на этой ОС программа сон не запрещает).")
	}
	res := toHostInstall(dst, plan, core.InstallOptions{Backup: b, Resolve: toHostResolve, PreviewAccepted: true})
	printLines(w, res.Lines())
	if !res.ReadyForRestore() {
		printInstallFailed(w, res)
		if res.Refused == "" && res.Measure == nil {
			fmt.Fprintln(w, "Маркер незавершённой операции оставлен: итог установки неизвестен, программа напомнит о нём при следующем запуске migrate.")
			return exitToHostUnknown
		}
		clearOpMarker(errOut)
		return exitToHostNo
	}
	mk.Step = "перенос клиентов"
	if err := core.WriteOpMarker(mk); err != nil {
		backupErr(errOut, "Маркер незавершённой операции не обновлён (останется шаг «установка»): ", err)
	}

	// --- перенос клиентов: тот же путь, что -to-key, с ответами, данными выше ---
	fmt.Fprintln(w)
	mf := o.mf
	mf.pre = &migratePre{layer: layer, warning: warning, confirmed: true, source: b}
	code = toHostMigrate(ctx, in, w, errOut, isTTY, src, dst, mf, now)
	if code == exitToHostUnknown {
		fmt.Fprintln(w, "Маркер незавершённой операции оставлен: итог переноса неизвестен, программа напомнит о нём при следующем запуске migrate.")
	} else {
		clearOpMarker(errOut)
	}

	// Ключ выдаётся и при неудаче переноса: без него контейнеры на новом
	// сервере не продолжить ничем (ревью PR #70, H1б).
	keyPath := ""
	if consent {
		keyPath = toHostIssueKey(ctx, w, errOut, isTTY, o, dst, host, port, user, plan, keyPw, now)
	}
	if code != 0 {
		var names []string
		for _, it := range plan.Items {
			names = append(names, it.Container)
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "ПЕРЕНОС НЕ ЗАВЕРШЁН. На новом сервере поставлены контейнеры Amnezia ("+strings.Join(names, ", ")+"); клиенты перенесены не все или не перенесены (см. выше). Источник не изменён и продолжает работать.")
		if keyPath != "" {
			sh, ps := continueHint(o, keyPath, needAddr)
			fmt.Fprintln(w, "Продолжить перенос на уже поставленный сервер (ключи — только файлами, в командную строку не попадают):")
			fmt.Fprintln(w, "  "+sh)
			fmt.Fprintln(w, "  PowerShell: "+ps)
		} else {
			fmt.Fprintln(w, "Ключ нового сервера не выдан — продолжить командой migrate -to-key-file можно, только добавив сервер в приложение Amnezia (логин и пароль) и взяв из него ключ. Повторный запуск -to-host откажет: сервер уже не чистый.")
		}
	} else if keyPath == "" {
		// M3 (аудит AU-1): перенос сделан, ключа нет — как управлять дальше.
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Перенос выполнен, но ключ vpn:// нового сервера не выдан. Команды amnezia-admin работают только по ключу: добавьте новый сервер в приложение Amnezia (адрес "+host+", пользователь "+user+", пароль), выгрузите из него ключ «полный доступ» в файл и передавайте его через -key-file. Повторный запуск -to-host откажет: сервер уже не чистый.")
	}
	return code
}

// pwCancelHint — как отменить ввод пароля. На Windows Ctrl+C во время
// ввода без эха перехватывается контекстом команды, а ввод ждёт Enter
// (проверено по коду x/term и signal.NotifyContext, не на живой консоли).
const pwCancelHint = "отмена — Ctrl+C, затем Enter"

// readKeyFile — ключ vpn:// из файла (-key-file/-to-key-file): пробелы и
// переводы строк по краям обрезаются; содержимое в текст ошибки не
// попадает; файл, открытый группе/прочим (Linux/macOS), — предупреждение.
func readKeyFile(path string, warn io.Writer) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			return "", fmt.Errorf("файл %s не прочитан: %v", path, pe.Err)
		}
		return "", fmt.Errorf("файл %s не прочитан", path)
	}
	k := strings.TrimSpace(string(b))
	clear(b)
	if k == "" {
		return "", fmt.Errorf("файл %s пуст", path)
	}
	if m, err := fileModeOf(path); err == nil && passwordFileOpen(m) {
		fmt.Fprintln(warn, "Предупреждение: файл ключа "+path+" доступен группе или прочим пользователям — закройте доступ: chmod 600 "+path)
	}
	return k, nil
}

// printOpMarker — если прошлая установка не завершена (или маркер не
// прочитан) — сказать; маркер не снимается (убрать — удалить файл).
func printOpMarker(errOut io.Writer) {
	m, err := core.ReadOpMarker()
	where := "файл маркера в каталоге данных программы"
	if p, perr := core.OpMarkerPath(); perr == nil {
		where = p
	}
	switch {
	case err != nil:
		fmt.Fprintln(errOut, "ВНИМАНИЕ: "+core.MaskText(err.Error())+" — итог прошлой установки на новый сервер может быть неизвестен.")
	case m != nil:
		fmt.Fprintln(errOut, "ВНИМАНИЕ: "+m.Text())
		fmt.Fprintln(errOut, "Когда сервер проверен — удалите маркер: "+where)
	}
}

// clearOpMarker — итог измерен: маркер снимается; не вышло — сказать.
func clearOpMarker(errOut io.Writer) {
	if err := core.ClearOpMarker(); err != nil {
		backupErr(errOut, "Маркер незавершённой операции не удалён (при следующем запуске будет ложное напоминание): ", err)
	}
}

// continueHint — команда продолжения переноса на уже поставленный сервер
// (аудит AU-1, M1/M2); собирается core.ContinueHint — тем же, что в GUI.
func continueHint(o toHostOpts, keyPath string, needAddr bool) (sh, ps string) {
	return core.ContinueHint(core.ContinueHintOptions{SrcKeyFile: o.srcKeyFile, KeyPath: keyPath,
		AddressChanges: needAddr || o.mf.addrOK, PasswordFile: o.mf.pwFile, NoPassword: o.mf.noPw, SkipXRay: o.mf.skipXRay})
}

// printInstallFailed — после неудачной установки: что осталось на сервере,
// что источник не тронут, что делать (ревью PR #70, M1).
func printInstallFailed(w io.Writer, res core.InstallResult) {
	fmt.Fprintln(w, "Клиенты НЕ перенесены. Источник не изменён и продолжает работать.")
	if res.Refused != "" {
		fmt.Fprintln(w, "Установка не начиналась — на новом сервере ничего не изменено.")
		return
	}
	var left []string
	unknown := false
	for _, c := range res.Containers {
		switch {
		case c.Rollback == core.RollbackDone:
		case c.Rollback == core.RollbackFailed:
			left = append(left, c.RollbackLeft...)
		case c.Rollback == core.RollbackUnknown:
			unknown = true
			left = append(left, c.Container+" (не подтверждено)")
		case c.Outcome == core.InstallInstalled:
			left = append(left, c.Container)
		}
	}
	switch {
	case len(left) > 0:
		fmt.Fprintln(w, "На новом сервере осталось: "+strings.Join(left, ", ")+". Повторный запуск -to-host откажет («сервер не чистый»); снос — в следующей версии, вручную: docker rm -f <контейнер> (и docker volume rm для тома XRay).")
	case unknown:
		fmt.Fprintln(w, "Что осталось на новом сервере — неизвестно; проверьте docker ps -a перед повтором.")
	default:
		fmt.Fprintln(w, "По измерению отката контейнеров Amnezia на новом сервере не осталось (Docker, если ставился, остался). Устраните причину и повторите.")
	}
}

// askKeyPassword — пароль для ключа vpn:// с терминала без эха; пусто —
// пустой Secret.
func askKeyPassword(ctx context.Context, w io.Writer, user, host string) core.Secret {
	b, err := toHostPassword(w, "Пароль "+user+"@"+host+" для ключа (не отображается; пусто — не выдавать ключ; "+pwCancelHint+"): ")
	if err != nil || len(b) == 0 || ctx.Err() != nil {
		clear(b)
		return core.Secret{}
	}
	s := core.NewSecret(b)
	clear(b)
	return s
}

// toHostKeyAttempts — сколько раз всего пробуется пароль для ключа.
const toHostKeyAttempts = 3

// toHostIssueKey — сборка, проверка входом и запись ключа; возвращает путь
// файла ("" — ключ не выдан, причина напечатана). Исход ключа на код выхода
// не влияет: перенос — главный результат (ревью PR #70, L2).
func toHostIssueKey(ctx context.Context, w, errOut io.Writer, isTTY bool, o toHostOpts, dst *core.Session, host string, port int, user string, plan core.InstallPlan, pw core.Secret, now time.Time) string {
	fmt.Fprintln(w)
	var names []string
	for _, it := range plan.Items {
		names = append(names, it.Container)
	}
	cs, notes, err := toHostKeyContainers(dst, names)
	if err != nil {
		backupErr(errOut, "Ключ vpn:// не выдан: ", err)
		return ""
	}
	for _, n := range notes {
		fmt.Fprintln(w, n)
	}
	for attempt := 1; ; attempt++ {
		in := core.AdminKeyInput{Host: host, Port: port, User: user, Password: pw, PasswordConsent: true,
			Containers: cs, DefaultContainer: names[0], Description: host}
		key, err := core.BuildAdminKey(in)
		if err != nil {
			backupErr(errOut, "Ключ vpn:// не выдан: ", err)
			return ""
		}
		verr := toHostVerify(key, in, dst.HostKeyFingerprint, o.knownHostsPath)
		switch {
		case errors.Is(verr, core.ErrAdminKeyAuthRejected):
			fmt.Fprintln(w, "Ключ НЕ годится: новый сервер не принял пароль из ключа — пароль не подошёл или вход по паролю на сервере выключен (PasswordAuthentication no).")
			if !isTTY || attempt >= toHostKeyAttempts {
				fmt.Fprintln(w, "Ключ vpn:// не выдан.")
				return ""
			}
			if pw = askKeyPassword(ctx, w, user, host); pw.Len() == 0 {
				fmt.Fprintln(w, "Ключ vpn:// не выдан: пароль не введён.")
				return ""
			}
			defer pw.Wipe()
			continue
		case errors.Is(verr, core.ErrAdminKeyMismatch):
			backupErr(errOut, "Ключ vpn:// НЕ выдан — собранный ключ не совпал с ожидаемым: ", verr)
			return ""
		case verr != nil:
			fmt.Fprintln(w, "Ключ проверить не удалось (это не «ключ плохой» и не «ключ хороший»): "+core.MaskText(verr.Error()))
		}
		path, err := writeAdminKeyFile(o.keyOut, host, key, now)
		if err != nil && strings.TrimSpace(o.keyOut) != "" {
			backupErr(errOut, "Ключ vpn:// не записан в -key-out: ", err)
			fmt.Fprintln(w, "Пробую каталог по умолчанию.")
			path, err = writeAdminKeyFile("", host, key, now)
		}
		if err != nil {
			backupErr(errOut, "Ключ vpn:// не записан: ", err)
			fmt.Fprintln(w, "Ключ vpn:// не выдан: записать файл не удалось. Перенос этим не затронут.")
			return ""
		}
		fmt.Fprintln(w, "Ключ vpn:// записан в файл ("+keyFilePermText(path)+"): "+path)
		fmt.Fprintln(w, "В файле — пароль "+user+" нового сервера: храните его как пароль, не пересылайте открыто; после импорта в приложение Amnezia удалите файл (для команд amnezia-admin держите его в закрытом месте и передавайте через -key-file).")
		if verr == nil {
			fmt.Fprintln(w, "Ключ проверен: разобран и вход на новый сервер по нему выполнен.")
		}
		return path
	}
}

// keyFilePermText — какие права у файла ключа на самом деле (аудит AU-1, L1):
// на Windows os.OpenFile(0600) ACL не ставит — файл наследует права
// каталога.
func keyFilePermText(path string) string {
	if runtime.GOOS == "windows" {
		return "доступ — по правам каталога " + filepath.Dir(path) + "; права 0600 на Windows не ставятся"
	}
	return "права 0600 — только владелец"
}

// writeAdminKeyFile — -key-out или каталог ключей по умолчанию; запись —
// core.WriteAdminKeyFile (общая с GUI).
func writeAdminKeyFile(keyOut, host string, key core.AdminKey, now time.Time) (string, error) {
	p := strings.TrimSpace(keyOut)
	if p == "" {
		dir, err := toHostKeyDir()
		if err != nil {
			return "", err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		p = filepath.Join(dir, core.AdminKeyFileName(host, now))
	}
	return core.WriteAdminKeyFile(p, key)
}
