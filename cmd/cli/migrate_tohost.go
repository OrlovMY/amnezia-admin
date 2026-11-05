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
// ключ vpn:// и пароль не печатаются (ключ — только Reveal() в файл 0600).
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
// как у provision-check: 1 занят измеренным «нельзя».

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
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
	toHostVerify   = core.VerifyAdminKey
	toHostPassword = readPasswordTTY
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
		fmt.Fprintln(errOut, "Не задан ключ источника: -key vpn://... или переменная AMNEZIA_KEY")
		return exitToHostUsage
	case host == "" || strings.ContainsAny(host, " /@:") && net.ParseIP(host) == nil:
		fmt.Fprintln(errOut, "-to-host: укажите IP или DNS-имя нового сервера (без пользователя и порта — они задаются -to-user и -to-port)")
		return exitToHostUsage
	}
	if strings.HasPrefix(strings.ToLower(host), "vpn://") {
		fmt.Fprintln(errOut, "-to-host принимает адрес сервера, а не ключ vpn://. Для цели с ключом используйте -to-key.")
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
	var loginPw core.Secret // пароль входа: живёт до выдачи ключа, не сохраняется
	auth := core.AuthSource{KeyDir: o.authKeyDir, AgentSocket: o.agentFS, NoAgent: o.noAgent}
	if isTTY {
		auth.Password = func(keys core.KeyAttempt) ([]byte, error) {
			fmt.Fprintln(w, "Вход ключами ПК: "+keys.Reason()+".")
			b, err := toHostPassword(w, "Пароль "+user+"@"+host+" (не отображается; не сохраняется): ")
			if err != nil {
				return nil, err
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
	// Адрес выдачи сменится почти всегда (новый IP): узнать это до
	// установки, а не после неё — иначе на сервере остались бы контейнеры
	// без клиентов.
	if !o.mf.addrOK {
		iss := b.IssuedAddress
		if iss.Value != host && iss.ResolvedIP != host {
			fmt.Fprintln(w, "ПЕРЕЕЗД ОСТАНОВЛЕН ДО УСТАНОВКИ: конфиги клиентов выданы на адрес «"+iss.Value+"», а новый сервер — «"+host+"». Если клиенты подключаются по DNS-имени, после переезда переключите DNS; повторите с флагом -address-changes.")
			return exitToHostUnknown
		}
	}

	// --- подтверждение установки ---
	if !o.mf.yes {
		if !isTTY {
			fmt.Fprintln(errOut, "Действие не выполнено: без терминала требуется флаг -yes (для скриптов).")
			return exitToHostUsage
		}
		if !askYes(in, w, "Поставить Amnezia на новый сервер с перечисленными изменениями? (y/n): ") {
			fmt.Fprintln(w, "Отменено: ничего не записано.")
			return exitToHostUsage
		}
	}
	res := toHostInstall(dst, plan, core.InstallOptions{Backup: b, Resolve: net.LookupIP, PreviewAccepted: true})
	printLines(w, res.Lines())
	if !res.ReadyForRestore() {
		fmt.Fprintln(w, "Клиенты НЕ перенесены.")
		if res.Refused == "" && res.Measure == nil {
			return exitToHostUnknown
		}
		return exitToHostNo
	}

	// --- перенос клиентов: тот же путь, что -to-key ---
	fmt.Fprintln(w)
	if code := toHostMigrate(ctx, in, w, errOut, isTTY, src, dst, o.mf, now); code != 0 {
		fmt.Fprintln(w, "Ключ vpn:// нового сервера не выдан: перенос не завершён.")
		return code
	}
	return toHostIssueKey(in, w, errOut, isTTY, o, dst, host, port, user, plan, &loginPw)
}

// toHostIssueKey — новый админский vpn://: согласие на пароль в ключе (на
// экране, -yes его не даёт), сборка, проверка входом, файл 0600.
func toHostIssueKey(in io.Reader, w, errOut io.Writer, isTTY bool, o toHostOpts, dst *core.Session, host string, port int, user string, plan core.InstallPlan, loginPw *core.Secret) int {
	fmt.Fprintln(w)
	var names []string
	for _, it := range plan.Items {
		names = append(names, it.Container)
	}
	cs, notes, err := toHostKeyContainers(dst, names)
	if err != nil {
		backupErr(errOut, "Ключ vpn:// не выдан: ", err)
		return exitToHostUnknown
	}
	for _, n := range notes {
		fmt.Fprintln(w, n)
	}
	if !isTTY {
		fmt.Fprintln(w, "Ключ vpn:// не выдан: в ключ кладётся пароль "+user+", и согласие на это даётся только на экране (терминал). Перенос выполнен.")
		return 0
	}
	fmt.Fprintln(w, "Новый ключ vpn:// (как «полный доступ» в приложении Amnezia) будет содержать пароль "+user+"@"+host+": кто получит ключ — получит root-доступ к серверу.")
	if !askYes(in, w, "Положить пароль в ключ и выдать ключ? (y/n): ") {
		fmt.Fprintln(w, "Ключ vpn:// не выдан (нет согласия). Перенос выполнен.")
		return 0
	}
	pw := *loginPw
	if pw.Len() == 0 {
		fmt.Fprintln(w, "Вход был по ключу ПК — пароля для ключа vpn:// у программы нет.")
		b, err := toHostPassword(w, "Пароль "+user+"@"+host+" для ключа (не отображается; пусто — не выдавать ключ): ")
		if err != nil || len(b) == 0 {
			fmt.Fprintln(w, "Ключ vpn:// не выдан: пароль не введён. Перенос выполнен.")
			return 0
		}
		pw = core.NewSecret(b)
		clear(b)
	}
	in2 := core.AdminKeyInput{Host: host, Port: port, User: user, Password: pw, PasswordConsent: true,
		Containers: cs, DefaultContainer: names[0], Description: host}
	key, err := core.BuildAdminKey(in2)
	if err != nil {
		backupErr(errOut, "Ключ vpn:// не выдан: ", err)
		return exitToHostNo
	}
	verr := toHostVerify(key, in2, dst.HostKeyFingerprint, o.knownHostsPath)
	verified := verr == nil
	switch {
	case errors.Is(verr, core.ErrAdminKeyMismatch):
		backupErr(errOut, "Ключ vpn:// НЕ выдан — собранный ключ не совпал с ожидаемым: ", verr)
		return exitToHostNo
	case verr != nil:
		fmt.Fprintln(w, "Ключ проверить не удалось (это не «ключ плохой» и не «ключ хороший»): "+core.MaskText(verr.Error()))
	}
	path, err := writeAdminKeyFile(o.keyOut, host, key)
	if err != nil {
		backupErr(errOut, "Ключ vpn:// не записан: ", err)
		return exitToHostNo
	}
	fmt.Fprintln(w, "Ключ vpn:// записан в файл (права 0600): "+path)
	if verified {
		fmt.Fprintln(w, "Ключ проверен: разобран и вход на новый сервер по нему выполнен.")
		return 0
	}
	return exitToHostUnknown
}

// writeAdminKeyFile — ключ (Reveal) в новый файл 0600; существующий файл не
// перезаписывается. Возвращает абсолютный путь.
func writeAdminKeyFile(keyOut, host string, key core.AdminKey) (string, error) {
	p := strings.TrimSpace(keyOut)
	if p == "" {
		dir, err := toHostKeyDir()
		if err != nil {
			return "", err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		safe := strings.Map(func(r rune) rune {
			if r == '.' || r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
				return r
			}
			return '_'
		}, host)
		p = filepath.Join(dir, "admin-"+safe+"-"+time.Now().Format("20060102-150405")+".vpn.txt")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("файл %s уже есть — не перезаписываю", abs)
		}
		return "", err
	}
	_, werr := f.WriteString(key.Reveal() + "\n")
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(abs)
		return "", fmt.Errorf("запись файла %s не удалась", abs)
	}
	return abs, nil
}
