package main

// Прямой переезд «на лету» (Б2): migrate -key <источник> -to-key <цель> ...
// Источник читается в память и переносится на цель без записи его копии на
// диск; на диск пишется только автокопия ЦЕЛИ перед заменой. Ядро —
// core/migrate_direct.go; стоп-правила, подтверждения и коды выхода — как у
// restore (0 — сделано; 1 — ошибка или перенос не весь; 2 — не подтверждено;
// 4 — переезд остановлен проверкой).

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"amnezia-admin/core"
	"amnezia-admin/internal/version"
)

// migrateFlags — флаги migrate (те же по смыслу, что у restore).
type migrateFlags struct {
	apply, addrOK, skipXRay, replaceUsers, yes bool
	pwFile                                     string // пароль автокопии ЦЕЛИ
	noPw                                       bool
}

// bypassAddressGate — шов теста: обойти проверку адреса в CLI, чтобы убедиться,
// что ядро без подтверждения само не пишет (вторая линия).
var bypassAddressGate bool

const migrateUnknownAddrHint = "Адрес выдачи у источника неизвестен (в ключе IP, адрес для клиентов не выбран). Чтобы не понадобился -address-changes, запускайте переезд с -client-host <имя> или -client-host keep-ip."

// migrateDial — подключение (шов теста: ошибка с ключом внутри).
var migrateDial = core.ConnectWithHostKey

// migrateConnect — сессия одной стороны переезда. role — «источник» /
// «цель» (в текстах); hostkeyFlag — имя флага отпечатка (для подсказки).
func migrateConnect(role, key, hostkey, hostkeyFlag, knownHostsPath string, in io.Reader, w, errOut io.Writer, isTTY bool) (*core.Session, int) {
	cfg, err := core.DecodeVpnKey(key)
	if err != nil {
		fmt.Fprintln(errOut, "Ошибка декодирования ключа ("+role+"): "+core.MaskText(err.Error()))
		return nil, 1
	}
	creds, err := core.CredsFromConfig(cfg)
	if err != nil {
		fmt.Fprintln(errOut, "Ошибка ("+role+"): "+core.MaskText(err.Error()))
		return nil, 1
	}
	sess, err := migrateDial(creds, hostKeyPolicyForCLI(in, w, errOut, isTTY, hostkey, knownHostsPath))
	if err != nil {
		fmt.Fprintln(errOut, "SSH ("+role+"):", core.MaskText(err.Error()))
		if !isTTY && errors.Is(err, core.ErrHostKeyUnknown) {
			what := "к новому серверу (цели)"
			if role == "источник" {
				what = "к серверу-источнику"
			}
			fmt.Fprintln(errOut, "Без терминала подключение "+what+" требует явного отпечатка: "+hostkeyFlag+" SHA256:... ("+role+")")
			return nil, 2
		}
		return nil, 1
	}
	return sess, 0
}

// runMigrateCmd — разбор двух ключей, подключение к обоим (ключ хоста цели —
// тем же TOFU/known_hosts, что и везде), затем runMigrate.
func runMigrateCmd(ctx context.Context, in io.Reader, w, errOut io.Writer, isTTY bool, srcKey, dstKey, srcHostkey, dstHostkey, knownHostsPath, clientHost string, clientHostOK bool, f migrateFlags, now time.Time) int {
	in = bufio.NewReader(in) // один буфер на все вопросы
	switch {
	case strings.TrimSpace(srcKey) == "":
		fmt.Fprintln(errOut, "Не задан ключ источника: -key vpn://... или переменная AMNEZIA_KEY")
		return 1
	case strings.TrimSpace(dstKey) == "":
		fmt.Fprintln(errOut, "Не задан ключ цели: -to-key vpn://... или переменная AMNEZIA_TO_KEY")
		return 1
	case strings.TrimSpace(srcKey) == strings.TrimSpace(dstKey):
		fmt.Fprintln(errOut, "ПЕРЕЕЗД ОСТАНОВЛЕН: ключ источника и ключ цели одинаковы — это один и тот же сервер. Переезд сервера на самого себя не выполняется.")
		return exitRestoreStopped
	}
	src, code := migrateConnect("источник", srcKey, srcHostkey, "-hostkey", knownHostsPath, in, w, errOut, isTTY)
	if code != 0 {
		return code
	}
	defer src.Close()
	dst, code := migrateConnect("цель", dstKey, dstHostkey, "-to-hostkey", knownHostsPath, in, w, errOut, isTTY)
	if code != 0 {
		return code
	}
	defer dst.Close()
	// Адрес для клиентов — у ИСТОЧНИКА: от него зависит «адрес выдачи».
	if strings.TrimSpace(clientHost) != "" {
		if proceed, code, _ := applyClientHost(in, w, errOut, isTTY, clientHost, clientHostOK, src); !proceed {
			return code
		}
	}
	return runMigrate(ctx, in, w, errOut, isTTY, src, dst, f, now)
}

func fpText(fp string) string {
	if fp == "" {
		return "не определён"
	}
	return fp
}

func sideLine(role string, s *core.Session) string {
	host, port := "?", "?"
	if s.Creds != nil {
		host, port = s.Creds.Host, s.Creds.Port
	}
	return fmt.Sprintf("%s: %s:%s, ключ хоста %s", role, host, port, fpText(s.HostKeyFingerprint))
}

// runMigrate — предпросмотр и (с -apply) перенос. Порядок и тексты — как у
// runRestore: цель с пользователями первым разделом, кто пропадёт, сводка,
// проверка, СТОП, подтверждение адреса, план, вопросы.
func runMigrate(ctx context.Context, in io.Reader, w, errOut io.Writer, isTTY bool, src, dst *core.Session, f migrateFlags, now time.Time) int {
	if _, ok := in.(*bufio.Reader); !ok {
		in = bufio.NewReader(in)
	}
	// отпечаток цели — до чтения и до любой записи
	fmt.Fprintln(w, sideLine("Источник (только чтение)", src))
	fmt.Fprintln(w, sideLine("Цель (сюда будет записано)", dst))
	fmt.Fprintln(w, "Копия источника на диск не записывается: данные идут из памяти программы на цель.")
	fmt.Fprintln(w)

	progress := cliProgress(errOut, isTTY)
	m, err := core.PrepareMigration(ctx, src, dst, core.MigrationOptions{ToolVersion: version.String(), Now: now, Resolve: net.LookupIP, Progress: progress})
	endProgress(errOut, isTTY)
	switch {
	case errors.Is(err, core.ErrCanceled):
		fmt.Fprintln(w, "Отменено — на серверах ничего не изменено.")
		return 2
	case errors.Is(err, core.ErrSameServer):
		backupErr(errOut, "ПЕРЕЕЗД ОСТАНОВЛЕН: ", err)
		return exitRestoreStopped
	case errors.Is(err, core.ErrRestoreStopped):
		backupErr(errOut, "", err)
		return exitRestoreStopped
	case err != nil:
		backupErr(errOut, "Переезд невозможен: ", err)
		return 1
	}
	rp, compat, b := m.Plan, m.Compat, m.Source()
	if rp != nil {
		if rp.NeedsTargetConfirm() {
			fmt.Fprintln(w, core.TargetWarnHead(rp))
			printLines(w, core.TargetWarnLines(rp, targetListMax))
			fmt.Fprintln(w)
		}
		if rm := core.RemovedLines(rp); rm != nil {
			printLines(w, rm)
			fmt.Fprintln(w)
		}
	}
	fmt.Fprintln(w, "Источник прочитан в память:")
	if lines := core.BackupSummaryLines(b); len(lines) > 1 {
		printLines(w, lines[1:]) // первая строка — про формат файла копии, здесь файла нет
	}
	fmt.Fprintln(w)
	printCompat(w, compat)
	if compat.Stop {
		fmt.Fprintln(w)
		printLines(w, core.CompatStopLines(compat))
		return exitRestoreStopped
	}
	if compat.NeedAddressConfirm && f.apply && !f.addrOK && !bypassAddressGate {
		fmt.Fprintln(w, "ПЕРЕЕЗД ОСТАНОВЛЕН: адрес другой или не проверен. Если вы понимаете последствия (см. «Адрес» выше) — повторите с флагом -address-changes.")
		if b.IssuedAddress.Kind == core.AddressKindUnknown {
			fmt.Fprintln(w, migrateUnknownAddrHint)
		}
		return exitRestoreStopped
	}
	fmt.Fprintln(w)
	printLines(w, core.RestorePlanLines(rp))
	hasXRay := false
	for _, it := range rp.Items {
		if it.RestartsXRay {
			hasXRay = true
			fmt.Fprintln(w, "    "+restartWarningText())
		}
	}
	if hasXRay && f.skipXRay {
		fmt.Fprintln(w, "Выбрано -skip-xray: XRay переноситься не будет — на цели он останется прежним.")
	}
	if !f.apply {
		fmt.Fprintln(w, "\nЭто предпросмотр: на серверах ничего не изменено и на диск ничего не записано. Чтобы выполнить — добавьте -apply.")
		return 0
	}
	xrayOK := hasXRay && !f.skipXRay
	askUsers := rp.NeedsTargetConfirm() && !f.replaceUsers
	targetOK := !rp.NeedsTargetConfirm() || f.replaceUsers
	if askUsers && (f.yes || !isTTY) && !bypassTargetGate {
		fmt.Fprintln(w, replaceUsersRefuse)
		return 2
	}
	// Единственное, что пишется на диск, — автокопия ЦЕЛИ: слой выбирается
	// явно (пароль / без пароля), как у backup.
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Перед заменой программа сохранит на диск АВТОКОПИЮ ЦЕЛИ (её нынешнее состояние; источник на диск не пишется).")
	layer, warning, code := backupLayerChoice(in, w, errOut, isTTY, f.pwFile, f.noPw)
	if code != 0 {
		return code
	}
	fmt.Fprintln(w, warning)
	if !f.yes {
		if !isTTY {
			fmt.Fprintln(errOut, "Действие не выполнено: без терминала требуется флаг -yes (для скриптов).")
			return 2
		}
		fmt.Fprint(w, "Заменить данные цели данными источника? (y/n): ")
		if a := strings.ToLower(strings.TrimSpace(readLine(in))); a != "y" && a != "yes" {
			fmt.Fprintln(w, "Отменено.")
			return 2
		}
		if askUsers {
			fmt.Fprint(w, replaceUsersPrompt)
			if a := strings.ToLower(strings.TrimSpace(readLine(in))); a != replaceUsersWord {
				fmt.Fprintln(w, "Отменено: ничего не записано.")
				return 2
			}
			targetOK = true
		}
		if xrayOK {
			fmt.Fprint(w, "Применение перезапустит XRay: все текущие подключения по XRay оборвутся. Перезапустить XRay? (y/n; чтобы перенести без XRay — отмените и повторите с -skip-xray): ")
			if a := strings.ToLower(strings.TrimSpace(readLine(in))); a != "y" && a != "yes" {
				fmt.Fprintln(w, "Отменено: ничего не записано.")
				return 2
			}
		}
	}
	dir, err := userBackupsDir()
	if err == nil {
		err = os.MkdirAll(dir, 0o700)
	}
	if err != nil {
		backupErr(errOut, "Каталог автокопии цели не определён — замена запрещена: ", err)
		return 1
	}
	opt := core.MigrateOptions{AddressConfirmed: f.addrOK || !compat.NeedAddressConfirm}
	opt.RestoreOptions = core.RestoreOptions{ToolVersion: version.String(), Now: now, Resolve: net.LookupIP, Layer: layer, AutoCopyDir: dir}
	opt.ConfirmXRay = func() bool { return xrayOK }
	opt.TargetConfirmed = targetOK
	opt.Ctx, opt.Progress = ctx, cliProgress(errOut, isTTY)
	auto, outs, err := m.Apply(opt)
	endProgress(errOut, isTTY)
	if errors.Is(err, core.ErrCanceled) {
		fmt.Fprintln(w, "Отменено — на цель ничего не записано.")
		if auto != "" {
			fmt.Fprintln(w, "Автокопия цели уже сохранена: "+auto)
		}
		return 2
	}
	if err != nil {
		backupErr(errOut, "", err)
		if errors.Is(err, core.ErrRestoreStopped) {
			return exitRestoreStopped // остановлено до записи (автокопия не снята и т. п.)
		}
		return 1
	}
	printLines(w, core.MigrationOutcomeLines(auto, layer.Name() == core.PasswordLayerName, outs))
	code = 0
	for _, o := range outs {
		if o.State != core.RestoreDone {
			code = 1
		}
	}
	return code
}
