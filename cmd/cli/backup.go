package main

// Копия пользователей и переезд (4/5): подкоманды backup, backup-info,
// restore. Ядро — core/backup.go, core/migrate.go, core/restore.go.
//
// Коды выхода: 0 — сделано; 1 — ошибка; 2 — не подтверждено (как у прочих
// подкоманд); 3 — копия записана, но неполная; 4 — переезд остановлен
// проверкой нового сервера (расхождение или «не удалось узнать»).

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"amnezia-admin/core"
	"amnezia-admin/internal/version"
)

const (
	exitBackupIncomplete = 3
	exitRestoreStopped   = 4
)

func userBackupsDir() (string, error) { return core.UserBackupsDir() }

func printLines(w io.Writer, lines []string) {
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}

func printBackupSummary(w io.Writer, b *core.Backup) { printLines(w, core.BackupSummaryLines(b)) }

// runBackup — backup [-o файл] [-password-file F | -no-password].
func runBackup(ctx context.Context, in io.Reader, w, errOut io.Writer, isTTY bool, sess *core.Session, out, pwFile string, noPw bool, now time.Time) int {
	in = bufio.NewReader(in)
	layer, warning, code := backupLayerChoice(in, w, errOut, isTTY, pwFile, noPw)
	if code != 0 {
		return code
	}
	progress := cliProgress(errOut, isTTY)
	b, err := sess.CollectBackupCtx(ctx, version.String(), now, net.LookupIP, progress)
	if errors.Is(err, core.ErrCanceled) {
		endProgress(errOut, isTTY)
		fmt.Fprintln(w, "Отменено — копия не сохранена.")
		return 2
	}
	if err != nil {
		backupErr(errOut, "Копия не снята: ", err)
		return 1
	}
	defaultName := false
	if out == "" {
		dir, err := userBackupsDir()
		if err != nil {
			backupErr(errOut, "Копия не записана: ", err)
			return 1
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			backupErr(errOut, "Копия не записана: каталог не создан: ", err)
			return 1
		}
		out = filepath.Join(dir, core.BackupFileName(b.Server.Host, now))
		defaultName = true
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		backupErr(errOut, "Копия не записана: ", err)
		return 1
	}
	printBackupSummary(w, b)
	fmt.Fprintln(w)
	fmt.Fprintln(w, warning)
	fmt.Fprintln(w)
	// имя по умолчанию — уникальное («(2)»…); явное -o занятым не затирается
	if defaultName {
		abs, err = core.WriteBackupFileUniqueCtx(ctx, abs, b, layer, progress)
	} else {
		err = core.WriteBackupFileCtx(ctx, abs, b, layer, progress)
	}
	endProgress(errOut, isTTY)
	if errors.Is(err, core.ErrCanceled) {
		fmt.Fprintln(w, "Отменено — копия не сохранена.")
		return 2
	}
	if err != nil {
		backupErr(errOut, "Копия не записана: ", err)
		return 1
	}
	fmt.Fprintln(w, "Копия записана: "+abs)
	if !b.Complete {
		return exitBackupIncomplete
	}
	return 0
}

// runBackupInfo — backup-info [-password-file F] <файл>: без ключа и без сети.
func runBackupInfo(w, errOut io.Writer, args []string) int {
	fs := flag.NewFlagSet("backup-info", flag.ContinueOnError)
	fs.SetOutput(errOut)
	pwFile := fs.String("password-file", "", "файл с паролем зашифрованной копии")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(errOut, "Использование: amnezia-admin backup-info [-password-file <файл>] <файл.aabk>")
		return 1
	}
	layers, code := readLayers(w, errOut, stdinIsTTY(), fs.Arg(0), *pwFile)
	if code != 0 {
		return code
	}
	b, err := core.ReadBackupFile(fs.Arg(0), layers...)
	if err != nil {
		backupErr(errOut, "", err)
		return 1
	}
	printBackupSummary(w, b)
	return 0
}

func printCompat(w io.Writer, r *core.CompatReport) { printLines(w, core.CompatLines(r)) }

// backupErr — единственный вывод ошибки в этом файле: через errText
// (core.MaskText на границе; SEC-01 р2). Сторож TestBackupCLIErrorsMasked
// запрещает прямой вывод err.
func backupErr(errOut io.Writer, prefix string, err error) {
	fmt.Fprintln(errOut, prefix+errText(err, func(x string) string { return x }))
}

// replaceUsersText — вопрос отдельного подтверждения (на новом сервере
// есть пользователи или конфликты с копией).
const (
	replaceUsersWord   = "записать"
	replaceUsersPrompt = "На новом сервере есть пользователи (список выше) — после замены их не будет. Всё равно записать? Введите «" + replaceUsersWord + "» (иначе — отмена): "
	replaceUsersRefuse = "ПЕРЕЕЗД ОСТАНОВЛЕН: на новом сервере есть пользователи или конфликты с копией (список выше). Если вы всё равно хотите их заменить — повторите с флагом -replace-users."
)

// targetListMax — сколько имён пользователей цели печатается в терминале
// (число печатается всегда).
const targetListMax = 50

// bypassTargetGate — шов теста (AU-LOGIC З2): обойти проверку CLI выше
// ядра, чтобы убедиться, что ядро без подтверждения само не пишет.
var bypassTargetGate bool

// runRestore — restore -file X [-apply] [-address-changes] [-skip-xray] [-replace-users] [-yes].
func runRestore(ctx context.Context, in io.Reader, w, errOut io.Writer, isTTY bool, sess *core.Session, file, pwFile string, apply, addrOK, skipXRay, replaceUsers, yes bool, now time.Time) int {
	if file == "" {
		fmt.Fprintln(errOut, "Не задан файл копии: -file <файл.aabk>")
		return 1
	}
	in = bufio.NewReader(in) // один буфер на все вопросы
	layers, code := readLayers(w, errOut, isTTY, file, pwFile)
	if code != 0 {
		return code
	}
	b, err := core.ReadBackupFile(file, layers...)
	if err != nil {
		backupErr(errOut, "", err)
		return 1
	}
	compat, err := sess.CheckTarget(b, net.LookupIP)
	if err != nil {
		backupErr(errOut, "", err)
		return exitRestoreStopped
	}
	var rp *core.RestorePlan
	if !compat.Stop {
		if rp, err = sess.PlanRestore(b, compat, true); err != nil {
			backupErr(errOut, "План не построен: ", err)
			return exitRestoreStopped
		}
		// Задача владельца 07.10: пользователи нового сервера и конфликты
		// с копией — первым разделом, с числом.
		if rp.NeedsTargetConfirm() {
			fmt.Fprintln(w, core.TargetWarnHead(rp))
			printLines(w, core.TargetWarnLines(rp, targetListMax))
			fmt.Fprintln(w)
		}
		// AU-UX M2: кто пропадёт.
		if rm := core.RemovedLines(rp); rm != nil {
			printLines(w, rm)
			fmt.Fprintln(w)
		}
	}
	printBackupSummary(w, b)
	fmt.Fprintln(w)
	printCompat(w, compat)
	if compat.Stop {
		fmt.Fprintln(w)
		printLines(w, core.CompatStopLines(compat))
		return exitRestoreStopped
	}
	if compat.NeedAddressConfirm && apply && !addrOK {
		fmt.Fprintln(w, "ПЕРЕЕЗД ОСТАНОВЛЕН: адрес другой или не проверен. Если вы понимаете последствия (см. «Адрес» выше) — повторите с флагом -address-changes.")
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
	if hasXRay && skipXRay {
		fmt.Fprintln(w, "Выбрано -skip-xray: XRay переноситься не будет — на новом сервере он останется прежним.")
	}
	if !apply {
		fmt.Fprintln(w, "\nЭто предпросмотр: на сервер ничего не записано. Чтобы выполнить — добавьте -apply.")
		return 0
	}
	// AU-UX M1: XRay — только явным выбором: перезапуск (вопрос или -yes)
	// или -skip-xray. Ответ «нет» — отмена всего, не молчаливый пропуск.
	xrayOK := hasXRay && !skipXRay
	// Пользователи на новом сервере: без терминала или с -yes — только с
	// -replace-users; в терминале — отдельный вопрос с вводом слова.
	askUsers := rp.NeedsTargetConfirm() && !replaceUsers
	// подтверждение для ядра — только полученное (флаг или ввод слова);
	// пользователей нет — подтверждать нечего (AU-LOGIC З2)
	targetOK := !rp.NeedsTargetConfirm() || replaceUsers
	if askUsers && (yes || !isTTY) && !bypassTargetGate {
		fmt.Fprintln(w, replaceUsersRefuse)
		return 2
	}
	if !yes {
		if !isTTY {
			fmt.Fprintln(errOut, "Действие не выполнено: без терминала требуется флаг -yes (для скриптов).")
			return 2
		}
		fmt.Fprint(w, "Заменить данные нового сервера содержимым копии? (y/n): ")
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
	// автокопия наследует режим копии-источника (тот же пароль, без
	// повторного вопроса)
	opt := core.RestoreOptions{ToolVersion: version.String(), Now: now, Resolve: net.LookupIP, Layer: layers[len(layers)-1]}
	dir, err := userBackupsDir()
	if err == nil {
		err = os.MkdirAll(dir, 0o700)
	}
	if err != nil {
		backupErr(errOut, "Каталог автокопии не определён — замена запрещена: ", err)
		return 1
	}
	opt.AutoCopyDir = dir
	opt.ConfirmXRay = func() bool { return xrayOK }
	opt.TargetConfirmed = targetOK
	opt.Ctx, opt.Progress = ctx, cliProgress(errOut, isTTY)
	auto, outs, err := sess.Restore(rp, opt)
	endProgress(errOut, isTTY)
	if errors.Is(err, core.ErrCanceled) {
		fmt.Fprintln(w, "Отменено — на сервер ничего не записано.")
		if auto != "" {
			fmt.Fprintln(w, "Автокопия нового сервера уже сохранена: "+auto)
		}
		return 2
	}
	if err != nil {
		backupErr(errOut, "", err)
		return 1
	}
	printLines(w, core.RestoreOutcomeLines(auto, opt.Layer.Name() == core.PasswordLayerName, outs))
	code = 0
	for _, o := range outs {
		if o.State != core.RestoreDone {
			code = 1
		}
	}
	return code
}

// cliProgress — прогресс строкой в stderr, только при терминале (без
// терминала вывод прежний). С началом записи на сервер — предупреждение,
// что прервать нельзя.
func cliProgress(errOut io.Writer, isTTY bool) core.ProgressFunc {
	if !isTTY {
		return nil
	}
	warned := false
	return func(p core.Progress) {
		if p.Writing && !warned {
			warned = true
			fmt.Fprint(errOut, "\r\033[K")
			fmt.Fprintln(errOut, "Идёт запись на сервер — прервать нельзя (Ctrl+C не действует), дождитесь итога.")
		}
		line := p.Text
		if p.Total > 0 {
			line = fmt.Sprintf("[%3d%%] %s", p.Done*100/p.Total, p.Text)
		}
		fmt.Fprint(errOut, "\r\033[K"+line)
	}
}

// endProgress — закончить строку прогресса.
func endProgress(errOut io.Writer, isTTY bool) {
	if isTTY {
		fmt.Fprint(errOut, "\r\033[K")
	}
}
