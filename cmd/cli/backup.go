package main

// Копия пользователей и переезд (4/5): подкоманды backup, backup-info,
// restore. Ядро — core/backup.go, core/migrate.go, core/restore.go.
//
// Коды выхода: 0 — сделано; 1 — ошибка; 2 — не подтверждено (как у прочих
// подкоманд); 3 — копия записана, но неполная; 4 — переезд остановлен
// проверкой нового сервера (расхождение или «не удалось узнать»).

import (
	"bufio"
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

// runBackup — backup [-o файл].
func runBackup(w, errOut io.Writer, sess *core.Session, out string, now time.Time) int {
	b, err := sess.CollectBackup(version.String(), now, net.LookupIP)
	if err != nil {
		fmt.Fprintln(errOut, "Копия не снята:", err)
		return 1
	}
	if out == "" {
		dir, err := userBackupsDir()
		if err != nil {
			fmt.Fprintln(errOut, "Копия не записана:", err)
			return 1
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			fmt.Fprintln(errOut, "Копия не записана: каталог не создан:", err)
			return 1
		}
		out = filepath.Join(dir, core.BackupFileName(b.Server.Host, now))
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		fmt.Fprintln(errOut, "Копия не записана:", err)
		return 1
	}
	printBackupSummary(w, b)
	fmt.Fprintln(w)
	fmt.Fprintln(w, core.BackupUnencryptedWarning)
	fmt.Fprintln(w)
	if err := core.WriteBackupFile(abs, b, core.PlainLayer{}); err != nil {
		fmt.Fprintln(errOut, "Копия не записана:", err)
		return 1
	}
	fmt.Fprintln(w, "Копия записана: "+abs)
	if !b.Complete {
		return exitBackupIncomplete
	}
	return 0
}

// runBackupInfo — backup-info <файл>: без ключа и без сети.
func runBackupInfo(w, errOut io.Writer, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(errOut, "Использование: amnezia-admin backup-info <файл.aabk>")
		return 1
	}
	b, err := core.ReadBackupFile(args[0], core.PlainLayer{})
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	printBackupSummary(w, b)
	return 0
}

func printCompat(w io.Writer, r *core.CompatReport) { printLines(w, core.CompatLines(r)) }

// runRestore — restore -file X [-apply] [-address-changes] [-yes].
func runRestore(in io.Reader, w, errOut io.Writer, isTTY bool, sess *core.Session, file string, apply, addrOK, yes bool, now time.Time) int {
	if file == "" {
		fmt.Fprintln(errOut, "Не задан файл копии: -file <файл.aabk>")
		return 1
	}
	in = bufio.NewReader(in) // один буфер на все вопросы
	b, err := core.ReadBackupFile(file, core.PlainLayer{})
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	printBackupSummary(w, b)
	fmt.Fprintln(w)
	compat, err := sess.CheckTarget(b, net.LookupIP)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return exitRestoreStopped
	}
	printCompat(w, compat)
	if compat.Stop {
		fmt.Fprintln(w, "ПЕРЕЕЗД ОСТАНОВЛЕН до записи: исправьте расхождения на новом сервере и повторите. Обновление версии при переезде программа не делает.")
		return exitRestoreStopped
	}
	if compat.NeedAddressConfirm && apply && !addrOK {
		fmt.Fprintln(w, "ПЕРЕЕЗД ОСТАНОВЛЕН: адрес другой или не проверен. Если вы понимаете последствия (см. «Адрес» выше) — повторите с флагом -address-changes.")
		return exitRestoreStopped
	}
	rp, err := sess.PlanRestore(b, compat, true)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return exitRestoreStopped
	}
	fmt.Fprintln(w)
	printLines(w, core.RestorePlanLines(rp))
	for _, it := range rp.Items {
		if it.RestartsXRay {
			fmt.Fprintln(w, "    "+restartWarningText())
		}
	}
	if !apply {
		fmt.Fprintln(w, "\nЭто предпросмотр: на сервер ничего не записано. Чтобы выполнить — добавьте -apply.")
		return 0
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
	}
	opt := core.RestoreOptions{ToolVersion: version.String(), Now: now, Resolve: net.LookupIP, Layer: core.PlainLayer{}}
	dir, err := userBackupsDir()
	if err == nil {
		err = os.MkdirAll(dir, 0o700)
	}
	if err != nil {
		fmt.Fprintln(errOut, "Каталог автокопии не определён — замена запрещена:", err)
		return 1
	}
	opt.AutoCopyDir = dir
	opt.ConfirmXRay = func() bool {
		if yes {
			return true
		}
		fmt.Fprint(w, "Применение перезапустит XRay: все текущие подключения по XRay оборвутся. Перезапустить XRay? (y/n): ")
		a := strings.ToLower(strings.TrimSpace(readLine(in)))
		return a == "y" || a == "yes"
	}
	auto, outs, err := sess.Restore(rp, opt)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	printLines(w, core.RestoreOutcomeLines(auto, outs))
	code := 0
	for _, o := range outs {
		if o.State != core.RestoreDone {
			code = 1
		}
	}
	return code
}
