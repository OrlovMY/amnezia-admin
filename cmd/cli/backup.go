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

// BackupUnencryptedWarning — SEC-01 (решение ядра, до решения Р-1): громко,
// ДО записи копии.
const BackupUnencryptedWarning = `ВНИМАНИЕ: файл копии НЕ ЗАШИФРОВАН.
В нём приватный ключ сервера WireGuard/AmneziaWG, PSK всех клиентов, ключ Reality и UUID клиентов XRay.
Кто получит этот файл, сможет подключаться под любым клиентом и выдавать себя за ваш сервер.
Храните его как пароль root: не отправляйте в мессенджеры, почту и облако без шифрования; удалите после переезда.
Права 600 защищают файл только от других пользователей этого компьютера; на Windows они не выставляются.
Если файл утёк — перевыпустите ключ сервера и конфиги всех клиентов.`

// AmneziaAppAfterRestore — Р-3 (amnezia-client 94b51df: installController.cpp
// 1207 и 1234-1268, PageSettingsServerData.qml 142, 172).
const AmneziaAppAfterRestore = "Приложение Amnezia помнит параметры нового сервера со своей установки. Чтобы оно выдавало новые конфиги верно: в приложении — настройки сервера → «Удалить сервер из приложения» (протоколы на сервере останутся), затем добавьте сервер заново по тем же данным SSH. НЕ нажимайте «Очистить сервер от протоколов и сервисов Amnezia» — это удалит протоколы с сервера. «Проверить сервер на наличие ранее установленных сервисов» уже известные протоколы не обновляет. При повторном добавлении приложение само создаст на сервере своего клиента «Admin […]»."

// UserBackupsDir — каталог копий по умолчанию (рядом с каталогом конфигов).
func userBackupsDir() (string, error) {
	cfg, err := core.UserConfigsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfg), "Резервные копии"), nil
}

var fileStateText = map[string]string{core.FileSaved: "сохранён", core.FileAbsent: "нет на сервере", core.FileUnreadable: "НЕ ПРОЧИТАН"}
var ctrStateText = map[string]string{core.CtrSaved: "сохранён", core.CtrNotIncluded: "не входит в копию (протокол не поддерживается)",
	core.CtrUnreadable: "НЕ ПРОЧИТАН", core.CtrInconsistent: "НЕСОГЛАСОВАННЫЙ СНИМОК (файлы менялись при чтении)"}

func addressLine(a core.IssuedAddress) string {
	switch {
	case a.Kind == core.AddressKindIP:
		return "IP " + a.Value + " — при переезде на другой IP старые конфиги к новому серверу не придут, пока адрес не перенесён у хостера"
	case a.Kind == core.AddressKindName && a.ResolveStatus == core.ResolveOK:
		return "имя " + a.Value + " (сейчас " + a.ResolvedIP + ") — при переезде перенаправьте имя на новый сервер"
	case a.Kind == core.AddressKindName:
		return "имя " + a.Value + " (разрешить его сейчас не удалось)"
	}
	return "в копии нет адреса"
}

// printBackupSummary — состав копии без содержимого файлов. Строка о
// полноте не говорит «полная», если есть «не входит» (наблюдение AU-LOGIC).
func printBackupSummary(w io.Writer, b *core.Backup) {
	fmt.Fprintf(w, "Копия: формат %d, снята %s, программа %s\n", b.FormatVersion, b.CreatedAt, b.ToolVersion)
	fmt.Fprintf(w, "Сервер: %s, ключ хоста %s\n", b.Server.Host, orDash(b.Server.HostKeySHA256))
	fmt.Fprintf(w, "Адрес в выданных конфигах: %s\n", addressLine(b.IssuedAddress))
	var notIncl []string
	for _, c := range b.Containers {
		fmt.Fprintf(w, "  %s (%s): %s", c.Name, c.Proto, ctrStateText[c.Status])
		if c.Reason != "" && c.Status != core.CtrSaved {
			fmt.Fprintf(w, " — %s", c.Reason)
		}
		fmt.Fprintln(w)
		if c.Status == core.CtrNotIncluded {
			notIncl = append(notIncl, c.Name)
			continue
		}
		if c.Status == core.CtrSaved {
			v := c.Version
			if c.VersionState != core.VersionKnown {
				v = "НЕ ОПРЕДЕЛЕНА (" + c.VersionReason + ")"
			}
			fmt.Fprintf(w, "      версия %s, порт %s, подсеть %s\n", v, orDash(c.Port), orDash(c.Subnet))
		}
		for _, f := range c.Files {
			fmt.Fprintf(w, "      %s: %s\n", f.Name, fileStateText[f.Status])
		}
	}
	switch {
	case !b.Complete:
		fmt.Fprintln(w, "Копия НЕПОЛНАЯ: часть данных сервера не прочитана (см. выше).")
	case len(notIncl) > 0:
		fmt.Fprintln(w, "Все поддерживаемые протоколы сохранены целиком. Не входят в копию: "+strings.Join(notIncl, ", ")+".")
	default:
		fmt.Fprintln(w, "Все протоколы сервера сохранены целиком.")
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

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
	fmt.Fprintln(w, BackupUnencryptedWarning)
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

func printCompat(w io.Writer, r *core.CompatReport) {
	fmt.Fprintln(w, "Проверка нового сервера:")
	for _, row := range r.Rows {
		fmt.Fprintf(w, "  %s, %s: %s — %s\n", row.Container, row.What, row.State, row.Text)
	}
	if len(r.Untouched) > 0 {
		fmt.Fprintln(w, "  На новом сервере есть и не будут тронуты: "+strings.Join(r.Untouched, ", "))
	}
	fmt.Fprintln(w, "Адрес: "+r.AddressText)
	fmt.Fprintln(w, core.ForeignConfigsNote)
}

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
	fmt.Fprintln(w, "\nПлан «заменить целиком» (файлы контейнеров на новом сервере заменяются содержимым копии):")
	for _, it := range rp.Items {
		fmt.Fprintf(w, "  %s (%s): клиентов в копии %d", it.Container, it.Proto, it.Clients)
		if len(it.Removed) > 0 {
			fmt.Fprintf(w, "; будут УДАЛЕНЫ клиенты нового сервера: %s", strings.Join(it.Removed, ", "))
		}
		fmt.Fprintln(w)
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
	fmt.Fprintln(w, "Автокопия нового сервера до замены: "+auto)
	code := 0
	for _, o := range outs {
		fmt.Fprintf(w, "  %s: %s", o.Container, o.State)
		if o.Err != nil {
			fmt.Fprintf(w, " — %s", core.MaskText(o.Err.Error()))
		}
		fmt.Fprintln(w)
		if o.State != core.RestoreDone {
			code = 1
		}
	}
	fmt.Fprintln(w, core.RestoreRuntimeNote)
	fmt.Fprintln(w, core.ForeignConfigsNote)
	fmt.Fprintln(w, AmneziaAppAfterRestore)
	return code
}
