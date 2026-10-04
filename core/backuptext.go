package core

// Тексты копии и переезда — одни для CLI и GUI (одно место правки).

import (
	"fmt"
	"path/filepath"
	"strings"
)

// BackupUnencryptedWarning — SEC-01 (решение ядра, пока нет шифрования Р-1):
// показывается ДО записи копии (CLI — в выводе, GUI — в окне сохранения).
const BackupUnencryptedWarning = `ВНИМАНИЕ: файл копии НЕ ЗАШИФРОВАН.
В нём приватный ключ сервера WireGuard/AmneziaWG, PSK всех клиентов, ключ Reality и UUID клиентов XRay.
Кто получит этот файл, сможет подключаться под любым клиентом и выдавать себя за ваш сервер.
Храните его как пароль root: не отправляйте в мессенджеры, почту и облако без шифрования; удалите после переезда.
Права 600 защищают файл только от других пользователей этого компьютера; на Windows они не выставляются.
Если файл утёк — перевыпустите ключ сервера и конфиги всех клиентов.`

// AmneziaAppAfterRestore — Р-3 (amnezia-client 94b51df: installController.cpp
// 1207 и 1234-1268, PageSettingsServerData.qml 142, 172).
const AmneziaAppAfterRestore = "Приложение Amnezia помнит параметры нового сервера со своей установки. Чтобы оно выдавало новые конфиги верно: в приложении — настройки сервера → «Удалить сервер из приложения» (протоколы на сервере останутся), затем добавьте сервер заново по тем же данным SSH. НЕ нажимайте «Очистить сервер от протоколов и сервисов Amnezia» — это удалит протоколы с сервера. «Проверить сервер на наличие ранее установленных сервисов» уже известные протоколы не обновляет. При повторном добавлении приложение само создаст на сервере своего клиента «Admin […]»."

// UserBackupsDir — каталог копий по умолчанию: рядом с каталогом конфигов,
// «Резервные копии» (абсолютный путь или ошибка).
func UserBackupsDir() (string, error) {
	cfg, err := UserConfigsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfg), "Резервные копии"), nil
}

var fileStateText = map[string]string{FileSaved: "сохранён", FileAbsent: "нет на сервере", FileUnreadable: "НЕ ПРОЧИТАН"}
var ctrStateText = map[string]string{CtrSaved: "сохранён", CtrNotIncluded: "не входит в копию (протокол не поддерживается)",
	CtrUnreadable: "НЕ ПРОЧИТАН", CtrInconsistent: "НЕСОГЛАСОВАННЫЙ СНИМОК (файлы менялись при чтении)"}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func issuedAddressLine(a IssuedAddress) string {
	switch {
	case a.Kind == AddressKindIP:
		return "IP " + a.Value + " — при переезде на другой IP старые конфиги к новому серверу не придут, пока адрес не перенесён у хостера"
	case a.Kind == AddressKindName && a.ResolveStatus == ResolveOK:
		return "имя " + a.Value + " (сейчас " + a.ResolvedIP + ") — при переезде перенаправьте имя на новый сервер"
	case a.Kind == AddressKindName:
		return "имя " + a.Value + " (разрешить его сейчас не удалось)"
	}
	return "в копии нет адреса"
}

// BackupSummaryLines — состав копии без содержимого файлов. Строка о
// полноте не говорит «все сохранены», если есть «не входит» (наблюдение
// AU-LOGIC).
func BackupSummaryLines(b *Backup) []string {
	var out []string
	add := func(f string, a ...any) { out = append(out, fmt.Sprintf(f, a...)) }
	add("Копия: формат %d, снята %s, программа %s", b.FormatVersion, b.CreatedAt, b.ToolVersion)
	add("Сервер: %s, ключ хоста %s", b.Server.Host, dash(b.Server.HostKeySHA256))
	add("Адрес в выданных конфигах: %s", issuedAddressLine(b.IssuedAddress))
	var notIncl []string
	for _, c := range b.Containers {
		line := fmt.Sprintf("  %s (%s): %s", c.Name, c.Proto, ctrStateText[c.Status])
		if c.Reason != "" && c.Status != CtrSaved {
			line += " — " + c.Reason
		}
		out = append(out, line)
		if c.Status == CtrNotIncluded {
			notIncl = append(notIncl, c.Name)
			continue
		}
		if c.Status == CtrSaved {
			v := c.Version
			if c.VersionState != VersionKnown {
				v = "НЕ ОПРЕДЕЛЕНА (" + c.VersionReason + ")"
			}
			add("      версия %s, порт %s, подсеть %s", v, dash(c.Port), dash(c.Subnet))
		}
		for _, f := range c.Files {
			add("      %s: %s", f.Name, fileStateText[f.Status])
		}
	}
	switch {
	case !b.Complete:
		add("Копия НЕПОЛНАЯ: часть данных сервера не прочитана (см. выше).")
	case len(notIncl) > 0:
		add("Все поддерживаемые протоколы сохранены целиком. Не входят в копию: %s.", strings.Join(notIncl, ", "))
	default:
		add("Все протоколы сервера сохранены целиком.")
	}
	return out
}

// CompatLines — проверка нового сервера по-человечески.
func CompatLines(r *CompatReport) []string {
	out := []string{"Проверка нового сервера:"}
	for _, row := range r.Rows {
		out = append(out, fmt.Sprintf("  %s, %s: %s — %s", row.Container, row.What, row.State, row.Text))
	}
	if len(r.Untouched) > 0 {
		out = append(out, "  На новом сервере есть и не будут тронуты: "+strings.Join(r.Untouched, ", "))
	}
	out = append(out, "Адрес: "+r.AddressText, ForeignConfigsNote)
	return out
}

// RestorePlanLines — предпросмотр «заменить целиком».
func RestorePlanLines(rp *RestorePlan) []string {
	out := []string{"План «заменить целиком» (файлы контейнеров на новом сервере заменяются содержимым копии):"}
	for _, it := range rp.Items {
		line := fmt.Sprintf("  %s (%s): клиентов в копии %d", it.Container, it.Proto, it.Clients)
		if len(it.Removed) > 0 {
			line += "; будут УДАЛЕНЫ клиенты нового сервера: " + strings.Join(it.Removed, ", ")
		}
		if it.RestartsXRay {
			line += "; XRay будет ПЕРЕЗАПУЩЕН — все его подключения оборвутся"
		}
		out = append(out, line)
	}
	return out
}

// RestoreOutcomeLines — итог переезда.
func RestoreOutcomeLines(autoCopy string, outs []RestoreOutcome) []string {
	out := []string{"Автокопия нового сервера до замены: " + autoCopy}
	for _, o := range outs {
		line := fmt.Sprintf("  %s: %s", o.Container, o.State)
		if o.Err != nil {
			line += " — " + MaskText(o.Err.Error())
		}
		out = append(out, line)
	}
	return append(out, RestoreRuntimeNote, ForeignConfigsNote, AmneziaAppAfterRestore)
}
