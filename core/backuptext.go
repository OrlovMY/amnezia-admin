package core

// Тексты копии и переезда — одни для CLI и GUI (одно место правки).

import (
	"fmt"
	"path/filepath"
	"strings"
)

// BackupUnencryptedWarning — SEC-01 (решение ядра, пока нет шифрования Р-1):
// показывается ДО записи копии (CLI — в выводе, GUI — в окне сохранения).
// Без жаргона (AU-UX Low).
const BackupUnencryptedWarning = `ВНИМАНИЕ: файл копии НЕ ЗАШИФРОВАН.
В нём секретный ключ вашего сервера и общие секреты подключения всех клиентов (для XRay — ещё ключ маскировки и личные коды клиентов).
Кто получит этот файл, сможет подключаться под любым клиентом и выдавать себя за ваш сервер.
Храните его как пароль администратора сервера: не отправляйте в мессенджеры, почту и облако без шифрования; удалите после переезда.
Доступ к файлу закрыт только для других пользователей этого компьютера (на Linux и macOS); на Windows программа такой запрет не ставит.
Если файл утёк — смените ключ сервера и выдайте всем клиентам новые конфиги.`

// IssuedConfigsNote — одна формулировка о выданных конфигах (AU-UX Low).
const IssuedConfigsNote = "Выданные конфиги продолжат работать на новом сервере, если он получит прежний адрес или конфиги выданы по имени, которое вы перенаправите на новый сервер. Приватных ключей клиентов на сервере нет — и в копии тоже."

// AmneziaAppSteps — Р-3, шаги для приложения Amnezia после переезда
// (amnezia-client 94b51df: installController.cpp 1207 и 1234-1268,
// PageSettingsServerData.qml 142, 172). AU-UX M3: нумерованные шаги,
// предостережение — отдельной строкой.
var AmneziaAppSteps = []string{
	"Приложение Amnezia помнит параметры нового сервера со своей установки. Чтобы оно выдавало новые конфиги верно:",
	"  1. В приложении откройте настройки сервера.",
	"  2. Нажмите «Удалить сервер из приложения» (протоколы на сервере останутся).",
	"  3. Добавьте сервер заново по тем же данным SSH (приложение само создаст на сервере своего клиента «Admin […]»).",
	"  !!! НЕ нажимайте «Очистить сервер от протоколов и сервисов Amnezia» — это удалит протоколы с сервера.",
	"  «Проверить сервер на наличие ранее установленных сервисов» уже известные протоколы не обновляет.",
}

// AmneziaAppAfterRestore — те же шаги одной строкой-абзацем.
var AmneziaAppAfterRestore = strings.Join(AmneziaAppSteps, "\n")

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

// RemovedLines — AU-UX M2: кто пропадёт с нового сервера — первым разделом.
func RemovedLines(rp *RestorePlan) []string {
	var out []string
	for _, it := range rp.Items {
		if len(it.Removed) > 0 {
			out = append(out, fmt.Sprintf("  %s: %s", it.Container, strings.Join(it.Removed, ", ")))
		}
	}
	if len(out) == 0 {
		return nil
	}
	return append([]string{"Будут УДАЛЕНЫ клиенты нового сервера (их нет в копии):"}, out...)
}

// CompatStopLines — AU-UX Low: при СТОП расхождения отдельным списком.
func CompatStopLines(r *CompatReport) []string {
	if !r.Stop {
		return nil
	}
	out := []string{"ПЕРЕЕЗД ОСТАНОВЛЕН до записи. Исправьте на новом сервере и повторите (обновление версии при переезде программа не делает):"}
	n := 0
	for _, row := range r.Rows {
		if row.State != CompatMatch {
			n++
			out = append(out, fmt.Sprintf("  %d. %s, %s: %s", n, row.Container, row.What, row.Text))
		}
	}
	return out
}

// RestorePlanLines — предпросмотр «заменить целиком».
func RestorePlanLines(rp *RestorePlan) []string {
	out := []string{"План «заменить целиком» (файлы контейнеров на новом сервере заменяются содержимым копии):"}
	for _, it := range rp.Items {
		line := fmt.Sprintf("  %s (%s): клиентов в копии %d", it.Container, it.Proto, it.Clients)
		if len(it.Removed) > 0 {
			line += fmt.Sprintf("; удаляется клиентов нового сервера: %d (список выше)", len(it.Removed))
		}
		if it.RestartsXRay {
			line += "; XRay будет ПЕРЕЗАПУЩЕН — все его подключения оборвутся"
		}
		out = append(out, line)
	}
	return out
}

// RestoreOutcomeLines — итог переезда: исход и граница проверки у каждого
// контейнера; при частичном переносе — прямо, что уже заменено (и не
// откатывается) и что делать с остальным.
func RestoreOutcomeLines(autoCopy string, outs []RestoreOutcome) []string {
	out := []string{"Автокопия нового сервера до замены: " + autoCopy}
	var done, notDone []string
	for _, o := range outs {
		line := fmt.Sprintf("  %s: %s", o.Container, o.State)
		if o.Err != nil {
			line += " — " + MaskText(o.Err.Error())
		}
		out = append(out, line)
		if o.State == RestoreDone {
			out = append(out, "      "+o.Checked)
			done = append(done, o.Container)
		} else {
			notDone = append(notDone, o.Container)
		}
	}
	if len(done) > 0 {
		out = append(out, RestoreOutsideNote)
	}
	if len(done) > 0 && len(notDone) > 0 {
		out = append(out, "ПЕРЕНЕСЕНО ЧАСТИЧНО. Уже заменены и НЕ откатываются: "+strings.Join(done, ", ")+
			". Не восстановлены: "+strings.Join(notDone, ", ")+
			". Устраните причину (см. выше) и запустите восстановление из той же копии ещё раз: перенесённые контейнеры уже совпадают с копией, проверка их пропустит без расхождений.")
	}
	out = append(out, ForeignConfigsNote)
	return append(out, AmneziaAppSteps...)
}
