package guiview

import (
	"fmt"

	"amnezia-admin/core"
)

// Тексты окна «Конфигурация клиента» (меню «Показать QR» / «Сохранить
// конфигурацию…»). Дословно сверяются тестом; три состояния поиска — три
// разных текста (CLAUDE.md, признак 1).

// Пункты меню сохранённого конфига (задача владельца 01.10.2026: «для
// каждого ключа должно быть QR и сохранить конфигурацию»).
const (
	MenuShowQR     = "Показать QR"
	MenuSaveConfig = "Сохранить конфигурацию…"
)

// SavedConfigTitle — заголовок окна.
func SavedConfigTitle(name string) string {
	return fmt.Sprintf("Конфигурация «%s»", name)
}

// SavedNotFoundText — конфиг не сохранялся на этом компьютере.
const SavedNotFoundText = "Конфигурация этого клиента не сохранялась на этом компьютере. " +
	"Восстановить её нельзя: ключ есть только у самого клиента. " +
	"Можно перевыпустить конфиг — прежний конфиг клиента после этого работать не будет."

// SavedUnreadableText — прочитать не удалось: сохранён ли — неизвестно.
func SavedUnreadableText(why string) string {
	return "Не удалось прочитать каталог конфигураций или файл, поэтому неизвестно, " +
		"сохранён ли конфиг этого клиента на этом компьютере. Подробности: " + why
}

// SavedFoundText — откуда взят конфиг.
func SavedFoundText(sc core.SavedConfig) string {
	s := "Конфиг из файла: " + sc.Path
	if sc.Matches > 1 {
		s += fmt.Sprintf("\nФайлов с ключом этого клиента: %d; показан первый по имени.", sc.Matches)
	}
	return s
}

// SavedCheckPending — пока идёт сверка с сервером.
const SavedCheckPending = "Сверяю с сервером…"

// SavedCheckText — итог сверки сохранённого конфига с сервером. Ключ клиента
// совпадает всегда (по нему файл найден); PresharedKey и адрес — три
// состояния; Endpoint показывается как есть.
func SavedCheckText(ch core.SavedCheck) string {
	line := func(what string, st core.CheckState) string {
		switch st {
		case core.CheckSame:
			return what + " совпадает с сервером."
		case core.CheckDiffer:
			return "ВНИМАНИЕ: " + what + " в файле НЕ совпадает с сервером — с этим конфигом клиент, скорее всего, не подключится. Файл устарел; если нужен рабочий конфиг — перевыпустите его."
		}
		return what + " с сервером не сверен" + reason(ch.Why) + "."
	}
	s := "Ключ клиента совпадает с ключом на сервере.\n" +
		line("PresharedKey", ch.PSK) + "\n" +
		line("Адрес клиента (Address)", ch.Address)
	if ch.Endpoint != "" {
		s += "\nАдрес сервера в файле (Endpoint): " + ch.Endpoint + " — как был при сохранении."
	}
	return s
}

func reason(why string) string {
	if why == "" {
		return ""
	}
	return ": " + why
}
