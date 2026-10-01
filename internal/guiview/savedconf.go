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

// SavedNotFoundText — конфиг НЕ НАЙДЕН в каталогах поиска (решение
// 01.10.2026: не «не сохранялся» — его могли сохранить в другое место).
// Перечень каталогов — абсолютными путями.
func SavedNotFoundText(searched []string) string {
	s := "Конфигурация этого клиента не найдена на этом компьютере.\nИскали в каталогах:"
	for _, p := range searched {
		s += "\n" + p
	}
	return s + "\nЕсли вы сохраняли её в другое место, откройте файл оттуда. " +
		"Иначе восстановить её нельзя — ключ есть только у самого клиента."
}

// SavedUnreadableText — прочитать не удалось: сохранён ли — неизвестно.
func SavedUnreadableText(why string) string {
	return "Не удалось прочитать каталог конфигураций или файл, поэтому неизвестно, " +
		"сохранён ли конфиг этого клиента на этом компьютере. Подробности: " + why
}

// SavedFoundText — откуда взят конфиг.
func SavedFoundText(sc core.SavedConfig) string {
	s := "Конфиг из файла: " + sc.Path
	if sc.Legacy {
		s += "\nКаталог прежних версий («Конфигурации» рядом с программой); файл не перемещается."
	} else {
		s += "\nКаталог конфигураций этой версии."
	}
	if sc.Matches > 1 {
		s += fmt.Sprintf("\nФайлов с ключом этого клиента: %d; показан первый по имени.", sc.Matches)
	}
	return s
}

// SavedServerKeyDiffers — [Peer] PublicKey файла не ключ этого сервера:
// конфиг ведёт клиента на ДРУГОЙ сервер (SEC-01 R1). QR скрыт.
const SavedServerKeyDiffers = "ВНИМАНИЕ: ключ сервера (PublicKey) в файле НЕ совпадает с ключом этого сервера — " +
	"конфиг подключит клиента к ДРУГОМУ серверу. Файл мог быть подменён. QR скрыт; не выдавайте этот конфиг, " +
	"если не уверены, откуда он."

// SavedShowQRAnyway — кнопка показа QR при несовпавшем ключе сервера.
const SavedShowQRAnyway = "Всё равно показать QR"

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
	var server string
	switch ch.ServerKey {
	case core.CheckSame:
		server = "Ключ сервера (PublicKey) совпадает с ключом этого сервера."
	case core.CheckDiffer:
		server = SavedServerKeyDiffers
	default:
		why := ch.Why
		if why == "" {
			why = ch.ServerKeyWhy
		}
		server = "Ключ сервера (PublicKey) с этим сервером не сверен" + reason(why) + "."
	}
	s := "Ключ клиента совпадает с ключом на сервере.\n" +
		server + "\n" +
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
