package provision

// Что ставит каждая ревизия: таблица installSupports[rev][семейство].
// Только данные с источником; выбор ревизии — не здесь (PR 4).
//
// Семейства — те же строки, что core/backup.go protoVersion: "3.1", "2",
// "1.5" (контейнер amnezia-awg2), "старый AWG" (amnezia-awg), "WireGuard",
// "XRay".

// SupportState — три состояния, а не два: «нет данных» ≠ «не ставит».
type SupportState int

const (
	// SupportUnknown — данных нет: ревизия или семейство вне таблицы.
	// Нулевое значение — намеренно: забытая запись не превращается в «да».
	SupportUnknown SupportState = iota
	SupportYes
	SupportNo
)

func (s SupportState) String() string {
	switch s {
	case SupportYes:
		return "ставит"
	case SupportNo:
		return "не ставит"
	}
	return "нет данных"
}

// Support — клетка таблицы.
type Support struct {
	State     SupportState
	Container string // контейнер, который поднимет установка
	Source    string // файл:строки ревизии — доказательство
	// BinaryPinned — версия исполняемого протокола закреплена ревизией.
	// false — образ берётся по плавающему тегу (:latest): что умеет бинарь
	// на момент установки, скрипт не гарантирует (не проверено).
	BinaryPinned bool
	Note         string
}

func awgRow(family string) Support {
	return Support{
		State: SupportYes, Container: "amnezia-awg2", BinaryPinned: false,
		Source: map[string]string{
			"3.1": "awg/configure_container.sh:28-36 (HeaderProtectionKey…DisableCookies), :45 пустые строки удаляются",
			"2":   "awg/configure_container.sh:22-27 (S3, S4, H1-H4 — в т.ч. диапазоны), :45",
			"1.5": "awg/configure_container.sh:17-27 (Jc…H4), :37-41 I1-I5 комментариями, :45",
		}[family],
		Note: "awg/Dockerfile:1 FROM amneziavpn/amneziawg-go:latest — версия бинаря не закреплена",
	}
}

func commonRows(xrayDockerfile string) map[string]Support {
	return map[string]Support{
		"3.1": awgRow("3.1"),
		"2":   awgRow("2"),
		"1.5": awgRow("1.5"),
		"старый AWG": {
			State: SupportYes, Container: "amnezia-awg",
			Source: "awg_legacy/configure_container.sh:12-31 (wg0.conf: Jc…H4)",
			Note:   "awg_legacy/Dockerfile:1 FROM amneziavpn/amnezia-wg:latest — версия бинаря не закреплена",
		},
		"WireGuard": {
			State: SupportYes, Container: "amnezia-wireguard",
			Source: "wireguard/configure_container.sh:12-16 (wg0.conf)",
			Note:   "wireguard/Dockerfile:1 FROM alpine:3.15, wireguard-tools из apk без версии",
		},
		"XRay": {
			State: SupportYes, Container: "amnezia-xray", BinaryPinned: true,
			Source: xrayDockerfile + "; xray/configure_container.sh — ключи x25519/uuid/shortId",
			Note:   "server.json пишет само приложение (XrayConfigurator::writeServerConfigForSetup), в скриптах его нет",
		},
	}
}

// installSupports — закрытая таблица. Клетка, которой нет, — SupportUnknown.
var installSupports = map[string]map[string]Support{
	RevDev94b51df: commonRows(`xray/Dockerfile:4 ARG XRAY_RELEASE="v26.7.28"`),
	Rev5106:       commonRows(`xray/Dockerfile:4 ARG XRAY_RELEASE="v26.10.31"`),
}

// InstallSupport — клетка таблицы; вне таблицы — SupportUnknown, никогда не
// SupportNo.
func InstallSupport(rev, family string) Support {
	if row, ok := installSupports[rev]; ok {
		if s, ok := row[family]; ok {
			return s
		}
	}
	return Support{State: SupportUnknown}
}
