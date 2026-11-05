package provision

// Что ставит каждая ревизия: таблица installSupports[rev][семейство].
// Только данные с источником; выбор ревизии — не здесь (PR 4).
//
// Семейства — те же строки, что core/backup.go protoVersion: "3.1", "2",
// "1.5" (контейнер amnezia-awg2), "старый AWG" (amnezia-awg), "WireGuard",
// "XRay".

// SupportState — состояние клетки. «Нет данных» ≠ «не ставит», и «скрипт
// пишет параметры» ≠ «ставит»: оговорка живёт в самом состоянии, а не в
// соседнем поле, чтобы печать одного State не выдала непроверенное за
// знание (ревью-1 M1).
type SupportState int

const (
	// SupportUnknown — данных нет: ревизия или семейство вне таблицы.
	// Нулевое значение — намеренно: забытая запись не превращается в «да».
	SupportUnknown SupportState = iota
	// SupportYes — скрипт пишет параметры семейства И версия бинаря
	// закреплена со сверкой. Только через InstallSupport при BinaryPinned.
	SupportYes
	// SupportScriptOnly — скрипт пишет параметры семейства, но версия
	// бинаря не закреплена (образ :latest, пакет без версии, загрузка без
	// сверки суммы): умеет ли бинарь это семейство — не проверено.
	SupportScriptOnly
	// SupportPartial — скрипт ставит контейнер, но параметры, отличающие
	// семейство, не включает (AWG 1.5: I1–I5 пишутся комментариями).
	SupportPartial
	SupportNo
)

func (s SupportState) String() string {
	switch s {
	case SupportYes:
		return "ставит"
	case SupportScriptOnly:
		return "скрипт пишет параметры, версия бинаря не закреплена"
	case SupportPartial:
		return "ставит без параметров семейства"
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
	// BinaryPinned — версия исполняемого протокола закреплена ревизией и
	// проверяется (сумма). false — плавающий тег или загрузка без сверки.
	BinaryPinned bool
	Note         string
}

func awgRow(family string) Support {
	s := Support{
		State: SupportScriptOnly, Container: "amnezia-awg2",
		Source: map[string]string{
			"3.1": "awg/configure_container.sh:28-36 (HeaderProtectionKey…DisableCookies), :45 пустые строки удаляются",
			"2":   "awg/configure_container.sh:22-27 (S3, S4, H1-H4 — в т.ч. диапазоны), :45",
			"1.5": "awg/configure_container.sh:37-41 I1-I5 пишутся комментариями `# Ik = …` — сервер их не применяет",
		}[family],
		Note: "awg/Dockerfile:1 FROM amneziavpn/amneziawg-go:latest — версия бинаря не закреплена",
	}
	if family == "1.5" {
		s.State = SupportPartial
		s.Note = "I1–I5 скриптом не включаются (включит ли их перенос/Restore — свойство переноса, не ревизии); " + s.Note
	}
	return s
}

func commonRows(xrayDockerfile, xrayNote string) map[string]Support {
	return map[string]Support{
		"3.1": awgRow("3.1"),
		"2":   awgRow("2"),
		"1.5": awgRow("1.5"),
		"старый AWG": {
			State: SupportScriptOnly, Container: "amnezia-awg",
			Source: "awg_legacy/configure_container.sh:12-31 (wg0.conf: Jc…H4)",
			Note:   "awg_legacy/Dockerfile:1 FROM amneziavpn/amnezia-wg:latest — версия бинаря не закреплена",
		},
		"WireGuard": {
			State: SupportScriptOnly, Container: "amnezia-wireguard",
			Source: "wireguard/configure_container.sh:12-16 (wg0.conf)",
			Note:   "wireguard/Dockerfile:1 FROM alpine:3.15, wireguard-tools из apk без версии",
		},
		"XRay": {
			State: SupportScriptOnly, Container: "amnezia-xray",
			Source: xrayDockerfile + "; xray/configure_container.sh — ключи x25519/uuid/shortId",
			Note: "тег релиза задан, но zip качается без сверки суммы (xray/Dockerfile:15) — не закреплён; " +
				"server.json пишет само приложение (XrayConfigurator::writeServerConfigForSetup), в скриптах его нет" + xrayNote,
		},
	}
}

// installSupports — закрытая таблица. Клетка, которой нет, — SupportUnknown.
var installSupports = map[string]map[string]Support{
	RevDev94b51df: commonRows(`xray/Dockerfile:4 ARG XRAY_RELEASE="v26.7.28"`, ""),
	Rev5106: commonRows(`xray/Dockerfile:4 ARG XRAY_RELEASE="v26.10.31"`,
		`; расхождение: protocolConstants.h 5.1.0.6 expectedServerXrayRelease = "v26.7.28", а Dockerfile ставит v26.10.31`),
}

// InstallSupport — клетка таблицы; вне таблицы — SupportUnknown, никогда не
// SupportNo. «Ставит» без закреплённого бинаря не выдаётся: такое
// состояние понижается до SupportScriptOnly.
func InstallSupport(rev, family string) Support {
	if row, ok := installSupports[rev]; ok {
		if s, ok := row[family]; ok {
			if s.State == SupportYes && !s.BinaryPinned {
				s.State = SupportScriptOnly
			}
			return s
		}
	}
	return Support{State: SupportUnknown}
}
