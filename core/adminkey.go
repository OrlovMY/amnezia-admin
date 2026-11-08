package core

// Сборка АДМИНСКОГО ключа vpn:// (PR 6 плана «перенос на чистый сервер»).
//
// Формат сверен по amnezia-client 5.1.0.6 (коммит ac175c8):
//   - ExportController::generateFullAccessConfig
//     (client/core/controllers/selfhosted/exportController.cpp:30-49):
//     JSON сервера → qCompress(…, 8) → base64url без «=» → "vpn://";
//     у каждого контейнера clearClientConfig() — клиентский last_config
//     в «полный доступ» не попадает;
//   - SelfHostedAdminServerConfig::toJson
//     (client/core/models/selfhosted/selfHostedAdminServerConfig.cpp:84-127):
//     formatVersion (=1, serverConfigUtils.h:28), description, hostName,
//     containers, defaultContainer, dns1, dns2, userName, password,
//     port — ЧИСЛО (импорт читает его toInt(), importController.cpp:415);
//   - ContainerConfig::toJson (client/core/models/containerConfig.cpp:25-37):
//     {"container": имя, <протокол по умолчанию>: {...}};
//   - ContainerUtils::defaultProtocol (containerUtils.cpp:217-240):
//     amnezia-awg и amnezia-awg2 → "awg", amnezia-wireguard → "wireguard",
//     amnezia-xray → "xray".
//
// Ключ несёт пароль root или приватный SSH-ключ — это секрет (CLAUDE.md):
// результат — AdminKey (печать и JSON — только сводка), тексты ошибок ни
// ключа, ни пароля не содержат.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// adminKeyFormatVersion — serverConfigUtils::currentConfigFormatVersion
// amnezia-client 5.1.0.6. Импорт отвергает ключ с версией БОЛЬШЕ своей.
const adminKeyFormatVersion = 1

var (
	// ErrAdminKeyNoConsent — человек не согласился положить пароль в ключ.
	// Без согласия ключ не выдаётся вовсе (не «тихо без пароля»).
	ErrAdminKeyNoConsent = errors.New("без согласия положить пароль в ключ ключ не выдаётся")
	// ErrAdminKeyNoPassword — согласие есть, но пароля нет (например, вход
	// был ключами ПК, а пароль отдельно не введён). Ключ без способа входа
	// бесполезен — не выдаётся.
	ErrAdminKeyNoPassword = errors.New("пароль для ключа не введён — ключ не выдаётся")
	// ErrAdminKeyMismatch — ключ разобран, но его содержимое не совпало с
	// ожидаемым (VerifyAdminKey). Отличается от «проверить не удалось».
	ErrAdminKeyMismatch = errors.New("содержимое ключа не совпало с ожидаемым")
	// ErrAdminKeyNoProtocolParams — у контейнера нет обязательных параметров
	// протокола. Пустой {} приложение приняло бы молча (порт, obfuscation —
	// пустые строки) — это «значение по умолчанию вместо ответа».
	ErrAdminKeyNoProtocolParams = errors.New("нет параметров протокола — ключ не выдаётся")
	// ErrAdminKeyAuthRejected — сервер ответил и НЕ принял вход по ключу
	// (пароль не подошёл или вход по паролю на сервере выключен). Это
	// измеренное «ключ не годится», а не «проверить не удалось» (ревью
	// PR #70, H2).
	ErrAdminKeyAuthRejected = errors.New("сервер не принял вход по паролю из ключа (пароль не подошёл или вход по паролю на сервере выключен)")
)

// adminKeyDial — вход при проверке ключа (шов теста).
var adminKeyDial = ConnectWithHostKey

// AdminKeyContainer — контейнер в составе ключа. Protocol — параметры
// протокола (как их хранит приложение); ОБЯЗАТЕЛЬНЫ поля из
// protocolRequired, брать их — ProtocolParamsFromServer. Ключ
// last_config убирается, как это делает приложение (clearClientConfig).
type AdminKeyContainer struct {
	Name     string
	Protocol map[string]any
}

// AdminKeyInput — всё, из чего собирается админский vpn://.
type AdminKeyInput struct {
	Host string
	Port int
	User string
	// Password — пароль SSH или приватный ключ в PEM.
	Password Secret
	// PasswordConsent — человек явно согласился на экране положить
	// пароль в ключ. false — ErrAdminKeyNoConsent.
	PasswordConsent  bool
	Containers       []AdminKeyContainer
	DefaultContainer string // "" — не указывать
	Description      string
	DNS1, DNS2       string
}

// errAdminKeyInputJSON — AdminKeyInput не сериализуется: в нём пароль root
// или приватный ключ (Secret.MarshalJSON раскрывает содержимое — так нужно
// файлу копии). Аудит AU PR #69, L1.
var errAdminKeyInputJSON = errors.New("AdminKeyInput не сериализуется: в нём пароль")

// MarshalJSON — отказ: входные данные ключа в JSON не попадают никогда.
func (AdminKeyInput) MarshalJSON() ([]byte, error) { return nil, errAdminKeyInputJSON }

// MarshalText — отказ по той же причине.
func (AdminKeyInput) MarshalText() ([]byte, error) { return nil, errAdminKeyInputJSON }

// adminKeyProto — ключ протокола контейнера (ContainerUtils::defaultProtocol).
// Закрытый список: незнакомый контейнер — отказ, а не угаданный протокол.
func adminKeyProto(container string) (string, bool) {
	switch container {
	case "amnezia-awg", "amnezia-awg2":
		return "awg", true
	case "amnezia-wireguard":
		return "wireguard", true
	case "amnezia-xray":
		return "xray", true
	}
	return "", false
}

// adminKeyJSON — JSON ключа; password может быть пустым только у вызова
// из теста формы (BuildAdminKey пустой не пропускает).
func adminKeyJSON(in AdminKeyInput) ([]byte, error) {
	if in.Host == "" || in.User == "" {
		return nil, errors.New("ключ: не указан адрес сервера или пользователь")
	}
	if in.Port < 1 || in.Port > 65535 {
		return nil, fmt.Errorf("ключ: порт %d вне 1…65535", in.Port)
	}
	top := map[string]any{
		"formatVersion": adminKeyFormatVersion,
		"hostName":      in.Host,
		"port":          in.Port,
		"userName":      in.User,
		"password":      string(in.Password.Bytes()),
	}
	if in.Description != "" {
		top["description"] = in.Description
	}
	if in.DNS1 != "" {
		top["dns1"] = in.DNS1
	}
	if in.DNS2 != "" {
		top["dns2"] = in.DNS2
	}
	seen := map[string]bool{}
	var cs []any
	for _, c := range in.Containers {
		proto, ok := adminKeyProto(c.Name)
		if !ok {
			return nil, fmt.Errorf("ключ: контейнер %q не из списка известных — в ключ не кладётся", c.Name)
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("ключ: контейнер %q указан дважды", c.Name)
		}
		seen[c.Name] = true
		if miss := missingProtocolParams(c.Name, c.Protocol); len(miss) > 0 {
			return nil, fmt.Errorf("%w: контейнер %q, нет %s", ErrAdminKeyNoProtocolParams, c.Name, strings.Join(miss, ", "))
		}
		p := map[string]any{}
		for k, v := range c.Protocol {
			if k != "last_config" {
				p[k] = v
			}
		}
		cs = append(cs, map[string]any{"container": c.Name, proto: p})
	}
	if len(cs) > 0 {
		top["containers"] = cs
	}
	if in.DefaultContainer != "" {
		if !seen[in.DefaultContainer] {
			return nil, fmt.Errorf("ключ: контейнер по умолчанию %q не входит в список контейнеров", in.DefaultContainer)
		}
		top["defaultContainer"] = in.DefaultContainer
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(top); err != nil {
		return nil, errors.New("ключ: не удалось собрать JSON")
	}
	return b.Bytes(), nil
}

// BuildAdminKey — админский vpn:// (как «Поделиться → полный доступ»
// приложения). Пароль кладётся только с согласия (PasswordConsent);
// пустой пароль — отказ: ключ без способа входа не выдаётся.
func BuildAdminKey(in AdminKeyInput) (AdminKey, error) {
	if !in.PasswordConsent {
		return AdminKey{}, ErrAdminKeyNoConsent
	}
	if in.Password.Len() == 0 {
		return AdminKey{}, ErrAdminKeyNoPassword
	}
	js, err := adminKeyJSON(in)
	if err != nil {
		return AdminKey{}, err
	}
	enc := base64.RawURLEncoding.EncodeToString(qCompress(js))
	return AdminKey{s: NewSecret([]byte("vpn://" + enc))}, nil
}

// AdminKey — выданный админский vpn:// (несёт пароль root или PEM).
// Отдельный тип, а не Secret: у Secret MarshalJSON отдаёт содержимое
// (нужно файлу копии), а ключ не раскрывается НИ ОДНИМ способом печати
// или сериализации — только явным Reveal().
type AdminKey struct{ s Secret }

// Reveal — текст ключа vpn:// целиком. Только для выдачи человеку
// (файл 0600, буфер обмена, QR) — не для журналов и ошибок.
func (k AdminKey) Reveal() string { return string(k.s.Bytes()) }

// Len — длина ключа в байтах (0 — ключа нет).
func (k AdminKey) Len() int { return k.s.Len() }

func (k AdminKey) String() string {
	return fmt.Sprintf("[ключ vpn:// скрыт, %d байт]", k.Len())
}
func (k AdminKey) GoString() string { return k.String() }

// Format — любой глагол fmt (%v %s %q %x %#v…) печатает только сводку.
func (k AdminKey) Format(f fmt.State, _ rune) { fmt.Fprint(f, k.String()) }

// MarshalJSON — сводка без содержимого; восстановить ключ из JSON нельзя.
func (k AdminKey) MarshalJSON() ([]byte, error) { return json.Marshal(k.String()) }

// MarshalText — то же для encoding (yaml, xml, ключи map в JSON).
func (k AdminKey) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// protocolRequired — поля параметров протокола, которые приложение
// 5.1.0.6 читает через toString() БЕЗ умолчаний (ac175c8):
// AwgServerConfig::fromJson (awgProtocolConfig.cpp:164-196),
// WireGuardServerConfig::fromJson (wireGuardProtocolConfig.cpp:43-56),
// XrayServerConfig::fromJson (xrayProtocolConfig.cpp:301-311).
// Имена — configKeys.h:14,46,63,66,80-90. Для awg2 обязательны S3/S4:
// по ним awgVersionOf (awgProtocolConfig.cpp:40-65) отличает AWG2 от AWG1.
var protocolRequired = map[string][]string{
	"amnezia-awg":       {"port", "transport_proto", "subnet_address", "Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"},
	"amnezia-awg2":      {"port", "transport_proto", "subnet_address", "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"},
	"amnezia-wireguard": {"port", "transport_proto", "subnet_address"},
	"amnezia-xray":      {"port", "transport_proto", "site"},
}

// protocolOptional — поля, которые переносятся из конфигурации сервера,
// если они там есть (AWG 1.5/2: I1…I5).
var protocolOptional = []string{"I1", "I2", "I3", "I4", "I5", "subnet_cidr"}

// missingProtocolParams — обязательные поля, которых нет или которые не
// непустая строка (число приложение через toString() прочтёт как "").
func missingProtocolParams(container string, p map[string]any) []string {
	var miss []string
	for _, k := range protocolRequired[container] {
		if s, ok := p[k].(string); !ok || strings.TrimSpace(s) == "" {
			miss = append(miss, k)
		}
	}
	return miss
}

// ProtocolParamsFromServer — параметры протокола для ключа из
// конфигурации, прочитанной с установленного сервера: awg0.conf/wg0.conf
// (amnezia-awg, amnezia-awg2, amnezia-wireguard) или server.json
// (amnezia-xray). Берутся только поля из закрытого списка — приватный
// ключ сервера и пиры в ключ не попадают. Нет обязательного поля —
// ErrAdminKeyNoProtocolParams с перечнем, а не неполный набор.
func ProtocolParamsFromServer(container string, conf []byte) (map[string]any, error) {
	p := map[string]any{}
	switch container {
	case "amnezia-awg", "amnezia-awg2", "amnezia-wireguard":
		iface := parseWgConf(string(conf)).iface
		p["transport_proto"] = "udp"
		if v := iface["ListenPort"]; v != "" {
			p["port"] = v
		}
		if a := strings.TrimSpace(strings.Split(iface["Address"], ",")[0]); a != "" {
			// subnet_address — адрес СЕТИ (10.8.1.1/24 → 10.8.1.0), как его
			// хранит приложение; адрес хоста интерфейса сюда не кладётся
			// (ревью PR #69, R1). Без маски сеть не вычислить — поля нет.
			if pfx, err := netip.ParsePrefix(a); err == nil && pfx.Addr().Is4() {
				p["subnet_address"] = pfx.Masked().Addr().String()
				p["subnet_cidr"] = strconv.Itoa(pfx.Bits())
			}
		}
		if container != "amnezia-wireguard" {
			for _, k := range append(append([]string{}, protocolRequired[container][3:]...), protocolOptional[:5]...) {
				if v := iface[k]; v != "" {
					p[k] = v
				}
			}
		}
	case "amnezia-xray":
		// Строгий разбор; пустой список клиентов допустим — flow для ключа
		// не нужен (ревью PR #70-2, M1; R3).
		srv, err := parseXRayServerEmptyOK(conf)
		if err != nil {
			return nil, fmt.Errorf("%w: контейнер %q, server.json: %v", ErrAdminKeyNoProtocolParams, container, err)
		}
		p["port"], p["site"] = srv.port, srv.serverName
		p["transport_proto"] = "tcp"
	default:
		return nil, fmt.Errorf("ключ: контейнер %q не из списка известных", container)
	}
	if miss := missingProtocolParams(container, p); len(miss) > 0 {
		return nil, fmt.Errorf("%w: контейнер %q, в конфигурации сервера нет %s", ErrAdminKeyNoProtocolParams, container, strings.Join(miss, ", "))
	}
	return p, nil
}

// VerifyAdminKey — проверка выданного ключа: разобрать тем же разборщиком,
// что читает ключи владельца (DecodeVpnKey + CredsFromConfig), сверить
// адрес/порт/пользователя/пароль/контейнеры с want и войти на сервер с
// ЗАКРЕПЛЁННЫМ отпечатком (без вопроса человеку).
//
// Исходы: nil — проверено; ErrAdminKeyMismatch — ключ НЕ тот;
// ErrAdminKeyAuthRejected — сервер ответил и не принял пароль из ключа
// (измеренное «не годится»); любая другая ошибка — проверить не удалось
// (сеть, отпечаток, обрыв) — это не «ключ плохой» и не «ключ хороший».
func VerifyAdminKey(key AdminKey, want AdminKeyInput, expectedFingerprint, knownHostsPath string) error {
	if expectedFingerprint == "" {
		return errors.New("проверка ключа: отпечаток сервера не задан — без закрепления не проверяем")
	}
	cfg, err := DecodeVpnKey(key.Reveal())
	if err != nil {
		return fmt.Errorf("%w: ключ не разбирается", ErrAdminKeyMismatch)
	}
	creds, err := CredsFromConfig(cfg)
	if err != nil {
		return fmt.Errorf("%w: в ключе нет SSH-доступа", ErrAdminKeyMismatch)
	}
	switch {
	case creds.Host != want.Host:
		return fmt.Errorf("%w: адрес сервера", ErrAdminKeyMismatch)
	case creds.Port != strconv.Itoa(want.Port):
		return fmt.Errorf("%w: порт", ErrAdminKeyMismatch)
	case creds.User != want.User:
		return fmt.Errorf("%w: пользователь", ErrAdminKeyMismatch)
	case creds.Password != string(want.Password.Bytes()):
		return fmt.Errorf("%w: пароль", ErrAdminKeyMismatch)
	}
	var got []map[string]any
	if arr, ok := cfg["containers"].([]any); ok {
		for _, c := range arr {
			m, _ := c.(map[string]any)
			got = append(got, m)
		}
	}
	if len(got) != len(want.Containers) {
		return fmt.Errorf("%w: число контейнеров %d, ожидалось %d", ErrAdminKeyMismatch, len(got), len(want.Containers))
	}
	for i, c := range want.Containers {
		if Str(got[i], "container") != c.Name {
			return fmt.Errorf("%w: контейнер №%d, ожидался %q", ErrAdminKeyMismatch, i+1, c.Name)
		}
		proto, _ := adminKeyProto(c.Name)
		p, _ := got[i][proto].(map[string]any)
		for _, k := range protocolRequired[c.Name] {
			if s, ok := p[k].(string); !ok || s != c.Protocol[k] {
				return fmt.Errorf("%w: контейнер %q, параметр %s", ErrAdminKeyMismatch, c.Name, k)
			}
		}
	}
	if Str(cfg, "defaultContainer") != want.DefaultContainer {
		return fmt.Errorf("%w: контейнер по умолчанию", ErrAdminKeyMismatch)
	}
	sess, err := adminKeyDial(creds, HostKeyPolicy{
		KnownHostsPath:      knownHostsPath,
		ExpectedFingerprint: expectedFingerprint,
	})
	if err != nil {
		if ce := ClassifyConnectError(err); ce != nil && ce.Kind == ConnectAuthRejected {
			return ErrAdminKeyAuthRejected
		}
		return fmt.Errorf("проверка ключа: войти не удалось: %w", err)
	}
	sess.Close()
	return nil
}

// AdminKeyContainersFromServer — параметры протокола для ключа по каждому
// контейнеру names, прочитанные с сервера после переноса (в ключ идёт то,
// что на сервере стоит, а не то, что было в копии). notes — оговорки для
// человека (у XRay нет ни одного клиента, ревью PR #69 R3). Контейнер,
// параметры которого не прочитаны, — ошибка с его именем: неполный ключ
// не выдаётся.
func (s *Session) AdminKeyContainersFromServer(names []string) (cs []AdminKeyContainer, notes []string, err error) {
	if len(names) == 0 {
		return nil, nil, errors.New("ключ: нет ни одного контейнера")
	}
	found, err := s.FindContainers()
	if err != nil {
		return nil, nil, fmt.Errorf("ключ: список контейнеров на сервере не прочитан: %w", err)
	}
	for _, n := range names {
		var c *Container
		for i := range found {
			if found[i].Name == n {
				c = &found[i]
			}
		}
		if c == nil {
			return nil, nil, fmt.Errorf("ключ: контейнера %q на сервере не видно — параметры не прочитаны", n)
		}
		kc, note, kerr := s.adminKeyContainerFrom(c)
		if kerr != nil {
			return nil, nil, kerr
		}
		if note != "" {
			notes = append(notes, note)
		}
		cs = append(cs, kc)
	}
	return cs, notes, nil
}

// XRayNoClientsNote — оговорка: XRay поставлен, но клиентов в нём нет.
const XRayNoClientsNote = "XRay: на сервере нет ни одного клиента XRay — ключ даёт управление сервером, но подключаться по XRay пока некому; клиента можно добавить в приложении Amnezia или командой add"
