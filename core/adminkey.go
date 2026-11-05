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
// результат — Secret, тексты ошибок ни ключа, ни пароля не содержат.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
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
)

// AdminKeyContainer — контейнер в составе ключа. Protocol — параметры
// протокола (как их хранит приложение); nil — пустой объект. Ключ
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
func BuildAdminKey(in AdminKeyInput) (Secret, error) {
	if !in.PasswordConsent {
		return Secret{}, ErrAdminKeyNoConsent
	}
	if in.Password.Len() == 0 {
		return Secret{}, ErrAdminKeyNoPassword
	}
	js, err := adminKeyJSON(in)
	if err != nil {
		return Secret{}, err
	}
	enc := base64.RawURLEncoding.EncodeToString(qCompress(js))
	return NewSecret([]byte("vpn://" + enc)), nil
}

// VerifyAdminKey — проверка выданного ключа: разобрать тем же разборщиком,
// что читает ключи владельца (DecodeVpnKey + CredsFromConfig), сверить
// адрес/порт/пользователя/пароль/контейнеры с want и войти на сервер с
// ЗАКРЕПЛЁННЫМ отпечатком (без вопроса человеку).
//
// Три исхода: nil — проверено; errors.Is(err, ErrAdminKeyMismatch) — ключ
// НЕ тот; любая другая ошибка — проверить не удалось (сеть, отпечаток,
// вход) — это не «ключ плохой» и не «ключ хороший».
func VerifyAdminKey(key Secret, want AdminKeyInput, expectedFingerprint, knownHostsPath string) error {
	if expectedFingerprint == "" {
		return errors.New("проверка ключа: отпечаток сервера не задан — без закрепления не проверяем")
	}
	cfg, err := DecodeVpnKey(string(key.Bytes()))
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
	var got []string
	if arr, ok := cfg["containers"].([]any); ok {
		for _, c := range arr {
			m, _ := c.(map[string]any)
			got = append(got, Str(m, "container"))
		}
	}
	if len(got) != len(want.Containers) {
		return fmt.Errorf("%w: число контейнеров %d, ожидалось %d", ErrAdminKeyMismatch, len(got), len(want.Containers))
	}
	for i, c := range want.Containers {
		if got[i] != c.Name {
			return fmt.Errorf("%w: контейнер №%d %q, ожидался %q", ErrAdminKeyMismatch, i+1, got[i], c.Name)
		}
	}
	if Str(cfg, "defaultContainer") != want.DefaultContainer {
		return fmt.Errorf("%w: контейнер по умолчанию", ErrAdminKeyMismatch)
	}
	sess, err := ConnectWithHostKey(creds, HostKeyPolicy{
		KnownHostsPath:      knownHostsPath,
		ExpectedFingerprint: expectedFingerprint,
	})
	if err != nil {
		return fmt.Errorf("проверка ключа: войти не удалось: %w", err)
	}
	sess.Close()
	return nil
}
