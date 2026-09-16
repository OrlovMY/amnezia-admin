package main

// Тесты печати конфига vpn:// (A2, Г1). Предмет — cmd/cli/main.go:
// redactConfig / printConfig, через которые ходят и подкоманда decode, и
// пункт меню «5».
//
// Доказано на базе 889a593: там decode печатал json.MarshalIndent(cfg)
// целиком, и TestDecodeMasksPassword падает — пароль виден в выводе
// (Probe-1, вывод в отчёте).
//
// ВСЕ литералы здесь — заведомо фиктивные и узнаваемые глазом
// (PROBE-ROOT-PASSWORD-…, test-token-ZZZZ). Ни один не похож на настоящий
// ключ владельца, и настоящий конфиг при подготовке этих тестов не
// открывался.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const fakeRootPassword = "PROBE-ROOT-PASSWORD-1234"

// decodeOutput прогоняет полный run() с подкомандой decode на конфиге cfg и
// возвращает stdout. Идёт через run(), а не через printConfig напрямую:
// покраснение 2 («вернуть json.MarshalIndent(cfg)») воспроизводится именно
// в ветке decode, и тест обязан её проверять.
func decodeOutput(t *testing.T, cfg map[string]any) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	key := "vpn://" + base64.RawURLEncoding.EncodeToString(data)

	var out, errOut bytes.Buffer
	code := run([]string{"decode", "-key", key}, strings.NewReader(""), &out, &errOut, t.TempDir()+"/known_hosts")
	if code != 0 {
		t.Fatalf("run(decode) = %d, stderr=%s", code, errOut.String())
	}
	return out.String()
}

// TestDecodeMasksPassword — покраснения 2 и 2а раздела Д.
//
// 2:  вернуть в decode печать через json.MarshalIndent(cfg) → пароль виден.
// 2а: убрать "password" из ЗАПРЕЩАЮЩЕГО списка configDeniedKeys
//
//	(правдоподобно: «он и так не в разрешённых») → пароль виден, потому что
//	при этом достаточно дописать его в разрешающий список. Эта проверка
//	доказывает, что защита держится на НАЛИЧИИ строки, а не на её отсутствии.
//
// Сверка — по подстроке самого пароля, а не по наличию маски: маска может
// стоять рядом с непомаскированным оригиналом.
func TestDecodeMasksPassword(t *testing.T) {
	out := decodeOutput(t, map[string]any{
		"hostName": "1.2.3.4",
		"userName": "root",
		"password": fakeRootPassword,
		"port":     "22",
	})

	if strings.Contains(out, fakeRootPassword) {
		t.Errorf("decode напечатал пароль в открытом виде:\n%s", out)
	}
	if !strings.Contains(out, `"password": "<скрыто>"`) {
		t.Errorf("decode не показал, что поле password существует и скрыто:\n%s", out)
	}
}

// TestDecodeDeniedBeatsAllowed — порядок списков: запрещающий сильнее
// разрешающего. Покраснение 2а в его второй половине: даже если "password"
// окажется в разрешающем списке, он обязан остаться скрытым.
func TestDecodeDeniedBeatsAllowed(t *testing.T) {
	configAllowedKeys["password"] = true
	t.Cleanup(func() { delete(configAllowedKeys, "password") })

	got := redactConfig(map[string]any{"password": fakeRootPassword})
	if got["password"] != configHiddenPlaceholder {
		t.Errorf("password в разрешающем списке открыл значение: %v — проверка на запрещающий список идёт не первой", got["password"])
	}
}

// TestDecodeUnknownFieldIsMasked — покраснение 1 раздела Д, главная строка Г1.
//
// В конфиг добавлено НОВОЕ поле, которого нет ни в одном из списков
// ("secretToken"). Оно обязано быть напечатано ПО ИМЕНИ (это диагностика:
// человек видит, какие поля в ключе есть) и СО СКРЫТЫМ значением (состава
// реального конфига мы не знаем и знать не можем — конфиг владельца
// секретный, и презумпция «неизвестное скрывается» заменить перечнем нельзя).
//
// Подмена «печатать неизвестные поля как есть» → FAIL.
//
// Сравнение вывода ЦЕЛИКОМ, а не Contains: иначе тест не заметит лишней
// строки и не поймает изменение формата (decode — договор со скриптами).
func TestDecodeUnknownFieldIsMasked(t *testing.T) {
	out := decodeOutput(t, map[string]any{
		"hostName":    "1.2.3.4",
		"userName":    "root",
		"password":    fakeRootPassword,
		"port":        "22",
		"secretToken": "test-token-ZZZZ",
		"containers":  []any{map[string]any{"container": "amnezia-awg"}},
	})

	const want = `{
  "containers": "<скрыто>",
  "hostName": "1.2.3.4",
  "password": "<скрыто>",
  "port": "22",
  "secretToken": "<скрыто>",
  "userName": "root"
}
`
	if out != want {
		t.Errorf("вывод decode дословно не совпал.\nхочу:\n%s\nполучил:\n%s", want, out)
	}

	// Договор со скриптами: вывод остаётся разбираемым JSON той же формы.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("вывод decode перестал быть разбираемым JSON: %v\n%s", err, out)
	}
	if parsed["hostName"] != "1.2.3.4" {
		t.Errorf("разрешённое поле hostName не доехало: %v", parsed["hostName"])
	}
}

// TestDecodeThreeStatesOfField — покраснение 7 раздела Д (П-НЕЗНАНИЕ,
// применённое к собственному выводу). Три состояния поля обязаны быть
// различимы дословно: отсутствует / есть и пусто / есть и скрыто. Подмена
// «печатать <скрыто> и для отсутствующего поля» → FAIL первой ветки.
func TestDecodeThreeStatesOfField(t *testing.T) {
	base := map[string]any{"hostName": "1.2.3.4", "userName": "root", "port": "22"}

	withKey := func(v any) map[string]any {
		m := map[string]any{}
		for k, val := range base {
			m[k] = val
		}
		if v != nil {
			m["password"] = v
		}
		return m
	}

	absent := decodeOutput(t, withKey(nil))
	empty := decodeOutput(t, withKey(""))
	hidden := decodeOutput(t, withKey(fakeRootPassword))

	if strings.Contains(absent, "password") {
		t.Errorf("поле отсутствует, но строка про password есть:\n%s", absent)
	}
	if !strings.Contains(empty, `"password": ""`) {
		t.Errorf("поле есть и пусто — ожидалась строка \"password\": \"\":\n%s", empty)
	}
	if !strings.Contains(hidden, `"password": "<скрыто>"`) {
		t.Errorf("поле есть и скрыто — ожидалась строка \"password\": \"<скрыто>\":\n%s", hidden)
	}
	if absent == empty || empty == hidden || absent == hidden {
		t.Errorf("три состояния поля неразличимы:\nотсутствует:\n%s\nпусто:\n%s\nскрыто:\n%s", absent, empty, hidden)
	}
}
