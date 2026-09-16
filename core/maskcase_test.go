package core

// Регистронезависимость маскировки и закрытый список несекретных имён
// wg0.conf (A2, Г3). Файл НЕ правит core/mask_test.go — тот остаётся
// зелёным без единой правки, это условие задания.
//
// Все секреты здесь — заведомо фиктивные литералы, узнаваемые глазом.

import (
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

const fakeCasePSK = "test-psk-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII="

// TestMaskSecretsIsCaseInsensitive — покраснение 5 раздела Д.
//
// Конфиг, записанный как "presharedkey =" или "PRESHAREDKEY =", проходил
// открытым текстом: обе регулярки знали только каноническое написание.
// Подмена «убрать (?i)» → FAIL.
//
// ЧЕСТНАЯ ОГОВОРКА, без которой это покраснение выглядело бы сильнее, чем
// оно есть: на СКВОЗНОМ пути Plan.Diff() строку "presharedkey = …" теперь
// перехватил бы и закрытый список несекретных имён (её имени в нём нет), то
// есть снятие (?i) секрет бы не открыло. Поэтому покраснение предъявляется
// на самих регулярках — единственном месте, где снятие (?i) различимо, — и
// на строке clientsTable, которую закрытый список НЕ покрывает (он про
// строки "имя = значение", а не про JSON).
func TestMaskSecretsIsCaseInsensitive(t *testing.T) {
	t.Run("wg0.conf: регулярка секретных имён знает любой регистр", func(t *testing.T) {
		for _, name := range []string{"PresharedKey", "presharedkey", "PRESHAREDKEY", "PreSharedKey", "privatekey"} {
			line := "-" + name + " = " + fakeCasePSK
			if !reWgSecretLine.MatchString(line) {
				t.Errorf("reWgSecretLine не узнала секретное имя в написании %q: %q", name, line)
			}
			if got := maskSecrets(line); strings.Contains(got, fakeCasePSK) {
				t.Errorf("maskSecrets пропустила секрет при написании %q: %s", name, got)
			}
		}
	})

	// clientsTable — JSON, и закрытый список несекретных имён его не
	// покрывает: здесь снятие (?i) открыло бы секрет по-настоящему.
	t.Run("clientsTable: \"PSK\" в другом регистре тоже маскируется", func(t *testing.T) {
		for _, name := range []string{"psk", "PSK", "Psk"} {
			line := `+        "` + name + `": "` + fakeCasePSK + `",`
			got := maskSecrets(line)
			if strings.Contains(got, fakeCasePSK) {
				t.Errorf("maskSecrets пропустила секрет clientsTable при написании %q: %s", name, got)
			}
			want := `+        "` + name + `": "` + hiddenPlaceholder + `",`
			if got != want {
				t.Errorf("структура строки clientsTable не сохранена.\n хочу: %s\nполучил: %s", want, got)
			}
		}
	})
}

// TestMaskSecretsClosedListOfPublicNames — покраснение 6 раздела Д.
//
// Строка wg0.conf с НЕИЗВЕСТНЫМ именем ключа и секретоподобным значением
// обязана быть замаскирована: список секретных имён пополняется только
// после того, как утечка уже случилась, а список несекретных — осознанно и
// видно в диффе. Подмена «маскировать только известные секретные имена» →
// FAIL.
func TestMaskSecretsClosedListOfPublicNames(t *testing.T) {
	t.Run("неизвестное имя — значение скрыто, имя видно", func(t *testing.T) {
		got := maskSecrets("+SecretBlob = " + fakeCasePSK)
		if strings.Contains(got, fakeCasePSK) {
			t.Errorf("строка с неизвестным именем ключа не замаскирована: %s", got)
		}
		if got != "+SecretBlob = "+hiddenPlaceholder {
			t.Errorf("имя ключа или структура строки не сохранены: %s", got)
		}
	})

	t.Run("имена из закрытого списка остаются открытыми", func(t *testing.T) {
		for _, line := range []string{
			"+PublicKey = " + fakeCasePSK,
			"+AllowedIPs = 10.8.1.2/32",
			"-Address = 10.8.1.1/24",
			"+ListenPort = 51820",
			"+Endpoint = 1.2.3.4:51820",
			"+PersistentKeepalive = 25",
			"+DNS = 1.1.1.1, 1.0.0.1",
			"+Jc = 4",
			"+H1 = 123456",
		} {
			if got := maskSecrets(line); got != line {
				t.Errorf("строка из закрытого списка несекретных имён замаскирована.\n было: %s\nстало: %s", line, got)
			}
		}
	})

	t.Run("заголовки секций и строки без '=' не трогаются", func(t *testing.T) {
		for _, line := range []string{"+[Peer]", "-[Interface]", "+", "-  ", `+    {`, `-    ],`} {
			if got := maskSecrets(line); got != line {
				t.Errorf("строка без пары «имя = значение» изменена.\n было: %q\nстало: %q", line, got)
			}
		}
	})
}

// TestMaskSecretsClosedListForClientsTable — ревью SEC-01, замечание 2.
//
// Раньше в clientsTable маскировались ТОЛЬКО три известных имени: закрытый
// список действовал лишь на wg0.conf, потому что reWgKVLine требовал имя с
// буквы, а строка JSON начинается с кавычки. Между тем ClientEntry.UserData —
// map[string]any (core/core.go:255), и кладёт туда что угодно КЛИЕНТ Amnezia,
// а не мы; readClientsTableRaw читает это с боевого сервера как есть.
//
// Подмена «снять закрытый список для clientsTable» → FAIL.
func TestMaskSecretsClosedListForClientsTable(t *testing.T) {
	t.Run("неизвестное имя — значение скрыто, имя видно", func(t *testing.T) {
		in := `-            "clientPrivKey": "` + fakeCasePSK + `",`
		want := `-            "clientPrivKey": "` + hiddenPlaceholder + `",`
		got := maskSecrets(in)
		if strings.Contains(got, fakeCasePSK) {
			t.Errorf("поле userData с неизвестным именем не замаскировано: %s", got)
		}
		if got != want {
			t.Errorf("имя поля или структура строки не сохранены.\n хочу: %s\nполучил: %s", want, got)
		}
	})

	t.Run("значение без запятой на последней строке объекта", func(t *testing.T) {
		in := `+            "clientPrivKey": "` + fakeCasePSK + `"`
		want := `+            "clientPrivKey": "` + hiddenPlaceholder + `"`
		if got := maskSecrets(in); got != want {
			t.Errorf("\n хочу: %s\nполучил: %s", want, got)
		}
	})

	t.Run("нестроковые значения тоже скрываются", func(t *testing.T) {
		for _, in := range []string{
			`+            "secretCount": 42,`,
			`+            "secretFlag": true`,
			`+            "secretNull": null,`,
		} {
			got := maskSecrets(in)
			if !strings.Contains(got, hiddenPlaceholder) {
				t.Errorf("нестроковое значение неизвестного поля не скрыто: %s", got)
			}
		}
	})

	t.Run("имена из закрытого списка остаются открытыми", func(t *testing.T) {
		for _, line := range []string{
			`+        "clientId": "` + fakeCasePSK + `",`,
			`+            "clientName": "Alice",`,
			`+            "creationDate": "2026-09-16T20:18:56+07:00"`,
			`+            "allowedIP": "10.8.1.2/32",`,
			`+            "disabled": true,`,
			`+            "disabledAt": "2026-09-16T20:18:56+07:00",`,
		} {
			if got := maskSecrets(line); got != line {
				t.Errorf("строка из закрытого списка несекретных имён замаскирована.\n было: %s\nстало: %s", line, got)
			}
		}
	})

	t.Run("открывающие скобки вложенных структур не трогаются", func(t *testing.T) {
		for _, line := range []string{
			`+        "userData": {`,
			`+        "someList": [`,
		} {
			if got := maskSecrets(line); got != line {
				t.Errorf("открывающая скобка изменена — значения на этой строке нет.\n было: %s\nстало: %s", line, got)
			}
		}
	})
}

// TestPlanDiffMasksUnknownClientsTableKey — та же утечка сквозным путём:
// поле, положенное в userData КЛИЕНТОМ Amnezia, не показывается открытым в
// предпросмотре. Воспроизводит прогон ревьюера (`[userData privkey] leak=true`).
func TestPlanDiffMasksUnknownClientsTableKey(t *testing.T) {
	c := awgContainer()
	srv := fakesrv.New()
	sess := NewSessionWithRunner(srv, testCreds())

	clients, err := sess.LoadClients(c)
	if err != nil {
		t.Fatalf("LoadClients: %v", err)
	}
	if len(clients) < 2 {
		t.Fatal("fakesrv.New() должен дать двух клиентов")
	}

	tbl, ok := srv.File(c.Dir + "/clientsTable")
	if !ok {
		t.Fatal("нет clientsTable в fakesrv")
	}
	const anchor = `"clientName"`
	if !strings.Contains(string(tbl), anchor) {
		t.Fatalf("в clientsTable fakesrv нет опорной строки %s — тест перестал что-либо проверять", anchor)
	}
	// Поле, которого продукт не кладёт и знать не может: его кладёт клиент
	// Amnezia. UserData — map[string]any, туда попадает что угодно.
	txt := strings.Replace(string(tbl), anchor,
		`"clientPrivKey": "`+fakeCasePSK+"\",\n            "+anchor, 1)
	srv.SetFile(c.Dir+"/clientsTable", []byte(txt))

	plan, err := sess.PlanDelete(c, clients[1].ClientID)
	if err != nil {
		t.Fatalf("PlanDelete: %v", err)
	}
	_, tblDiff := plan.Diff()

	if !strings.Contains(tblDiff, "clientPrivKey") {
		t.Fatalf("строка clientPrivKey не попала в diff — тест перестал что-либо проверять:\n%s", tblDiff)
	}
	if strings.Contains(tblDiff, fakeCasePSK) {
		t.Errorf("Plan.Diff() показал значение поля userData открытым:\n%s", tblDiff)
	}
	if !strings.Contains(tblDiff, `"clientPrivKey": "`+hiddenPlaceholder+`"`) {
		t.Errorf("имя поля пропало из diff — теряется диагностика:\n%s", tblDiff)
	}
}

// TestMaskSecretsNameWithDot — ревью SEC-01, замечание 6.
//
// Строка wg0.conf вида "Some.Name = …" не подходила под прежний шаблон имени
// ([A-Za-z][A-Za-z0-9_-]*) и проваливалась в «открыто», а не в «скрыто». В
// конструкции «запрет по умолчанию» это дыра наизнанку: непонятая строка
// обязана скрываться. Подмена «вернуть узкий класс имени» → FAIL.
func TestMaskSecretsNameWithDot(t *testing.T) {
	for _, name := range []string{"Some.Name", "vendor.secret.key", "x-team_secret", "«имя»"} {
		in := "+" + name + " = " + fakeCasePSK
		got := maskSecrets(in)
		if strings.Contains(got, fakeCasePSK) {
			t.Errorf("строка с именем %q не замаскирована: %s", name, got)
		}
		if got != "+"+name+" = "+hiddenPlaceholder {
			t.Errorf("имя или структура строки не сохранены для %q: %s", name, got)
		}
	}
}

// TestPlanDiffMasksUnknownWgKey — то же сквозным путём: неизвестное имя
// ключа, попавшее в настоящий wg0.conf на сервере, не показывается открытым
// в предпросмотре Plan.Diff().
func TestPlanDiffMasksUnknownWgKey(t *testing.T) {
	c := awgContainer()
	srv := fakesrv.New()

	wg0, ok := srv.File(c.Dir + "/wg0.conf")
	if !ok {
		t.Fatal("нет wg0.conf в fakesrv")
	}
	// Неизвестное продукту поле ВНУТРИ первого блока [Peer] — того, который
	// операция удаляет. Так строка гарантированно попадает в изменившуюся
	// середину diff'а (lineDiff обрезает общий префикс и общий суффикс), и
	// тесту есть на чём падать.
	const anchor = "AllowedIPs = 10.8.1.2/32"
	text := string(wg0)
	if !strings.Contains(text, anchor) {
		t.Fatalf("в wg0.conf fakesrv нет опорной строки %q — тест перестал что-либо проверять:\n%s", anchor, text)
	}
	text = strings.Replace(text, anchor, anchor+"\nSecretBlob = "+fakeCasePSK, 1)
	srv.SetFile(c.Dir+"/wg0.conf", []byte(text))

	sess := NewSessionWithRunner(srv, testCreds())
	clients, err := sess.LoadClients(c)
	if err != nil {
		t.Fatalf("LoadClients: %v", err)
	}
	if len(clients) == 0 {
		t.Fatal("fakesrv.New() должен дать хотя бы одного клиента")
	}
	plan, err := sess.PlanDelete(c, clients[0].ClientID)
	if err != nil {
		t.Fatalf("PlanDelete: %v", err)
	}
	wgDiff, _ := plan.Diff()

	if !strings.Contains(wgDiff, "SecretBlob") {
		t.Fatalf("строка SecretBlob не попала в diff — тест перестал что-либо проверять:\n%s", wgDiff)
	}
	if strings.Contains(wgDiff, fakeCasePSK) {
		t.Errorf("Plan.Diff() показал значение неизвестного поля открытым:\n%s", wgDiff)
	}
	if !strings.Contains(wgDiff, "SecretBlob = "+hiddenPlaceholder) {
		t.Errorf("имя неизвестного поля пропало из diff — теряется диагностика:\n%s", wgDiff)
	}
}
