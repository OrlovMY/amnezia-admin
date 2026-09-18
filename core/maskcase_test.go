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
// оно есть, — и она верна ТОЛЬКО ДЛЯ wg0.conf (ревью SEC-01, замечание 3):
//
//   - wg0.conf: на сквозном пути Plan.Diff() строку "presharedkey = …"
//     перехватил бы и закрытый список несекретных имён (её имени в нём нет),
//     то есть снятие (?i) секрет бы НЕ открыло. Здесь покраснение
//     предъявляется на самой регулярке — единственном месте, где снятие
//     (?i) различимо.
//   - clientsTable: закрытый список tblPublicNames проверяется ПОСЛЕ
//     reTblSecretLine, и имя "PSK" в нём отсутствует — значит оно тоже
//     маскируется по умолчанию. Но до введения tblPublicNames (ревью,
//     замечание 2) снятие (?i) открывало секрет ПО-НАСТОЯЩЕМУ, и это было
//     предъявлено прогоном ревьюера.
//
// То есть сегодня обе ветви прикрыты вторым слоем, и это надо говорить
// прямо, а не выдавать (?i) за единственную защиту. (?i) остаётся нужным:
// он закрывает известные имена ДО того, как дело дойдёт до списков, и он
// единственное, что работает в maskFreeText, где списков нет вовсе.
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
			got := maskTableSecrets(line)
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
	// Ревью SEC-01, B2: скрывается ВСЯ строка, включая «имя». Прежняя
	// редакция прятала только хвост после "=", и у значения, оканчивающегося
	// на "==", «именем» оказывался сам секрет — скрыт был один символ.
	t.Run("неизвестное имя — скрыта вся строка, включая имя", func(t *testing.T) {
		got := maskSecrets("+SecretBlob = " + fakeCasePSK)
		if strings.Contains(got, fakeCasePSK) {
			t.Errorf("строка с неизвестным именем ключа не замаскирована: %s", got)
		}
		if strings.Contains(got, "SecretBlob") {
			t.Errorf("неизвестное имя осталось открытым — а «имя» может само быть секретом: %s", got)
		}
		if got != `+"`+hiddenPlaceholder+`"` {
			t.Errorf("непонятая строка замаскирована не целиком: %q", got)
		}
	})

	// Та самая форма, на которой прежняя редакция скрывала один символ.
	t.Run("голая строка base64 с «==» скрыта целиком", func(t *testing.T) {
		for _, in := range []string{"+MDEyMzQ1Njc4OWFiY2RlZg==", "+" + fakeCasePSK + "="} {
			body := strings.TrimPrefix(in, "+")
			got := maskSecrets(in)
			if strings.Contains(got, strings.TrimSuffix(body, "=")) {
				t.Errorf("ключ напечатан целиком, скрыт только хвост — защита-видимость: %s", got)
			}
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

	t.Run("заголовки секций и пустые строки не трогаются", func(t *testing.T) {
		for _, line := range []string{"+[Peer]", "-[Interface]", "+", "-  ", "-\t", "+[Interface] "} {
			if got := maskSecrets(line); got != line {
				t.Errorf("структурная строка wg0.conf изменена.\n было: %q\nстало: %q", line, got)
			}
		}
	})

	// Ревью SEC-01, Новое-2: запрет по умолчанию действует и в wg0.conf —
	// строка, не подошедшая ни под одно правило, скрывается, а не
	// показывается. Раньше она проваливалась в «открыто».
	t.Run("непонятая строка wg0.conf скрывается целиком", func(t *testing.T) {
		for _, line := range []string{"+" + fakeCasePSK, "-  " + fakeCasePSK, "+какой-то мусор"} {
			got := maskSecrets(line)
			if got == line {
				t.Errorf("строка, не подошедшая ни под одно правило, осталась открытой: %q", line)
			}
			if strings.Contains(got, fakeCasePSK) {
				t.Errorf("секрет виден в непонятой строке: %s", got)
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
	// Ревью SEC-01, B2: скрывается вся строка, включая имя поля.
	t.Run("неизвестное имя — скрыта вся строка, включая имя", func(t *testing.T) {
		in := `-            "clientPrivKey": "` + fakeCasePSK + `",`
		want := `-            "` + hiddenPlaceholder + `",`
		got := maskTableSecrets(in)
		if strings.Contains(got, fakeCasePSK) {
			t.Errorf("поле userData с неизвестным именем не замаскировано: %s", got)
		}
		if strings.Contains(got, "clientPrivKey") {
			t.Errorf("неизвестное имя поля осталось открытым: %s", got)
		}
		if got != want {
			t.Errorf("отступ или завершающая запятая не сохранены.\n хочу: %q\nполучил: %q", want, got)
		}
	})

	t.Run("значение без запятой на последней строке объекта", func(t *testing.T) {
		in := `+            "clientPrivKey": "` + fakeCasePSK + `"`
		want := `+            "` + hiddenPlaceholder + `"`
		if got := maskTableSecrets(in); got != want {
			t.Errorf("\n хочу: %q\nполучил: %q", want, got)
		}
	})

	// Ревью SEC-01, B1: userData ВЫВЕДЕН из закрытого списка. Довод
	// «контейнер, своего значения не несёт» был утверждением о ФОРМЕ
	// значения, а код сверяет только ИМЯ — и все три формы со значением
	// текли.
	t.Run("userData со значением: все три формы скрыты", func(t *testing.T) {
		for _, in := range []string{
			`-        "userData": {"psk": "` + fakeCasePSK + `"},`,
			`-        "userData": "` + fakeCasePSK + `",`,
			`-        "userData": ["` + fakeCasePSK + `"],`,
		} {
			if got := maskTableSecrets(in); strings.Contains(got, fakeCasePSK) {
				t.Errorf("userData со значением напечатан открытым: %s", got)
			}
		}
	})

	t.Run("userData как открывающая скобка остаётся открытым", func(t *testing.T) {
		const in = `+        "userData": {`
		if got := maskTableSecrets(in); got != in {
			t.Errorf("строка открывающей скобки изменена — удаление userData из списка не должно было её задеть.\n было: %q\nстало: %q", in, got)
		}
	})

	t.Run("нестроковые значения тоже скрываются", func(t *testing.T) {
		for _, in := range []string{
			`+            "secretCount": 42,`,
			`+            "secretFlag": true`,
			`+            "secretNull": null,`,
		} {
			got := maskTableSecrets(in)
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
			if got := maskTableSecrets(line); got != line {
				t.Errorf("строка из закрытого списка несекретных имён замаскирована.\n было: %s\nстало: %s", line, got)
			}
		}
	})

	t.Run("открывающие и закрывающие скобки не трогаются", func(t *testing.T) {
		for _, line := range []string{
			`+        "userData": {`,
			`+        "someList": [`,
			`+    {`,
			`-    },`,
			`-            ],`,
			`+    }`,
			`-`,
			`+   `,
		} {
			if got := maskTableSecrets(line); got != line {
				t.Errorf("структурная строка JSON изменена — значения на этой строке нет.\n было: %q\nстало: %q", line, got)
			}
		}
	})

	// Ревью SEC-01, Новое-2 — воспроизведено прогоном (leak=true).
	t.Run("элемент массива: имени нет, значение всё равно скрыто", func(t *testing.T) {
		in := `+                "` + fakeCasePSK + `",`
		got := maskTableSecrets(in)
		if strings.Contains(got, fakeCasePSK) {
			t.Errorf("элемент массива JSON напечатан открытым: %s", got)
		}
		if got != `+                "`+hiddenPlaceholder+`",` {
			t.Errorf("отступ или завершающая запятая не сохранены: %q", got)
		}
	})

	t.Run("ключ с экранированной кавычкой скрывается целиком", func(t *testing.T) {
		in := `+            "a\"b": "` + fakeCasePSK + `",`
		got := maskTableSecrets(in)
		if strings.Contains(got, fakeCasePSK) {
			t.Errorf("значение под ключом с экранированной кавычкой напечатано открытым: %s", got)
		}
	})

	t.Run("нестроковый элемент массива тоже скрыт", func(t *testing.T) {
		for _, in := range []string{`+                42,`, `+                true`} {
			got := maskTableSecrets(in)
			if !strings.Contains(got, hiddenPlaceholder) {
				t.Errorf("нестроковый элемент массива не скрыт: %s", got)
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

	// Непустота проверяется по НЕмаскированному диффу: после правки B2 имя
	// неизвестного поля в маскированном не видно, и искать его там значило бы
	// сделать тест непадающим.
	if !strings.Contains(lineDiff(plan.tblBefore, plan.tblAfter), "clientPrivKey") {
		t.Fatalf("строка clientPrivKey не попала в diff — тест перестал что-либо проверять:\n%s", tblDiff)
	}
	if strings.Contains(tblDiff, fakeCasePSK) {
		t.Errorf("Plan.Diff() показал значение поля userData открытым:\n%s", tblDiff)
	}
	if strings.Contains(tblDiff, "clientPrivKey") {
		t.Errorf("неизвестное имя поля осталось открытым (ревью SEC-01, B2):\n%s", tblDiff)
	}
	if !strings.Contains(tblDiff, hiddenPlaceholder) {
		t.Errorf("в diff нет ни одного плейсхолдера — маскировка не сработала:\n%s", tblDiff)
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
		// Ревью SEC-01, B2: скрывается вся строка, имя тоже.
		if got != `+"`+hiddenPlaceholder+`"` {
			t.Errorf("непонятая строка с именем %q замаскирована не целиком: %q", name, got)
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

	// Непустота проверяется по НЕмаскированному диффу: после правки B2 имя
	// неизвестного поля в маскированном не видно, и искать его там значило бы
	// сделать тест непадающим.
	if !strings.Contains(lineDiff(plan.wgBefore, plan.wgAfter), "SecretBlob") {
		t.Fatalf("строка SecretBlob не попала в diff — тест перестал что-либо проверять:\n%s", wgDiff)
	}
	if strings.Contains(wgDiff, fakeCasePSK) {
		t.Errorf("Plan.Diff() показал значение неизвестного поля открытым:\n%s", wgDiff)
	}
	if strings.Contains(wgDiff, "SecretBlob") {
		t.Errorf("неизвестное имя осталось открытым (ревью SEC-01, B2):\n%s", wgDiff)
	}
	if !strings.Contains(wgDiff, hiddenPlaceholder) {
		t.Errorf("в diff нет ни одного плейсхолдера — маскировка не сработала:\n%s", wgDiff)
	}
}

// TestPlanDiffMasksArrayElement — ревью SEC-01, Новое-2, сквозным путём.
//
// Клиент Amnezia положил в userData МАССИВ. У его элементов имени нет:
// правило для пар `"имя": значение` их не видит, правило для `имя = значение`
// требует знака равенства — и строка проваливалась в «открыто». Ровно та
// дыра наизнанку, которую мы чинили для wg0.conf по замечанию 6.
// Воспроизведено прогоном до правки: leak=true.
func TestPlanDiffMasksArrayElement(t *testing.T) {
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
	txt := strings.Replace(string(tbl), anchor,
		"\"keys\": [\n                \""+fakeCasePSK+"\"\n            ],\n            "+anchor, 1)
	srv.SetFile(c.Dir+"/clientsTable", []byte(txt))

	plan, err := sess.PlanDelete(c, clients[1].ClientID)
	if err != nil {
		t.Fatalf("PlanDelete: %v", err)
	}
	_, tblDiff := plan.Diff()

	if !strings.Contains(tblDiff, "keys") {
		t.Fatalf("массив keys не попал в diff — тест перестал что-либо проверять:\n%s", tblDiff)
	}
	if strings.Contains(tblDiff, fakeCasePSK) {
		t.Errorf("Plan.Diff() показал элемент массива открытым:\n%s", tblDiff)
	}
}
