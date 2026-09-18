package core

// Тест на звенья (A2, Г4(а)): ошибка, поднятая из sshRunner.Run с заведомо
// фиктивным секретом в stderr, проводится по цепочке до места печати, и ни
// на одном звене секрет не присутствует.
//
// Звенья, которые тест проходит:
//   - значение ошибки, напечатанное через %v;
//   - err.Error();
//   - обёртка fmt.Errorf("...: %w", err) — одинарная и двойная;
//   - каждое звено цепочки errors.Unwrap.
//
// ЧЕГО ТЕСТ НЕ ПРОХОДИТ, и это называется прямо: диалог GUI (cmd/gui в этот
// PR не входит вовсе) и печать ошибки внутри run() в cmd/cli. И CLI, и GUI
// печатают именно err.Error() — звено, которое здесь проверено, — но сама
// ветка печати здесь не исполняется. Проверка CLI-текста — в
// cmd/cli/stderrmask_test.go.
//
// СВЕРКА — ПО ПОДСТРОКЕ САМОГО СЕКРЕТА, а не по наличию маски: маска может
// стоять рядом с непомаскированным оригиналом, и проверка «есть <скрыто>»
// это пропустит.
//
// Сервер — fakesrv.ListenSSH на ЭФЕМЕРНОМ порту 127.0.0.1:0 (никакого порта
// 22 — инцидент 15.09), транспорт — настоящий sshRunner: именно его, а не
// fakesrv.Server напрямую, предмет этого теста.
//
// Секрет — заведомо фиктивный литерал, узнаваемый глазом.

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// fakeStderrSecret — фиктивный PSK. Ни на что настоящее не похож.
const fakeStderrSecret = "test-psk-AAAABBBBCCCC"

// runWithSecretInStderr поднимает настоящий SSH к fakesrv и выполняет
// команду, которую fakesrv не знает: тот возвращает ошибку с текстом
// команды, sshserver пишет её в Channel.Stderr(), и sshRunner.Run
// подставляет её в fmt.Errorf. Секрет оказывается СРАЗУ В ОБЕИХ
// подстановках — и в %q текста команды, и в stderr, — то есть тест
// покрывает оба требования Г2 одним прогоном.
func runWithSecretInStderr(t *testing.T) error {
	t.Helper()
	srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
	sess, err := ConnectWithHostKey(credsForFakeSSH(t, srv), HostKeyPolicy{
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		Prompt:         alwaysTrustPrompt,
	})
	if err != nil {
		t.Fatalf("ConnectWithHostKey: %v", err)
	}
	t.Cleanup(sess.Close)

	_, runErr := sess.r.Run("echo PresharedKey = "+fakeStderrSecret, nil)
	if runErr == nil {
		t.Fatal("ожидалась ошибка от неизвестной команды — без неё тесту нечего проверять")
	}
	return runErr
}

func TestRunErrorChainHasNoSecret(t *testing.T) {
	runErr := runWithSecretInStderr(t)

	links := map[string]string{
		"значение ошибки (%v)": fmt.Sprintf("%v", runErr),
		"err.Error()":          runErr.Error(),
		"обёртка %w":           fmt.Errorf("не удалось выполнить операцию: %w", runErr).Error(),
		"двойная обёртка %w":   fmt.Errorf("внешняя: %w", fmt.Errorf("внутренняя: %w", runErr)).Error(),
		"печать обёртки (%v)":  fmt.Sprintf("%v", fmt.Errorf("не удалось выполнить операцию: %w", runErr)),
		"текст, который печатает CLI (fmt.Sprintln как в run())": fmt.Sprintln("Ошибка:", runErr),
	}
	for _, e := errors.Unwrap(runErr), error(nil); e != nil; e = errors.Unwrap(e) {
		links["звено errors.Unwrap: "+fmt.Sprintf("%T", e)] = e.Error()
	}

	for name, text := range links {
		if strings.Contains(text, fakeStderrSecret) {
			t.Errorf("звено %q содержит секрет в открытом виде: %q\nтекст: %s", name, fakeStderrSecret, text)
		}
	}

	// Диагностика обязана остаться: имя ключа и структура строки сохраняются,
	// маскируется только значение. Маскировка, съедающая строку, чинит утечку
	// ценой того, ради чего сообщение печатается.
	got := runErr.Error()
	if !strings.Contains(got, "PresharedKey = "+hiddenPlaceholder) {
		t.Errorf("маскировка съела имя ключа или структуру строки — ожидалось %q в:\n%s",
			"PresharedKey = "+hiddenPlaceholder, got)
	}
	if !strings.Contains(got, "stderr:") {
		t.Errorf("из сообщения пропала часть про stderr — диагностика потеряна:\n%s", got)
	}
}

// TestMaskSecretsIsNoOpOnFreeText — предъявление механизма, на котором
// строится покраснение 3а, наблюдением, а не рассуждением: существующая
// maskSecrets на свободном тексте stderr не меняет НИ ОДНОГО СИМВОЛА, потому
// что обе её регулярки привязаны к ^([-+]\s*) — строке диффа.
//
// Тест защищает от того, чтобы кто-нибудь «упростил» sshRunner.Run до вызова
// maskSecrets: функция с подходящим именем уже есть, и это правдоподобнейшая
// ошибка исполнения.
func TestMaskSecretsIsNoOpOnFreeText(t *testing.T) {
	const stderr = `wg: неизвестная строка "PresharedKey = ` + fakeStderrSecret + `"`

	if got := maskSecrets(stderr); got != stderr {
		t.Fatalf("maskSecrets изменила свободный текст — якорь ^([-+]\\s*) исчез?\nбыло:  %s\nстало: %s", stderr, got)
	}
	if !strings.Contains(maskSecrets(stderr), fakeStderrSecret) {
		t.Fatal("внутренняя несогласованность теста")
	}
	if got := maskFreeText(stderr); strings.Contains(got, fakeStderrSecret) {
		t.Errorf("maskFreeText пропустила секрет: %s", got)
	}
}

// TestMaskFreeTextForms — формы, в которых сервер печатает секрет. Имя ключа
// и структура строки сохраняются, длина значения не сохраняется.
func TestMaskFreeTextForms(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"wg0.conf-строка", "PresharedKey = " + fakeStderrSecret, "PresharedKey = " + hiddenPlaceholder},
		{"без пробелов", "PrivateKey=" + fakeStderrSecret, "PrivateKey=" + hiddenPlaceholder},
		{"JSON-поле", `"psk": "` + fakeStderrSecret + `"`, `"psk": "` + hiddenPlaceholder + `"`},
		{"в середине сообщения", `sh: bad line "PresharedKey = ` + fakeStderrSecret + `" at 3`, `sh: bad line "PresharedKey = ` + hiddenPlaceholder + `" at 3`},
		{"нижний регистр", "presharedkey = " + fakeStderrSecret, "presharedkey = " + hiddenPlaceholder},
		{"верхний регистр", "PRESHAREDKEY = " + fakeStderrSecret, "PRESHAREDKEY = " + hiddenPlaceholder},
		{"пустой вход", "", ""},
		{"нет секретов — текст не трогается", "cat: /opt/amnezia/awg/wg0.conf: No such file", "cat: /opt/amnezia/awg/wg0.conf: No such file"},
		{"имя без значения не ломает текст", "wg: invalid PresharedKey", "wg: invalid PresharedKey"},

		// Ревью SEC-01, замечание 4 — три формы, которые не ловились.
		{"апостроф как кавычка", "psk='" + fakeStderrSecret + "'", "psk='" + hiddenPlaceholder + "'"},
		{"апостроф, имя wg0.conf", "PrivateKey='" + fakeStderrSecret + "'", "PrivateKey='" + hiddenPlaceholder + "'"},
		{"экранированные кавычки", `sh: {\"psk\": \"` + fakeStderrSecret + `\"}`, `sh: {\"psk\": \"` + hiddenPlaceholder + `\"}`},
	}
	for _, c := range cases {
		if got := maskFreeText(c.in); got != c.want {
			t.Errorf("%s: maskFreeText(%q)\n хочу: %q\nполучил: %q", c.name, c.in, c.want, got)
		}
	}

	// Длина секрета не сохраняется: разные по длине значения дают один и тот
	// же вывод.
	short := maskFreeText(`PresharedKey = "ABC"`)
	long := maskFreeText(`PresharedKey = "` + strings.Repeat("Z", 44) + `"`)
	if short != long {
		t.Errorf("длина секрета видна по выводу: %q против %q", short, long)
	}
}

// TestMaskFreeTextKeepsDiagnostics — ревью SEC-01, потеря диагностики «а».
//
// Разделитель ":" без кавычек стоит в любом сообщении вида «Unable to parse
// PresharedKey: No such file», и маскировка по одному лишь разделителю
// съедала первое слово: «…PresharedKey: <скрыто> such file». Это ложное
// «здесь был секрет» там, где секрета не было, — П-НЕЗНАНИЕ наизнанку.
//
// Подмена «маскировать любое слово после разделителя» → FAIL.
func TestMaskFreeTextKeepsDiagnostics(t *testing.T) {
	t.Run("сообщение без секрета остаётся нетронутым", func(t *testing.T) {
		for _, in := range []string{
			"Unable to parse PresharedKey: No such file",
			"wg: PrivateKey: permission denied",
			"wg: psk: invalid",
			"cat: /opt/amnezia/awg/wg0.conf: No such file or directory",
			"PresharedKey: /opt/amnezia/awg/wg0.conf",
		} {
			if got := maskFreeText(in); got != in {
				t.Errorf("сообщение без секрета изменено — ложное «здесь был секрет».\n было: %s\nстало: %s", in, got)
			}
		}
	})

	t.Run("настоящий секрет без кавычек всё равно скрыт", func(t *testing.T) {
		for _, secret := range []string{
			"cFNLc2VjcmV0VkFMVUUxMjM0NTY3ODkwYWJjZGVmZ2hpag=",
			strings.Repeat("A", 43) + "=",
			fakeStderrSecret,
		} {
			in := "wg: PresharedKey: " + secret
			got := maskFreeText(in)
			if strings.Contains(got, secret) {
				t.Errorf("секрет без кавычек не замаскирован: %s", got)
			}
		}
	})

	// Ревью SEC-01, Новое-4: обратная косая обрывала маскировку.
	t.Run("ключ, вклеенный в путь с обратной косой", func(t *testing.T) {
		const secret = "cFNLsecretVALUE1234567890abcdefghij"
		in := `psk=C:\keys\` + secret
		got := maskFreeText(in)
		if strings.Contains(got, secret) {
			t.Errorf("ключ внутри пути с обратной косой не замаскирован: %s", got)
		}
	})
}

// TestMaskFreeTextPEM — ревью SEC-01, замечание 4, третья форма.
//
// В поле password лежит пароль root ЛИБО ПРИВАТНЫЙ SSH-КЛЮЧ, и ключ этот —
// многострочный PEM (core/hostkey.go:144 отличает его по подстроке
// "PRIVATE KEY"). Маскировка по парам «имя = значение» его тела не видит
// вовсе: раньше скрывалась только строка "-----BEGIN", а тело оставалось.
// Это хуже отсутствия защиты — создаёт ложное впечатление сработавшей.
//
// Заголовок BEGIN остаётся видимым намеренно: человек обязан видеть, что
// сервер ругается на ключ, не видя самого ключа.
func TestMaskFreeTextPEM(t *testing.T) {
	// Заведомо фиктивное «тело ключа» — не ключ, а узнаваемый глазом литерал.
	const body = "test-pem-body-AAAABBBB\ntest-pem-body-CCCCDDDD\ntest-pem-body-EEEEFFFF"

	t.Run("целый блок: тело и END скрыты, BEGIN виден", func(t *testing.T) {
		in := "ssh: не удалось разобрать ключ:\n-----BEGIN OPENSSH PRIVATE KEY-----\n" +
			body + "\n-----END OPENSSH PRIVATE KEY-----\nпопробуйте ещё раз"
		got := maskFreeText(in)
		for _, frag := range strings.Split(body, "\n") {
			if strings.Contains(got, frag) {
				t.Errorf("тело PEM осталось в тексте (%q):\n%s", frag, got)
			}
		}
		if strings.Contains(got, "-----END") {
			t.Errorf("строка END не замаскирована — маскировать надо до END включительно:\n%s", got)
		}
		if !strings.Contains(got, "-----BEGIN OPENSSH PRIVATE KEY-----") {
			t.Errorf("заголовок BEGIN пропал — человек не узнает, на что ругается сервер:\n%s", got)
		}
		if !strings.Contains(got, "попробуйте ещё раз") {
			t.Errorf("маскировка съела диагностику после блока:\n%s", got)
		}
	})

	t.Run("оборванный блок: BEGIN без END — скрыто до конца текста", func(t *testing.T) {
		in := "ssh: ключ отвергнут:\n-----BEGIN RSA PRIVATE KEY-----\n" + body
		got := maskFreeText(in)
		for _, frag := range strings.Split(body, "\n") {
			if strings.Contains(got, frag) {
				t.Errorf("тело оборванного PEM осталось в тексте (%q):\n%s", frag, got)
			}
		}
		if !strings.Contains(got, "-----BEGIN RSA PRIVATE KEY-----") {
			t.Errorf("заголовок BEGIN пропал:\n%s", got)
		}
	})

	// Ревью SEC-01, Новое-3: порядок операций. Целый блок первым, оборванный
	// вторым — END первого засчитывался за END второго, и тело второго ключа
	// выходило открытым.
	t.Run("целый блок, затем оборванный: тело второго тоже скрыто", func(t *testing.T) {
		const second = "test-pem-second-GGGGHHHH"
		in := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + body +
			"\n-----END OPENSSH PRIVATE KEY-----\nnext: -----BEGIN RSA PRIVATE KEY-----\n" + second
		got := maskFreeText(in)
		if strings.Contains(got, second) {
			t.Errorf("тело ВТОРОГО (оборванного) ключа осталось открытым:\n%s", got)
		}
		for _, frag := range strings.Split(body, "\n") {
			if strings.Contains(got, frag) {
				t.Errorf("тело первого блока осталось в тексте (%q):\n%s", frag, got)
			}
		}
	})

	// Ревью SEC-01, потеря диагностики «б»: обрыв обязан быть виден, иначе
	// человек не отличит «сервер замолчал» от «мы обрезали».
	t.Run("обрыв помечается, а не происходит молча", func(t *testing.T) {
		in := "ssh: ключ отвергнут:\n-----BEGIN RSA PRIVATE KEY-----\n" + body
		got := maskFreeText(in)
		if !strings.Contains(got, truncatedNote) {
			t.Errorf("обрезка не помечена — потеря диагностики невидима:\n%s", got)
		}
	})

	t.Run("целый блок обрезкой НЕ помечается", func(t *testing.T) {
		in := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + body +
			"\n-----END OPENSSH PRIVATE KEY-----\nпопробуйте ещё раз"
		got := maskFreeText(in)
		if strings.Contains(got, truncatedNote) {
			t.Errorf("целый блок помечен как обрезанный — ложное сообщение о потере:\n%s", got)
		}
	})

	t.Run("текст без PEM не трогается", func(t *testing.T) {
		const in = "cat: /opt/amnezia/awg/wg0.conf: No such file or directory"
		if got := maskFreeText(in); got != in {
			t.Errorf("текст без PEM изменён.\n было: %s\nстало: %s", in, got)
		}
	})
}

// TestMaskFreeTextPassword — ревью SEC-01, V1.
//
// «Единый список» уже разошёлся: имена секретов живут в двух местах
// (secretKeyNames здесь и configDeniedKeys в cmd/cli), и слова password в
// core-половине не было. Прогон «sshpass: password=Qw3rty!Sup3rSecret»
// проходил открытым. Сегодня не эксплуатируется — creds.Password уходит
// только в ssh.Password/KeyboardInteractive/ParsePrivateKey и ни в один
// текст команды, — но это отсутствующий слой: первая же команда вида
// `echo … | sudo -S` или `sshpass -p` напечаталась бы открытой и тихо.
//
// У пароля алфавит произвольный, поэтому признак «похоже на base64» для него
// заменён на «длина от 8 и есть небуквенный символ»: слова диагностики
// (permission, denied, required) — чистые буквы и не маскируются.
func TestMaskFreeTextPassword(t *testing.T) {
	const pw = "Qw3rty!Sup3rSecret"

	t.Run("пароль в тексте команды скрыт", func(t *testing.T) {
		for _, in := range []string{
			"sshpass: password=" + pw,
			`echo "password=` + pw + `" | sudo -S`,
			"passwd=" + pw,
			"PASSWORD = " + pw,
		} {
			got := maskFreeText(in)
			if strings.Contains(got, pw) {
				t.Errorf("пароль напечатан открытым: %s", got)
			}
		}
	})

	t.Run("слова диагностики не съедаются", func(t *testing.T) {
		for _, in := range []string{
			"wg: password: permission denied",
			"password: required",
			"passwd: No",
			"sudo: password required",
		} {
			if got := maskFreeText(in); got != in {
				t.Errorf("сообщение без пароля изменено.\n было: %s\nстало: %s", in, got)
			}
		}
	})
}

// TestMaskFreeTextPEMTruncatedHead — ревью SEC-01, V2.
//
// END без BEGIN выше: stderr обрезан СПЕРЕДИ (кольцевой буфер, tail, обрезка
// чужой утилитой) — те же условия, ради которых заведена ветка обрыва с
// конца. Тело ключа выходило открытым перед строкой END.
func TestMaskFreeTextPEMTruncatedHead(t *testing.T) {
	const body = "test-pem-head-AAAABBBB\ntest-pem-head-CCCCDDDD"

	t.Run("тело перед END скрыто, END и хвост видны", func(t *testing.T) {
		in := body + "\n-----END RSA PRIVATE KEY-----\nошибка входа"
		got := maskFreeText(in)
		for _, frag := range strings.Split(body, "\n") {
			if strings.Contains(got, frag) {
				t.Errorf("тело обрезанного спереди ключа осталось открытым (%q):\n%s", frag, got)
			}
		}
		if !strings.Contains(got, "-----END RSA PRIVATE KEY-----") {
			t.Errorf("строка END пропала — человек не узнает, на что ругается сервер:\n%s", got)
		}
		if !strings.Contains(got, "ошибка входа") {
			t.Errorf("маскировка съела диагностику после END:\n%s", got)
		}
		if !strings.Contains(got, truncatedNoteHead) {
			t.Errorf("обрезка спереди не помечена — потеря диагностики невидима:\n%s", got)
		}
	})

	t.Run("целый блок этой веткой не задет", func(t *testing.T) {
		in := "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----"
		got := maskFreeText(in)
		if strings.Contains(got, truncatedNoteHead) {
			t.Errorf("целый блок помечен как обрезанный спереди — ложное сообщение:\n%s", got)
		}
		if !strings.Contains(got, "-----BEGIN RSA PRIVATE KEY-----") {
			t.Errorf("заголовок BEGIN пропал:\n%s", got)
		}
	})
}

// TestMaskFreeTextNoFalseTruncation — ревью SEC-01, M1.
//
// BEGIN в самом конце текста ничего за собой не имеет, и пометка об обрезке
// утверждала бы факт, которого не было, — тот же класс «незнание выдано за
// знание», только наизнанку.
func TestMaskFreeTextNoFalseTruncation(t *testing.T) {
	got := maskFreeText("ssh: ошибка\n-----BEGIN RSA PRIVATE KEY-----")
	if strings.Contains(got, truncatedNote) {
		t.Errorf("пометка об обрезке поставлена там, где ничего не обрезано:\n%s", got)
	}
	if !strings.Contains(got, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("заголовок BEGIN пропал:\n%s", got)
	}
	if !strings.Contains(got, "ssh: ошибка") {
		t.Errorf("диагностика до заголовка съедена:\n%s", got)
	}
}

// TestMaskFreeTextQuotedValueWithComma — ревью SEC-01, M2.
//
// Внутри кавычек и запятая, и пробел — часть значения. Прежняя редакция
// маскировала только до первой запятой, и хвост ключа оставался открытым.
func TestMaskFreeTextQuotedValueWithComma(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"запятые внутри кавычек", `{"psk": "AAAA,BBBB,CCCC-secret-1234567890"}`, `{"psk": "` + hiddenPlaceholder + `"}`},
		{"пробелы внутри кавычек", `psk = "AAAA BBBB CCCC secret"`, `psk = "` + hiddenPlaceholder + `"`},
		{"апостроф и запятая", `psk='AAAA,BBBB,secret'`, `psk='` + hiddenPlaceholder + `'`},
		{"точка с запятой внутри кавычек", `PrivateKey: "AAAA;BBBB;secret"`, `PrivateKey: "` + hiddenPlaceholder + `"`},
	}
	for _, c := range cases {
		if got := maskFreeText(c.in); got != c.want {
			t.Errorf("%s: maskFreeText(%q)\n хочу: %q\nполучил: %q", c.name, c.in, c.want, got)
		}
	}
}
