package main

// Долг У6 (ДОЛГИ-ПРОДУКТ, 30.09.2026): меню CLI при конце ввода. Тест
// запускает НАСТОЯЩИЙ main() без аргументов (меню) в дочернем процессе —
// тот же тестовый бинарник — против fakesrv.ListenSSH на эфемерном порту
// 127.0.0.1. Пользуется только API c65420e и компилируется там; на c65420e
// меню печаталось бесконечно, и тест падает по таймауту.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
	"amnezia-admin/internal/testpath"
)

const debtsMenuChildEnv = "AMNEZIA_ADMIN_DEBTS_MENU_CHILD"

// TestDebtsMenuChild — не тест, а тело дочернего процесса: без переменной
// окружения ничего не делает.
func TestDebtsMenuChild(t *testing.T) {
	if os.Getenv(debtsMenuChildEnv) != "1" {
		t.Skip("тело дочернего процесса TestDebtsMenuEOFExits")
	}
	os.Args = []string{"amnezia-admin"}
	main()
	os.Exit(0) // старый main() без аргументов возвращался, не выходя
}

// menuVaultDir — каталог known_hosts меню (core.DefaultVaultDir() —
// рядом с тестовым бинарником, во временном каталоге сборки). Прежнее
// содержимое откладывается и возвращается.
func menuVaultDir(t *testing.T) string {
	t.Helper()
	dir := core.DefaultVaultDir()
	// Fatalf, а не Skip (ревью QA долгов): пропущенный тест выглядит как
	// зелёный прогон. Пути — через testpath (EvalSymlinks с обеих сторон).
	if !testpath.InsideTempDir(dir) {
		t.Fatalf("каталог %s не во временном каталоге %s — тест его не трогает, "+
			"и проверка У6 НЕ ВЫПОЛНЕНА; запустите тестовый бинарник из временного каталога", dir, os.TempDir())
	}
	if _, err := os.Stat(dir); err == nil {
		aside := dir + ".debts-aside"
		if err := os.Rename(dir, aside); err != nil {
			t.Fatalf("не удалось отложить %s: %v", dir, err)
		}
		t.Cleanup(func() { os.RemoveAll(dir); os.Rename(aside, dir) })
	} else {
		t.Cleanup(func() { os.RemoveAll(dir) })
	}
	return dir
}

// TestDebtsMenuEOFExits — ТЕСТ ДОЕЗДА и РАЗЛИЧЕНИЯ: ввод кончился сразу
// (пустой stdin) и после одного выбора («1» — список) — оба раза выход с
// кодом 2 и строкой «Ввод закончился — выход.»; штатный выбор «0» — код 0
// без этой строки.
func TestDebtsMenuEOFExits(t *testing.T) {
	const user, password = "root", "fakepw-debts-menu"
	hostKey, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := fakesrv.ListenSSH("127.0.0.1:0", user, password, hostKey, fakesrv.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	key := buildTestVpnKey(t, srv.Addr(), user, password)
	kh := filepath.Join(menuVaultDir(t), "known_hosts")
	var o, e bytes.Buffer
	if code := run([]string{"list", "-key", key, "-hostkey", srv.Fingerprint()}, strings.NewReader(""), &o, &e, kh); code != 0 {
		t.Fatalf("прогрев known_hosts: code=%d %s", code, e.String())
	}

	cases := []struct {
		name     string
		stdin    string
		wantCode int
		wantLine bool
	}{
		{"пустой ввод", "", 2, true},
		{"ввод кончился после выбора", "1\n", 2, true},
		{"штатный выход", "0\n", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDebtsMenuChild$")
			cmd.Env = append(os.Environ(), debtsMenuChildEnv+"=1", "AMNEZIA_KEY="+key, "NO_COLOR=1")
			cmd.Stdin = strings.NewReader(c.stdin)
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			err := cmd.Run()
			if ctx.Err() != nil {
				t.Fatalf("меню не завершилось за 20 с при конце ввода (напечатано %d байт) — зацикливание", out.Len())
			}
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			tail := out.String()
			if len(tail) > 600 {
				tail = tail[len(tail)-600:]
			}
			if !strings.Contains(out.String(), "Выбор: ") {
				t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: меню не показано (код %d):\n%s", code, tail)
			}
			if code != c.wantCode {
				t.Fatalf("код выхода %d, ожидался %d; конец вывода:\n%s", code, c.wantCode, tail)
			}
			if got := strings.Contains(out.String(), textInputEndedLiteral); got != c.wantLine {
				t.Fatalf("строка %q: есть=%v, ожидалось %v; конец вывода:\n%s", textInputEndedLiteral, got, c.wantLine, tail)
			}
		})
	}
}

// TestDebtsListNamesUnknownEnabled — У1, ДОЕЗД через полный run() list
// против fakesrv: у Alice поле disabled испорчено («true» строкой). Список
// обязан сказать, что включена ли она — неизвестно; при исправном поле
// (различение) этой строки нет. На c65420e строки не было вовсе: запись
// выглядела активной.
func TestDebtsListNamesUnknownEnabled(t *testing.T) {
	for _, c := range []struct {
		name string
		v    any
		want bool
	}{{"исправное поле", false, false}, {"испорченное поле", "true", true}} {
		t.Run(c.name, func(t *testing.T) {
			key, kh, srv := setupFakeSSHForRunWithExec(t)
			const path = "/opt/amnezia/awg/clientsTable"
			raw, _ := srv.File(path)
			var list []map[string]any
			if err := json.Unmarshal(raw, &list); err != nil || len(list) == 0 {
				t.Fatalf("подготовка: %v", err)
			}
			list[0]["userData"].(map[string]any)["disabled"] = c.v
			out, _ := json.Marshal(list)
			srv.SetFile(path, out)
			var o, e bytes.Buffer
			if code := run([]string{"list", "-key", key}, strings.NewReader(""), &o, &e, kh); code != 0 {
				t.Fatalf("list: code=%d %s", code, e.String())
			}
			got := strings.Contains(o.String(), "Неизвестно, включены ли эти пользователи") &&
				strings.Contains(o.String(), `"Alice"`)
			if got != c.want {
				t.Fatalf("строка о неизвестном состоянии: есть=%v, ожидалось %v:\n%s", got, c.want, o.String())
			}
			// Раунд 2 (QA п.5): и в САМОЙ строке таблицы — не как у активного.
			var aliceRow string
			for _, l := range strings.Split(o.String(), "\n") {
				if strings.Contains(l, "Alice") && !strings.Contains(l, "Неизвестно") {
					aliceRow = l
				}
			}
			if aliceRow == "" {
				t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: строки Alice нет:\n%s", o.String())
			}
			// раунд 3: строка не разъезжается с шапкой — ключ Alice стоит под
			// «Публичный ключ» и при длинной ячейке «Активности».
			var head string
			for _, l := range strings.Split(o.String(), "\n") {
				if strings.Contains(l, "Публичный ключ") {
					head = l
				}
			}
			aliceKey := list[0]["clientId"].(string)
			if hi, ki := runeIndex(head, "Публичный ключ"), runeIndex(aliceRow, aliceKey); hi < 0 || hi != ki {
				t.Errorf("колонка ключа разъехалась: в шапке с %d-го знака, в строке Alice с %d-го:\n%s\n%s", hi, ki, head, aliceRow)
			}
			// раунд 3 (Я1): пометка — рядом с показанием («—»), а не вместо
			if marked := strings.Contains(aliceRow, "— (вкл/откл: ?)"); marked != c.want {
				t.Fatalf("строка Alice: пометка «(вкл/откл: ?)» есть=%v, ожидалось %v: %q", marked, c.want, aliceRow)
			}
		})
	}
}

// TestDebtsToggleUnknownDisables — раунд 4 (AU-UX High, решение ядра),
// ДОЕЗД через полный run(): toggle клиента с испорченным disabled —
// отключение проходит (код 0, «отключён»), rekey — отказ с шагом
// «Отключите пользователя». На f5951bc toggle отказывал.
func TestDebtsToggleUnknownDisables(t *testing.T) {
	key, kh, srv := setupFakeSSHForRunWithExec(t)
	const path = "/opt/amnezia/awg/clientsTable"
	raw, _ := srv.File(path)
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err != nil || len(list) == 0 {
		t.Fatalf("подготовка: %v", err)
	}
	list[0]["userData"].(map[string]any)["disabled"] = "yes"
	name := list[0]["userData"].(map[string]any)["clientName"].(string)
	out, _ := json.Marshal(list)
	srv.SetFile(path, out)

	var o, e bytes.Buffer
	if code := run([]string{"rekey", "-key", key, "-name", name, "-yes"}, strings.NewReader(""), &o, &e, kh); code == 0 ||
		!strings.Contains(e.String(), "Отключите пользователя — это исправит запись") {
		t.Errorf("rekey при неизвестном: код %d, stderr %q — ожидался отказ с шагом", code, e.String())
	}
	o.Reset()
	e.Reset()
	if code := run([]string{"toggle", "-key", key, "-name", name, "-yes"}, strings.NewReader(""), &o, &e, kh); code != 0 {
		t.Fatalf("toggle при неизвестном: код %d, stderr %q — отключение должно пройти", code, e.String())
	}
	if !strings.Contains(o.String(), "отключён") {
		t.Errorf("toggle при неизвестном не отключил: %q", o.String())
	}
	raw, _ = srv.File(path)
	if !strings.Contains(string(raw), `"disabled": true`) && !strings.Contains(string(raw), `"disabled":true`) {
		t.Errorf("после отключения запись не исправлена: %s", raw)
	}
}

// TestDebtsToggleUnknownNoPeerSaysRecordOnly — раунд 5 (Н-4), ДОЕЗД через
// полный run(): у клиента с "true" строкой peer'а в wg0.conf нет. toggle
// проходит, итог прямо говорит, что правилась только запись; -dry-run
// говорит то же до записи. wg0.conf не меняется. На aab4da6 — отказ «peer
// не найден».
func TestDebtsToggleUnknownNoPeerSaysRecordOnly(t *testing.T) {
	key, kh, srv := setupFakeSSHForRunWithExec(t)
	const tbl, wg = "/opt/amnezia/awg/clientsTable", "/opt/amnezia/awg/wg0.conf"
	raw, _ := srv.File(tbl)
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err != nil || len(list) == 0 {
		t.Fatalf("подготовка: %v", err)
	}
	ud := list[0]["userData"].(map[string]any)
	ud["disabled"] = "true"
	id, name := list[0]["clientId"].(string), ud["clientName"].(string)
	out, _ := json.Marshal(list)
	srv.SetFile(tbl, out)
	conf, _ := srv.File(wg)
	var kept []string
	for _, b := range strings.Split(string(conf), "\n\n") {
		if !strings.Contains(b, id) {
			kept = append(kept, b)
		}
	}
	srv.SetFile(wg, []byte(strings.Join(kept, "\n\n")))
	wgBefore, _ := srv.File(wg)
	const note = "Доступ уже отрезан: клиента нет в wg0.conf. Исправлена только запись в clientsTable (disabled = true)."

	var o, e bytes.Buffer
	if code := run([]string{"toggle", "-dry-run", "-key", key, "-name", name}, strings.NewReader(""), &o, &e, kh); code != 0 ||
		!strings.Contains(o.String(), note) {
		t.Errorf("-dry-run: код %d, вывод без пояснения:\n%s\n%s", code, o.String(), e.String())
	}
	o.Reset()
	e.Reset()
	if code := run([]string{"toggle", "-key", key, "-name", name, "-yes"}, strings.NewReader(""), &o, &e, kh); code != 0 {
		t.Fatalf("toggle: код %d, stderr %q — отключение без peer'а должно пройти", code, e.String())
	}
	if !strings.Contains(o.String(), "отключён") || !strings.Contains(o.String(), note) {
		t.Errorf("итог не говорит, что правилась только запись: %q", o.String())
	}
	if wgAfter, _ := srv.File(wg); string(wgAfter) != string(wgBefore) {
		t.Error("wg0.conf изменён, хотя peer'а не было")
	}
}

// handshakeRunner — fakesrv, у которого в ответе `wg show` у всех peer'ов
// время последнего рукопожатия — сейчас (fakesrv отдаёт 0).
type handshakeRunner struct{ inner *fakesrv.Server }

func (r handshakeRunner) Run(cmd string, stdin []byte) (string, error) {
	out, err := r.inner.Run(cmd, stdin)
	if err != nil || !strings.Contains(cmd, "wg show wg0 dump") {
		return out, err
	}
	lines := strings.Split(out, "\n")
	for i := 1; i < len(lines); i++ {
		f := strings.Split(lines[i], "\t")
		if len(f) >= 5 {
			f[4] = strconv.FormatInt(time.Now().Unix(), 10)
			lines[i] = strings.Join(f, "\t")
		}
	}
	return strings.Join(lines, "\n"), nil
}

// TestDebtsListGreenOnlyActive — раунд 3 (SEC): зелёный в «Активности»
// list означает «активен, подключался». Клиент с неизвестным состоянием
// зелёным не красится, хотя показание измерено. Различение: при
// disabled=false у той же записи с тем же рукопожатием ячейка зелёная.
// Боевой путь: listUsers против fakesrv. На c65420e испорченное поле
// читалось как «активен», и ячейка была зелёной.
func TestDebtsListGreenOnlyActive(t *testing.T) {
	saved := colorsEnabled
	colorsEnabled = true
	t.Cleanup(func() { colorsEnabled = saved })
	const green = "\x1b[32m"
	for _, c := range []struct {
		v     any
		green bool
	}{{false, true}, {"yes", false}} {
		srv := fakesrv.New()
		const path = "/opt/amnezia/awg/clientsTable"
		raw, _ := srv.File(path)
		var list []map[string]any
		if err := json.Unmarshal(raw, &list); err != nil || len(list) == 0 {
			t.Fatalf("подготовка: %v", err)
		}
		list[0]["userData"].(map[string]any)["disabled"] = c.v
		out, _ := json.Marshal(list)
		srv.SetFile(path, out)
		sess := core.NewSessionWithRunner(handshakeRunner{srv}, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
		cur := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
		var o bytes.Buffer
		if _, err := listUsers(&o, sess, cur); err != nil {
			t.Fatalf("listUsers: %v", err)
		}
		var aliceRow string
		for _, l := range strings.Split(o.String(), "\n") {
			if strings.Contains(l, "Alice") && !strings.Contains(l, "Неизвестно") {
				aliceRow = l
			}
		}
		if aliceRow == "" {
			t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: строки Alice нет:\n%s", o.String())
		}
		// Колонка ключа не разъезжается с шапкой при самой длинной ячейке
		// «<время> (вкл/откл: ?)» (раунд 3, Я1). Цвета не считаются в знаки.
		plain := regexp.MustCompile("\x1b\\[[0-9;]*m")
		var head string
		for _, l := range strings.Split(o.String(), "\n") {
			if strings.Contains(l, "Публичный ключ") {
				head = plain.ReplaceAllString(l, "")
			}
		}
		key := list[0]["clientId"].(string)
		if hi, ki := runeIndex(head, "Публичный ключ"), runeIndex(plain.ReplaceAllString(aliceRow, ""), key); hi < 0 || hi != ki {
			t.Errorf("disabled=%#v: колонка ключа разъехалась: шапка %d, строка Alice %d:\n%s\n%s", c.v, hi, ki, head, plain.ReplaceAllString(aliceRow, ""))
		}
		if got := strings.Contains(aliceRow, green); got != c.green {
			t.Errorf("disabled=%#v: зелёный в строке Alice: %v, ожидалось %v: %q", c.v, got, c.green, aliceRow)
		}
	}
}

// Литерал, а не константа из main.go: на c65420e её нет, а тест обязан там
// компилироваться.
const textInputEndedLiteral = "Ввод закончился — выход."

func runeIndex(s, sub string) int {
	i := strings.Index(s, sub)
	if i < 0 {
		return -1
	}
	return len([]rune(s[:i]))
}
