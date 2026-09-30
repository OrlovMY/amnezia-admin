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
		})
	}
}

// Литерал, а не константа из main.go: на c65420e её нет, а тест обязан там
// компилироваться.
const textInputEndedLiteral = "Ввод закончился — выход."
