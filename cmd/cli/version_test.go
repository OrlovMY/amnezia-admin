// Файл version_test.go — тесты подкоманды "version" в run() (PR-6а):
// доказывают, что version|-version|--version печатают версию без ключа и
// без сети, коды возврата (0/1/2, PR-4-Б/PR-5) не изменены, а сборка с
// -ldflags -X реально вшивает переданную версию (не только компилируется).
package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"amnezia-admin/internal/version"
)

// TestRunVersionNoKey доказывает: version/-version/--version (в т.ч. с лишними
// аргументами, П19) работают без -key/AMNEZIA_KEY и без сети, код 0, stdout
// строго "amnezia-admin "+version.String()+"\n", stderr пуст (иначе сработала
// бы проверка ключа с кодом 1), known_hosts не создаётся (П16).
func TestRunVersionNoKey(t *testing.T) {
	t.Setenv("AMNEZIA_KEY", "")

	cases := [][]string{
		{"version"},
		{"-version"},
		{"--version"},
		{"version", "лишнее"},
	}

	for _, args := range cases {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
			var out, errOut bytes.Buffer
			code := run(args, strings.NewReader(""), &out, &errOut, knownHostsPath)

			if code != 0 {
				t.Fatalf("code = %d, хочу 0; stderr:\n%s", code, errOut.String())
			}
			want := "amnezia-admin " + version.String() + "\n"
			if out.String() != want {
				t.Errorf("stdout = %q, хочу %q", out.String(), want)
			}
			if errOut.String() != "" {
				t.Errorf("stderr не пуст (значит сработала проверка ключа): %q", errOut.String())
			}
			if _, err := os.Stat(knownHostsPath); err == nil {
				t.Errorf("known_hosts создан, хотя version не должен трогать сеть/vault: %s", knownHostsPath)
			} else if !os.IsNotExist(err) {
				t.Errorf("os.Stat(known_hosts): неожиданная ошибка: %v", err)
			}
		})
	}
}

// TestLdflagsInjectVersion доказывает, что путь -ldflags -X
// amnezia-admin/internal/version.Version/.Commit верен: сборка с этими
// флагами печатает заданную версию по "cli version", а не "dev (unknown)".
// Подсадка (П15): временная опечатка в пути -X (…/internal/versio.Version)
// должна дать FAIL с выводом "dev (…)" — проверяется отдельно вручную и
// зафиксирована в отчёте, не в этом тесте (правка пути в исходнике теста
// потребовала бы держать в дереве заведомо ломающийся вариант).
func TestLdflagsInjectVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("сборка компилятором — пропуск в -short")
	}

	tmp := t.TempDir()
	exe := "cli"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	outPath := filepath.Join(tmp, exe)

	ldflags := "-X amnezia-admin/internal/version.Version=v9.9.9-test " +
		"-X amnezia-admin/internal/version.Commit=0123456789abcdef"

	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", outPath, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	var buildOut bytes.Buffer
	cmd.Stdout = &buildOut
	cmd.Stderr = &buildOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build: %v\n%s", err, buildOut.String())
	}

	runCmd := exec.Command(outPath, "version")
	var out bytes.Buffer
	runCmd.Stdout = &out
	runCmd.Stderr = &out
	if err := runCmd.Run(); err != nil {
		t.Fatalf("запуск собранного бинаря: %v\n%s", err, out.String())
	}

	want := "amnezia-admin v9.9.9-test (0123456)\n"
	if out.String() != want {
		t.Fatalf("вывод = %q, хочу %q", out.String(), want)
	}
}
