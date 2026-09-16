// Файл check_test.go — тесты подкоманды "check" в run() (ENVCHECK):
// доказывают, что check печатает признаки окружения без ключа, без сети и
// без known_hosts, а код возврата — 0 (коды 1/2 из PR-4-Б/PR-5 не тронуты).
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRunCheckNoKey доказывает вставку check в run(): без -key/AMNEZIA_KEY
// команда печатает отчёт об окружении и возвращает 0. Без вставки run()
// доходит до требования ключа и возвращает 1 с «Не задан ключ…» в stderr —
// именно на этом тест и обязан краснеть.
func TestRunCheckNoKey(t *testing.T) {
	t.Setenv("AMNEZIA_KEY", "")

	for _, args := range [][]string{{"check"}, {"check", "лишнее"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
			var out, errOut bytes.Buffer
			code := run(args, strings.NewReader(""), &out, &errOut, knownHostsPath)

			if code != 0 {
				t.Fatalf("code = %d, хочу 0; stderr:\n%s", code, errOut.String())
			}
			if errOut.String() != "" {
				t.Errorf("stderr не пуст (значит сработала проверка ключа): %q", errOut.String())
			}
			if !strings.HasPrefix(out.String(), "Проверка окружения\n") {
				t.Errorf("stdout не начинается заголовком отчёта:\n%s", out.String())
			}
			if _, err := os.Stat(knownHostsPath); err == nil {
				t.Errorf("known_hosts создан, хотя check не должен трогать сеть: %s", knownHostsPath)
			} else if !os.IsNotExist(err) {
				t.Errorf("os.Stat(known_hosts): неожиданная ошибка: %v", err)
			}

			// На windows/amd64 вывод целиком известен заранее — эталон (д1)
			// задания. На прочих платформах состав строк зависит от машины и
			// проверяется тестом дословности в internal/envcheck.
			if runtime.GOOS == "windows" && runtime.GOARCH == "amd64" {
				want := "Проверка окружения\nОС: Windows\nАрхитектура: amd64\nГрафический интерфейс запустится.\n"
				if out.String() != want {
					t.Errorf("stdout = %q, хочу %q", out.String(), want)
				}
			}
		})
	}
}
