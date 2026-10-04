package main

import (
	"bytes"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/canary"
)

// TestFinishRunsK9 — сторож прогона 04.10 (canary-a3b @ 1f5c909: К9 не
// вызывался, 70 ПРОЙДЕН без единой строки К9). finish — тот код, что
// печатает таблицу и ИТОГ программы канарейки; в его выводе и в таблице
// обязаны быть строки К9 для amnezia-xray и для каждого проверяемого
// контейнера WG, а К9 обязан обратиться к серверу. Подмена «не вызывать K9»
// роняет тест; xray нет на сервере — строка К9 НЕ ПРОВЕРЕНО и итог не
// ПРОЙДЕН.
func TestFinishRunsK9(t *testing.T) {
	calls := 0
	remote := func(cmd string) (string, error) {
		if strings.Contains(cmd, "exec amnezia-xray") || strings.Contains(cmd, "exec amnezia-awg ") {
			calls++
		}
		return "N\n", nil // файлов нет — К9.0 НЕ ПРОВЕРЕНО, но шаг исполнен
	}
	remoteIn := func(string, []byte) (string, error) { return "", nil }
	sel := []core.Container{{Name: "amnezia-awg", Dir: "/opt/amnezia/awg"}}
	pass := []canary.Result{{ID: "К3", Name: "x", Status: canary.Pass}}

	for _, c := range []struct {
		name  string
		found []string
		skip  bool
	}{
		{"xray есть", []string{"amnezia-awg", "amnezia-xray"}, false},
		{"xray нет", []string{"amnezia-awg"}, false},
		{"xray пропущен флагом", []string{"amnezia-awg"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			calls = 0
			var out bytes.Buffer
			per := map[string][]canary.Result{"amnezia-awg": pass}
			code := finish(&out, remote, remoteIn, c.found, sel, c.skip, []string{"amnezia-awg"}, per,
				append([]canary.Result(nil), pass...), nil, nil, nil, false, nil)
			o := out.String()
			table := o[strings.Index(o, "шаг |"):]
			if !strings.Contains(table, "К9.0 amnezia-awg:") {
				t.Errorf("в таблице нет строки К9 для amnezia-awg:\n%s", o)
			}
			switch {
			case c.skip:
				if strings.Contains(o, "amnezia-xray:") {
					t.Errorf("пропущенный флагом xray дал строки:\n%s", o)
				}
			case contains(c.found, "amnezia-xray"):
				if !strings.Contains(table, "К9.0 amnezia-xray:") {
					t.Errorf("в таблице нет строки К9 для amnezia-xray:\n%s", o)
				}
			default:
				if !strings.Contains(table, "К9 amnezia-xray:") || !strings.Contains(o, "контейнера на сервере нет") {
					t.Errorf("xray нет — ждали строку К9 НЕ ПРОВЕРЕНО:\n%s", o)
				}
			}
			if calls == 0 {
				t.Error("К9 ни разу не обратился к серверу")
			}
			if code == 0 {
				t.Errorf("итог 0 (ПРОЙДЕН) при К9 НЕ ПРОВЕРЕНО:\n%s", o)
			}
		})
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
