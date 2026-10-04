package main

// PR-W1: -container выбирает контейнер протокола явно (канарейка проходит
// по всем контейнерам семейства WG). Нет такого на сервере — отказ с
// перечнем найденных, а не молчаливый выбор другого.

import (
	"bytes"
	"strings"
	"testing"
)

func TestContainerFlag(t *testing.T) {
	key, kh, exec := setupFakeSSHForRunWithExec(t)
	exec.Names = []string{"amnezia-awg", "amnezia-xray"}

	var out, errOut bytes.Buffer
	if code := run([]string{"list", "-key", key, "-container", "amnezia-awg2"}, strings.NewReader(""), &out, &errOut, kh); code != 1 {
		t.Fatalf("контейнера нет: код %d, ждали 1; stderr %q", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "контейнера amnezia-awg2 на сервере нет") || !strings.Contains(errOut.String(), "amnezia-xray") {
		t.Errorf("отказ не называет контейнер и найденные: %q", errOut.String())
	}

	out.Reset()
	errOut.Reset()
	// AL-01 (живая проверка 04.10): XRay «только просмотр» — список с
	// причиной, код 0; выбран именно xray — в выводе его причина, не Alice.
	if code := run([]string{"list", "-key", key, "-container", "amnezia-xray"}, strings.NewReader(""), &out, &errOut, kh); code != 0 ||
		!strings.Contains(out.String(), "Только просмотр: не удалось прочитать server.json") || strings.Contains(out.String(), "Alice") {
		t.Errorf("list -container amnezia-xray: код %d, вывод %q", code, out.String())
	}

	out.Reset()
	errOut.Reset()
	if code := run([]string{"list", "-key", key, "-container", "amnezia-awg"}, strings.NewReader(""), &out, &errOut, kh); code != 0 {
		t.Fatalf("list -container amnezia-awg: код %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Alice") {
		t.Errorf("список amnezia-awg не напечатан: %q", out.String())
	}
}
