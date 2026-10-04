package main

// QA-01 р5, Н2 (остаток): list по контейнеру семейства WG печатает дату
// формата приложения Amnezia с годом (core.CreatedText), а не срез до 19
// знаков без года. Доезд — полный run() через SSH fakesrv.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"amnezia-admin/core"
)

func TestWGListAppDateHasYear(t *testing.T) {
	key, kh, exec := setupFakeSSHForRunWithExec(t)
	b, _ := exec.File("/opt/amnezia/awg/clientsTable")
	var list []core.ClientEntry
	if err := json.Unmarshal(b, &list); err != nil || len(list) == 0 {
		t.Fatalf("стенд: %v", err)
	}
	list[0].UserData["creationDate"] = "Thu Oct 1 23:18:48 2026" // как пишет приложение
	out, _ := json.MarshalIndent(list, "", "    ")
	exec.SetFile("/opt/amnezia/awg/clientsTable", out)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"list", "-key", key, "-container", "amnezia-awg"}, strings.NewReader(""), &stdout, &stderr, kh); code != 0 {
		t.Fatalf("код %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "2026-10-01 23:18") {
		t.Fatalf("дата приложения в list без года:\n%s", stdout.String())
	}
}
