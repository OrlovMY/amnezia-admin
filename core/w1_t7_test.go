package core

// PR-W1: эталон серверных команд для amnezia-awg2 (T7 семейства WG). Для
// amnezia-awg эталон прежний (TestServerCommandsUnchanged): изменилось
// только имя файла — аргумент $4 команды записи. Здесь — то же для
// amnezia-awg2: каждая команда — из шаблонов ниже, ТОЧНОЕ число каждой, и
// команда записи несёт файл awg0.conf.

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

var awg2Templates = []string{
	"docker exec " + dyn + " cat " + dyn,
	"docker exec " + dyn + " sh -c 'mkdir -p " + dyn + "/backup && ts=$(date +%Y%m%d-%H%M%S) && " +
		"cp " + dyn + "/awg0.conf " + dyn + "/backup/awg0.conf.$ts && " +
		"(cp " + dyn + "/clientsTable " + dyn + "/backup/clientsTable.$ts 2>/dev/null; " +
		"ls -1t " + dyn + "/backup/awg0.conf.* 2>/dev/null | tail -n +21 | while read f; do rm -f \"$f\"; done; " +
		"ls -1t " + dyn + "/backup/clientsTable.* 2>/dev/null | tail -n +21 | while read f; do rm -f \"$f\"; done)'",
	"docker exec " + dyn + " awg show awg0 dump",
	"docker exec " + dyn + " bash -c 'awg syncconf awg0 <(awg-quick strip " + dyn + "/awg0.conf)'",
	"docker exec " + dyn + " sh -c 'test -f " + dyn + "/clientsTable && echo yes || echo no'",
	casWriteTemplate("amnezia-admin-apply"),
	casWriteTemplate("amnezia-admin-rollback"),
}

// awg2Want — точное число команд каждого шаблона в сценарии ниже.
var awg2Want = []int{8, 2, 3, 3, 2, 2, 1}

func TestServerCommandsAWG2(t *testing.T) {
	srv := fakesrv.NewAWG2()
	sess := NewSessionWithRunner(srv, testCreds())
	c := &Container{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg", Proto: "awg2", Support: SupportYes}
	if _, err := sess.GetPeerStats(c); err != nil {
		t.Fatalf("GetPeerStats: %v", err)
	}
	if _, err := sess.AddUser(c, "Carol"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	srv.FailSyncconf = fmt.Errorf("awg: syncconf: I/O error")
	if _, err := sess.AddUser(c, "Dave"); err == nil {
		t.Fatal("AddUser при сбое syncconf: ждали ошибку отката")
	}
	res := make([]*regexp.Regexp, len(awg2Templates))
	for i, tmpl := range awg2Templates {
		res[i] = mustTemplateRegex(tmpl)
	}
	seen := make([]int, len(res))
	for _, cmd := range srv.Commands() {
		m := -1
		for i, re := range res {
			if re.MatchString(cmd) {
				m = i
				break
			}
		}
		if m < 0 {
			t.Errorf("%s команда amnezia-awg2 вне шаблонов: %.140q", t7Marker, cmd)
			continue
		}
		seen[m]++
		if m >= 5 && !strings.HasSuffix(cmd, " awg0.conf") {
			t.Errorf("%s команда записи amnezia-awg2 несёт не awg0.conf: …%q", t7Marker, cmd[len(cmd)-40:])
		}
		if strings.Contains(cmd, "wg0.conf") && !strings.Contains(cmd, "awg0.conf") {
			t.Errorf("%s amnezia-awg2 обратился к wg0.conf: %.140q", t7Marker, cmd)
		}
	}
	for i := range res {
		if seen[i] != awg2Want[i] {
			t.Errorf("%s шаблон awg2 #%d: команд %d, ждали ровно %d: %.70s", t7Marker, i, seen[i], awg2Want[i], awg2Templates[i])
		}
	}
}

// TestWGFamilyTable — таблица семейства WG: amnezia-awg и amnezia-wireguard —
// прежние wg0.conf/wg/wg0; amnezia-awg2 — awg0.conf/awg/awg0 в
// /opt/amnezia/awg; чужой контейнер — ошибка, а не догадка.
func TestWGFamilyTable(t *testing.T) {
	want := map[string]WGFamily{
		"amnezia-awg":       {"amnezia-awg", "/opt/amnezia/awg", "wg0.conf", "wg", "wg0"},
		"amnezia-wireguard": {"amnezia-wireguard", "/opt/amnezia/wireguard", "wg0.conf", "wg", "wg0"},
		"amnezia-awg2":      {"amnezia-awg2", "/opt/amnezia/awg", "awg0.conf", "awg", "awg0"},
	}
	if len(WGFamilies()) != len(want) {
		t.Errorf("строк в таблице %d, ждали ровно %d", len(WGFamilies()), len(want))
	}
	for name, w := range want {
		got, err := WGFamilyOf(&Container{Name: name})
		if err != nil || got != w {
			t.Errorf("%s: %+v (%v), ждали %+v", name, got, err, w)
		}
	}
	for _, name := range []string{"amnezia-xray", "amnezia-awg3", "amnezia-foo", ""} {
		if _, err := WGFamilyOf(&Container{Name: name}); err == nil {
			t.Errorf("%q: ждали ошибку «не семейство WG», а не догадку", name)
		}
	}
}

// TestCASFingerprintChangedByW1 — текст скрипта записи изменился (имя файла
// стало аргументом $4), значит изменился и отпечаток: перед rc-тегом его
// сверяют заново (RELEASING 6а). Сумма скрипта на e1c942b посчитана из
// `git show e1c942b:core/caswrite.go`.
func TestCASFingerprintChangedByW1(t *testing.T) {
	const scriptAtE1c942b = "2f4f94fd9e4a5ed7bc391fe91dd0d7500dd44bca3e1615b66fe565654670bbda"
	s, _, _ := CASFingerprint()
	if s == scriptAtE1c942b {
		t.Errorf("сумма CASWriteScript не изменилась — имя файла не стало аргументом?")
	}
	if !strings.Contains(CASWriteScript, "cf=$4") {
		t.Errorf("в скрипте записи нет cf=$4")
	}
}
