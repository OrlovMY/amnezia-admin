package core

// PR-W1: эталон серверных команд для amnezia-awg2 (T7 семейства WG). Для
// amnezia-awg эталон прежний (TestServerCommandsUnchanged): изменилось
// только имя файла — аргумент $4 команды записи. Здесь — то же для
// amnezia-awg2: каждая команда — из шаблонов ниже, ТОЧНОЕ число каждой, и
// команда записи несёт файл awg0.conf.

import (
	"fmt"
	"os"
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
var awg2Want = []int{13, 3, 4, 4, 4, 3, 1}

func TestServerCommandsAWG2(t *testing.T) {
	srv := fakesrv.NewAWG2()
	sess := NewSessionWithRunner(srv, testCreds())
	c := &Container{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg", Proto: "awg2", Managed: true}
	if _, err := sess.GetPeerStats(c); err != nil {
		t.Fatalf("GetPeerStats: %v", err)
	}
	nu, err := sess.AddUser(c, "Carol")
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	// Посадки канарейки (TestServerCommandsGuardCanary, ревью QA W1): только
	// в дочернем процессе, по переменной окружения.
	plant := os.Getenv(t7PlantEnv)
	if plant != "drop-delete" {
		cl, err := sess.LoadClients(c)
		if err != nil {
			t.Fatalf("LoadClients: %v", err)
		}
		id := ""
		for _, x := range cl {
			if x.Name() == nu.Name {
				id = x.ClientID
			}
		}
		if err := sess.DeleteByID(c, id); err != nil {
			t.Fatalf("DeleteByID: %v", err)
		}
	}
	if plant == "extra-stats" {
		if _, err := sess.GetPeerStats(c); err != nil {
			t.Fatalf("GetPeerStats: %v", err)
		}
	}
	if plant == "alien-cmd" {
		_, _ = sess.r.Run("docker exec amnezia-awg2 rm -f /opt/amnezia/awg/awg0.conf", nil)
	}
	srv.FailSyncconf = fmt.Errorf("awg: syncconf: I/O error")
	if _, err := sess.AddUser(c, "Dave"); err == nil {
		t.Fatal("AddUser при сбое syncconf: ждали ошибку отката")
	}
	res := make([]*regexp.Regexp, len(awg2Templates))
	for i, tmpl := range awg2Templates {
		res[i] = mustTemplateRegex(tmpl)
	}
	// Вердикт — общий с T7 (serverCommandsVerdict), его держит канарейка.
	for _, msg := range awg2Verdict(res, srv.Commands()) {
		t.Errorf("%s %s", t7Marker, msg)
	}
}

// awg2Verdict — общий вердикт T7 по таблице awg2 плюс привязка к файлу
// семейства: запись несёт awg0.conf, к wg0.conf обращений нет.
func awg2Verdict(res []*regexp.Regexp, cmds []string) []string {
	bad := serverCommandsVerdict(res, awg2Templates, awg2Want, cmds)
	for _, cmd := range cmds {
		if (res[5].MatchString(cmd) || res[6].MatchString(cmd)) && !strings.HasSuffix(cmd, " awg0.conf") {
			bad = append(bad, fmt.Sprintf("команда записи amnezia-awg2 несёт не awg0.conf: %.140q", cmd))
		}
		if strings.Contains(strings.ReplaceAll(cmd, "awg0.conf", ""), "wg0.conf") {
			bad = append(bad, fmt.Sprintf("amnezia-awg2 обратился к wg0.conf: %.140q", cmd))
		}
	}
	return bad
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
		got, err := WGFamilyOf(&Container{Name: name, Dir: w.Dir})
		if err != nil || got != w {
			t.Errorf("%s: %+v (%v), ждали %+v", name, got, err, w)
		}
	}
	// SEC W-R1: каталог контейнера расходится с таблицей — отказ.
	for _, c := range []Container{
		{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg2"},
		{Name: "amnezia-awg", Dir: "/opt/amnezia/wireguard"},
		{Name: "amnezia-awg", Dir: ""},
	} {
		if _, err := WGFamilyOf(&c); err == nil || !strings.Contains(err.Error(), "расходится") {
			t.Errorf("%+v: ждали отказ «каталог расходится», получено %v", c, err)
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
