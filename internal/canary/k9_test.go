package canary

import (
	"encoding/base64"
	"strings"
	"testing"

	"amnezia-admin/core"
)

type k9Exit struct{ code int }

func (e k9Exit) Error() string   { return "exit" }
func (e k9Exit) ExitStatus() int { return e.code }

// k9Fake — сервер для К9: файлы в памяти, stat отвечает perms, запись —
// исходом из writes по очереди.
func k9Fake(perms string, keepInode bool, writes []struct {
	out  string
	code int
}) (func(string) (string, error), func(string, []byte) (string, error), *int) {
	files := map[string]string{"wg0.conf": "[Interface]\n", "clientsTable": "[]", "wireguard_server_public_key.key": "PUB\n", "wireguard_psk.key": "PSK\n"}
	n := 0
	remote := func(cmd string) (string, error) {
		if strings.Contains(cmd, "stat -c %i") {
			// до первой записи — 1, после — 2 (keepInode — прежние)
			v := "1"
			if n > 0 && !keepInode {
				v = "2"
			}
			return v + " " + v + " " + v, nil
		}
		if strings.Contains(cmd, "stat -c") {
			return perms, nil
		}
		for name, v := range files {
			if strings.Contains(cmd, "[ -e "+name+" ]") {
				return "Y\n" + base64.StdEncoding.EncodeToString([]byte(v)) + "\n", nil
			}
		}
		return "N\n", nil
	}
	remoteIn := func(cmd string, _ []byte) (string, error) {
		w := writes[n]
		n++
		if w.code == 0 {
			return w.out, nil
		}
		return w.out, k9Exit{w.code}
	}
	return remote, remoteIn, &n
}

var k9tg = K9WGTarget(core.WGFamily{Container: "amnezia-awg", Dir: "/opt/amnezia/awg", File: "wg0.conf"})

func k9Statuses(rs []Result) string {
	var b []string
	for _, r := range rs {
		b = append(b, r.ID+"="+r.Status.String())
	}
	return strings.Join(b, " ")
}

// TestK9Table — различение: нет контейнера — НЕ ПРОВЕРЕНО (не «пройдено» и
// не пусто); пропуск флагом — строк нет; запись прошла и сверка отказала —
// ПРОЙДЕН; сверка ключа НЕ отказала (подмена «скрипт не сверяет ключ») —
// НЕ ПРОЙДЕН; права не 600 — НЕ ПРОЙДЕН.
func TestK9Table(t *testing.T) {
	type w = struct {
		out  string
		code int
	}
	if rs := K9(nil, nil, k9tg, false, false); len(rs) != 1 || rs[0].Status != NotChecked {
		t.Errorf("нет контейнера: %s", k9Statuses(rs))
	}
	if rs := K9(nil, nil, k9tg, true, true); len(rs) != 0 {
		t.Errorf("пропуск флагом дал строки: %s", k9Statuses(rs))
	}
	cases := []struct {
		name, perms string
		keep        bool
		writes      []w
		want        string
	}{
		{"всё верно", "600 600 600 0", false, []w{{"", 0}, {"changed: wireguard_psk.key", 3}}, "К9.0=ПРОЙДЕН К9.1=ПРОЙДЕН К9.2=ПРОЙДЕН"},
		{"сверка ключа не остановила запись", "600 600 600 0", false, []w{{"", 0}, {"", 0}}, "К9.0=ПРОЙДЕН К9.1=ПРОЙДЕН К9.2=НЕ ПРОЙДЕН"},
		{"права 644", "600 644 600 0", false, []w{{"", 0}, {"changed: wireguard_psk.key", 3}}, "К9.0=ПРОЙДЕН К9.1=НЕ ПРОЙДЕН К9.2=ПРОЙДЕН"},
		{"временные файлы остались", "600 600 600 2", false, []w{{"", 0}, {"changed: wireguard_psk.key", 3}}, "К9.0=ПРОЙДЕН К9.1=НЕ ПРОЙДЕН К9.2=ПРОЙДЕН"},
		{"inode прежний — файл не заменён (AU Medium-2)", "600 600 600 0", true, []w{{"", 0}, {"changed: wireguard_psk.key", 3}}, "К9.0=ПРОЙДЕН К9.1=НЕ ПРОЙДЕН К9.2=ПРОЙДЕН"},
		{"запись отказала", "600 600 600 0", false, []w{{"changed: wg0.conf", 3}, {"changed: wireguard_psk.key", 3}}, "К9.0=ПРОЙДЕН К9.1=НЕ ПРОЙДЕН К9.2=ПРОЙДЕН"},
	}
	for _, c := range cases {
		r, ri, n := k9Fake(c.perms, c.keep, c.writes)
		got := k9Statuses(K9(r, ri, k9tg, true, false))
		if got != c.want {
			t.Errorf("%s: %s, ждали %s", c.name, got, c.want)
		}
		if *n != 2 {
			t.Errorf("%s: записей %d, ждали 2", c.name, *n)
		}
	}
}
