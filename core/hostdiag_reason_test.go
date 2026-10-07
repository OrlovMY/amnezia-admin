package core_test

// Причина iptables для человека (живая проверка: у amnezia-wireguard первая
// строка ошибки — modprobe, а «Table does not exist» — вторая). Проба
// исполняется настоящим sh.

import (
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/core"
)

func TestDiagIPTablesReasonLine(t *testing.T) {
	const (
		mod   = "modprobe: can't load module ip_tables (kernel/net/ipv4/netfilter/ip_tables.ko.zst): invalid module format"
		table = "iptables v1.8.7 (legacy): can't initialize iptables table `nat': Table does not exist (do you need to insmod?)"
		perh  = "Perhaps iptables or your kernel needs to be upgraded."
	)
	for _, tc := range []struct {
		name  string
		lines []string
		want  []string // подстроки причины
		not   []string
	}{
		{"вживую modprobe, Table, Perhaps", []string{mod, table, perh}, []string{"invalid module format", "Table does not exist"}, []string{"Perhaps"}},
		{"прежде Table, Perhaps", []string{table, perh}, []string{"Table does not exist"}, []string{"Perhaps", "; "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shim, sbin := t.TempDir(), t.TempDir()
			writeExe(t, shim, "ip", "exit 0\n")
			body := `case "$1" in -V) echo "iptables v1.8.7 (legacy)";; *) cat >&2 <<'X'` + "\n" + strings.Join(tc.lines, "\n") + "\nX\nexit 3;; esac\n"
			writeExe(t, shim, "iptables", body)
			out := runSh(t, shim, core.DiagContainerScriptForTest("wg0", filepath.ToSlash(sbin)))
			c := core.ParseProbeForTest(out)
			f := core.ClassifyIPTablesForTest(c)
			if f.State != core.DiagYes {
				t.Fatalf("классификация изменилась: %v\n%s", f.State, out)
			}
			for _, w := range tc.want {
				if !strings.Contains(f.Reason, w) {
					t.Errorf("в причине нет %q: %q", w, f.Reason)
				}
			}
			for _, w := range tc.not {
				if strings.Contains(f.Reason, w) {
					t.Errorf("в причине лишнее %q: %q", w, f.Reason)
				}
			}
		})
	}
}
