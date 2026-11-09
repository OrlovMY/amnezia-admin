package core

import (
	"strings"
	"testing"
)

// Имя клиента XRay с хвостовым переводом строки (так пишет приложение
// Amnezia) не должно доезжать до итога переноса. Доезд — боевым путём:
// копия → BackupWithout → SkippedXRayLines, как в -to-host -skip-xray.
func TestXRayClientNameTrimmedOnRead(t *testing.T) {
	cases := []struct {
		name, raw, want string
	}{
		{"LF", `[{"clientId":"a","userData":{"clientName":"Admin\n"}}]`, "Admin"},
		{"CRLF", `[{"clientId":"a","userData":{"clientName":"Admin\r\n"}}]`, "Admin"},
		{"только перевод строки", `[{"clientId":"a","userData":{"clientName":"\n"}}]`, "(без имени)"},
		{"чистое", `[{"clientId":"a","userData":{"clientName":"Admin"}}]`, "Admin"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := &Backup{Containers: []BackupContainer{{
				Name: XRayContainer, Status: CtrSaved,
				Files: []BackupFile{{Name: "clientsTable", Status: FileSaved, Data: NewSecret([]byte(c.raw))}},
			}}}
			_, sk := BackupWithout(b, XRayContainer)
			if !sk.Clients.Known || len(sk.Clients.Names) != 1 || sk.Clients.Names[0] != c.want {
				t.Fatalf("имена: %q (known=%v), ожидалось [%q]", sk.Clients.Names, sk.Clients.Known, c.want)
			}
			for _, l := range SkippedXRayLines(sk) {
				if strings.ContainsAny(l, "\r\n") {
					t.Errorf("в строке итога перевод строки: %q", l)
				}
			}
		})
	}
	if got := (ClientEntry{UserData: map[string]any{"clientName": "x\r\n"}}).Name(); got != "x" {
		t.Errorf("Name() = %q", got)
	}
}
