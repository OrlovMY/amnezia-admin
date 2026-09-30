package main

// Тесты A1б (сплошная сверка по четырём признакам CLAUDE.md) для CLI. Идут
// через listUsers — ту же функцию, что подкоманда list и пункты меню, — над
// fakesrv. Только API, существовавший на f0febbd: на нём тесты компилируются
// и падают поведением.

import (
	"errors"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

const wgConfPath = "/opt/amnezia/awg/wg0.conf"

// withOrphan — fakesrv, в wg0.conf которого есть peer без записи в
// clientsTable.
func withOrphan(t *testing.T) (*fakesrv.Server, string) {
	t.Helper()
	srv := fakesrv.New()
	conf, ok := srv.File(wgConfPath)
	if !ok {
		t.Fatal("тест перестал что-либо проверять: у fakesrv нет wg0.conf")
	}
	const orphan = "OrphanPeerKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	srv.SetFile(wgConfPath, append(conf, []byte("\n[Peer]\nPublicKey = "+orphan+"\nAllowedIPs = 10.8.1.9/32\n")...))
	return srv, orphan
}

// TestA1bOrphanUnknownDiffersFromNone — ТЕСТ РАЗЛИЧЕНИЯ. Строка о peers без
// имени печатается только когда они есть, поэтому МОЛЧАНИЕ list — это
// утверждение «сирот нет». Три случая обязаны различаться: сирот нет
// (молчание), сирота есть (перечень), проверить не удалось (сказано прямо).
// На f0febbd третий случай печатался ровно как первый.
func TestA1bOrphanUnknownDiffersFromNone(t *testing.T) {
	// «Нет» и «не удалось» — на ОДНОМ сервере: ключи fakesrv случайны, и
	// выводы двух разных серверов различались бы всегда, ничего не доказав.
	srv := fakesrv.New()
	sess := core.NewSessionWithRunner(srv, a1Creds())
	clean := runList(t, sess)
	srv.FailRead = map[string]error{wgConfPath: errors.New("cat: wg0.conf: Permission denied")}
	failed := runList(t, sess)

	orphSrv, orphan := withOrphan(t)
	withOrph := runList(t, core.NewSessionWithRunner(orphSrv, a1Creds()))

	if strings.Contains(clean, "Peers в wg0.conf без имени") || strings.Contains(clean, "не удалось") {
		t.Errorf("чистый сервер: лишние строки о сиротах:\n%s", clean)
	}
	if !strings.Contains(withOrph, "Peers в wg0.conf без имени в clientsTable: 1") || !strings.Contains(withOrph, orphan) {
		t.Errorf("сирота есть, а перечня нет — тест различения перестал что-либо проверять:\n%s", withOrph)
	}
	if failed == clean {
		t.Errorf("wg0.conf прочитать не удалось, а вывод list дословно тот же, что на чистом сервере — "+
			"«проверить не удалось» выдано за «сирот нет»:\n%s", failed)
	}
	if strings.Contains(failed, "Peers в wg0.conf без имени в clientsTable: ") {
		t.Errorf("при отказе чтения напечатан перечень сирот:\n%s", failed)
	}
}

// TestA1bOrphanReadFailReachesList — ТЕСТ ДОЕЗДА: отказ чтения wg0.conf
// приходит боевым путём (fakesrv.FailRead → core.Session.OrphanPeers →
// listUsers), и в выводе сказано, что проверка не состоялась и почему.
func TestA1bOrphanReadFailReachesList(t *testing.T) {
	srv := fakesrv.New()
	srv.FailRead = map[string]error{wgConfPath: errors.New("cat: wg0.conf: Permission denied")}
	out := runList(t, core.NewSessionWithRunner(srv, a1Creds()))
	if !strings.Contains(out, "Проверить peers в wg0.conf без имени в clientsTable не удалось") {
		t.Errorf("отказ чтения wg0.conf не доехал до вывода list:\n%s", out)
	}
	if !strings.Contains(out, "Permission denied") {
		t.Errorf("причина отказа не названа — человеку нечего чинить:\n%s", out)
	}
	if !strings.Contains(out, "Есть ли такие — неизвестно.") {
		t.Errorf("не сказано, что наличие сирот неизвестно:\n%s", out)
	}
	// Таблица при этом напечатана: отказ второстепенной проверки не прячет
	// основной ответ.
	listRow(t, out, "Alice")
	listRow(t, out, "Bob")
}

// corruptWgShow — fakesrv, у которого в ответе `wg show` время рукопожатия
// первого peer'а не число.
type corruptWgShow struct{ inner *fakesrv.Server }

func (c corruptWgShow) Run(cmd string, stdin []byte) (string, error) {
	out, err := c.inner.Run(cmd, stdin)
	if err != nil || !strings.Contains(cmd, "wg show wg0 dump") {
		return out, err
	}
	lines := strings.Split(out, "\n")
	if len(lines) > 1 {
		if f := strings.Split(lines[1], "\t"); len(f) >= 8 {
			f[4] = "n/a"
			lines[1] = strings.Join(f, "\t")
		}
	}
	return strings.Join(lines, "\n"), nil
}

// TestA1bUnparsedStatsReachesList — ТЕСТ ДОЕЗДА признака 2 в parsePeerStats
// по пути list: неразобранный ответ `wg show` — «статистику получить не
// удалось», а не «—» и «0 B / 0 B». На f0febbd непонятое поле становилось
// нулём: строка утверждала «не подключался, трафик ноль». Тест различения
// того же места — core.TestA1bUnparsedStatsIsNotZero.
func TestA1bUnparsedStatsReachesList(t *testing.T) {
	out := runList(t, core.NewSessionWithRunner(corruptWgShow{inner: fakesrv.New()}, a1Creds()))
	if strings.Contains(out, "0 B / 0 B") {
		t.Errorf("неразобранный ответ сервера напечатан измеренным нулём:\n%s", out)
	}
	for _, name := range []string{"Alice", "Bob"} {
		if row := listRow(t, out, name); strings.Count(row, "?") < 2 {
			t.Errorf("строка %q без «?» в активности и трафике:\n%s", name, row)
		}
	}
	if !strings.Contains(out, "Статистику с сервера получить не удалось") {
		t.Errorf("под таблицей не сказано, что статистику получить не удалось:\n%s", out)
	}
}
