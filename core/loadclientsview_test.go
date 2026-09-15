// Пакет core_test (внешний): TestContainersWasNowTable и
// TestLoadClientsViewNoExtraCommands (FIX-VIEW, задание Е) используют
// internal/guiview, который сам импортирует core — во внутреннем пакете core
// (core_test.go, "package core") это дало бы цикл импорта. Внешний тестовый
// пакет core_test импортирует и core, и internal/guiview напрямую, цикла нет.
package core_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
	"amnezia-admin/internal/guiview"
)

func viewCreds() *core.ServerCreds {
	return &core.ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"}
}

// containersWasNow — 12 контейнеров: 10 известных (core.knownContainers на
// 8c20da1, дословно проверено чтением core/core.go) + amnezia-awg2
// (неизвестный WG-подобный) + amnezia-foo (неизвестный произвольный).
//
// wasManagedOriginal — Managed на d6b3a5a, проверено `git show
// d6b3a5a:core/core.go` (не по памяти, В2 п.1 задания): единственное
// структурное отличие — amnezia-awg2 был Managed=true (эвристика "суффикс
// начинается с awg/wireguard", core.go:226-229 на d6b3a5a). Managed=false для
// awg2 появился ещё в PR-1 (аудит-2026-09-14, Backlog) — ДО этого задания;
// здесь это факт истории, не находка этого PR и не переоткрывается (реш. Б).
var containersWasNow = []struct {
	name               string
	proto              string
	managed            bool // на 8c20da1 + FIX-VIEW — текущее состояние
	wasManagedOriginal bool // на d6b3a5a
}{
	{"amnezia-awg", "AmneziaWG", true, true},
	{"amnezia-wireguard", "WireGuard", true, true},
	{"amnezia-xray", "XRay", false, false},
	{"amnezia-openvpn", "OpenVPN", false, false},
	{"amnezia-shadowsocks", "OpenVPN+ShadowSocks", false, false},
	{"amnezia-openvpn-cloak", "OpenVPN+Cloak", false, false},
	{"amnezia-ikev2", "IKEv2", false, false},
	{"amnezia-sftp", "SFTP", false, false},
	{"amnezia-tor", "Tor site", false, false},
	{"amnezia-dns", "DNS", false, false},
	{"amnezia-awg2", "awg2", false, true},
	{"amnezia-foo", "foo", false, false},
}

func containerNames() []string {
	names := make([]string, len(containersWasNow))
	for i, s := range containersWasNow {
		names[i] = s.name
	}
	return names
}

// setVariant готовит один из четырёх исходов clientsTable для path (Е):
// "ok" — две записи, "missing" — файла нет, "failread" — файл есть, но cat
// возвращает ошибку (fakesrv.FailRead), "badjson" — файл есть, непустой, но
// не JSON-массив ClientEntry (объект {"inbounds":[]}, как реальный формат
// XRay/V2Ray, П3) — ошибка разбора.
func setVariant(srv *fakesrv.Server, path, variant string) {
	switch variant {
	case "ok":
		data, err := json.Marshal([]core.ClientEntry{
			{ClientID: "pub1", UserData: map[string]any{"clientName": "Alice"}},
			{ClientID: "pub2", UserData: map[string]any{"clientName": "Bob"}},
		})
		if err != nil {
			panic(err)
		}
		srv.SetFile(path, data)
	case "missing":
		srv.DeleteFile(path)
	case "failread":
		srv.SetFile(path, []byte(`[{"clientId":"pub1"}]`)) // файл есть — иначе test -f сказал бы "нет"
		if srv.FailRead == nil {
			srv.FailRead = map[string]error{}
		}
		srv.FailRead[path] = errors.New("i/o timeout")
	case "badjson":
		srv.SetFile(path, []byte(`{"inbounds":[]}`)) // не JSON-массив — как реальный формат XRay (риск, П7)
	}
}

// TestContainersWasNowTable — табличный тест (задание Е): docker ps отдаёт
// все 12 контейнеров, для каждого — 4 варианта clientsTable. Проверяет:
// Proto без хвоста «не поддерживается» (Э1, разница только от 8c20da1, не от
// d6b3a5a — строка (в) ниже), Managed (реш. Б — строка (а)), состояние
// просмотра через LoadClientsView, и решение guiview.ViewState поверх него
// (LoadStats/CanManage = Managed — строка (г): для !Managed не запрашивается
// wg-статистика, в отличие от оригинала).
//
// Намеренные отличия от d6b3a5a (не находки, см. секцию А/Б/В2 задания):
//
//	(а) amnezia-awg2: Managed true(d6b3a5a)→false — решение Б, до этого PR.
//	(б) у ВСЕХ контейнеров (кроме Managed, где поведение не менялось этим
//	    PR) варианты "файла нет"/"failread" в оригинале LoadClients глотал
//	    ошибку cat и показывал "Пользователей: 0" (проверено чтением
//	    d6b3a5a: LoadClients возвращал []ClientEntry{}, nil при ЛЮБОЙ ошибке
//	    cat); теперь для !Managed — разные состояния "не ведёт список" /
//	    "не удалось прочитать" (реш. А, В — из-за этого DNS показывал
//	    "0 пользователей" в оригинале, жалоба владельца).
//	(в) Proto неизвестных amnezia-* (awg2, foo) — без хвоста "(не
//	    поддерживается...)", как и в оригинале: отличие от 8c20da1 (где хвост
//	    был добавлен PR-1), не от d6b3a5a.
//	(г) для !Managed не вызываются GetHandshakes/GetPeerStats (проверяет
//	    отдельно TestLoadClientsViewNoExtraCommands + чтение refresh() BE-01);
//	    оригинал их вызывал всегда (проверено чтением d6b3a5a:cmd/gui/main.go
//	    refresh()).
func TestContainersWasNowTable(t *testing.T) {
	variants := []string{"ok", "missing", "failread", "badjson"}
	for _, spec := range containersWasNow {
		for _, variant := range variants {
			t.Run(spec.name+"/"+variant, func(t *testing.T) {
				srv := fakesrv.New()
				srv.Names = containerNames()
				dir := "/opt/amnezia/" + strings.TrimPrefix(spec.name, "amnezia-")
				path := dir + "/clientsTable"
				setVariant(srv, path, variant)
				sess := core.NewSessionWithRunner(srv, viewCreds())

				containers, err := sess.FindContainers()
				if err != nil {
					t.Fatalf("FindContainers: %v", err)
				}
				var c *core.Container
				for i := range containers {
					if containers[i].Name == spec.name {
						c = &containers[i]
					}
				}
				if c == nil {
					t.Fatalf("%s не найден среди контейнеров: %+v", spec.name, containers)
				}

				// (в), Э1: Proto — без хвоста "не поддерживается", как в d6b3a5a
				if c.Proto != spec.proto {
					t.Errorf("Proto = %q, want %q (Э1: без хвоста «не поддерживается»)", c.Proto, spec.proto)
				}
				// (а), реш. Б: Managed сейчас (может отличаться от d6b3a5a — awg2)
				if c.Managed != spec.managed {
					t.Errorf("Managed = %v, want %v (was %v on d6b3a5a)", c.Managed, spec.managed, spec.wasManagedOriginal)
				}
				if c.Dir != dir {
					t.Fatalf("Dir = %q, want %q (тест держит их согласованными)", c.Dir, dir)
				}

				clients, existed, loadErr := sess.LoadClientsView(c)

				switch variant {
				case "ok":
					if loadErr != nil {
						t.Fatalf("LoadClientsView: unexpected error %v", loadErr)
					}
					if !existed {
						t.Error("existed = false, want true")
					}
					if len(clients) != 2 {
						t.Errorf("clients = %d, want 2: %+v", len(clients), clients)
					}
				case "missing":
					if loadErr != nil {
						t.Fatalf("LoadClientsView: unexpected error %v", loadErr)
					}
					if existed {
						t.Error("existed = true, want false")
					}
					if len(clients) != 0 {
						t.Errorf("clients = %+v, want empty", clients)
					}
				case "failread":
					if loadErr == nil {
						t.Fatal("LoadClientsView: expected error (cat failed), got nil")
					}
				case "badjson":
					if loadErr == nil {
						t.Fatal("LoadClientsView: expected error (не JSON-массив), got nil")
					}
				}

				// guiview.ViewState — решения и текст статуса (дословно, UI-01)
				view := guiview.ViewState(*c, clients, existed, loadErr)
				if view.CanManage != spec.managed {
					t.Errorf("CanManage = %v, want %v", view.CanManage, spec.managed)
				}
				if view.LoadStats != spec.managed {
					t.Errorf("LoadStats = %v, want %v (г: для !Managed статистика не запрашивается)", view.LoadStats, spec.managed)
				}
				if !view.LoadList {
					t.Error("LoadList = false, want true (Д2: всегда true для amnezia-*)")
				}

				var want string
				switch {
				case spec.managed && loadErr != nil:
					want = "Ошибка: " + loadErr.Error()
				case spec.managed:
					want = fmt.Sprintf("Пользователей: %d · трафик и активность — с момента перезапуска сервера", len(clients))
				case loadErr != nil:
					want = fmt.Sprintf("Не удалось прочитать список пользователей %s: %s.", spec.proto, loadErr.Error())
				case !existed:
					want = fmt.Sprintf("Протокол %s не ведёт список пользователей в этой утилите — только просмотр.", spec.proto)
				default:
					want = fmt.Sprintf("Пользователей: %d — только просмотр: управление для протокола %s не поддерживается.", len(clients), spec.proto)
				}
				if view.Status != want {
					t.Errorf("Status = %q, want %q", view.Status, want)
				}
			})
		}
	}
}

// TestLoadClientsViewNoExtraCommands (Е, строка "г"): журнал fakesrv после
// LoadClientsView для XRay и DNS равен ровно [test -f, cat] (или только
// [test -f], если файла нет) — никаких других команд, в т.ч. `wg show`.
// Что refresh() САМ не вызывает GetHandshakes/GetPeerStats для !Managed —
// отдельно проверяют BE-01 (чтение диффа) и интеграционный прогон против
// cmd/fakeserver (П6) — этот тест доказывает только то, что LoadClientsView
// сама по себе не тянет лишних команд.
func TestLoadClientsViewNoExtraCommands(t *testing.T) {
	for _, name := range []string{"amnezia-xray", "amnezia-dns"} {
		t.Run(name+"/файл есть", func(t *testing.T) {
			srv := fakesrv.New()
			srv.Names = []string{name}
			suffix := strings.TrimPrefix(name, "amnezia-")
			dir := "/opt/amnezia/" + suffix
			setVariant(srv, dir+"/clientsTable", "ok")
			sess := core.NewSessionWithRunner(srv, viewCreds())
			c := &core.Container{Name: name, Dir: dir, Proto: suffix, Managed: false}

			if _, _, err := sess.LoadClientsView(c); err != nil {
				t.Fatalf("LoadClientsView: %v", err)
			}
			want := []string{
				fmt.Sprintf("docker exec %s sh -c 'test -f %s/clientsTable && echo yes || echo no'", name, dir),
				fmt.Sprintf("docker exec %s cat %s/clientsTable", name, dir),
			}
			if got := srv.Commands(); !equalCmds(got, want) {
				t.Errorf("Commands() = %v, want %v", got, want)
			}
		})

		t.Run(name+"/файла нет", func(t *testing.T) {
			srv := fakesrv.New()
			srv.Names = []string{name}
			suffix := strings.TrimPrefix(name, "amnezia-")
			dir := "/opt/amnezia/" + suffix
			setVariant(srv, dir+"/clientsTable", "missing")
			sess := core.NewSessionWithRunner(srv, viewCreds())
			c := &core.Container{Name: name, Dir: dir, Proto: suffix, Managed: false}

			if _, _, err := sess.LoadClientsView(c); err != nil {
				t.Fatalf("LoadClientsView: %v", err)
			}
			want := []string{
				fmt.Sprintf("docker exec %s sh -c 'test -f %s/clientsTable && echo yes || echo no'", name, dir),
			}
			if got := srv.Commands(); !equalCmds(got, want) {
				t.Errorf("Commands() = %v, want %v", got, want)
			}
		})
	}
}

func equalCmds(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
