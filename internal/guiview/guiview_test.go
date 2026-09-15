package guiview

import (
	"errors"
	"fmt"
	"testing"

	"amnezia-admin/core"
)

// containerSpec — те же 12 контейнеров, что и в core.TestContainersWasNowTable
// (core/core_test.go): 10 известных (core.knownContainers на 8c20da1) +
// amnezia-awg2 (неизвестный WG-подобный, Managed=false — реш. Б) +
// amnezia-foo (неизвестный произвольный, Managed=false, как и в d6b3a5a).
// internal/guiview не импортирует fakesrv (пакет тестируется без сети и без
// сервера вообще — Д2), поэтому список продублирован здесь буквально; при
// расхождении с core/core_test.go — синхронизировать оба места.
var containerSpecs = []struct {
	name    string
	proto   string
	managed bool
}{
	{"amnezia-awg", "AmneziaWG", true},
	{"amnezia-wireguard", "WireGuard", true},
	{"amnezia-xray", "XRay", false},
	{"amnezia-openvpn", "OpenVPN", false},
	{"amnezia-shadowsocks", "OpenVPN+ShadowSocks", false},
	{"amnezia-openvpn-cloak", "OpenVPN+Cloak", false},
	{"amnezia-ikev2", "IKEv2", false},
	{"amnezia-sftp", "SFTP", false},
	{"amnezia-tor", "Tor site", false},
	{"amnezia-dns", "DNS", false},
	{"amnezia-awg2", "awg2", false}, // реш. Б: не наш формат конфига, управление не включаем
	{"amnezia-foo", "foo", false},   // произвольный неизвестный контейнер
}

func mkContainer(spec struct {
	name    string
	proto   string
	managed bool
}) core.Container {
	return core.Container{Name: spec.name, Dir: "/opt/amnezia/" + spec.name, Proto: spec.proto, Managed: spec.managed}
}

// twoClients — вариант "две записи" (N=2) для LoadClientsView.
func twoClients() []core.ClientEntry {
	return []core.ClientEntry{
		{ClientID: "pub1", UserData: map[string]any{"clientName": "Alice"}},
		{ClientID: "pub2", UserData: map[string]any{"clientName": "Bob"}},
	}
}

// TestViewState — табличный тест (Е): для каждого из 12 контейнеров и
// каждого из 4 исходов LoadClientsView (две записи / файла нет / ошибка
// чтения / ошибка разбора) проверяет дословные Status, флаги LoadList,
// LoadStats, CanManage и подпись протокола ProtoLabel — единственный источник
// решений, которым пользуется refresh() (Э3а).
func TestViewState(t *testing.T) {
	readErr := errors.New("чтение clientsTable: i/o timeout")
	parseErr := errors.New("clientsTable повреждена: json: cannot unmarshal object into Go value of type []core.ClientEntry")

	for _, spec := range containerSpecs {
		c := mkContainer(spec)

		t.Run(spec.name+"/две записи", func(t *testing.T) {
			v := ViewState(c, twoClients(), true, nil)
			if !v.LoadList {
				t.Error("LoadList = false, want true (Д2: всегда true для amnezia-*)")
			}
			if v.LoadStats != spec.managed {
				t.Errorf("LoadStats = %v, want %v (= Managed)", v.LoadStats, spec.managed)
			}
			if v.CanManage != spec.managed {
				t.Errorf("CanManage = %v, want %v (= Managed)", v.CanManage, spec.managed)
			}
			var want string
			if spec.managed {
				want = "Пользователей: 2 · трафик и активность — с момента перезапуска сервера"
			} else {
				want = fmt.Sprintf("Пользователей: 2 — только просмотр: управление для протокола %s не поддерживается.", spec.proto)
			}
			if v.Status != want {
				t.Errorf("Status = %q, want %q", v.Status, want)
			}
		})

		t.Run(spec.name+"/файла нет", func(t *testing.T) {
			v := ViewState(c, nil, false, nil)
			var want string
			if spec.managed {
				want = "Пользователей: 0 · трафик и активность — с момента перезапуска сервера"
			} else {
				want = fmt.Sprintf("Протокол %s не ведёт список пользователей в этой утилите — только просмотр.", spec.proto)
			}
			if v.Status != want {
				t.Errorf("Status = %q, want %q", v.Status, want)
			}
		})

		t.Run(spec.name+"/ошибка чтения", func(t *testing.T) {
			v := ViewState(c, nil, false, readErr)
			var want string
			if spec.managed {
				want = "Ошибка: " + readErr.Error()
			} else {
				want = fmt.Sprintf("Не удалось прочитать список пользователей %s: %s.", spec.proto, readErr.Error())
			}
			if v.Status != want {
				t.Errorf("Status = %q, want %q", v.Status, want)
			}
		})

		t.Run(spec.name+"/ошибка разбора", func(t *testing.T) {
			v := ViewState(c, nil, true, parseErr)
			var want string
			if spec.managed {
				want = "Ошибка: " + parseErr.Error()
			} else {
				want = fmt.Sprintf("Не удалось прочитать список пользователей %s: %s.", spec.proto, parseErr.Error())
			}
			if v.Status != want {
				t.Errorf("Status = %q, want %q", v.Status, want)
			}
		})
	}
}

// TestProtoLabel — единственное место подписи "(только просмотр)" (Д2): без
// второго суффикса, дословно.
func TestProtoLabel(t *testing.T) {
	managed := core.Container{Proto: "AmneziaWG", Managed: true}
	if got := ProtoLabel(managed); got != "AmneziaWG" {
		t.Errorf("ProtoLabel(managed) = %q, want %q", got, "AmneziaWG")
	}
	unmanaged := core.Container{Proto: "XRay", Managed: false}
	if got := ProtoLabel(unmanaged); got != "XRay (только просмотр)" {
		t.Errorf("ProtoLabel(unmanaged) = %q, want %q", got, "XRay (только просмотр)")
	}
}
