package core

// TestAllocateIPSkipsInterfaceAndPeers — Д (рекомендация), чистая функция:
// таблица случаев для allocateIP, без сети и без fakesrv.
//
// Тест обязан падать на fe5e013: на этой ревизии allocateIP/usedIPs не
// существуют (пакет не собирается без них), а nextFreeIP (её тогдашний
// аналог) не учитывает резерв отключённых клиентов — падение здесь
// доказывается вместе с TestReservedIPNotReused (core/txn_ipalloc_test.go),
// которая гоняет тот же путь через Session/fakesrv.

import (
	"fmt"
	"strings"
	"testing"
)

func TestAllocateIPSkipsInterfaceAndPeers(t *testing.T) {
	t.Run("пустой конфиг — 10.8.1.2", func(t *testing.T) {
		conf := parseWgConf("")
		ip, err := allocateIP(conf, nil)
		if err != nil {
			t.Fatalf("allocateIP: %v", err)
		}
		if ip != "10.8.1.2" {
			t.Errorf("ip = %q, want 10.8.1.2", ip)
		}
	})

	t.Run("интерфейс .1, peer'ы .2 и .3 — следующий .4", func(t *testing.T) {
		conf := parseWgConf(
			"[Interface]\nAddress = 10.8.1.1/24\n\n" +
				"[Peer]\nPublicKey = A\nAllowedIPs = 10.8.1.2/32\n\n" +
				"[Peer]\nPublicKey = B\nAllowedIPs = 10.8.1.3/32\n")
		ip, err := allocateIP(conf, nil)
		if err != nil {
			t.Fatalf("allocateIP: %v", err)
		}
		if ip != "10.8.1.4" {
			t.Errorf("ip = %q, want 10.8.1.4", ip)
		}
	})

	t.Run("резерв отключённого тоже занимает адрес", func(t *testing.T) {
		conf := parseWgConf("[Interface]\nAddress = 10.8.1.1/24\n\n" +
			"[Peer]\nPublicKey = A\nAllowedIPs = 10.8.1.2/32\n")
		clients := []ClientEntry{
			{ClientID: "A", UserData: map[string]any{"clientName": "Alice"}},
			{ClientID: "BOB", UserData: map[string]any{
				"clientName": "Bob", "disabled": true, "allowedIP": "10.8.1.3/32",
			}},
		}
		ip, err := allocateIP(conf, clients)
		if err != nil {
			t.Fatalf("allocateIP: %v", err)
		}
		if ip != "10.8.1.4" {
			t.Errorf("ip = %q, want 10.8.1.4 (резерв .3 должен быть пропущен)", ip)
		}
	})

	t.Run("все адреса до .254 заняты — ошибка", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("[Interface]\nAddress = 10.8.1.1/24\n\n")
		for n := 2; n <= 254; n++ {
			fmt.Fprintf(&b, "[Peer]\nPublicKey = P%d\nAllowedIPs = 10.8.1.%d/32\n\n", n, n)
		}
		conf := parseWgConf(b.String())
		_, err := allocateIP(conf, nil)
		if err == nil {
			t.Fatal("allocateIP: ожидалась ошибка (адресов не осталось)")
		}
		if !strings.Contains(err.Error(), "свободных адресов") {
			t.Errorf("текст ошибки не про исчерпание адресов: %v", err)
		}
	})
}

// TestHostIP — сравнение адресов по хост-части без маски (Г1): "10.8.1.5/32"
// и "10.8.1.5" — один и тот же адрес; несколько адресов через запятую —
// берётся первый IPv4 (тем же ipRe, что и весь остальной код).
func TestHostIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.8.1.5/32", "10.8.1.5"},
		{"10.8.1.5", "10.8.1.5"},
		{"10.8.1.5/32, fd00::5/128", "10.8.1.5"},
		{"", ""},
		{"fd00::5/128", ""},
	}
	for _, tc := range cases {
		if got := hostIP(tc.in); got != tc.want {
			t.Errorf("hostIP(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestAllocateIPSubnetDeterministic — review-reply PR-3 круга 2 (Low,
// AR-01): при отсутствующем Address в [Interface] подсеть раньше бралась
// обходом map usedIPs — порядок итерации карты в Go не определён и меняется
// от запуска к запуску, поэтому результат мог "мигать" между несколькими
// подсетями при одних и тех же входных данных. Конфиг ниже без Address,
// с peer'ами в ДВУХ разных подсетях (10.8.2.x первым в срезе conf.peers,
// 10.8.3.x вторым) и резервом отключённого в ТРЕТЬЕЙ (10.8.9.x) — если бы
// подсеть бралась из map, результат мог бы совпасть с любой из трёх.
// Правильный (детерминированный) результат — всегда первая по СРЕЗУ
// conf.peers подсеть (10.8.2.x), независимо от resulting map usedIPs.
// Много итераций — Go рандомизирует порядок обхода map при каждом range,
// а не один раз на программу, поэтому один прогон недостаточен, чтобы
// поймать регресс.
func TestAllocateIPSubnetDeterministic(t *testing.T) {
	conf := parseWgConf(
		"[Interface]\nListenPort = 51820\n\n" + // без Address
			"[Peer]\nPublicKey = A\nAllowedIPs = 10.8.2.5/32\n\n" +
			"[Peer]\nPublicKey = B\nAllowedIPs = 10.8.3.7/32\n")
	clients := []ClientEntry{
		{ClientID: "A", UserData: map[string]any{"clientName": "Alice"}},
		{ClientID: "B", UserData: map[string]any{"clientName": "Bob"}},
		{ClientID: "RESERVED", UserData: map[string]any{
			"clientName": "Carol", "disabled": true, "allowedIP": "10.8.9.9/32",
		}},
	}
	const want = "10.8.2.2" // used[5,7,9] заняты (по номеру хоста, без учёта подсети), .2 свободен
	for i := 0; i < 200; i++ {
		ip, err := allocateIP(conf, clients)
		if err != nil {
			t.Fatalf("итерация %d: allocateIP: %v", i, err)
		}
		if ip != want {
			t.Fatalf("итерация %d: ip = %q, want %q (подсеть должна браться из первого peer'а в срезе conf.peers, детерминированно)", i, ip, want)
		}
	}
}
