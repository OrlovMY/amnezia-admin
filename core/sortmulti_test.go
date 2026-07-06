package core

import (
	"testing"
	"time"
)

func TestSortClientsMultiKeyPrimaryOnly(t *testing.T) {
	clients := []ClientEntry{
		{ClientID: "b", UserData: map[string]any{"clientName": "Bob"}},
		{ClientID: "a", UserData: map[string]any{"clientName": "Alice"}},
		{ClientID: "c", UserData: map[string]any{"clientName": "Carol"}},
	}
	SortClientsMultiKey(clients, nil, SortByName, Asc, SortNone, Asc)
	got := []string{clients[0].Name(), clients[1].Name(), clients[2].Name()}
	want := []string{"Alice", "Bob", "Carol"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestSortClientsMultiKeyDirectionToggle(t *testing.T) {
	clients := []ClientEntry{
		{ClientID: "a", UserData: map[string]any{"clientName": "Alice"}},
		{ClientID: "b", UserData: map[string]any{"clientName": "Bob"}},
	}
	SortClientsMultiKey(clients, nil, SortByName, Desc, SortNone, Asc)
	if clients[0].Name() != "Bob" || clients[1].Name() != "Alice" {
		t.Fatalf("desc order wrong: %+v", clients)
	}
}

// TestSortClientsMultiKeySecondaryTieBreak — ключевой сценарий: равные значения
// по primary разрешаются по secondary (в его направлении).
func TestSortClientsMultiKeySecondaryTieBreak(t *testing.T) {
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	clients := []ClientEntry{
		{ClientID: "x", UserData: map[string]any{"clientName": "Xavier"}},
		{ClientID: "y", UserData: map[string]any{"clientName": "Yvonne"}},
		{ClientID: "z", UserData: map[string]any{"clientName": "Zack"}},
	}
	// все три имеют ОДИНАКОВЫЙ LastHandshake (primary=Activity даёт ничью
	// для всех пар) — должны быть упорядочены по secondary=Name(Asc)
	stats := map[string]PeerStat{
		"x": {LastHandshake: now},
		"y": {LastHandshake: now},
		"z": {LastHandshake: now},
	}
	SortClientsMultiKey(clients, stats, SortByActivityCol, Desc, SortByName, Asc)
	got := []string{clients[0].Name(), clients[1].Name(), clients[2].Name()}
	want := []string{"Xavier", "Yvonne", "Zack"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (secondary tie-break by name asc)", got, want)
		}
	}

	// смена направления secondary -> обратный порядок при той же ничьей по primary
	SortClientsMultiKey(clients, stats, SortByActivityCol, Desc, SortByName, Desc)
	got2 := []string{clients[0].Name(), clients[1].Name(), clients[2].Name()}
	want2 := []string{"Zack", "Yvonne", "Xavier"}
	for i := range want2 {
		if got2[i] != want2[i] {
			t.Fatalf("got %v, want %v (secondary tie-break by name desc)", got2, want2)
		}
	}
}

func TestSortClientsMultiKeyByTrafficUsesRx(t *testing.T) {
	clients := []ClientEntry{
		{ClientID: "a", UserData: map[string]any{"clientName": "A"}},
		{ClientID: "b", UserData: map[string]any{"clientName": "B"}},
	}
	stats := map[string]PeerStat{
		"a": {RxBytes: 100, TxBytes: 9999}, // большой Tx, но маленький Rx
		"b": {RxBytes: 500, TxBytes: 1},
	}
	SortClientsMultiKey(clients, stats, SortByTraffic, Asc, SortNone, Asc)
	if clients[0].ClientID != "a" || clients[1].ClientID != "b" {
		t.Fatalf("сортировка трафика должна учитывать RxBytes, а не Tx: %+v", clients)
	}
}

func TestSortClientsMultiKeyByCreated(t *testing.T) {
	clients := []ClientEntry{
		{ClientID: "a", UserData: map[string]any{"creationDate": "2022-01-01T00:00:00Z"}},
		{ClientID: "b", UserData: map[string]any{"creationDate": "2020-01-01T00:00:00Z"}},
		{ClientID: "c", UserData: map[string]any{"creationDate": "2021-01-01T00:00:00Z"}},
	}
	SortClientsMultiKey(clients, nil, SortByCreated, Asc, SortNone, Asc)
	got := []string{clients[0].ClientID, clients[1].ClientID, clients[2].ClientID}
	want := []string{"b", "c", "a"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestSortClientsMultiKeyStableWithoutSecondary(t *testing.T) {
	// без secondary и с равными значениями primary порядок не должен меняться
	// (сортировка стабильна) — проверяем через одинаковые имена
	clients := []ClientEntry{
		{ClientID: "first", UserData: map[string]any{"clientName": "Same"}},
		{ClientID: "second", UserData: map[string]any{"clientName": "Same"}},
		{ClientID: "third", UserData: map[string]any{"clientName": "Same"}},
	}
	SortClientsMultiKey(clients, nil, SortByName, Asc, SortNone, Asc)
	got := []string{clients[0].ClientID, clients[1].ClientID, clients[2].ClientID}
	want := []string{"first", "second", "third"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v (порядок должен сохраниться при ничьей)", got, want)
		}
	}
}
