package core_test

import (
	"path/filepath"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// TestSavedConfigRoundTrip — ДОЕЗД: конфиг, выданный AddUser и сохранённый
// WriteClientConfig, находится по ключу клиента из clientsTable, а его PSK и
// адрес совпадают с сервером (ClientPeerParams по fakesrv). После
// перевыпуска прежний файл этому клиенту больше не подходит — «не
// сохранялся», а не «найден».
func TestSavedConfigRoundTrip(t *testing.T) {
	srv := fakesrv.New()
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
	ct := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Support: core.SupportYes}
	nu, err := sess.AddUser(ct, "Carol")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "Конфигурации")
	if _, _, err := core.WriteClientConfig(dir, "Другое имя", nu.Config); err != nil {
		t.Fatal(err)
	}
	cl := clientByName(t, sess, ct, "Carol")
	got := core.FindSavedConfig(dir, nil, cl.ClientID)
	if got.State != core.SavedFound {
		t.Fatalf("сохранённый конфиг не найден: %v %s", got.State, got.Why)
	}
	sp, err := sess.ClientPeerParams(ct, cl)
	ch := core.CheckSavedConfig(got.Config, sp, err)
	if ch.PSK != core.CheckSame || ch.Address != core.CheckSame || ch.ServerKey != core.CheckSame {
		t.Errorf("сверка с сервером: PSK %v адрес %v (%s)", ch.PSK, ch.Address, ch.Why)
	}

	// отключённый: параметры берутся из записи clientsTable
	if err := sess.SetEnabled(ct, cl.ClientID, false); err != nil {
		t.Fatal(err)
	}
	cl = clientByName(t, sess, ct, "Carol")
	sp, err = sess.ClientPeerParams(ct, cl)
	if ch := core.CheckSavedConfig(got.Config, sp, err); ch.PSK != core.CheckSame || ch.Address != core.CheckSame || ch.ServerKey != core.CheckSame {
		t.Errorf("отключённый: PSK %v адрес %v (%s)", ch.PSK, ch.Address, ch.Why)
	}
	if err := sess.SetEnabled(ct, cl.ClientID, true); err != nil {
		t.Fatal(err)
	}

	// перевыпуск: прежний файл больше не этого клиента
	if _, err := sess.RegenerateUser(ct, cl.ClientID); err != nil {
		t.Fatal(err)
	}
	cl = clientByName(t, sess, ct, "Carol")
	if got := core.FindSavedConfig(dir, nil, cl.ClientID); got.State != core.SavedNotFound {
		t.Errorf("после перевыпуска старый файл принят за конфиг клиента: %v", got.State)
	}
}

func clientByName(t *testing.T, sess *core.Session, ct *core.Container, name string) core.ClientEntry {
	t.Helper()
	cls, err := sess.LoadClients(ct)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cls {
		if c.Name() == name {
			return c
		}
	}
	t.Fatalf("клиента %q нет", name)
	return core.ClientEntry{}
}
