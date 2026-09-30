package core_test

// T1, второй вариант (раунд 2, условие QA): писатель B меняет ТОЛЬКО
// clientsTable (переименование), wg0.conf остаётся прежним. Сверка суммы
// wg0.conf тут ничего не ловит — потерю предотвращает только сверка
// clientsTable в скрипте. Поэтому подмена «убрана сверка clientsTable»
// обязана ронять этот тест поведением, а не только дословную копию в T7.

import (
	"errors"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

func TestLostUpdateTableOnlyWriter(t *testing.T) {
	srv := fakesrv.New()
	c := raceContainer()
	sessB := core.NewSessionWithRunner(srv, raceCreds())
	clients, err := sessB.LoadClients(c)
	if err != nil || len(clients) == 0 {
		t.Fatalf("LoadClients: %v", err)
	}
	aliceID := clients[0].ClientID
	oldName := clients[0].Name()

	var errB error
	hr := &hookRunner{
		base: srv,
		when: func(_ string, stdin []byte) bool { return stdin != nil },
		inject: func() {
			errB = sessB.RenameUser(c, aliceID, "Renamed")
		},
	}
	_, errA := core.NewSessionWithRunner(hr, raceCreds()).AddUser(c, "Carol")

	renamed, still := userOnServer(t, srv, "Renamed"), userOnServer(t, srv, oldName)
	t.Logf("A(Carol): err=%v; B(rename): err=%v; Renamed=%v, %s=%v", errA, errB, renamed, oldName, still)
	if errB != nil {
		t.Fatalf("B шёл первым и обязан был записать: %v", errB)
	}
	if !renamed || still {
		t.Errorf("переименование B, которому сказано «готово», потеряно")
	}
	if errA == nil {
		t.Errorf("A получил успех поверх чужой записи в clientsTable")
	} else if !errors.Is(errA, core.ErrCASMismatch) {
		t.Errorf("проигравший A: ждали ErrCASMismatch, получили %v", errA)
	}
}
