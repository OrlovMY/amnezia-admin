package core_test

// A3б, PR-1: гонка двух писателей (T1, T2, T6 проекта БК-A3Б-ГОНКА-CAS.md).
//
// Внешний тестовый пакет и ТОЛЬКО публичный API (NewSessionWithRunner,
// AddUser, LoadClients, обёртка над Runner) — поэтому файл компилируется и на
// main до починки (e4db2c4) и падает там ПОВЕДЕНИЕМ, а не сборкой.
//
// Пользователь второго писателя называется Dave, а не Bob, как в проекте:
// fakesrv.New() уже содержит клиента Bob, и повтор имени отклонялся бы
// проверкой дубликата, а не гонкой.

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

func raceCreds() *core.ServerCreds {
	return &core.ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"}
}

func raceContainer() *core.Container {
	return &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
}

// hookRunner — Runner сессии A: перед командой, для которой when() вернёт
// true, один раз выполняет inject() (полную операцию сессии B).
type hookRunner struct {
	base   core.Runner
	when   func(cmd string, stdin []byte) bool
	inject func()
	once   sync.Once
}

func (r *hookRunner) Run(cmd string, stdin []byte) (string, error) {
	if r.when(cmd, stdin) {
		r.once.Do(r.inject)
	}
	return r.base.Run(cmd, stdin)
}

// userOnServer — есть ли пользователь name в итоговой clientsTable И его
// PublicKey в итоговом wg0.conf (чтение идёт свежей сессией).
func userOnServer(t *testing.T, srv *fakesrv.Server, name string) bool {
	t.Helper()
	c := raceContainer()
	clients, err := core.NewSessionWithRunner(srv, raceCreds()).LoadClients(c)
	if err != nil {
		t.Fatalf("LoadClients: %v", err)
	}
	wg, _ := srv.File(c.Dir + "/wg0.conf")
	for _, cl := range clients {
		if cl.Name() == name {
			return strings.Contains(string(wg), "PublicKey = "+cl.ClientID+"\n")
		}
	}
	return false
}

// TestLostUpdateTwoWriters — T1. A прочитал сервер и прошёл свою проверку; перед
// первой ЗАПИСЬЮ A (первая команда со stdin) B целиком добавляет Dave.
// Инвариант: каждый вызов, вернувший nil, оставил своего пользователя в
// итоговых файлах; проигравший — errors.Is(err, ErrCASMismatch).
func TestLostUpdateTwoWriters(t *testing.T) {
	srv := fakesrv.New()
	c := raceContainer()
	sessB := core.NewSessionWithRunner(srv, raceCreds())

	var errB error
	hr := &hookRunner{
		base: srv,
		when: func(_ string, stdin []byte) bool { return stdin != nil },
		inject: func() {
			_, errB = sessB.AddUser(c, "Dave")
		},
	}
	sessA := core.NewSessionWithRunner(hr, raceCreds())
	_, errA := sessA.AddUser(c, "Carol")

	carol, dave := userOnServer(t, srv, "Carol"), userOnServer(t, srv, "Dave")
	t.Logf("A(Carol): err=%v, на сервере=%v; B(Dave): err=%v, на сервере=%v", errA, carol, errB, dave)

	if errA == nil && !carol {
		t.Errorf("A сказано «готово», но Carol на сервере нет")
	}
	if errB == nil && !dave {
		t.Errorf("B сказано «готово», но Dave на сервере нет — потерянное обновление")
	}
	if errA == nil && errB == nil {
		t.Errorf("оба писателя получили успех — один из них обязан был получить отказ")
	}
	if errA != nil && !errors.Is(errA, core.ErrCASMismatch) {
		t.Errorf("проигравший A: ждали errors.Is(err, ErrCASMismatch), получили %v", errA)
	}
	if errB != nil {
		t.Errorf("B шёл первым и обязан был записать: %v", errB)
	}
}

// TestRestoreDoesNotEraseForeignWrite — T2. A записал; до проверки A (первое
// чтение файла после записи) B целиком добавляет Dave. Проверка A расходится,
// A откатывается — и откат обязан НЕ трогать файлы, потому что после записи A
// их изменил B. Dave, которому сказано «готово», остаётся на сервере.
func TestRestoreDoesNotEraseForeignWrite(t *testing.T) {
	srv := fakesrv.New()
	c := raceContainer()
	sessB := core.NewSessionWithRunner(srv, raceCreds())

	wrote := false
	var errB error
	hr := &hookRunner{
		base: srv,
		when: func(cmd string, stdin []byte) bool {
			if stdin != nil {
				wrote = true
				return false
			}
			return wrote && strings.Contains(cmd, " cat ")
		},
		inject: func() {
			_, errB = sessB.AddUser(c, "Dave")
		},
	}
	sessA := core.NewSessionWithRunner(hr, raceCreds())
	_, errA := sessA.AddUser(c, "Carol")

	dave := userOnServer(t, srv, "Dave")
	t.Logf("A(Carol): err=%v; B(Dave): err=%v, Dave на сервере=%v", errA, errB, dave)

	if errB != nil {
		t.Fatalf("B писал на согласованный сервер и обязан был записать: %v", errB)
	}
	if !dave {
		t.Errorf("откат A стёр запись B: Dave, которому сказано «готово», пропал")
	}
	if errA == nil {
		t.Fatalf("A обязан был получить ошибку: его проверка разошлась")
	}
	if !strings.Contains(errA.Error(), "изменил другой") {
		t.Errorf("ошибка A обязана сказать, что откат не выполнен из-за чужой записи: %v", errA)
	}
}

// TestParallelWritersStress — T6. N горутин, у каждой своя Session над одним
// fakesrv. Стресс, не доказательство (доказательство — T1/T2): каждому, кому
// сказано «готово», обязан соответствовать пользователь на сервере.
func TestParallelWritersStress(t *testing.T) {
	const n = 12
	srv := fakesrv.New()
	c := raceContainer()

	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sess := core.NewSessionWithRunner(srv, raceCreds())
			_, errs[i] = sess.AddUser(c, fmt.Sprintf("U%02d", i))
		}(i)
	}
	wg.Wait()

	ok := 0
	for i, err := range errs {
		name := fmt.Sprintf("U%02d", i)
		present := userOnServer(t, srv, name)
		if err == nil {
			ok++
			if !present {
				t.Errorf("%s: сказано «готово», но на сервере его нет", name)
			}
			continue
		}
		// Отказ с пользователем на сервере законен: откат, не выполненный
		// из-за чужой записи поверх нашей (T2), оставляет нашу запись.
		t.Logf("%s: отказ (на сервере=%v): %v", name, present, err)
	}
	if ok == 0 {
		t.Errorf("ни один из %d писателей не записал", n)
	}
	t.Logf("записали %d из %d", ok, n)
}
