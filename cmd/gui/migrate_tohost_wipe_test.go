package main

// Режим «Новый чистый сервер» при НЕчистой цели: окно сноса с составом,
// клиентами, путём будущей копии и явным подтверждением; снос — перед
// установкой, через шов (ни одного настоящего сервера).

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2/test"

	"amnezia-admin/core"
)

type wipeFix struct {
	*thFixture
	plan    *core.TeardownPlan
	planErr error
	res     core.TeardownResult
	calls   int
	opt     core.TeardownOptions
	dir     string
}

func dirtyProv() core.ProvisionReport {
	return core.ProvisionReport{Items: []core.ProvItem{
		{What: "ОС", State: core.ProvOK, Reason: "Ubuntu 24.04"},
		{What: "контейнеры amnezia-*", State: core.ProvBad, Reason: "уже есть: amnezia-awg"},
	}}
}

func wipePlan(known, copy bool) *core.TeardownPlan {
	tc := core.TargetClients{Container: "amnezia-awg", Known: true, Names: []string{"Иван"}}
	if !known {
		tc = core.TargetClients{Container: "amnezia-awg", Why: "не удалось прочитать (копия не снята)"}
	}
	p := &core.TeardownPlan{Inv: &core.TargetInventory{Containers: []string{"amnezia-awg"}, PortsKnown: true,
		Ports: map[string]string{"amnezia-awg": "0.0.0.0:51820->51820/udp"}, Clients: []core.TargetClients{tc}}}
	if copy {
		p.Copy = &core.Backup{Containers: []core.BackupContainer{{Name: "amnezia-awg", Status: core.CtrSaved}}}
	}
	return p
}

func newWipeFix(t *testing.T) *wipeFix {
	f := &wipeFix{thFixture: newTHFixture(t), plan: wipePlan(true, true), dir: t.TempDir()}
	f.keysOut = core.KeysAccepted
	f.prov = dirtyProv()
	f.res = core.TeardownResult{State: core.TeardownDone, CopyPath: f.dir + "/203.0.113.5-перед-сносом.aabk"}
	o1, o2, o3 := toHostTeardownPlan, toHostTeardown, toHostBackupsDir
	t.Cleanup(func() { toHostTeardownPlan, toHostTeardown, toHostBackupsDir = o1, o2, o3 })
	toHostBackupsDir = func() (string, error) { return f.dir, nil }
	toHostTeardownPlan = func(context.Context, *core.Session, time.Time) (*core.TeardownPlan, error) { return f.plan, f.planErr }
	toHostTeardown = func(_ *core.Session, _ *core.TeardownPlan, opt core.TeardownOptions) core.TeardownResult {
		f.calls++
		f.opt = opt
		switch f.res.State {
		case core.TeardownDone:
			f.prov = core.ProvisionReport{Items: []core.ProvItem{{What: "ОС", State: core.ProvOK, Reason: "ок"}}}
		case core.TeardownUnknown:
			// как ядро: маркер сноса оставлен
			if err := core.WriteOpMarker(core.OpMarker{Target: "x", Step: "снос Amnezia на новом сервере"}); err != nil {
				t.Error(err)
			}
		}
		return f.res
	}
	return f
}

// toWipe — «Далее» на просмотре открывает окно сноса.
func (f *wipeFix) toWipe(t *testing.T) *toHostWipe {
	t.Helper()
	f.startHost(t)
	r := f.u.toHostReviewed
	if r == nil || r.next.Disabled() {
		t.Fatalf("«Далее» на просмотре нет или выключена:\n%s", f.allText())
	}
	test.Tap(r.next)
	w := f.u.toHostWiped
	if w == nil {
		t.Fatal("окна сноса нет")
	}
	return w
}

// choices — выборы шага 2 (как fill, без перехода с просмотра).
func (f *wipeFix) choices(t *testing.T) *toHostView {
	t.Helper()
	v := f.u.toHostShown
	if v == nil {
		t.Fatal("окна выборов нет")
	}
	v.replace.SetChecked(true)
	if v.addrCheck != nil {
		v.addrCheck.SetChecked(true)
	}
	v.mode.SetSelected(backupWithPassword)
	v.pw.SetText(migTestAutoPw)
	v.pw2.SetText(migTestAutoPw)
	if v.apply.Disabled() {
		t.Fatalf("«Установить и перенести» выключена: %s", v.reason.Text)
	}
	return v
}

// Полный путь: состав и клиенты на просмотре, окно сноса с путём копии,
// кнопка погашена до галки, снос до установки, итог называет копию.
func TestGUIToHostWipeFlow(t *testing.T) {
	f := newWipeFix(t)
	w := f.toWipe(t)
	rt := f.u.toHostReviewed.text
	for _, want := range []string{"контейнер amnezia-awg", "клиенты (1): Иван", "окно сноса"} {
		if !strings.Contains(rt, want) {
			t.Errorf("просмотр: нет %q:\n%s", want, rt)
		}
	}
	if !w.ok.Disabled() {
		t.Fatal("«Снести» включена без подтверждения")
	}
	if w.noCopy != nil {
		t.Error("галка «без копии» при полной копии")
	}
	if !strings.Contains(w.text, f.dir) || !strings.Contains(w.text, "-перед-сносом.aabk") || !strings.Contains(w.text, "клиенты (1): Иван") {
		t.Errorf("окно сноса: нет пути копии или клиентов:\n%s", w.text)
	}
	w.check.SetChecked(true)
	if w.ok.Disabled() {
		t.Fatalf("«Снести» выключена после галки: %s", w.reason.Text)
	}
	if f.calls != 0 {
		t.Fatal("снос выполнен до выборов")
	}
	test.Tap(w.ok)
	v := f.choices(t)
	test.Tap(v.apply)
	waitGUIGoroutines(t)
	if f.calls != 1 || f.installed != 1 {
		t.Fatalf("сносов %d, установок %d\n%s", f.calls, f.installed, f.allText())
	}
	if !f.opt.Confirmed || f.opt.NoCopyConfirmed || f.opt.Layer == nil || f.opt.CopyDir != f.dir {
		t.Errorf("параметры сноса: %+v", f.opt)
	}
	txt := f.allText()
	if !strings.Contains(txt, "Снос Amnezia на новом сервере: снесено") || !strings.Contains(txt, f.res.CopyPath) {
		t.Errorf("итог: нет сноса или пути копии:\n%s", txt)
	}
	if strings.Contains(txt, migTestAutoPw) {
		t.Error("пароль автокопии в тексте итога")
	}
}

// Различение: клиенты не прочитаны — «не удалось прочитать», не «нет»;
// без копии — вторая галка обязательна.
func TestGUIToHostWipeUnknownClients(t *testing.T) {
	f := newWipeFix(t)
	f.plan = wipePlan(false, false)
	w := f.toWipe(t)
	for _, txt := range []string{f.u.toHostReviewed.text, w.text} {
		if !strings.Contains(txt, "клиенты: не удалось прочитать") || strings.Contains(txt, "клиенты: нет") {
			t.Errorf("клиенты не как «не удалось прочитать»:\n%s", txt)
		}
	}
	if w.noCopy == nil {
		t.Fatal("нет галки «без копии»")
	}
	w.check.SetChecked(true)
	if !w.ok.Disabled() {
		t.Fatal("«Снести» включена без второго подтверждения")
	}
	w.noCopy.SetChecked(true)
	if w.ok.Disabled() {
		t.Fatal("«Снести» выключена после обеих галок")
	}
	test.Tap(w.ok)
	test.Tap(f.choices(t).apply)
	waitGUIGoroutines(t)
	if !f.opt.NoCopyConfirmed {
		t.Error("отдельное согласие без копии не дошло до сноса")
	}
}

// Состав не прочитан — «не клиентов нет», дальше нельзя.
func TestGUIToHostWipePlanNotRead(t *testing.T) {
	f := newWipeFix(t)
	f.planErr = errors.New("состав нового сервера прочитать не удалось: список томов не получен")
	f.startHost(t)
	r := f.u.toHostReviewed
	if !strings.Contains(r.text, "это не «клиентов нет»") || !r.next.Disabled() {
		t.Fatalf("next %v:\n%s", r.next.Disabled(), r.text)
	}
}

// Итоги сноса: неизвестно (маркер остаётся), не выполнялся, не всё.
func TestGUIToHostWipeOutcomes(t *testing.T) {
	for _, c := range []struct {
		name   string
		res    core.TeardownResult
		head   string
		marker bool
	}{
		{"неизвестно", core.TeardownResult{State: core.TeardownUnknown, Why: "связь"}, "НЕИЗВЕСТНО — снос Amnezia", true},
		{"копия не записана", core.TeardownResult{State: core.TeardownRefused, Why: "копия нового сервера не записана — снос не выполнялся"}, "НЕ ПЕРЕНЕСЕНО — снос не выполнялся", false},
		{"осталось", core.TeardownResult{State: core.TeardownFailed, Why: "на сервере осталось: контейнер amnezia-awg"}, "снос Amnezia на новом сервере выполнен не полностью", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newWipeFix(t)
			f.res = c.res
			w := f.toWipe(t)
			w.check.SetChecked(true)
			test.Tap(w.ok)
			test.Tap(f.choices(t).apply)
			waitGUIGoroutines(t)
			txt := f.allText()
			if f.installed != 0 || !strings.Contains(txt, c.head) || !strings.Contains(txt, c.res.Why) {
				t.Fatalf("установок %d; нет %q:\n%s", f.installed, c.head, txt)
			}
			if _, err := os.Stat(f.marker); (err == nil) != c.marker {
				t.Errorf("маркер есть = %v, ждали %v", err == nil, c.marker)
			}
		})
	}
}

// «Назад» из окна сноса — к просмотру, согласие снимается.
func TestGUIToHostWipeBack(t *testing.T) {
	f := newWipeFix(t)
	w := f.toWipe(t)
	w.check.SetChecked(true)
	f.u.toHostReviewed = nil
	test.Tap(findEsc(f.u.win.Canvas().Overlays().Top(), toHostBackText))
	if f.u.toHostReviewed == nil || f.calls != 0 {
		t.Fatalf("после «Назад» нет просмотра или был снос (%d)", f.calls)
	}
}

// L4/L2 (ревью-1): остановленный контейнер назван в окне сноса как «в копию
// не попадёт»; снос получает контекст отмены окна прогресса.
func TestGUIToHostWipeStoppedAndCtx(t *testing.T) {
	f := newWipeFix(t)
	f.plan.Inv.Containers = append(f.plan.Inv.Containers, "amnezia-wireguard")
	f.plan.Inv.State = map[string]string{"amnezia-awg": "running", "amnezia-wireguard": "exited"}
	f.plan.Inv.Clients = append(f.plan.Inv.Clients, core.TargetClients{Container: "amnezia-wireguard", Why: "не удалось прочитать (контейнер не запущен)"})
	w := f.toWipe(t)
	if !strings.Contains(w.text, "В КОПИЮ НЕ ПОПАДЁТ (контейнер остановлен (exited)") || w.noCopy == nil {
		t.Fatalf("остановленный контейнер не назван или нет второй галки:\n%s", w.text)
	}
	w.check.SetChecked(true)
	w.noCopy.SetChecked(true)
	test.Tap(w.ok)
	test.Tap(f.choices(t).apply)
	waitGUIGoroutines(t)
	if f.opt.Ctx == nil {
		t.Fatal("снос без контекста отмены")
	}
	if f.opt.Ctx.Err() == nil {
		t.Error("контекст сноса не связан с окном (после итога должен быть закрыт)")
	}
}
