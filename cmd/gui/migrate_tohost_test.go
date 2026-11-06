package main

// PR 7б: режим «Новый чистый сервер (по IP/имени)» окна «Перенести на
// сервер…». Тестовый драйвер Fyne, serialUI; ни одного настоящего сервера:
// вход, предпроверка, установка, перенос и проверка ключа — швы.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

const (
	thLoginPw = "LOGIN-PW-7b-Qx81"
	thKeyPw   = "KEY-PW-7b-Zr42"
)

// thFixture — источник (fakesrv) + швы режима «новый чистый сервер».
type thFixture struct {
	*migFixture
	connects     int
	pwGiven      []string // пароль, отданный ConnectNew колбэком (по попыткам)
	keysOut      core.KeyOutcome
	prov         core.ProvisionReport
	install      func() core.InstallResult
	applyErr     error
	applyOuts    []core.RestoreOutcome
	applied      int
	installed    int
	verifyErr    error
	keyDir       string
	opened       []string
	marker       string
	awake        int
	awakeStopped int
}

func okInstall(names ...string) core.InstallResult {
	r := core.InstallResult{Measure: &core.CompatReport{}}
	for _, n := range names {
		r.Containers = append(r.Containers, core.InstallContainerResult{Container: n, Outcome: core.InstallInstalled, Measured: core.CompatMatch, VPN: core.CompatMatch})
	}
	return r
}

func newTHFixture(t *testing.T) *thFixture {
	t.Helper()
	return newTHFixtureOn(t, newMigFixture(t, migTestDstHost, "SHA256:srcfp", "SHA256:dstfp"))
}

func newTHFixtureOn(t *testing.T, m *migFixture) *thFixture {
	t.Helper()
	f := &thFixture{migFixture: m, keysOut: core.KeysRejected}
	f.prov = core.ProvisionReport{Items: []core.ProvItem{{What: "ОС", State: core.ProvOK, Reason: "Ubuntu 24.04"}}}
	f.keyDir = t.TempDir()
	save := []func(){}
	o1, o2, o3, o4, o5, o6, o7, o8 := toHostConnectNew, toHostProvCheck, toHostInstall, toHostApply, toHostKeyContainers, toHostVerify, toHostKeyDir, toHostOpenDir
	save = append(save, func() {
		toHostConnectNew, toHostProvCheck, toHostInstall, toHostApply, toHostKeyContainers, toHostVerify, toHostKeyDir, toHostOpenDir = o1, o2, o3, o4, o5, o6, o7, o8
	})
	t.Cleanup(func() {
		for _, s := range save {
			s()
		}
	})
	toHostConnectNew = func(host, port, user string, src core.AuthSource, pol core.HostKeyPolicy) (*core.Session, core.KeyAttempt, error) {
		f.connects++
		att := core.KeyAttempt{Outcome: f.keysOut}
		if f.keysOut == core.KeysAccepted {
			return f.dstSess(host, port), att, nil
		}
		if src.Password == nil {
			return nil, att, &core.AuthError{Keys: att}
		}
		pw, _ := src.Password(att)
		f.pwGiven = append(f.pwGiven, string(pw))
		if string(pw) != thLoginPw {
			return nil, att, &core.AuthError{Keys: att, PasswordTried: true, Err: errors.New("отказ")}
		}
		return f.dstSess(host, port), att, nil
	}
	toHostProvCheck = func(*core.Session, *core.Backup) core.ProvisionReport { return f.prov }
	toHostInstall = func(s *core.Session, p core.InstallPlan, o core.InstallOptions) core.InstallResult {
		f.installed++
		if !o.PreviewAccepted {
			t.Error("Install без PreviewAccepted")
		}
		if f.install != nil {
			return f.install()
		}
		var names []string
		for _, it := range p.Items {
			names = append(names, it.Container)
		}
		return okInstall(names...)
	}
	toHostApply = func(ctx context.Context, src, dst *core.Session, b *core.Backup, l core.BackupLayer, xrayOK, addrOK bool, now time.Time, p core.ProgressFunc) (string, []core.RestoreOutcome, error) {
		f.applied++
		if b == nil || l == nil {
			t.Error("перенос без копии или слоя автокопии")
		}
		if f.applyErr != nil {
			return "", nil, f.applyErr
		}
		if f.applyOuts != nil {
			return "/tmp/auto.aabk", f.applyOuts, nil
		}
		return "/tmp/auto.aabk", []core.RestoreOutcome{{Container: "amnezia-awg", State: core.RestoreDone}}, nil
	}
	toHostKeyContainers = func(_ *core.Session, names []string) ([]core.AdminKeyContainer, []string, error) {
		var cs []core.AdminKeyContainer
		for _, n := range names {
			p := map[string]any{"port": "51820", "transport_proto": "udp", "subnet_address": "10.8.1.0", "site": "x.com"}
			for _, k := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"} {
				p[k] = "1"
			}
			cs = append(cs, core.AdminKeyContainer{Name: n, Protocol: p})
		}
		return cs, nil, nil
	}
	toHostVerify = func(core.AdminKey, core.AdminKeyInput, string, string) error { return f.verifyErr }
	toHostKeyDir = func() (string, error) { return f.keyDir, nil }
	toHostOpenDir = func(d string) error { f.opened = append(f.opened, d); return nil }
	// маркер — в свой каталог теста; запрет сна — шов (ОС не трогается)
	f.marker = filepath.Join(t.TempDir(), "marker.json")
	oldMk, oldAw := core.OpMarkerPath, toHostKeepAwake
	core.OpMarkerPath = func() (string, error) { return f.marker, nil }
	toHostKeepAwake = func() (func(), bool) { f.awake++; return func() { f.awakeStopped++ }, true }
	t.Cleanup(func() { core.OpMarkerPath, toHostKeepAwake = oldMk, oldAw })
	return f
}

func (f *thFixture) dstSess(host, port string) *core.Session {
	s := core.NewSessionWithRunner(f.dst, &core.ServerCreds{Host: host, Port: port, User: "root"})
	s.HostKeyFingerprint = "SHA256:dstfp"
	return s
}

// startHost — настоящий путь: «Копия» → «Перенести на сервер…» → режим
// «Новый чистый сервер» → «Продолжить» → адрес → «Подключиться».
func (f *thFixture) startHost(t *testing.T) {
	t.Helper()
	f.u.backupMenu()
	menu := topPopup(t, f.u.win.Canvas())
	test.Tap(buttonByText(t, menu, migrateMenuText))
	ov := f.u.win.Canvas().Overlays().Top()
	var radio *widget.RadioGroup
	walkObjects(ov, func(o fyne.CanvasObject) {
		if r, ok := o.(*widget.RadioGroup); ok && radio == nil {
			radio = r
		}
	})
	if radio == nil || len(radio.Options) != 2 || radio.Options[1] != migrateModeHost {
		t.Fatal("в первом окне нет выбора режима «" + migrateModeHost + "»")
	}
	radio.SetSelected(migrateModeHost)
	ok := findEsc(ov, migrateAskNext)
	if ok == nil || ok.Disabled() {
		t.Fatal("«Продолжить» выключена в режиме нового сервера")
	}
	test.Tap(ok)
	cv := f.u.toHostConnShown
	if cv == nil {
		t.Fatal("окна адреса нет")
	}
	if cv.port.Text != "22" || cv.user.Text != "root" {
		t.Errorf("умолчания порт/пользователь: %q/%q", cv.port.Text, cv.user.Text)
	}
	if !cv.ok.Disabled() {
		t.Error("«Подключиться» включена без адреса")
	}
	cv.host.SetText(migTestDstHost)
	if cv.ok.Disabled() {
		t.Fatalf("«Подключиться» выключена при адресе: %s", cv.reason.Text)
	}
	test.Tap(cv.ok)
	waitGUIGoroutines(t)
}

// password — окно снова, с полем пароля: ввести и «Подключиться».
func (f *thFixture) password(t *testing.T, pw string) {
	t.Helper()
	cv := f.u.toHostConnShown
	if !cv.pw.Visible() || cv.why.Text == "" {
		t.Fatal("поле пароля или причина не показаны")
	}
	cv.pw.SetText(pw)
	test.Tap(cv.ok)
	if cv.pw.Text != "" {
		t.Error("пароль остался в поле после «Подключиться»")
	}
	waitGUIGoroutines(t)
}

// fill — все обязательные выборы; consent/keyPw — согласие на ключ.
// next — шаг «Просмотр» → «Далее: выборы».
func (f *thFixture) next(t *testing.T) *toHostView {
	t.Helper()
	r := f.u.toHostReviewed
	if r == nil {
		t.Fatal("шага «Просмотр» нет")
	}
	if r.next.Disabled() {
		t.Fatalf("«Далее» выключена: %s", r.reason.Text)
	}
	test.Tap(r.next)
	return f.u.toHostShown
}

func (f *thFixture) fill(t *testing.T, consent bool, keyPw string) *toHostView {
	t.Helper()
	v := f.next(t)
	if v == nil {
		t.Fatal("окна установки нет")
	}
	if !v.apply.Disabled() {
		t.Fatal("«Установить и перенести» включена до выборов")
	}
	if v.consent.Checked {
		t.Error("согласие «пароль в ключ» включено по умолчанию")
	}
	v.replace.SetChecked(true)
	if v.addrCheck != nil {
		v.addrCheck.SetChecked(true)
	}
	if v.xrayRadio != nil {
		v.xrayRadio.SetSelected(migrateXRayRestart)
	}
	v.mode.SetSelected(backupWithPassword)
	v.pw.SetText(migTestAutoPw)
	v.pw2.SetText(migTestAutoPw)
	if consent {
		v.consent.SetChecked(true)
		if v.keyPw != nil {
			if v.apply.Disabled() == false {
				t.Error("«Установить» включена при согласии без пароля для ключа")
			}
			v.keyPw.SetText(keyPw)
		}
	}
	if v.apply.Disabled() {
		t.Fatalf("«Установить и перенести» выключена: %s", v.reason.Text)
	}
	return v
}

// TestGUIToHostKeysThenPassword — ТЕСТ ДОЕЗДА входа: ключи ПК не подошли →
// окно снова с полем пароля и причиной по исходу ключей; неверный пароль →
// снова; верный → окно установки; пароль в поле не остаётся.
// Подмены: без причины в окне пароля; пароль не передаётся в ConnectNew.
func TestGUIToHostKeysThenPassword(t *testing.T) {
	f := newTHFixture(t)
	f.startHost(t)
	cv := f.u.toHostConnShown
	if !strings.Contains(cv.why.Text, core.KeysRejected.String()) {
		t.Fatalf("причина пароля не по исходу ключей: %q", cv.why.Text)
	}
	if f.u.toHostReviewed != nil {
		t.Fatal("окно установки до входа")
	}
	f.password(t, "wrong")
	if !strings.Contains(f.allText(), "пароль не подошёл") {
		t.Errorf("неверный пароль не назван:\n%s", f.allText())
	}
	f.password(t, thLoginPw)
	if f.u.toHostReviewed == nil {
		t.Fatalf("после верного пароля окна установки нет:\n%s", f.allText())
	}
	if len(f.pwGiven) != 2 || f.pwGiven[1] != thLoginPw {
		t.Errorf("пароли в ConnectNew: %d", len(f.pwGiven))
	}
	if !strings.Contains(f.u.toHostReviewed.text, "по паролю. Ключи ПК: "+core.KeysRejected.String()) {
		t.Errorf("строки входа нет:\n%s", f.u.toHostReviewed.text)
	}
	// ключ ПК подошёл — пароль не спрашивается, поле для ключа есть
	g := newTHFixture(t)
	g.keysOut = core.KeysAccepted
	g.startHost(t)
	if g.next(t) == nil || g.u.toHostShown.keyPw == nil {
		t.Fatal("вход ключом ПК: нет окна установки или поля пароля для ключа")
	}
	if g.connects != 1 {
		t.Errorf("подключений %d", g.connects)
	}
}

// TestGUIToHostWindowShowsAll — всё до кнопки: три исхода пунктов
// предпроверки, план (Verdict, не String; Skipped целиком; оговорка
// версии), превью целиком, стороны с отпечатками. Каждый неготовый итог
// гасит кнопку с причиной.
func TestGUIToHostWindowShowsAll(t *testing.T) {
	f := newTHFixture(t)
	f.keysOut = core.KeysAccepted
	f.prov = core.ProvisionReport{Items: []core.ProvItem{
		{What: "ОС", State: core.ProvOK, Reason: "Ubuntu 24.04"},
		{What: "AppArmor", State: core.ProvUnknown, Reason: "не прочитан"},
	}}
	f.startHost(t)
	v := f.u.toHostReviewed
	if v == nil {
		t.Fatal("окна нет")
	}
	txt := f.allText()
	plan := core.PlanInstall(mustBackup(t, f), nil)
	if len(plan.Items) == 0 {
		t.Fatal("сцена пуста: план без контейнеров")
	}
	preview, err := core.InstallPreview(plan)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ОС: годится — Ubuntu 24.04", "AppArmor: узнать не удалось — не прочитан", "Итог предпроверки: неизвестно, можно ли ставить",
		"это не «годится»", plan.Items[0].Container + ": " + plan.Items[0].Verdict(), "закреплены в этой сборке программы",
		"SHA256:srcfp", "SHA256:dstfp", "Установка изменит на новом сервере:"}
	want = append(want, preview...)
	for _, s := range plan.Skipped {
		want = append(want, "Не ставится: "+s.Container+" — "+s.Reason)
	}
	for _, w := range want {
		if !strings.Contains(txt, w) {
			t.Errorf("в окне нет %q", w)
		}
	}
	if !v.next.Disabled() || !strings.Contains(v.reason.Text, "предпроверка") || !strings.Contains(v.reason.Text, toHostNextText) {
		t.Errorf("«неизвестно» в предпроверке не гасит «Далее»: %q", v.reason.Text)
	}
}

// mustBackup — копия источника фикстуры (той же дорогой, что окно).
func mustBackup(t *testing.T, f *thFixture) *core.Backup {
	t.Helper()
	b, err := toHostCollect(context.Background(), f.u.sess, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestGUIToHostProvTableNotYes — таблица: «нельзя» и «неизвестно» — разные
// тексты, обе гасят кнопку; «можно» — не гасит по предпроверке.
func TestGUIToHostProvTableNotYes(t *testing.T) {
	for _, c := range []struct {
		name  string
		items []core.ProvItem
		text  string
		block bool
	}{
		{"нельзя", []core.ProvItem{{What: "Контейнеры Amnezia", State: core.ProvBad, Reason: "есть amnezia-awg"}}, "Новый сервер не чистый", true},
		{"неизвестно", []core.ProvItem{{What: "ОС", State: core.ProvUnknown, Reason: "нет ответа"}}, "это не «годится»", true},
		{"нет данных", nil, "неизвестно, можно ли ставить", true},
		{"можно", []core.ProvItem{{What: "ОС", State: core.ProvOK, Reason: "ок"}}, "можно ставить", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newTHFixture(t)
			f.keysOut = core.KeysAccepted
			f.prov = core.ProvisionReport{Items: c.items}
			f.startHost(t)
			v := f.u.toHostReviewed
			if !strings.Contains(v.text, c.text) {
				t.Errorf("нет %q:\n%s", c.text, v.text)
			}
			if v.next.Disabled() != c.block {
				t.Errorf("причина %q", v.reason.Text)
			}
		})
	}
}

// TestGUIToHostThreeOutcomes — итог: перенесено / не перенесено /
// неизвестно; установка не измерена — НЕИЗВЕСТНО (не «не перенесено»);
// перенос не удался после установки — подсказка продолжения с файлом ключа.
func TestGUIToHostThreeOutcomes(t *testing.T) {
	for _, c := range []struct {
		name     string
		install  func() core.InstallResult
		applyErr error
		head     string
		applied  int
		extra    string
	}{
		{"перенесено", nil, nil, "ПЕРЕНЕСЕНО — все контейнеры", 1, "Ключ vpn:// записан в файл"},
		{"отказ установки", func() core.InstallResult { return core.InstallResult{Refused: "нет места"} }, nil, "НЕ ПЕРЕНЕСЕНО — установка не начиналась", 0, "не выдавался: установка не готова"},
		{"не измерено", func() core.InstallResult {
			return core.InstallResult{Containers: []core.InstallContainerResult{{Container: "amnezia-awg", Outcome: core.InstallInstalled}}}
		}, nil, "НЕИЗВЕСТНО — установка не измерена", 0, "amnezia-awg (не подтверждено)"},
		{"перенос не удался", nil, errors.New("связь"), "НЕ ПЕРЕНЕСЕНО — Amnezia на новом сервере поставлена", 1, "режим «" + migrateModeKey + "» → кнопка «" + migrateFromFileText + "» и выберите файл"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newTHFixture(t)
			f.install, f.applyErr = c.install, c.applyErr
			f.startHost(t)
			f.password(t, thLoginPw)
			v := f.fill(t, true, "")
			test.Tap(v.apply)
			waitGUIGoroutines(t)
			txt := f.allText()
			if !strings.Contains(txt, c.head) || !strings.Contains(txt, c.extra) {
				t.Errorf("нет %q / %q:\n%s", c.head, c.extra, txt)
			}
			if f.applied != c.applied || f.installed != 1 {
				t.Errorf("установок %d, переносов %d", f.installed, f.applied)
			}
			if f.u.migDst != nil {
				t.Error("сессия нового сервера не закрыта после итога")
			}
		})
	}
}

// TestToHostVerdictTable — порядок ветвей: прерванная и неизмеренная
// установка — НЕИЗВЕСТНО, раньше «не удалась»; нулевой итог — не «перенесено».
func TestToHostVerdictTable(t *testing.T) {
	bad := core.InstallResult{Measure: &core.CompatReport{}, Containers: []core.InstallContainerResult{{Container: "a", Outcome: core.InstallNotInstalled, Rollback: core.RollbackDone}}}
	for _, c := range []struct {
		name string
		o    toHostOutcome
		want migState
	}{
		{"пусто", toHostOutcome{}, migUnknown},
		{"прервано, измерено плохо", toHostOutcome{canceled: true, res: bad}, migNotDone},
		{"прервано, не измерено", toHostOutcome{canceled: true, res: core.InstallResult{Containers: bad.Containers}}, migUnknown},
		{"прервано, поставлено", toHostOutcome{canceled: true, res: okInstall("a")}, migNotDone},
		{"не удалось", toHostOutcome{res: bad}, migNotDone},
		{"отказ", toHostOutcome{res: core.InstallResult{Refused: "x"}}, migNotDone},
		{"поставлено, перенос не начат", toHostOutcome{res: okInstall("a")}, migNotDone},
		{"поставлено, перенос без итога", toHostOutcome{res: okInstall("a"), applied: true}, migUnknown},
		{"всё", toHostOutcome{res: okInstall("a"), applied: true, outs: []core.RestoreOutcome{{State: core.RestoreDone}}}, migDone},
	} {
		if got, h := toHostVerdict(c.o); got != c.want {
			t.Errorf("%s: %v (%s)", c.name, got, h)
		}
	}
}

// TestGUIToHostCancelDuringInstall — «Отмена» во время установки: сначала
// честное предупреждение (установка дойдёт до конца); «Прервать» —
// установка доходит до конца, итог — НАСТОЯЩИЙ по контейнерам, перенос
// клиентов не выполняется, ключ не выдаётся (хотя согласие было),
// подсказка — снос контейнеров или приложение Amnezia.
func TestGUIToHostCancelDuringInstall(t *testing.T) {
	f := newTHFixture(t)
	f.keysOut = core.KeysAccepted
	gate, seen := make(chan struct{}), make(chan struct{})
	var once, gateOnce sync.Once
	release := func() { gateOnce.Do(func() { close(gate) }) }
	toHostBeforeInstall = func() { once.Do(func() { close(seen) }); <-gate }
	t.Cleanup(func() { release(); toHostBeforeInstall = nil })
	f.startHost(t)
	v := f.fill(t, true, thKeyPw)
	test.Tap(v.apply)
	<-seen
	pv := f.u.op
	if pv == nil {
		t.Fatal("окна прогресса нет")
	}
	test.Tap(pv.cancel)
	if txt := f.allText(); !strings.Contains(txt, "она дойдёт до конца") {
		t.Fatalf("нет честного предупреждения:\n%s", txt)
	}
	test.Tap(buttonByText(t, f.u.win.Canvas().Overlays().Top(), toHostCancelYes))
	release()
	waitGUIGoroutines(t)
	txt := f.allText()
	for _, w := range []string{"НЕ ПЕРЕНЕСЕНО — Amnezia на новом сервере поставлена, перенос клиентов не начинался (отменено)",
		"перенос клиентов не выполнялся (отменено)", "не выдавался: отменено", "Продолжить режимом «" + migrateModeKey + "» нельзя: ключа нового сервера нет", "docker rm -f"} {
		if !strings.Contains(txt, w) {
			t.Errorf("в итоге нет %q:\n%s", w, txt)
		}
	}
	for _, l := range okInstall("amnezia-awg").Lines() {
		if !strings.Contains(txt, l) {
			t.Errorf("в итоге нет настоящего итога установки %q", l)
		}
	}
	if f.installed != 1 || f.applied != 0 {
		t.Errorf("установок %d, переносов %d", f.installed, f.applied)
	}
	if ents, _ := os.ReadDir(f.keyDir); len(ents) != 0 {
		t.Error("ключ выдан после отмены")
	}
}

// TestGUIToHostNoSecretsInWidgets — пароль входа, пароль для ключа, пароль
// автокопии и сам ключ vpn:// не попадают ни в виджеты, ни в тексты итога;
// ключ — только в файле, на экране путь; «Открыть папку» открывает его
// каталог. Подмены: показать ключ в итоге; оставить пароль в поле.
func TestGUIToHostNoSecretsInWidgets(t *testing.T) {
	for _, viaKeys := range []bool{false, true} {
		f := newTHFixture(t)
		if viaKeys {
			f.keysOut = core.KeysAccepted
		}
		f.startHost(t)
		if !viaKeys {
			f.password(t, thLoginPw)
		}
		v := f.fill(t, true, thKeyPw)
		test.Tap(v.apply)
		waitGUIGoroutines(t)
		txt := f.allText()
		ents, _ := os.ReadDir(f.keyDir)
		if len(ents) != 1 {
			t.Fatalf("файлов ключа: %d\n%s", len(ents), txt)
		}
		path := filepath.Join(f.keyDir, ents[0].Name())
		raw, _ := os.ReadFile(path)
		key := strings.TrimSpace(string(raw))
		if !strings.HasPrefix(key, "vpn://") {
			t.Fatalf("в файле не ключ")
		}
		if !strings.Contains(txt, path) {
			t.Errorf("путь файла ключа не показан:\n%s", txt)
		}
		body := strings.TrimPrefix(key, "vpn://")
		for k := 0; k+16 <= len(body); k += 4 {
			if strings.Contains(txt, body[k:k+16]) {
				t.Fatalf("кусок ключа на экране")
			}
		}
		for _, s := range []string{thLoginPw, thKeyPw, migTestAutoPw, migTestSecret} {
			if strings.Contains(txt, s) {
				t.Errorf("секрет %q в виджетах", s)
			}
		}
		btn := buttonByText(t, f.u.win.Canvas().Overlays().Top(), toHostOpenDirText)
		test.Tap(btn)
		if len(f.opened) != 1 || f.opened[0] != f.keyDir {
			t.Errorf("«Открыть папку»: %v", f.opened)
		}
	}
}

// TestGUIToHostConsentOffNoKey — без согласия ключ не пишется, итог говорит,
// как управлять дальше.
func TestGUIToHostConsentOffNoKey(t *testing.T) {
	f := newTHFixture(t)
	f.startHost(t)
	f.password(t, thLoginPw)
	v := f.fill(t, false, "")
	test.Tap(v.apply)
	waitGUIGoroutines(t)
	if ents, _ := os.ReadDir(f.keyDir); len(ents) != 0 {
		t.Error("ключ записан без согласия")
	}
	if !strings.Contains(f.allText(), "ключ vpn:// нового сервера не выдан") {
		t.Errorf("нет подсказки:\n%s", f.allText())
	}
}

// TestGUIToHostCancelClosesTarget — «Отмена» окна установки закрывает
// сессию нового сервера.
func TestGUIToHostCancelClosesTarget(t *testing.T) {
	var closed int
	old := migClose
	migClose = func(*core.Session) { closed++ }
	t.Cleanup(func() { migClose = old })
	f := newTHFixture(t)
	f.keysOut = core.KeysAccepted
	f.startHost(t)
	if f.u.migDst == nil {
		t.Fatal("сессии нет")
	}
	// «Назад» с выборов — к просмотру, сессия жива
	f.next(t)
	test.Tap(findEsc(f.u.win.Canvas().Overlays().Top(), toHostBackText))
	if closed != 0 || f.u.migDst == nil {
		t.Fatalf("«Назад» с выборов закрыл сессию (%d)", closed)
	}
	// «Назад» с просмотра — к окну адреса, сессия закрыта
	test.Tap(f.u.toHostReviewed.back)
	if closed != 1 || f.u.migDst != nil {
		t.Errorf("закрыто %d раз", closed)
	}
	if f.u.toHostConnShown.host.Text != migTestDstHost {
		t.Errorf("адрес не сохранён при «Назад»: %q", f.u.toHostConnShown.host.Text)
	}
}

// TestGUIToHostPinnedVisible — 900×600: обязательные выборы, причина и
// кнопка — вне прокрутки и в границах канвы.
func TestGUIToHostPinnedVisible(t *testing.T) {
	for _, xr := range []bool{false, true} {
		pinnedCase(t, xr)
	}
}

func pinnedCase(t *testing.T, xr bool) {
	f := newTHFixture(t)
	if xr {
		f = newTHFixtureOn(t, newMigFixtureOn(t, xrayMigServer(), xrayMigServer(), migTestDstHost, realFpSrc, realFpDst))
	}
	f.keysOut = core.KeysAccepted
	f.u.win.Resize(fyne.NewSize(900, 600))
	f.startHost(t)
	v := f.next(t)
	v.mode.SetSelected(backupWithPassword)
	v.consent.SetChecked(true)
	top := f.u.win.Canvas().Overlays().Top()
	osmotrFrame(top, nil)
	scroll := inScroll(top)
	cs := f.u.win.Canvas().Size()
	if xr && v.xrayRadio == nil {
		t.Fatal("сцена ничего не значит: XRay нет в плане")
	}
	t.Logf("xray=%v адрес=%v", xr, v.addrCheck != nil)
	must := map[string]fyne.CanvasObject{"замена": v.replace, "автокопия": v.mode, "пароль": v.pw, "согласие": v.consent, "пароль ключа": v.keyPw, "причина": v.reason, "кнопка": v.apply}
	if v.xrayRadio != nil {
		must["XRay"] = v.xrayRadio
	}
	if v.addrCheck != nil {
		must["адрес"] = v.addrCheck
	}
	for name, o := range must {
		if scroll[o] {
			t.Errorf("%s в прокрутке", name)
		}
		p, s := absPos(o), o.Size()
		t.Logf("%s: (%.0f,%.0f) %.0fx%.0f", name, p.X, p.Y, s.Width, s.Height)
		if !o.Visible() || s.Height <= 0 || p.Y < 0 || p.Y+s.Height > cs.Height+0.5 || p.X+s.Width > cs.Width+0.5 {
			t.Errorf("%s не виден в окне 900×600", name)
		}
	}
	f.shot(t, map[bool]string{false: "tohost-900x600", true: "tohost-xray-900x600"}[xr], nil)
}

// TestToHostPlanLines — план целиком: Verdict() (не число состояния),
// не поставленные из копии — каждый с причиной, оговорка о версии.
// Подмены: Skipped не выводится; Compat вместо Verdict() — роняют.
func TestToHostPlanLines(t *testing.T) {
	it := core.InstallItem{Container: "amnezia-xray", Family: "XRay", Revision: "5.1.0.6", Compat: core.CompatMatch, NeedsMeasurement: true}
	plan := core.InstallPlan{Items: []core.InstallItem{it},
		Skipped: []core.InstallSkip{{Container: "amnezia-openvpn", Reason: "протокол не ставится"}, {Container: "amnezia-dns", Reason: "служебный"}}}
	txt := strings.Join(toHostPlanLines(plan), "\n")
	for _, w := range []string{"amnezia-xray: " + it.Verdict(), "[скрипты 5.1.0.6]", "Не ставится: amnezia-openvpn — протокол не ставится",
		"Не ставится: amnezia-dns — служебный", "закреплены в этой сборке программы", "Готовность:"} {
		if !strings.Contains(txt, w) {
			t.Errorf("нет %q:\n%s", w, txt)
		}
	}
}

// TestGUIToHostReviewLayout — шаг «Просмотр» на всё окно: прокрутка не
// ниже 60% высоты на 900×600 и на широком; на шаге «Выборы» — сводка по
// контейнеру одной строкой. Подмена: просмотр размером по fitDialog — роняет.
func TestGUIToHostReviewLayout(t *testing.T) {
	for _, sz := range []fyne.Size{fyne.NewSize(900, 600), fyne.NewSize(1600, 1000)} {
		f := newTHFixtureOn(t, newMigFixtureOn(t, xrayMigServer(), xrayMigServer(), migTestDstHost, realFpSrc, realFpDst))
		f.keysOut = core.KeysAccepted
		f.u.win.Resize(sz)
		f.startHost(t)
		top := f.u.win.Canvas().Overlays().Top()
		osmotrFrame(top, nil)
		var best float32
		walkObjects(top, func(o fyne.CanvasObject) {
			if sc, ok := o.(*container.Scroll); ok && sc.Size().Height > best {
				best = sc.Size().Height
			}
		})
		t.Logf("просмотр %.0fx%.0f: прокрутка %.0f (%.0f%%)", sz.Width, sz.Height, best, 100*best/sz.Height)
		if best < 0.6*sz.Height {
			t.Errorf("%.0fx%.0f: прокрутка просмотра %.0f < 60%% высоты", sz.Width, sz.Height, best)
		}
		var pop fyne.CanvasObject = top
		if pp, ok := top.(*widget.PopUp); ok {
			pop = pp.Content
		}
		t.Logf("окно просмотра %.0fx%.0f", pop.Size().Width, pop.Size().Height)
		if pop.Size().Height < 0.95*sz.Height {
			t.Errorf("%.0fx%.0f: просмотр не на всё окно (%.0f)", sz.Width, sz.Height, pop.Size().Height)
		}
		f.shot(t, fmt.Sprintf("tohost-review-%.0fx%.0f", sz.Width, sz.Height), nil)
		v := f.next(t)
		plan := core.PlanInstall(mustBackup(t, f), nil)
		for _, it := range plan.Items {
			if !strings.Contains(v.text, "  "+it.Container+" [скрипты "+it.Revision+"] — "+it.Verdict()) {
				t.Errorf("в сводке нет строки %s:\n%s", it.Container, v.text)
			}
		}
		f.shot(t, fmt.Sprintf("tohost-choices-%.0fx%.0f", sz.Width, sz.Height), nil)
	}
}

// TestGUIToHostIssueKeyOutcomes — четыре исхода проверки ключа (ревью #71
// H1): отвергнут и не совпал — файла нет, причина названа; не удалось
// проверить — файл есть с оговоркой; проверен — файл есть.
// Подмена: убрать ветку «отвергнут» — роняет.
func TestGUIToHostIssueKeyOutcomes(t *testing.T) {
	for _, c := range []struct {
		name  string
		err   error
		file  bool
		text  string
		never string
	}{
		{"проверен", nil, true, "Ключ проверен", "проверить не удалось"},
		{"не совпал", fmt.Errorf("%w: порт", core.ErrAdminKeyMismatch), false, "собранный ключ не совпал", "записан в файл"},
		{"пароль отвергнут", fmt.Errorf("%w", core.ErrAdminKeyAuthRejected), false, "не принял пароль из ключа", "проверить не удалось"},
		{"проверить не удалось", errors.New("сеть недоступна"), true, "Ключ проверить не удалось (это не «ключ плохой» и не «ключ хороший»)", "Ключ проверен"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newTHFixture(t)
			f.verifyErr = c.err
			st := &toHostState{host: migTestDstHost, port: "22", user: "root", dst: f.dstSess(migTestDstHost, "22")}
			path, lines := toHostIssueKey(st, []string{"amnezia-awg"}, core.NewSecret([]byte(thKeyPw)), time.Now())
			txt := strings.Join(lines, "\n")
			ents, _ := os.ReadDir(f.keyDir)
			if (len(ents) == 1) != c.file || (path != "") != c.file {
				t.Errorf("файл: %d, путь %q", len(ents), path)
			}
			if !strings.Contains(txt, c.text) || strings.Contains(txt, c.never) {
				t.Errorf("текст:\n%s", txt)
			}
			if strings.Contains(txt, thKeyPw) {
				t.Error("пароль в тексте")
			}
		})
	}
}

// TestToHostKeyAllowed — ключ при отмене выдаётся, только если перенос к
// ней уже полностью выполнен (ревью #71 L2).
func TestToHostKeyAllowed(t *testing.T) {
	done := []core.RestoreOutcome{{State: core.RestoreDone}}
	for _, c := range []struct {
		name string
		o    toHostOutcome
		want bool
	}{
		{"без согласия", toHostOutcome{res: okInstall("a"), applied: true, outs: done}, false},
		{"обычно", toHostOutcome{consent: true, res: okInstall("a")}, true},
		{"установка не готова", toHostOutcome{consent: true}, false},
		{"отмена до переноса", toHostOutcome{consent: true, canceled: true, res: okInstall("a")}, false},
		{"отмена, перенос выполнен", toHostOutcome{consent: true, canceled: true, res: okInstall("a"), applied: true, outs: done}, true},
		{"отмена, перенос без итога", toHostOutcome{consent: true, canceled: true, res: okInstall("a"), applied: true}, false},
	} {
		if got := toHostKeyAllowed(c.o); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

// TestGUIToHostCancelButtonsAndClose — надпись «Прервать» не обещает
// «неизвестно» (ревью #71 M1); крестик во время установки — «закрыть
// нельзя», «Продолжить установку» сбрасывает флаг закрытия (M3); во время
// переноса клиентов «Отмена» погашена с причиной (M2).
func TestGUIToHostCancelButtonsAndClose(t *testing.T) {
	if strings.Contains(toHostCancelYes, "неизвестно") || !strings.Contains(toHostCancelYes, "клиентов не переносить") ||
		!strings.Contains(toHostCancelWarn, "клиентов переносить НЕ будет") {
		t.Errorf("кнопка не согласована с предупреждением: %q", toHostCancelYes)
	}
	f := newTHFixture(t)
	f.keysOut = core.KeysAccepted
	gate, seen := make(chan struct{}), make(chan struct{})
	var once, gateOnce sync.Once
	release := func() { gateOnce.Do(func() { close(gate) }) }
	toHostBeforeInstall = func() { once.Do(func() { close(seen) }); <-gate }
	agate, aseen := make(chan struct{}), make(chan struct{})
	var aonce, agateOnce sync.Once
	arelease := func() { agateOnce.Do(func() { close(agate) }) }
	t.Cleanup(func() { release(); arelease(); toHostBeforeInstall = nil })
	inner := toHostApply
	toHostApply = func(ctx context.Context, src, dst *core.Session, b *core.Backup, l core.BackupLayer, x, a bool, now time.Time, p core.ProgressFunc) (string, []core.RestoreOutcome, error) {
		aonce.Do(func() { close(aseen) })
		<-agate
		return inner(ctx, src, dst, b, l, x, a, now, p)
	}
	f.startHost(t)
	v := f.fill(t, false, "")
	test.Tap(v.apply)
	<-seen
	pv := f.u.op
	// крестик во время установки
	f.u.closeIntercept()
	if f.u.closeAfterOp || !strings.Contains(f.allText(), progressCloseWriting) {
		t.Errorf("крестик во время установки: closeAfterOp=%v", f.u.closeAfterOp)
	}
	// просили закрыть, но человек выбрал «Продолжить установку»
	f.u.closeAfterOp = true
	test.Tap(pv.cancel)
	test.Tap(buttonByText(t, f.u.win.Canvas().Overlays().Top(), toHostCancelNo))
	if f.u.closeAfterOp || pv.cancel.Disabled() {
		t.Errorf("«Продолжить установку»: closeAfterOp=%v, отмена погашена=%v", f.u.closeAfterOp, pv.cancel.Disabled())
	}
	release()
	<-aseen
	if !pv.cancel.Disabled() || pv.note.Text != toHostNoCancelApply {
		t.Errorf("во время переноса клиентов «Отмена» не погашена: %q", pv.note.Text)
	}
	test.Tap(pv.cancel)
	if strings.Contains(texts(f.u.win.Canvas().Overlays().Top()), toHostCancelTitle) {
		t.Error("во время переноса открылось «Прервать?»")
	}
	arelease()
	waitGUIGoroutines(t)
	if f.applied != 1 || !strings.Contains(f.allText(), "ПЕРЕНЕСЕНО — все контейнеры") {
		t.Errorf("перенос не завершён:\n%s", f.allText())
	}
	if strings.Contains(f.allText(), "Программа не закрыта") {
		t.Error("ложное «Программа не закрыта» после «Продолжить установку»")
	}
}

// TestGUIToHostLoginPwWipedOnClose — пароль входа затирается при закрытии
// программы на шаге «Просмотр» (ревью #71 L1).
func TestGUIToHostLoginPwWipedOnClose(t *testing.T) {
	f := newTHFixture(t)
	f.startHost(t)
	f.password(t, thLoginPw)
	p := f.u.toHostLogin
	if p == nil || string(p.Bytes()) != thLoginPw {
		t.Fatal("пароля входа нет — сцена ничего не значит")
	}
	f.u.closeWin = func() {}
	f.u.closeWindow()
	if b := p.Bytes(); strings.Trim(string(b), "\x00") != "" {
		t.Error("пароль входа не затёрт при закрытии")
	}
}

// TestGUIToHostOpMarker — маркер незавершённой операции (аудит AU M1):
// измеренный итог снимает, неизвестный оставляет; при запуске — окно с
// «Понятно — убрать» / «Оставить»; повреждённый маркер — не «нет маркера».
// Запрет сна ставится и снимается.
// Подмены: снимать всегда; не писать до установки — роняют.
func TestGUIToHostOpMarker(t *testing.T) {
	for _, c := range []struct {
		name    string
		install func() core.InstallResult
		keep    bool
	}{
		{"перенесено", nil, false},
		{"установка не удалась (измерено)", func() core.InstallResult {
			return core.InstallResult{Measure: &core.CompatReport{}, Containers: []core.InstallContainerResult{{Container: "amnezia-awg", Outcome: core.InstallNotInstalled, Rollback: core.RollbackDone}}}
		}, false},
		{"установка не измерена", func() core.InstallResult {
			return core.InstallResult{Containers: []core.InstallContainerResult{{Container: "amnezia-awg", Outcome: core.InstallInstalled}}}
		}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newTHFixture(t)
			f.keysOut = core.KeysAccepted
			sawMarker := false
			f.install = func() core.InstallResult {
				m, err := core.ReadOpMarker()
				sawMarker = err == nil && m != nil && m.Target == migTestDstHost
				if c.install != nil {
					return c.install()
				}
				return okInstall("amnezia-awg")
			}
			f.startHost(t)
			v := f.fill(t, false, "")
			if !strings.Contains(f.allText(), "не рвите сеть") {
				t.Error("нет строки «не рвите сеть» перед кнопкой")
			}
			test.Tap(v.apply)
			waitGUIGoroutines(t)
			if !sawMarker {
				t.Error("маркера не было во время установки")
			}
			if f.awake != 1 || f.awakeStopped != 1 {
				t.Errorf("запрет сна: поставлен %d, снят %d", f.awake, f.awakeStopped)
			}
			m, err := core.ReadOpMarker()
			if err != nil || (m != nil) != c.keep {
				t.Fatalf("маркер после итога: %v %v (ждали оставлен=%v)", m, err, c.keep)
			}
			d := f.u.showOpMarker()
			if (d != nil) != c.keep {
				t.Fatalf("окно при запуске: %v", d != nil)
			}
			if !c.keep {
				return
			}
			if !strings.Contains(f.allText(), "итог неизвестен") || !strings.Contains(f.allText(), migTestDstHost) {
				t.Errorf("нет текста маркера:\n%s", f.allText())
			}
			test.Tap(findEsc(f.u.win.Canvas().Overlays().Top(), opMarkerKeep))
			if m, _ := core.ReadOpMarker(); m == nil {
				t.Error("«Оставить» сняло маркер")
			}
			f.u.showOpMarker()
			test.Tap(findEsc(f.u.win.Canvas().Overlays().Top(), opMarkerClear))
			if m, err := core.ReadOpMarker(); m != nil || err != nil {
				t.Errorf("«Понятно — убрать» не сняло маркер: %v %v", m, err)
			}
		})
	}
	// повреждённый маркер — окно «не прочитан», а не тишина
	f := newTHFixture(t)
	if err := os.WriteFile(f.marker, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if d := f.u.showOpMarker(); d == nil || !strings.Contains(f.allText(), "повреждён") {
		t.Errorf("повреждённый маркер не показан:\n%s", f.allText())
	}
}

// TestGUIToHostContinueHintParity — команда продолжения в GUI = core
// (та же, что CLI): -address-changes при подтверждённом адресе, слой
// автокопии, -replace-users, -apply (аудит AU M3).
func TestGUIToHostContinueHintParity(t *testing.T) {
	for _, pw := range []bool{true, false} {
		f := newTHFixture(t)
		f.keysOut = core.KeysAccepted
		f.applyErr = errors.New("связь")
		f.startHost(t)
		v := f.next(t)
		if v.addrCheck == nil {
			t.Fatal("сцена ничего не значит: адрес не требует подтверждения")
		}
		v.replace.SetChecked(true)
		v.addrCheck.SetChecked(true)
		if pw {
			v.mode.SetSelected(backupWithPassword)
			v.pw.SetText(migTestAutoPw)
			v.pw2.SetText(migTestAutoPw)
		} else {
			v.mode.SetSelected(backupNoPassword)
		}
		v.consent.SetChecked(true)
		v.keyPw.SetText(thKeyPw)
		test.Tap(v.apply)
		waitGUIGoroutines(t)
		ents, _ := os.ReadDir(f.keyDir)
		if len(ents) != 1 {
			t.Fatal("ключа нет")
		}
		path := filepath.Join(f.keyDir, ents[0].Name())
		sh, ps := core.ContinueHint(core.ContinueHintOptions{KeyPath: path, AddressChanges: true, PasswordAsk: pw, NoPassword: !pw})
		txt := f.allText()
		if !strings.Contains(txt, sh) || !strings.Contains(txt, ps) {
			t.Errorf("команда продолжения не совпала с core:\nждали %s\n%s", sh, txt)
		}
		for _, w := range []string{"-address-changes", "-replace-users", "-apply", map[bool]string{true: "-password-file", false: "-no-password"}[pw]} {
			if !strings.Contains(sh, w) {
				t.Errorf("нет %s", w)
			}
		}
	}
}

// TestGUIMigrateKeyFromFile — «Из файла…»: ключ читается из файла, в окне —
// только имя файла; доходит до подключения к цели (аудит AU M2).
func TestGUIMigrateKeyFromFile(t *testing.T) {
	f := newMigFixture(t, migTestDstHost, "SHA256:srcfp", "SHA256:dstfp")
	kf := filepath.Join(t.TempDir(), "new.vpn.txt")
	if err := os.WriteFile(kf, []byte(f.key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := migrateKeyFileOpen
	migrateKeyFileOpen = func(_ *ui, pick func(string)) { pick(kf) }
	t.Cleanup(func() { migrateKeyFileOpen = old })
	f.u.backupMenu()
	test.Tap(buttonByText(t, topPopup(t, f.u.win.Canvas()), migrateMenuText))
	ov := f.u.win.Canvas().Overlays().Top()
	ok := findEsc(ov, migrateAskNext)
	if !ok.Disabled() {
		t.Fatal("«Продолжить» включена без ключа")
	}
	test.Tap(buttonByText(t, ov, migrateFromFileText))
	txt := f.allText()
	if !strings.Contains(txt, "ключ из файла new.vpn.txt") {
		t.Errorf("имени файла нет:\n%s", txt)
	}
	body := strings.TrimPrefix(f.key, "vpn://")
	if strings.Contains(txt, body[:16]) || strings.Contains(txt, migTestSecret) {
		t.Fatal("ключ на экране")
	}
	if ok.Disabled() {
		t.Fatal("«Продолжить» выключена при ключе из файла")
	}
	test.Tap(ok)
	waitGUIGoroutines(t)
	if f.connects != 1 || f.gotCreds == nil || f.gotCreds.Host != migTestDstHost {
		t.Fatalf("ключ из файла не дошёл до подключения: %d", f.connects)
	}
}

// TestGUIToHostOpMarkerPending — прежний маркер молча не перезаписывается и
// не снимается: есть / повреждён → «установка не начиналась» с причиной,
// Install не вызван, маркер тот же; нет → установка идёт. Признак — тип
// ошибки (errors.Is), не начало строки. Подмена: снимать маркер при отказе
// (прежнее условие по тексту) — роняет.
func TestGUIToHostOpMarkerPending(t *testing.T) {
	for _, c := range []struct {
		name, body string
		refuse     bool
	}{
		{"нет маркера", "", false},
		{"есть маркер", `{"target":"192.0.2.77","started":"2026-11-06T10:00:00Z","step":"установка"}`, true},
		{"повреждён", "{", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newTHFixture(t)
			f.keysOut = core.KeysAccepted
			if c.body != "" {
				if err := os.WriteFile(f.marker, []byte(c.body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			f.startHost(t)
			v := f.fill(t, false, "")
			test.Tap(v.apply)
			waitGUIGoroutines(t)
			txt := f.allText()
			if !c.refuse {
				if f.installed != 1 {
					t.Fatalf("без маркера установка не шла:\n%s", txt)
				}
				return
			}
			if f.installed != 0 || !strings.Contains(txt, "установка не начиналась") || !strings.Contains(txt, "сначала проверьте") || !strings.Contains(txt, f.marker) {
				t.Errorf("отказ не тот (установок %d):\n%s", f.installed, txt)
			}
			if b, _ := os.ReadFile(f.marker); string(b) != c.body {
				t.Error("прежний маркер изменён или снят")
			}
		})
	}
	o := toHostOutcome{markerErr: fmt.Errorf("обёртка: %w", core.ErrOpMarkerPending)}
	if !errors.Is(o.markerErr, core.ErrOpMarkerPending) || errors.Is(o.markerErr, core.ErrOpMarkerNotWritten) {
		t.Error("типы ошибок маркера не различаются")
	}
}
