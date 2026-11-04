package main

import (
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

const (
	migTestSrcHost = "203.0.113.1"
	migTestDstHost = "198.51.100.9"
	migTestSecret  = "SECRET-ROOT-PW-9f3a"
	migTestAutoPw  = "автокопия-пароль-12345"
)

// migFixture — GUI с источником (fakesrv) и фейковым подключением к цели.
type migFixture struct {
	u        *ui
	src, dst *fakesrv.Server
	key      string
	connects int
	gotCreds *core.ServerCreds
}

// migrateKey — ключ vpn://: base64 от JSON без сжатия (вариант 3 DecodeVpnKey).
func migrateKey(host string) string {
	j := `{"hostName":"` + host + `","userName":"root","password":"` + migTestSecret + `","port":"22"}`
	return "vpn://" + base64.RawURLEncoding.EncodeToString([]byte(j))
}

// newMigFixture — srcFp/dstFp: отпечатки ключей хоста источника и цели.
func newMigFixture(t *testing.T, dstHost, srcFp, dstFp string) *migFixture {
	t.Helper()
	serialUI(t)
	src, dst := fakesrv.New(), fakesrv.New()
	src.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("OLD-PSK\n"))
	dst.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("NEW-PSK\n"))
	u := backupUI(t, src, migTestSrcHost)
	u.sess = keepIPSession(src, migTestSrcHost)
	u.sess.HostKeyFingerprint = srcFp
	f := &migFixture{u: u, src: src, dst: dst, key: migrateKey(dstHost)}
	old := migrateConnect
	migrateConnect = func(c *core.ServerCreds, _ core.HostKeyPolicy) (*core.Session, error) {
		f.connects++
		f.gotCreds = c
		s := core.NewSessionWithRunner(dst, c)
		s.HostKeyFingerprint = dstFp
		return s, nil
	}
	t.Cleanup(func() { migrateConnect = old })
	old2 := core.ProdArgonParams
	core.ProdArgonParams = core.ArgonParams{MemoryKiB: 64, Time: 1, Threads: 1}
	t.Cleanup(func() { core.ProdArgonParams = old2 })
	return f
}

// start — настоящий путь человека: «Копия» → «Перенести на сервер…» → ключ
// → «Продолжить».
func (f *migFixture) start(t *testing.T) {
	t.Helper()
	f.u.backupMenu()
	menu := topPopup(t, f.u.win.Canvas())
	test.Tap(buttonByText(t, menu, migrateMenuText))
	ov := f.u.win.Canvas().Overlays().Top()
	e := firstEntry(ov)
	if e == nil {
		t.Fatal("в окне переноса нет поля ключа")
	}
	e.SetText(f.key)
	ok := findEsc(ov, migrateAskNext)
	if ok == nil || ok.Disabled() {
		t.Fatalf("«%s» не найдена или выключена", migrateAskNext)
	}
	test.Tap(ok)
	if e.Text != "" {
		t.Errorf("ключ остался в поле ввода после «Продолжить»")
	}
	waitGUIGoroutines(t)
}

func findEsc(root fyne.CanvasObject, text string) *escButton {
	var found *escButton
	walkObjects(root, func(o fyne.CanvasObject) {
		if b, ok := o.(*escButton); ok && b.Text == text && found == nil {
			found = b
		}
	})
	return found
}

// confirm — выбрать режим автокопии, отметить адрес/XRay и нажать «Перенести».
func (f *migFixture) confirm(t *testing.T, pw string) {
	t.Helper()
	v := f.u.migShown
	if v == nil {
		t.Fatal("окна подтверждения нет")
	}
	if !v.apply.Disabled() {
		t.Fatal("«Перенести» включена до выбора режима автокопии")
	}
	if pw == "" {
		v.mode.SetSelected(backupNoPassword)
	} else {
		v.mode.SetSelected(backupWithPassword)
		v.pw.SetText(pw)
		v.pw2.SetText(pw)
	}
	if v.addrCheck != nil {
		v.addrCheck.SetChecked(true)
	}
	if v.xrayRadio != nil {
		v.xrayRadio.SetSelected(restoreXRayCheck)
	}
	if v.apply.Disabled() {
		t.Fatalf("«Перенести» выключена при полном наборе условий:\n%s", v.text)
	}
	test.Tap(v.apply)
	if v.users != nil { // на цели есть пользователи — отдельное «Всё равно записать»
		if n := guiFlocks(f.dst); n != 0 {
			t.Fatalf("до «Всё равно записать» на цель записано %d раз", n)
		}
		test.Tap(v.users.force)
	}
	waitGUIGoroutines(t)
}

func (f *migFixture) overlayText(t *testing.T) string {
	t.Helper()
	var all []string
	for _, o := range f.u.win.Canvas().Overlays().List() {
		all = append(all, texts(o))
	}
	return strings.Join(all, "\n")
}

// allText — все тексты окон и полей ввода (включая парольные) на канве.
func (f *migFixture) allText() string {
	var b strings.Builder
	var add func(fyne.CanvasObject)
	add = func(o fyne.CanvasObject) {
		b.WriteString(texts(o))
		walkObjects(o, func(x fyne.CanvasObject) {
			if e, ok := x.(*widget.Entry); ok {
				b.WriteString(e.Text + "\n")
			}
		})
	}
	for _, o := range f.u.win.Canvas().Overlays().List() {
		add(o)
	}
	if c := f.u.win.Canvas().Content(); c != nil {
		add(c)
	}
	return b.String()
}

// TestGUIMigrateReachesPrepareAndApply — ТЕСТ ДОЕЗДА: кнопка в меню «Копия…»
// боевым путём доходит до PrepareMigration (окно со сверкой, до записи на
// цели ни одной записи) и до Apply (данные источника на цели, автокопия цели
// на диске, источник не писался, итог «ПЕРЕНЕСЕНО»).
// Подмены: (а) кнопки нет в меню; (б) migrateStart не зовёт PrepareMigration;
// (в) doMigrate не зовёт Apply — каждая роняет тест.
func TestGUIMigrateReachesPrepareAndApply(t *testing.T) {
	f := newMigFixture(t, migTestDstHost, "SHA256:srcfp", "SHA256:dstfp")
	f.start(t)
	if f.connects != 1 || f.gotCreds == nil || f.gotCreds.Host != migTestDstHost {
		t.Fatalf("подключение к цели: %d раз, creds %+v", f.connects, f.gotCreds)
	}
	win := f.overlayText(t)
	for _, want := range []string{migTestDstHost, "SHA256:dstfp", "SHA256:srcfp", migrateNoDiskText, "Источник (только чтение)", "Цель (сюда будет записано)", "[" + migrateApplyText + "]"} {
		if !strings.Contains(win, want) {
			t.Errorf("в окне до записи нет %q:\n%s", want, win)
		}
	}
	if n := guiFlocks(f.dst); n != 0 {
		t.Fatalf("до подтверждения на цель записано %d раз", n)
	}
	if got, _ := f.dst.File("/opt/amnezia/awg/wireguard_psk.key"); string(got) != "NEW-PSK\n" {
		t.Fatalf("цель изменена до подтверждения: %q", got)
	}
	f.confirm(t, "")
	if got, _ := f.dst.File("/opt/amnezia/awg/wireguard_psk.key"); string(got) != "OLD-PSK\n" {
		t.Errorf("данные источника не доехали до цели: %q", got)
	}
	if n := guiFlocks(f.src); n != 0 {
		t.Errorf("источник писался: %d", n)
	}
	if got, _ := f.src.File("/opt/amnezia/awg/wireguard_psk.key"); string(got) != "OLD-PSK\n" {
		t.Errorf("источник изменён: %q", got)
	}
	dir, _ := core.UserBackupsDir()
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(files) != 1 {
		t.Fatalf("на диске должна быть ровно одна автокопия цели, есть: %v", files)
	}
	res := f.overlayText(t)
	for _, want := range []string{"ПЕРЕНЕСЕНО — все контейнеры", files[0], migrateSrcSafeText, "Источник на диск не записывался"} {
		if !strings.Contains(res, want) {
			t.Errorf("в итоге нет %q:\n%s", want, res)
		}
	}
}

// TestGUIMigrateThreeOutcomes — ТЕСТ РАЗЛИЧЕНИЯ и ДОЕЗДА итога: три исхода
// получаются боевым путём (отказ записи цели, обрыв связи на записи, успех)
// и различимы в тексте. «Неизвестно» не содержит «ПЕРЕНЕСЕНО —» и «НЕ
// ПЕРЕНЕСЕНО».
// Подмены: (а) migrateVerdict считает RestoreUnknown как NotDone; (б) проверка
// «неизвестно» стоит после «перенесено»; (в) при len(outs)==0 — migDone.
func TestGUIMigrateThreeOutcomes(t *testing.T) {
	cases := []struct {
		name   string
		prep   func(*fakesrv.Server)
		want   string
		forbid []string
	}{
		{"перенесено", func(*fakesrv.Server) {}, "ПЕРЕНЕСЕНО — все", []string{"НЕИЗВЕСТНО", "НЕ ПЕРЕНЕСЕНО"}},
		{"не перенесено", func(s *fakesrv.Server) { s.LockBusy = true }, "НЕ ПЕРЕНЕСЕНО —", []string{"НЕИЗВЕСТНО —"}},
		{"неизвестно", func(s *fakesrv.Server) { s.WriteFault = map[int]fakesrv.WriteFault{1: {Code: 124}} }, "НЕИЗВЕСТНО — связь потеряна", []string{"ПЕРЕНЕСЕНО —", "НЕ ПЕРЕНЕСЕНО"}},
	}
	got := map[string]string{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newMigFixture(t, migTestDstHost, "SHA256:srcfp", "SHA256:dstfp")
			f.start(t)
			c.prep(f.dst)
			f.confirm(t, "")
			res := f.overlayText(t)
			if !strings.Contains(res, c.want) {
				t.Fatalf("нет заголовка %q:\n%s", c.want, res)
			}
			for _, bad := range c.forbid {
				if strings.Contains(res, bad) {
					t.Errorf("в итоге %q лишнее %q:\n%s", c.name, bad, res)
				}
			}
			if !strings.Contains(res, migrateSrcSafeText) {
				t.Errorf("не сказано, что старый сервер работает:\n%s", res)
			}
			got[c.name] = res
		})
	}
	if got["перенесено"] == got["неизвестно"] || got["неизвестно"] == got["не перенесено"] || got["перенесено"] == got["не перенесено"] {
		t.Error("итоги разных исходов совпали")
	}
}

// TestMigrateVerdictTable — таблица заголовка: «нет данных» (пустой итог без
// ошибки) — «неизвестно», а не «перенесено» и не «не перенесено»; частично и
// неизвестный контейнер среди перенесённых — «неизвестно».
func TestMigrateVerdictTable(t *testing.T) {
	o := func(s core.RestoreState) core.RestoreOutcome { return core.RestoreOutcome{Container: "c", State: s} }
	cases := []struct {
		name string
		err  error
		outs []core.RestoreOutcome
		want migState
	}{
		{"нет итога", nil, nil, migUnknown},
		{"нулевое состояние контейнера", nil, []core.RestoreOutcome{{Container: "c"}}, migUnknown},
		{"всё сделано", nil, []core.RestoreOutcome{o(core.RestoreDone), o(core.RestoreDone)}, migDone},
		{"сделано и неизвестно", nil, []core.RestoreOutcome{o(core.RestoreDone), o(core.RestoreUnknown)}, migUnknown},
		{"сделано и не записано", nil, []core.RestoreOutcome{o(core.RestoreDone), o(core.RestoreNotWritten)}, migNotDone},
		{"ничего", nil, []core.RestoreOutcome{o(core.RestoreNotWritten)}, migNotDone},
		{"ошибка до записи", errors.New("x"), nil, migNotDone},
		{"отмена", core.ErrCanceled, nil, migNotDone},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		st, text := migrateVerdict(c.err, c.outs)
		if st != c.want {
			t.Errorf("%s: %v, ждали %v (%s)", c.name, st, c.want, text)
		}
		seen[text] = true
	}
	if len(seen) < 6 {
		t.Errorf("тексты разных исходов совпадают: %d различных", len(seen))
	}
}

// TestGUIMigrateCloneSaysUnknown — клон VPS (одинаковый ключ хоста, разные
// адреса): текст «узнать не удалось» с советом, а не «один сервер»; ничего не
// читается и не пишется. Тест различения: тот же адрес и тот же ключ —
// другой текст («один и тот же сервер»).
// Подмена: migrateSameText для любого не-SameNo отвечает «один и тот же
// сервер» — роняет.
func TestGUIMigrateCloneSaysUnknown(t *testing.T) {
	f := newMigFixture(t, migTestDstHost, "SHA256:same", "SHA256:same")
	f.start(t)
	txt := f.overlayText(t)
	for _, want := range []string{"узнать не удалось", "клон", "dpkg-reconfigure openssh-server"} {
		if !strings.Contains(txt, want) {
			t.Errorf("текст про клон без %q:\n%s", want, txt)
		}
	}
	if strings.Contains(txt, "это один и тот же сервер") || f.u.migShown != nil {
		t.Errorf("клон назван «одним сервером» или окно переноса открыто:\n%s", txt)
	}
	if len(f.src.Commands()) != 0 || guiFlocks(f.dst) != 0 {
		t.Errorf("при «не знаем» серверы тронуты: источник %d команд", len(f.src.Commands()))
	}
	same := newMigFixture(t, migTestSrcHost, "SHA256:same", "SHA256:same")
	same.start(t)
	stxt := same.overlayText(t)
	if !strings.Contains(stxt, "это один и тот же сервер") || strings.Contains(stxt, "узнать не удалось") {
		t.Errorf("один сервер описан неверно:\n%s", stxt)
	}
}

// TestGUIMigrateNoSecretsInWidgets — ключ vpn:// (в нём пароль root), пароль
// автокопии и содержимое источника не попадают в виджеты, тексты ошибок и
// итога; в поле ввода ключа ключа после «Продолжить» нет.
// Подмены: (а) ошибка подключения печатается без MaskText; (б) итог
// печатает пароль автокопии; (в) ключ остаётся в поле — каждая роняет.
func TestGUIMigrateNoSecretsInWidgets(t *testing.T) {
	f := newMigFixture(t, migTestDstHost, "SHA256:srcfp", "SHA256:dstfp")
	f.start(t)
	f.confirm(t, migTestAutoPw)
	txt := f.allText()
	for _, secret := range []string{migTestSecret, f.key, migTestAutoPw, "OLD-PSK", "NEW-PSK"} {
		if strings.Contains(txt, secret) {
			t.Errorf("секрет %q попал в виджеты", secret)
		}
	}
	if !strings.Contains(txt, "автокопия нового сервера зашифрована паролем") {
		t.Errorf("итог не сообщает, что автокопия зашифрована:\n%s", txt)
	}
	// ошибка подключения, в которую попал ключ целиком
	g := newMigFixture(t, migTestDstHost, "SHA256:srcfp", "SHA256:dstfp")
	migrateConnect = func(c *core.ServerCreds, _ core.HostKeyPolicy) (*core.Session, error) {
		return nil, errors.New("dial " + g.key + " password=" + migTestSecret)
	}
	g.start(t)
	etxt := g.allText()
	if !strings.Contains(etxt, "подключение к новому серверу не удалось") {
		t.Fatalf("ошибка подключения не показана:\n%s", etxt)
	}
	if strings.Contains(etxt, g.key) || strings.Contains(etxt, migTestSecret) {
		t.Errorf("ключ или пароль в тексте ошибки:\n%s", etxt)
	}
	// нечитаемый ключ: ошибка тоже без ключа
	h := newMigFixture(t, migTestDstHost, "SHA256:srcfp", "SHA256:dstfp")
	h.key = "vpn://" + migTestSecret + "не-ключ"
	h.start(t)
	if htxt := h.allText(); strings.Contains(htxt, migTestSecret) || !strings.Contains(htxt, "не разобран") {
		t.Errorf("текст про нечитаемый ключ:\n%s", htxt)
	}
}
