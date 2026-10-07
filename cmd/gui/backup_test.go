package main

import (
	"bytes"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

func backupUI(t *testing.T, srv *fakesrv.Server, host string) *ui {
	t.Helper()
	a := test.NewApp()
	t.Cleanup(a.Quit)
	w := test.NewWindow(nil)
	w.Resize(fyne.NewSize(1229, 620))
	t.Cleanup(w.Close)
	base := t.TempDir()
	t.Setenv("LOCALAPPDATA", base)
	t.Setenv("XDG_CONFIG_HOME", base)
	t.Setenv("HOME", base)
	old := backupResolve
	backupResolve = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.7")}, nil }
	t.Cleanup(func() { backupResolve = old })
	t.Cleanup(core.SetXRayWaits(0, 0))
	return &ui{win: w, selectedRow: -1, status: widget.NewLabel(""),
		sess: core.NewSessionWithRunner(srv, &core.ServerCreds{Host: host, User: "root"})}
}

// texts — все тексты подписей, кнопок и галок под объектом.
func texts(o fyne.CanvasObject) string {
	var b strings.Builder
	var walk func(fyne.CanvasObject)
	walk = func(o fyne.CanvasObject) {
		switch v := o.(type) {
		case *widget.Label:
			b.WriteString(v.Text + "\n")
		case *widget.Button:
			b.WriteString("[" + v.Text + "]\n")
		case *widget.Check:
			b.WriteString("[x] " + v.Text + "\n")
		case *escButton:
			b.WriteString("[" + v.Text + "]\n")
		case fyne.Widget:
			walk(test.WidgetRenderer(v).Objects()[0])
			for _, c := range test.WidgetRenderer(v).Objects()[1:] {
				walk(c)
			}
			return
		case *fyne.Container:
			for _, c := range v.Objects {
				walk(c)
			}
		}
	}
	walk(o)
	return b.String()
}

func topOverlay(t *testing.T, u *ui) string {
	t.Helper()
	ov := u.win.Canvas().Overlays().Top()
	if ov == nil {
		t.Fatal("окна нет")
	}
	return texts(ov)
}

// TestGUIBackupWarningInSaveWindow — SEC-01: в окне сохранения (до записи)
// предупреждение «НЕ ЗАШИФРОВАН» целиком и каталог записи.
func TestGUIBackupWarningInSaveWindow(t *testing.T) {
	u := backupUI(t, fakesrv.New(), "203.0.113.1")
	v := u.backupDialog()
	// решение владельца по Р-1: выбора по умолчанию нет — «Сохранить» выключена
	if v.mode.Selected != "" || !v.ok.Disabled() {
		t.Fatalf("без выбора: выбрано %q, выключена=%v", v.mode.Selected, v.ok.Disabled())
	}
	v.mode.SetSelected(backupNoPassword)
	got := topOverlay(t, u)
	for _, l := range strings.Split(core.BackupUnencryptedWarning, "\n") {
		if !strings.Contains(got, l) {
			t.Errorf("в окне сохранения нет строки предупреждения: %q", l)
		}
	}
	if !strings.Contains(got, "Резервные копии") || !strings.Contains(got, "["+backupSaveOK+"]") || v.ok.Disabled() {
		t.Errorf("окно сохранения (без пароля):\n%s", got)
	}
}

// TestGUIBackupPasswordMode — с паролем: «Сохранить» выключена, пока пароль
// короче 12 символов или повтор не совпал; предупреждение «забудете пароль»;
// копия зашифрована и читается этим паролем; пароля в окнах нет.
func TestGUIBackupPasswordMode(t *testing.T) {
	old := core.ProdArgonParams
	core.ProdArgonParams = core.ArgonParams{MemoryKiB: 64, Time: 1, Threads: 1}
	t.Cleanup(func() { core.ProdArgonParams = old })
	u := backupUI(t, fakesrv.New(), "203.0.113.1")
	v := u.backupDialog()
	v.mode.SetSelected(backupWithPassword)
	const pw = "пароль-копии-окна"
	for _, c := range []struct{ a, b string }{{"", ""}, {"короткий", "короткий"}, {pw, pw + "x"}} {
		v.pw.SetText(c.a)
		v.pw2.SetText(c.b)
		if !v.ok.Disabled() {
			t.Errorf("пароль %q/%q — «Сохранить» включена", c.a, c.b)
		}
	}
	v.pw.SetText(pw)
	v.pw2.SetText(pw)
	if v.ok.Disabled() || !strings.Contains(topOverlay(t, u), "Забудете пароль") {
		t.Fatalf("верный пароль: выключена=%v", v.ok.Disabled())
	}
	dir, _ := core.UserBackupsDir()
	p, b, err := u.runBackupTo(dir, time.Now(), v.layer())
	if err != nil {
		t.Fatal(err)
	}
	if l, _ := core.BackupLayerOf(p); l != core.PasswordLayerName {
		t.Fatalf("слой %q", l)
	}
	if _, err := core.ReadBackupFile(p, core.PasswordLayer{Password: core.NewSecret([]byte(pw))}); err != nil {
		t.Fatalf("не читается своим паролем: %v", err)
	}
	u.backupResult(p, b, nil)
	if strings.Contains(topOverlay(t, u), pw) {
		t.Error("пароль в окне итога")
	}
	if _, _, err := u.runBackupTo(dir, time.Now(), nil); err == nil {
		t.Error("без выбора режима копия снята")
	}
}

// TestGUIEncryptedRestorePrompt — зашифрованная копия: окно пароля, «Открыть»
// выключена при пустом пароле; неверный пароль — «неверный пароль или файл
// повреждён»; верный — план построен.
func TestGUIEncryptedRestorePrompt(t *testing.T) {
	old := core.ProdArgonParams
	core.ProdArgonParams = core.ArgonParams{MemoryKiB: 64, Time: 1, Threads: 1}
	t.Cleanup(func() { core.ProdArgonParams = old })
	u, _, _, plain := guiMigration(t, "203.0.113.1")
	b, err := core.ReadBackupFile(plain, core.PlainLayer{})
	if err != nil {
		t.Fatal(err)
	}
	p := plain + ".enc.aabk"
	const pw = "пароль-копии-окна"
	if err := core.WriteBackupFile(p, b, core.PasswordLayer{Password: core.NewSecret([]byte(pw))}); err != nil {
		t.Fatal(err)
	}
	var got core.Secret
	e, ok := u.passwordPrompt(func(s core.Secret) { got = s })
	if !ok.Disabled() {
		t.Error("пустой пароль — «Открыть» включена")
	}
	e.SetText(pw)
	if ok.Disabled() {
		t.Fatal("пароль введён — «Открыть» выключена")
	}
	ok.OnTapped()
	if string(got.Bytes()) != pw {
		t.Fatal("пароль не передан")
	}
	if _, _, _, _, err := u.restorePrepare(p, core.PlainLayer{}, core.PasswordLayer{Password: core.NewSecret([]byte("неверный-пароль!!"))}); err == nil ||
		!strings.Contains(err.Error(), "неверный пароль или файл повреждён") {
		t.Errorf("неверный пароль: %v", err)
	}
	if _, _, rp, planErr, err := u.restorePrepare(p, core.PlainLayer{}, core.PasswordLayer{Password: got}); err != nil || planErr != nil || rp == nil {
		t.Errorf("верный пароль: %v %v", err, planErr)
	}
}

// TestGUIBackupSaves — копия записана в каталог данных, итог показывает
// путь и кнопку «Скопировать путь»; приватного ключа сервера в окне нет.
func TestGUIBackupSaves(t *testing.T) {
	srv := fakesrv.New()
	u := backupUI(t, srv, "203.0.113.1")
	dir, _ := core.UserBackupsDir()
	p, b, err := u.runBackupTo(dir, time.Now(), core.PlainLayer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.ReadBackupFile(p, core.PlainLayer{}); err != nil || filepath.Dir(p) != dir {
		t.Fatalf("копия: %v %s", err, p)
	}
	u.backupResult(p, b, nil)
	got := topOverlay(t, u)
	wg, _ := srv.File("/opt/amnezia/awg/wg0.conf")
	priv := strings.TrimSpace(strings.SplitN(strings.SplitN(string(wg), "PrivateKey = ", 2)[1], "\n", 2)[0])
	if !strings.Contains(got, p) || !strings.Contains(got, "["+backupCopyPathText+"]") || strings.Contains(got, priv) {
		t.Errorf("итог:\n%s", got)
	}
}

func guiMigration(t *testing.T, tgtHost string) (*ui, *fakesrv.Server, *fakesrv.Server, string) {
	t.Helper()
	src, tgt := fakesrv.New(), fakesrv.New()
	src.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("OLD-PSK\n"))
	tgt.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("NEW-PSK\n"))
	b, err := core.NewSessionWithRunner(src, &core.ServerCreds{Host: "203.0.113.1"}).CollectBackup("t", time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "c.aabk")
	if err := core.WriteBackupFile(p, b, core.PlainLayer{}); err != nil {
		t.Fatal(err)
	}
	return backupUI(t, tgt, tgtHost), src, tgt, p
}

// TestGUIRestoreGates — кнопка замены: выключена при СТОП; при адресе
// «другой» — выключена до галки; включена, когда всё сошлось. Замена
// переносит данные старого сервера на новый.
func TestGUIRestoreGates(t *testing.T) {
	t.Run("СТОП — выключена", func(t *testing.T) {
		u, _, tgt, p := guiMigration(t, "203.0.113.1")
		wg, _ := tgt.File("/opt/amnezia/awg/wg0.conf")
		tgt.SetFile("/opt/amnezia/awg/wg0.conf", []byte(strings.Replace(string(wg), "ListenPort = 51820", "ListenPort = 40000", 1)))
		b, compat, rp, planErr, err := u.restorePrepare(p)
		if err != nil {
			t.Fatal(err)
		}
		v := u.restoreWindow(b, compat, rp, planErr)
		if !v.apply.Disabled() || !strings.Contains(v.text, "ОСТАНОВЛЕН") {
			t.Errorf("СТОП: кнопка выключена=%v\n%s", v.apply.Disabled(), v.text)
		}
	})
	t.Run("адрес другой — галка", func(t *testing.T) {
		u, _, _, p := guiMigration(t, "198.51.100.9")
		b, compat, rp, planErr, err := u.restorePrepare(p)
		if err != nil {
			t.Fatal(err)
		}
		v := u.restoreWindow(b, compat, rp, planErr)
		if v.addrCheck == nil || !v.apply.Disabled() {
			t.Fatalf("без галки: галка=%v выключена=%v", v.addrCheck != nil, v.apply.Disabled())
		}
		v.addrCheck.SetChecked(true)
		if v.apply.Disabled() {
			t.Error("после галки кнопка не включилась")
		}
		if !strings.Contains(v.text, "НЕ ПРИДУТ") {
			t.Errorf("нет прямого текста про старые конфиги:\n%s", v.text)
		}
	})
	t.Run("всё сошлось — замена", func(t *testing.T) {
		u, src, tgt, p := guiMigration(t, "203.0.113.1")
		b, compat, rp, planErr, err := u.restorePrepare(p)
		if err != nil {
			t.Fatal(err)
		}
		v := u.restoreWindow(b, compat, rp, planErr)
		if v.apply.Disabled() || v.apply.Importance != widget.DangerImportance {
			t.Fatalf("кнопка: выключена=%v вид=%v", v.apply.Disabled(), v.apply.Importance)
		}
		auto, outs, err := u.runRestore(rp, false, true, time.Now())
		if err != nil || len(outs) != 1 || outs[0].State != core.RestoreDone {
			t.Fatalf("замена: %v %+v", err, outs)
		}
		for _, n := range []string{"wg0.conf", "clientsTable", "wireguard_psk.key"} {
			a, _ := src.File("/opt/amnezia/awg/" + n)
			c, _ := tgt.File("/opt/amnezia/awg/" + n)
			if !bytes.Equal(a, c) {
				t.Errorf("%s не перенесён", n)
			}
		}
		u.restoreResult(auto, outs, nil)
		got := topOverlay(t, u)
		for _, part := range []string{auto, "Удалить сервер из приложения", "не этой программой"} {
			if !strings.Contains(got, part) {
				t.Errorf("в итоге нет «%s»", part)
			}
		}
	})
}

// TestGUICopyButtonBusy — «Копия…» выключается на время серверной
// операции (присутствие кнопки на главном экране сторожит опись прибора
// осмотра: «кнопка:Копия…» в формах главного окна).
func TestGUICopyButtonBusy(t *testing.T) {
	u := backupUI(t, fakesrv.New(), "203.0.113.1")
	u.copyBtn = widget.NewButton("Копия", nil)
	u.setBusy(true)
	if !u.copyBtn.Disabled() || !u.busy {
		t.Error("во время операции «Копия…» не выключена")
	}
	u.setBusy(false)
	if u.copyBtn.Disabled() {
		t.Error("после операции «Копия…» не включилась")
	}
}
