package core_test

// АУДИТ-МЕНЮ-QR-LOGIC К-1: запись конфига НЕ затирает файл ДРУГОГО клиента.
// Доезд через AddUser / RenameUser / AddUser на fakesrv и WriteClientConfig
// (тот же вход, что у автосохранения GUI и у CLI): на c0759a7 тест
// компилируется и падает поведением — второй файл затирал первый.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

func k1Session(t *testing.T) (*core.Session, *core.Container) {
	t.Helper()
	srv := fakesrv.New()
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
	return sess, &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
}

func k1Found(t *testing.T, sess *core.Session, ct *core.Container, dir, name string) core.SavedConfig {
	t.Helper()
	cl := clientByName(t, sess, ct, name)
	return core.FindSavedConfig(dir, nil, cl.ClientID)
}

// Путь (а): «Phone» переименован в «Old phone», создан новый «Phone».
func TestSaveDoesNotOverwriteRenamedClient(t *testing.T) {
	sess, ct := k1Session(t)
	dir := filepath.Join(t.TempDir(), "Конфигурации")
	a, err := sess.AddUser(ct, "Phone")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := core.WriteClientConfig(dir, a.Name, a.Config); err != nil {
		t.Fatal(err)
	}
	old := clientByName(t, sess, ct, "Phone")
	if err := sess.RenameUser(ct, old.ClientID, "Old phone"); err != nil {
		t.Fatal(err)
	}
	b, err := sess.AddUser(ct, "Phone")
	if err != nil {
		t.Fatal(err)
	}
	p2, _, err := core.WriteClientConfig(dir, b.Name, b.Config)
	if err != nil {
		t.Fatal(err)
	}
	if got := k1Found(t, sess, ct, dir, "Old phone"); got.State != core.SavedFound {
		t.Errorf("конфиг «Old phone» затёрт: %v %s", got.State, got.Why)
	}
	if got := k1Found(t, sess, ct, dir, "Phone"); got.State != core.SavedFound || got.Path != p2 {
		t.Errorf("конфиг нового «Phone» не найден там, куда записан: %v %q / %q", got.State, got.Path, p2)
	}
	if filepath.Base(p2) != "Phone (2).conf" {
		t.Errorf("новый «Phone» записан как %q, ожидалось «Phone (2).conf»", filepath.Base(p2))
	}
}

// Путь (б): имена, разные только регистром («Phone» и «phone») — на Windows
// и macOS это один файл. Сравнение имён — без учёта регистра на всех ОС.
func TestSaveDoesNotOverwriteCaseVariant(t *testing.T) {
	sess, ct := k1Session(t)
	dir := filepath.Join(t.TempDir(), "Конфигурации")
	a, err := sess.AddUser(ct, "Phone")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := core.WriteClientConfig(dir, a.Name, a.Config); err != nil {
		t.Fatal(err)
	}
	b, err := sess.AddUser(ct, "phone")
	if err != nil {
		t.Skipf("ядро не дало создать «phone» рядом с «Phone»: %v — путь (б) невозможен", err)
	}
	if _, _, err := core.WriteClientConfig(dir, b.Name, b.Config); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"Phone", "phone"} {
		if got := k1Found(t, sess, ct, dir, n); got.State != core.SavedFound {
			t.Errorf("конфиг %q затёрт: %v %s", n, got.State, got.Why)
		}
	}
}

// Файл с этим именем не читается (не разбирается) — не перезаписывать:
// новое имя и Occupied; содержимое чужого файла цело.
func TestSaveUnreadableNameTaken(t *testing.T) {
	sess, ct := k1Session(t)
	dir := filepath.Join(t.TempDir(), "Конфигурации")
	os.MkdirAll(dir, 0o700)
	junk := []byte("не конфиг")
	os.WriteFile(filepath.Join(dir, "Phone.conf"), junk, 0o600)
	a, err := sess.AddUser(ct, "Phone")
	if err != nil {
		t.Fatal(err)
	}
	r, err := core.SaveClientConfig(dir, a.Name, a.Config, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Occupied != "Phone.conf" || filepath.Base(r.Path) != "Phone (2).conf" {
		t.Errorf("занятое имя: Occupied %q, путь %q", r.Occupied, r.Path)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "Phone.conf")); string(b) != string(junk) {
		t.Error("непроверяемый файл перезаписан")
	}
}

// rekey: файл того же клиента со СТАРЫМ ключом — перезаписать можно (ключ
// мёртв), имя не меняется; повтор сохранения того же — тоже на месте.
func TestSaveRekeyOverwritesOwnFile(t *testing.T) {
	sess, ct := k1Session(t)
	dir := filepath.Join(t.TempDir(), "Конфигурации")
	a, err := sess.AddUser(ct, "Phone")
	if err != nil {
		t.Fatal(err)
	}
	p1, _, err := core.WriteClientConfig(dir, a.Name, a.Config)
	if err != nil {
		t.Fatal(err)
	}
	if p, _, _ := core.WriteClientConfig(dir, a.Name, a.Config); p != p1 {
		t.Errorf("повтор того же конфига ушёл в %q", p)
	}
	cl := clientByName(t, sess, ct, "Phone")
	nu, err := sess.RegenerateUser(ct, cl.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if nu.Replaces != cl.ClientID {
		t.Fatalf("RegenerateUser не назвал прежний ключ: %q", nu.Replaces)
	}
	r, err := core.SaveClientConfig(dir, nu.Name, nu.Config, nu.Replaces)
	if err != nil {
		t.Fatal(err)
	}
	if r.Path != p1 || r.Occupied != "" {
		t.Errorf("rekey: путь %q (ожидался %q), Occupied %q", r.Path, p1, r.Occupied)
	}
	b, _ := os.ReadFile(p1)
	if !strings.Contains(string(b), strings.SplitN(strings.SplitN(nu.Config, "PrivateKey = ", 2)[1], "\n", 2)[0]) {
		t.Error("после rekey в файле не новый ключ")
	}
	// без Replaces чужой (старый) ключ — не перезаписывается
	nu2, err := sess.RegenerateUser(ct, clientByName(t, sess, ct, "Phone").ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := core.SaveClientConfig(dir, nu2.Name, nu2.Config, ""); r.Path == p1 || r.Occupied == "" {
		t.Errorf("без прежнего ключа файл перезаписан: %q", r.Path)
	}
}
