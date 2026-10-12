package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDefaultAndChooseServerName(t *testing.T) {
	cases := []struct {
		name, label, host string
		cfg               map[string]any
		def, chosen       string
	}{
		{"описание из ключа", "", "1.2.3.4", map[string]any{"description": "AEZA test", "hostName": "1.2.3.4"}, "AEZA test", "AEZA test"},
		{"метка человека главнее описания", "Мой VPN", "1.2.3.4", map[string]any{"description": "AEZA test", "hostName": "1.2.3.4"}, "AEZA test", "Мой VPN"},
		{"старая метка по умолчанию = адрес — уступает описанию", "1.2.3.4", "1.2.3.4", map[string]any{"description": "AEZA test", "hostName": "1.2.3.4"}, "AEZA test", "AEZA test"},
		{"описания нет — адрес; порт 22 и root не пишутся", "", "1.2.3.4", map[string]any{"hostName": "1.2.3.4", "port": "22", "userName": "root"}, "1.2.3.4", "1.2.3.4"},
		{"нестандартные порт и пользователь", "", "1.2.3.4", map[string]any{"hostName": "1.2.3.4", "port": "2222", "userName": "admin"}, "admin@1.2.3.4:2222", "admin@1.2.3.4:2222"},
		{"ничего не известно", "", "", map[string]any{}, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DefaultServerName(c.cfg); got != c.def {
				t.Errorf("DefaultServerName = %q, ожидалось %q", got, c.def)
			}
			if got := ChooseServerName(c.label, c.host, c.cfg); got != c.chosen {
				t.Errorf("ChooseServerName = %q, ожидалось %q", got, c.chosen)
			}
		})
	}
}

// Состояния подписи: нет / есть и верна / повреждена / не от этого файла;
// перезапись .avlt программой перепривязывает только верную подпись.
func TestReadVaultLabelStates(t *testing.T) {
	dir := t.TempDir()
	v := filepath.Join(dir, "a.avlt")
	if err := os.WriteFile(v, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, st, err := ReadVaultLabel(v); st != LabelAbsent || err != nil {
		t.Errorf("нет подписи: st=%v err=%v", st, err)
	}
	if err := WriteVaultLabel(v, VaultLabel{Name: "AEZA test", Addr: "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	if l, st, err := ReadVaultLabel(v); st != LabelOK || err != nil || l.Name != "AEZA test" {
		t.Errorf("верная: %+v st=%v err=%v", l, st, err)
	}
	if fi, err := os.Stat(v + ".label"); err == nil && fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("права подписи %v, ожидались 0600", fi.Mode().Perm())
	}
	// Перезапись программой (reseal/ForgetHostKey) — подпись остаётся верной.
	if err := WriteVaultFile(v, []byte("v2")); err != nil {
		t.Fatal(err)
	}
	if _, st, _ := ReadVaultLabel(v); st != LabelOK {
		t.Errorf("после WriteVaultFile подпись не перепривязана: st=%v", st)
	}
	// Файл заменили в обход программы — подпись чужая.
	os.WriteFile(v, []byte("подменённый"), 0o600)
	if _, st, _ := ReadVaultLabel(v); st != LabelMismatch {
		t.Errorf("подменённый .avlt: st=%v, ожидался LabelMismatch", st)
	}
	if n := VaultNames([]string{v})[0].Full; n != "Сервер 1 ("+LabelMismatchNote+")" {
		t.Errorf("подменённый → %q", n)
	}
	// Несовпадающая подпись перезаписью программы не узаконивается.
	WriteVaultFile(v, []byte("v3"))
	if _, st, _ := ReadVaultLabel(v); st != LabelMismatch {
		t.Errorf("неверная подпись узаконена перезаписью: st=%v", st)
	}
	os.WriteFile(v+".label", []byte("{битый"), 0o600)
	if _, st, err := ReadVaultLabel(v); st != LabelBroken || err == nil {
		t.Errorf("битая: st=%v err=%v", st, err)
	}
	if n := VaultNames([]string{v})[0].Full; n != "Сервер 1 ("+LabelBrokenNote+")" {
		t.Errorf("битая → %q", n)
	}
	os.Remove(v + ".label")
	if n := VaultNames([]string{v})[0].Full; n != "Сервер 1" {
		t.Errorf("нет подписи → %q", n)
	}
}

// Пустое имя: пишется адрес; нет и адреса — подпись не пишется.
func TestWriteVaultLabelEmptyName(t *testing.T) {
	dir := t.TempDir()
	v := filepath.Join(dir, "a.avlt")
	os.WriteFile(v, nil, 0o600)
	if err := WriteVaultLabel(v, VaultLabel{Name: "  ", Addr: "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	if l, st, _ := ReadVaultLabel(v); st != LabelOK || l.Name != "1.2.3.4" {
		t.Errorf("пустое имя: %+v st=%v", l, st)
	}
	os.Remove(v + ".label")
	if err := WriteVaultLabel(v, VaultLabel{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(v + ".label"); !os.IsNotExist(err) {
		t.Error("пустая подпись записана")
	}
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("остался временный файл %s", e.Name())
		}
	}
}

func TestRemoveOrphanVaultLabels(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.avlt"), nil, 0o600)
	os.WriteFile(filepath.Join(dir, "a.avlt.label"), []byte("{}"), 0o600)
	os.WriteFile(filepath.Join(dir, "b.avlt.label"), []byte("{}"), 0o600)
	if err := RemoveOrphanVaultLabels(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a.avlt.label")); err != nil {
		t.Error("удалена подпись живого ключа")
	}
	if _, err := os.Stat(filepath.Join(dir, "b.avlt.label")); !os.IsNotExist(err) {
		t.Error("сирота осталась")
	}
}

func TestVaultNamesDuplicates(t *testing.T) {
	ok := LabelOK
	got := vaultNamesFrom(
		[]VaultLabel{{Name: "Дом", Addr: "1.1.1.1"}, {Name: "Дом", Addr: "1.1.1.1"}, {Name: "Дом", Addr: "2.2.2.2"}, {}},
		[]LabelState{ok, ok, ok, LabelAbsent})
	want := []string{"Дом — 1.1.1.1 (1)", "Дом — 1.1.1.1 (2)", "Дом — 2.2.2.2", "Сервер 4"}
	for i := range want {
		if got[i].Full != want[i] {
			t.Errorf("%d: %q, ожидалось %q", i, got[i].Full, want[i])
		}
	}
}

// M1: обрезается имя, различитель сохраняется.
func TestVaultNamesLongDuplicatesKeepSuffix(t *testing.T) {
	long := strings.Repeat("я", 58)
	got := vaultNamesFrom([]VaultLabel{{Name: long, Addr: "1.1.1.1"}, {Name: long, Addr: "2.2.2.2"}},
		[]LabelState{LabelOK, LabelOK})
	if got[0].Short == got[1].Short {
		t.Fatalf("одинаковые: %q", got[0].Short)
	}
	for i, a := range []string{"1.1.1.1", "2.2.2.2"} {
		if !strings.HasSuffix(got[i].Short, " — "+a) || utf8.RuneCountInString(got[i].Short) > VaultLabelMaxRunes {
			t.Errorf("%d: %q", i, got[i].Short)
		}
	}
}
