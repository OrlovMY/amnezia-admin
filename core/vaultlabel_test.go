package core

import (
	"os"
	"path/filepath"
	"testing"
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

// Три состояния подписи: есть / нет (старый файл) / не читается.
func TestReadVaultLabelStates(t *testing.T) {
	dir := t.TempDir()
	v := filepath.Join(dir, "a.avlt")
	if _, ok, err := ReadVaultLabel(v); ok || err != nil {
		t.Errorf("нет файла: ok=%v err=%v", ok, err)
	}
	if err := WriteVaultLabel(v, VaultLabel{Name: "AEZA test", Addr: "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	if l, ok, err := ReadVaultLabel(v); !ok || err != nil || l.Name != "AEZA test" {
		t.Errorf("есть файл: %+v ok=%v err=%v", l, ok, err)
	}
	if fi, err := os.Stat(v + ".label"); err == nil && fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("права подписи %v, ожидались 0600", fi.Mode().Perm())
	}
	os.WriteFile(v+".label", []byte("{битый"), 0o600)
	if _, ok, err := ReadVaultLabel(v); ok || err == nil {
		t.Errorf("битый файл должен дать ошибку: ok=%v err=%v", ok, err)
	}
	names := VaultNames([]string{v})
	if names[0].Full != "Сервер 1" {
		t.Errorf("нечитаемая подпись → %q, ожидался «Сервер 1»", names[0].Full)
	}
}

func TestVaultNamesDuplicates(t *testing.T) {
	got := vaultNamesFrom(
		[]VaultLabel{{Name: "Дом", Addr: "1.1.1.1"}, {Name: "Дом", Addr: "1.1.1.1"}, {Name: "Дом", Addr: "2.2.2.2"}, {}},
		[]bool{true, true, true, false})
	want := []string{"Дом — 1.1.1.1 (1)", "Дом — 1.1.1.1 (2)", "Дом — 2.2.2.2", "Сервер 4"}
	for i := range want {
		if got[i].Full != want[i] {
			t.Errorf("%d: %q, ожидалось %q", i, got[i].Full, want[i])
		}
	}
}
