package core

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func confWithKey(t *testing.T, priv, psk, addr string) string {
	t.Helper()
	return "[Interface]\nPrivateKey = " + priv + "\nAddress = " + addr + "\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = SRV=\nPresharedKey = " + psk + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.10:51820\n"
}

// TestFindSavedConfigStates — три состояния различимы: «не сохранялся»
// (каталога нет / конфига нет), «не прочитано» (каталог, файл, каталог не
// определён), «найден» — по публичному ключу, а не по имени файла.
func TestFindSavedConfigStates(t *testing.T) {
	priv, pub, err := genKey()
	if err != nil {
		t.Fatal(err)
	}
	otherPriv, _, _ := genKey()
	base := t.TempDir()

	dirMissing := filepath.Join(base, "нет")
	withOther := filepath.Join(base, "чужие")
	os.MkdirAll(withOther, 0o700)
	os.WriteFile(filepath.Join(withOther, "Петя.conf"), []byte(confWithKey(t, otherPriv, "P", "10.8.1.9/32")), 0o600)
	os.WriteFile(filepath.Join(withOther, "мусор.conf"), []byte("не конфиг"), 0o600)

	found := filepath.Join(base, "есть")
	os.MkdirAll(found, 0o700)
	// имя файла — чужое: сопоставление по ключу
	os.WriteFile(filepath.Join(found, "Вася.conf"), []byte(confWithKey(t, priv, "P", "10.8.1.5/32")), 0o600)
	os.WriteFile(filepath.Join(found, "Вася-копия.CONF"), []byte(confWithKey(t, priv, "P", "10.8.1.5/32")), 0o600)
	os.WriteFile(filepath.Join(found, "Петя.conf"), []byte(confWithKey(t, otherPriv, "P", "10.8.1.9/32")), 0o600)

	notDir := filepath.Join(base, "файл")
	os.WriteFile(notDir, []byte("x"), 0o600)

	for _, c := range []struct {
		name    string
		dir     string
		dirErr  error
		want    SavedConfState
		matches int
	}{
		{"каталога нет", dirMissing, nil, SavedNotFound, 0},
		{"конфига этого клиента нет", withOther, nil, SavedNotFound, 0},
		{"найден по ключу, имя чужое, два файла", found, nil, SavedFound, 2},
		{"каталог не читается", notDir, nil, SavedUnreadable, 0},
		{"каталог не определён", "", errors.New("LOCALAPPDATA не задана"), SavedUnreadable, 0},
	} {
		got := FindSavedConfig(c.dir, c.dirErr, pub)
		if got.State != c.want || got.Matches != c.matches {
			t.Errorf("%s: %v (совпадений %d) — %s", c.name, got.State, got.Matches, got.Why)
		}
		if c.want == SavedFound {
			if !strings.Contains(got.Config, priv) || filepath.Base(got.Path) != "Вася-копия.CONF" && filepath.Base(got.Path) != "Вася.conf" {
				t.Errorf("%s: не тот файл %q", c.name, got.Path)
			}
		} else if got.Config != "" || strings.Contains(got.Why, priv) {
			t.Errorf("%s: секрет вне состояния «найден»", c.name)
		}
	}

	// файл не читается: про этого клиента — «не знаем», а не «не сохранялся»
	old := readSavedFile
	readSavedFile = func(p string) ([]byte, error) {
		if strings.HasSuffix(p, "Петя.conf") {
			return nil, errors.New("open " + p + ": Access is denied.")
		}
		return old(p)
	}
	defer func() { readSavedFile = old }()
	if got := FindSavedConfig(withOther, nil, pub); got.State != SavedUnreadable || !strings.Contains(got.Why, "Access is denied") {
		t.Errorf("нечитаемый файл: %v — %s", got.State, got.Why)
	}
	// а если клиент найден среди прочитанных — найден
	if got := FindSavedConfig(found, nil, pub); got.State != SavedFound {
		t.Errorf("нечитаемый чужой файл помешал найти свой: %v", got.State)
	}
}

// TestCheckSavedConfigTable — сверка с сервером: совпал / не совпал / не
// сверено (сервер не прочитан или параметра нет).
func TestCheckSavedConfigTable(t *testing.T) {
	conf := confWithKey(t, "KEY", "PSK1", "10.8.1.5/32")
	for _, c := range []struct {
		name         string
		psk, addr    string
		err          error
		wantP, wantA CheckState
	}{
		{"всё совпало", "PSK1", "10.8.1.5/32", nil, CheckSame, CheckSame},
		{"PSK другой", "PSK2", "10.8.1.5/32", nil, CheckDiffer, CheckSame},
		{"адрес другой", "PSK1", "10.8.1.6/32", nil, CheckSame, CheckDiffer},
		{"сервер не прочитан", "", "", errors.New("wg0.conf не прочитан"), CheckUnknown, CheckUnknown},
		{"у сервера параметра нет", "", "", nil, CheckUnknown, CheckUnknown},
		{"адрес с пробелами", "PSK1", " 10.8.1.5/32 ", nil, CheckSame, CheckSame},
	} {
		got := CheckSavedConfig(conf, c.psk, c.addr, c.err)
		if got.PSK != c.wantP || got.Address != c.wantA {
			t.Errorf("%s: PSK %v адрес %v", c.name, got.PSK, got.Address)
		}
		if got.Endpoint != "203.0.113.10:51820" {
			t.Errorf("%s: Endpoint %q", c.name, got.Endpoint)
		}
		if c.err != nil && got.Why == "" {
			t.Errorf("%s: причина не названа", c.name)
		}
	}
}
