package main

// Раунд 3 (РЕВЬЮ-МЕНЮ-QR-SEC): ключ сервера в файле (R1) и права файла,
// выбранного в «Сохранить ещё в…» (M1).

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/internal/guiview"
)

func qrVisible(t *testing.T, u *ui) bool {
	t.Helper()
	seen := false
	walkVisible(topPopup(t, u.win.Canvas()), func(o fyne.CanvasObject) {
		if im, ok := o.(*canvas.Image); ok && im.Resource != nil && strings.HasSuffix(im.Resource.Name(), "-qr.png") {
			seen = true
		}
	})
	return seen
}

// TestMenuForeignServerKeyHidesQR — ДОЕЗД R1: подложенный файл с ВЕРНЫМ
// ключом клиента, но чужим ключом сервера ([Peer] PublicKey). Громкое
// «ВНИМАНИЕ», QR скрыт до явного «Всё равно показать QR»; «Сохранить
// конфигурацию…» само окно сохранения не открывает. Различение: с верным
// ключом сервера QR виден сразу.
func TestMenuForeignServerKeyHidesQR(t *testing.T) {
	u, dir, conf := savedFixture(t)
	row := rowOf(t, u, "Carol")

	// верный ключ сервера — QR виден
	u.cellMenu(widget.TableCellID{Row: row, Col: 1}).Items[2].Action()
	waitGUIGoroutines(t)
	if !qrVisible(t, u) || !strings.Contains(popupText(t, u), "Ключ сервера (PublicKey) совпадает с ключом этого сервера.") {
		t.Fatalf("верный ключ сервера: QR не виден или сверка не названа:\n%s", popupText(t, u))
	}
	u.win.Canvas().Overlays().Top().Hide()

	// подмена [Peer] PublicKey
	i := strings.Index(conf, "[Peer]\nPublicKey = ")
	if i < 0 {
		t.Fatal("тест ничего не значит: в конфиге нет [Peer] PublicKey")
	}
	k := i + len("[Peer]\nPublicKey = ")
	j := strings.Index(conf[k:], "\n")
	forged := conf[:k] + "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" + conf[k+j:]
	if err := os.WriteFile(filepath.Join(dir, "Carol.conf"), []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	u.cellMenu(widget.TableCellID{Row: row, Col: 1}).Items[3].Action() // «Сохранить конфигурацию…»
	waitGUIGoroutines(t)
	txt := popupText(t, u)
	if !strings.Contains(txt, guiview.SavedServerKeyDiffers) {
		t.Errorf("чужой ключ сервера не назван:\n%s", txt)
	}
	if !strings.Contains(txt, "Конфигурация «Carol»") {
		t.Errorf("поверх окна открылось окно сохранения — при чужом ключе сервера оно само открываться не должно:\n%s", txt)
	}
	if qrVisible(t, u) {
		t.Error("QR показан при чужом ключе сервера")
	}
	test.Tap(buttonByText(t, topPopup(t, u.win.Canvas()), guiview.SavedShowQRAnyway))
	if !qrVisible(t, u) {
		t.Error("«Всё равно показать QR» не показала QR")
	}
}

// chosenWriter — подставной URIWriteCloser поверх настоящего файла (как
// окно сохранения Fyne: os.Create с правами по умолчанию).
type chosenWriter struct {
	f   *os.File
	uri fyne.URI
}

func (w *chosenWriter) Write(b []byte) (int, error) { return w.f.Write(b) }
func (w *chosenWriter) Close() error                { return w.f.Close() }
func (w *chosenWriter) URI() fyne.URI               { return w.uri }

func newChosenWriter(t *testing.T, path string) *chosenWriter {
	t.Helper()
	f, err := os.Create(path) // как окно сохранения Fyne: права по умолчанию (0666 & umask)
	if err != nil {
		t.Fatal(err)
	}
	return &chosenWriter{f: f, uri: storage.NewFileURI(path)}
}

// TestChosenConfigFilePerms — M1: файл из «Сохранить ещё в…» получает 0600;
// отказ chmod — громкая ошибка «права доступа не ограничены».
func TestChosenConfigFilePerms(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.conf")
	if _, err := writeChosenConfig(newChosenWriter(t, p), "[Interface]\nPrivateKey = СЕКРЕТ\n"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("права файла %v, ожидалось 0600", fi.Mode().Perm())
	}

	old := chmodChosen
	var called string
	chmodChosen = func(name string, mode os.FileMode) error {
		called = name
		return errors.New("operation not permitted")
	}
	defer func() { chmodChosen = old }()
	p2 := filepath.Join(t.TempDir(), "y.conf")
	_, err = writeChosenConfig(newChosenWriter(t, p2), "[Interface]\nPrivateKey = СЕКРЕТ\n")
	if !errors.Is(err, errPermsNotLimited) || !strings.Contains(err.Error(), "могут прочитать другие пользователи") || filepath.FromSlash(called) != p2 {
		t.Errorf("отказ chmod не назван громко: %v (chmod для %q)", err, called)
	}
	if strings.Contains(err.Error(), "СЕКРЕТ") {
		t.Error("ключ в тексте ошибки")
	}
}
