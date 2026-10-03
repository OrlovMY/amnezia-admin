package main

// Задача владельца 01.10.2026: «В контекстном меню для каждого ключа должно
// быть QR и сохранить конфигурацию. Если вдруг админ создал УЗ, но забыл
// сохранить конфигурацию.»
//
// Доезд — настоящим путём: клиент создан AddUser на fakesrv, окно «Конфиг
// готов» само сохраняет .conf, меню строки находит его по публичному ключу и
// сверяет с сервером. Различение — три состояния поиска и три состояния
// сверки дают разный текст.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

const (
	wantSavedNotFound    = "Конфигурация этого клиента не найдена в папках, где программа её ищет:"
	wantSavedNotFoundEnd = "Если вы сохраняли её в другое место, откройте файл оттуда. " +
		"Иначе восстановить её нельзя — ключ есть только у самого клиента."
	wantUnreadablePrefix = "Не удалось прочитать папку конфигураций или файл в ней, поэтому неизвестно, " +
		"сохранён ли там конфиг этого клиента. Не перевыпускайте его, пока это не выяснено: " +
		"проверьте доступ к папке и откройте окно ещё раз. Подробности: "
)

// configsEnv — свой каталог данных пользователя; возвращает каталог конфигураций.
func configsEnv(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	t.Setenv("LOCALAPPDATA", base)
	t.Setenv("XDG_CONFIG_HOME", base)
	t.Setenv("HOME", base) // macOS: UserConfigsDir от HOME
	d, err := core.UserConfigsDir()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// savedFixture — fakesrv с клиентом «Carol», созданным НАСТОЯЩИМ путём через
// окно: Apply → showConfigDialog (автосохранение). Возвращает ui после
// refresh, каталог и выданный конфиг.
func savedFixture(t *testing.T) (*ui, string, string) {
	t.Helper()
	dir := configsEnv(t)
	srv := fakesrv.New()
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
	ct := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Support: core.SupportYes}
	nu, err := sess.AddUser(ct, "Carol")
	if err != nil {
		t.Fatal(err)
	}
	u := refreshedUI(t, sess, ct)
	u.showConfigDialog(nu, "создан") // автосохранение
	u.win.Canvas().Overlays().Top().Hide()
	return u, dir, nu.Config
}

func rowOf(t *testing.T, u *ui, name string) int {
	t.Helper()
	for i, c := range u.clients {
		if c.Name() == name {
			return i
		}
	}
	t.Fatalf("строки %q нет", name)
	return -1
}

func popupText(t *testing.T, u *ui) string {
	t.Helper()
	return strings.Join(visibleTexts(topPopup(t, u.win.Canvas())), " | ")
}

// TestConfigDialogAutoSaves — ДОЕЗД автосохранения: окно «Конфиг готов»
// само кладёт .conf в каталог конфигураций и говорит где; сбой — громко
// «НЕ сохранён» в самом окне, файла нет.
func TestConfigDialogAutoSaves(t *testing.T) {
	u := testUI(t)
	dir := configsEnv(t)
	nu := &core.NewUser{Name: "Петя", IP: "10.8.1.8", Config: "[Interface]\nPrivateKey = СЕКРЕТ\n"}
	u.showConfigDialog(nu, "создан")
	want := filepath.Join(dir, "Петя.conf")
	b, err := os.ReadFile(want)
	if err != nil || string(b) != nu.Config {
		t.Fatalf("конфиг не сохранён сам: %v", err)
	}
	txt := popupText(t, u)
	if !strings.Contains(txt, "Конфиг сохранён: "+want) || strings.Contains(txt, "НЕ сохранён") {
		t.Errorf("окно не говорит, где сохранено: %s", txt)
	}
	u.win.Canvas().Overlays().Top().Hide()

	// сбой: каталог данных не определяется
	t.Setenv("LOCALAPPDATA", "rel")
	t.Setenv("XDG_CONFIG_HOME", "rel")
	t.Setenv("HOME", "")
	u.showConfigDialog(&core.NewUser{Name: "Вася", IP: "10.8.1.9", Config: "[Interface]\nPrivateKey = СЕКРЕТ\n"}, "создан")
	txt = popupText(t, u)
	if !strings.Contains(txt, "Конфиг НЕ сохранён. Сохраните его кнопкой «Сохранить ещё в…» до закрытия окна.") || !strings.Contains(txt, "Подробности: ") {
		t.Errorf("сбой автосохранения не назван в окне: %s", txt)
	}
	if strings.Contains(txt, "СЕКРЕТ") || strings.Contains(u.status.Text, "СЕКРЕТ") {
		t.Error("приватный ключ попал в текст окна или строки состояния")
	}
	if u.status.Text != "Конфиг НЕ сохранён" {
		t.Errorf("строка состояния: %q", u.status.Text)
	}
}

// TestMenuShowsSavedConfigQR — ДОЕЗД пункта «Показать QR»: файл назван
// ЧУЖИМ именем (имени не доверяем) — найден по ключу; QR показан; сверка с
// сервером — «совпадает». Ключа в текстах нет.
func TestMenuShowsSavedConfigQR(t *testing.T) {
	u, dir, conf := savedFixture(t)
	// переименовать файл: сопоставление обязано идти по ключу
	if err := os.Rename(filepath.Join(dir, "Carol.conf"), filepath.Join(dir, "кто-то другой.conf")); err != nil {
		t.Fatal(err)
	}
	row := rowOf(t, u, "Carol")
	m := u.cellMenu(widget.TableCellID{Row: row, Col: 1})
	m.Items[2].Action()
	waitGUIGoroutines(t)
	txt := popupText(t, u)
	for _, want := range []string{
		"Конфигурация «Carol»",
		"Конфиг из файла: " + filepath.Join(dir, "кто-то другой.conf"),
		"Ключ клиента совпадает с ключом на сервере.",
		"PresharedKey совпадает с сервером.",
		"Адрес клиента (Address) совпадает с сервером.",
		"Адрес сервера в файле (Endpoint): 203.0.113.10:",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("в окне нет %q:\n%s", want, txt)
		}
	}
	qr := false
	walkVisible(topPopup(t, u.win.Canvas()), func(o fyne.CanvasObject) {
		if _, ok := o.(*canvas.Image); ok {
			qr = true
		}
	})
	if !qr {
		t.Error("QR не показан")
	}
	priv := strings.TrimSpace(strings.SplitN(strings.SplitN(conf, "PrivateKey = ", 2)[1], "\n", 2)[0])
	if strings.Contains(txt, priv) || strings.Contains(u.status.Text, priv) {
		t.Error("приватный ключ в тексте окна или строке состояния")
	}
}

// TestMenuSavedConfigDiffersFromServer — РАЗЛИЧЕНИЕ сверки: PresharedKey в
// файле не тот, что на сервере, — сказано прямо, а не показан молча старый
// конфиг (признак 4).
func TestMenuSavedConfigDiffersFromServer(t *testing.T) {
	u, dir, conf := savedFixture(t)
	i := strings.Index(conf, "PresharedKey = ")
	j := strings.Index(conf[i:], "\n")
	stale := conf[:i] + "PresharedKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" + conf[i+j:]
	if err := os.WriteFile(filepath.Join(dir, "Carol.conf"), []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	u.cellMenu(widget.TableCellID{Row: rowOf(t, u, "Carol"), Col: 1}).Items[2].Action()
	waitGUIGoroutines(t)
	txt := popupText(t, u)
	if !strings.Contains(txt, "ВНИМАНИЕ: PresharedKey в файле НЕ совпадает с сервером") {
		t.Errorf("расхождение PSK не названо:\n%s", txt)
	}
	if !strings.Contains(txt, "Адрес клиента (Address) совпадает с сервером.") {
		t.Errorf("адрес должен совпасть:\n%s", txt)
	}
}

// TestMenuSavedConfigServerUnknown — сверка не выполнена (нет сессии):
// «не сверен», а не «совпадает».
func TestMenuSavedConfigServerUnknown(t *testing.T) {
	u, _, _ := savedFixture(t)
	u.sess = nil
	u.cellMenu(widget.TableCellID{Row: rowOf(t, u, "Carol"), Col: 1}).Items[2].Action()
	waitGUIGoroutines(t)
	txt := popupText(t, u)
	if !strings.Contains(txt, "PresharedKey с сервером не сверен: нет подключения к серверу.") || strings.Contains(txt, "совпадает с сервером") {
		t.Errorf("сверка без сервера:\n%s", txt)
	}
}

// TestMenuSavedConfigNotSavedOffersRekey — РАЗЛИЧЕНИЕ «не сохранялся» и
// «не прочитано» и доезд «Перевыпустить…» в существующий поток перевыпуска.
func TestMenuSavedConfigNotSavedOffersRekey(t *testing.T) {
	u, dir, _ := savedFixture(t)
	if err := os.Remove(filepath.Join(dir, "Carol.conf")); err != nil {
		t.Fatal(err)
	}
	row := rowOf(t, u, "Carol")
	u.cellMenu(widget.TableCellID{Row: row, Col: 1}).Items[3].Action()
	txt := popupText(t, u)
	if !strings.Contains(txt, wantSavedNotFound) || !strings.Contains(txt, wantSavedNotFoundEnd) || strings.Contains(txt, wantUnreadablePrefix) {
		t.Fatalf("«не найден»:\n%s", txt)
	}
	// перечень каталогов поиска — абсолютными путями, все
	for _, d := range savedSearchDirs() {
		if !filepath.IsAbs(d.Path) || !strings.Contains(txt, d.Path) {
			t.Errorf("в тексте «не найден» нет каталога поиска %q:\n%s", d.Path, txt)
		}
	}
	rk := buttonByText(t, topPopup(t, u.win.Canvas()), "Перевыпустить — старый перестанет работать…")
	// UX-01 П1: не безобидный вид — опасная кнопка со значком предупреждения
	if rk.Importance != widget.DangerImportance || rk.Icon != theme.WarningIcon() {
		t.Errorf("кнопка перевыпуска выглядит безобидно: важность %v, значок %v", rk.Importance, rk.Icon)
	}
	test.Tap(rk)
	if got := popupText(t, u); !strings.Contains(got, "Перевыпустить конфиг?") {
		t.Errorf("«Перевыпустить…» не привела к подтверждению перевыпуска:\n%s", got)
	}
	if u.selectedRow != row {
		t.Errorf("перевыпуск не для этой строки: %d, ожидалась %d", u.selectedRow, row)
	}
	u.win.Canvas().Overlays().Top().Hide()

	// каталог конфигураций — файл: прочитать нельзя, это НЕ «не сохранялся»
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	u.cellMenu(widget.TableCellID{Row: row, Col: 1}).Items[2].Action()
	txt = popupText(t, u)
	if !strings.Contains(txt, wantUnreadablePrefix) || strings.Contains(txt, wantSavedNotFound) {
		t.Errorf("«не прочитано»:\n%s", txt)
	}
	for _, o := range []string{"Перевыпустить"} {
		if strings.Contains(txt, o) {
			t.Errorf("при «не прочитано» предложено %q — сохранён ли конфиг, неизвестно", o)
		}
	}
}
