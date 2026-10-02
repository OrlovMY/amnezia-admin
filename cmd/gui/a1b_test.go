package main

// Тесты A1б (сплошная сверка по четырём признакам CLAUDE.md) для GUI. Все
// идут боевыми путями окна: экран подключения, диалог сохранения ключа,
// refresh() против fakesrv. Файл прогоняется поверх продуктового кода
// f0febbd (см. ОТЧЁТ-A1Б.md): все тесты, кроме TestA1bActivityUnknownWhenStatsFail,
// там падают; исключение объяснено в шапке самого теста.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
	"amnezia-admin/internal/testpath"
)

// vaultDirForTest — каталог хранилищ ТЕСТОВОГО бинарника (рядом с ним, во
// временном каталоге сборки), гарантированно отсутствующий на время теста.
// Работает только во временном каталоге. Если там уже что-то есть (его
// оставляют другие тесты пакета — например, клик по заголовку таблицы
// сохраняет ui.json), оно откладывается в сторону и возвращается после
// теста, а не удаляется: итог не должен зависеть от порядка прогона.
func vaultDirForTest(t *testing.T) string {
	t.Helper()
	dir := core.DefaultVaultDir()
	if !insideTempDir(dir) {
		t.Fatalf("каталог хранилищ %s не во временном каталоге %s — тест его не трогает", dir, os.TempDir())
	}
	if _, err := os.Stat(dir); err == nil {
		aside := dir + ".a1b-aside"
		if _, err := os.Stat(aside); err == nil {
			t.Fatalf("%s уже существует — отложить %s некуда", aside, dir)
		}
		if err := os.Rename(dir, aside); err != nil {
			t.Fatalf("не удалось отложить %s: %v", dir, err)
		}
		t.Cleanup(func() {
			os.RemoveAll(dir)
			if err := os.Rename(aside, dir); err != nil {
				t.Errorf("не удалось вернуть %s: %v", dir, err)
			}
		})
	}
	return dir
}

// canonPath — путь в одной форме для сравнения (ревью QA-01, п.6): Abs,
// затем EvalSymlinks. На macOS это /var → /private/var; на Windows
// EvalSymlinks сверяет каждую часть пути с файловой системой и возвращает
// ДЛИННЫЕ имена (RUNNER~1 → runneradmin). Несуществующий хвост
// (каталог хранилищ до создания) приводится через ближайшего
// существующего родителя.
func canonPath(p string) string { return testpath.Canon(p) }

// insideTempDir — лежит ли p внутри временного каталога ОС. Сравнение по
// частям пути через filepath.Rel, на Windows без учёта регистра.
func insideTempDir(p string) bool { return testpath.InsideTempDir(p) }

// vaultPathIsAFile — по пути каталога хранилищ лежит ФАЙЛ: каталог «есть»,
// а прочитать его как каталог нельзя. Переносимый на все три ОС способ
// получить «не удалось прочитать», отличный от «каталога нет».
func vaultPathIsAFile(t *testing.T) {
	t.Helper()
	dir := vaultDirForTest(t)
	if err := os.WriteFile(dir, []byte("не каталог"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(dir) })
}

// connectScreenTexts — все видимые тексты НАСТОЯЩЕГО экрана подключения.
func connectScreenTexts(t *testing.T) []string {
	t.Helper()
	u := focusTestUI(t)
	u.showConnectScreen("")
	return visibleTexts(u.win.Canvas().Content())
}

// TestA1bVaultListUnknownDiffersFromNone — ТЕСТ РАЗЛИЧЕНИЯ: «каталога
// сохранённых ключей нет» (штатно: блока нет) и «каталог прочитать не
// удалось» дают РАЗНЫЙ блок. На f0febbd savedVaultsBlock возвращал nil в
// обоих случаях.
func TestA1bVaultListUnknownDiffersFromNone(t *testing.T) {
	u := focusTestUI(t)
	vaultDirForTest(t) // каталога нет
	if b := u.savedVaultsBlock(widget.NewButton("", nil), widget.NewLabel("")); b != nil {
		t.Fatalf("каталога нет — блок сохранённых ключей должен отсутствовать, а он есть: %T", b)
	}
	vaultPathIsAFile(t)
	b := u.savedVaultsBlock(widget.NewButton("", nil), widget.NewLabel(""))
	if b == nil {
		t.Fatal("каталог сохранённых ключей не прочитан, а экран выглядит так же, как без ключей — " +
			"незнание выдано за «сохранённых ключей нет» (признак 2)")
	}
	texts := visibleTexts(b)
	if !hasTextContaining(texts, "Сохранённые ключи прочитать не удалось") {
		t.Errorf("блок есть, но не говорит, что ключи прочитать не удалось: %q", texts)
	}
}

// TestA1bVaultListUnreadableReachesConnectScreen — ТЕСТ ДОЕЗДА: отказ
// чтения каталога боевым путём (настоящий os.Stat/ReadDir) доезжает до
// экрана подключения, собранного showConnectScreen.
func TestA1bVaultListUnreadableReachesConnectScreen(t *testing.T) {
	vaultPathIsAFile(t)
	texts := connectScreenTexts(t)
	if !hasTextContaining(texts, "Сохранённые ключи прочитать не удалось") {
		t.Errorf("экран подключения молчит о том, что сохранённые ключи прочитать не удалось: %q", texts)
	}
	if !hasTextContaining(texts, "неизвестно") {
		t.Errorf("не сказано, что наличие сохранённых ключей неизвестно: %q", texts)
	}
}

func hasTextContaining(texts []string, sub string) bool {
	for _, s := range texts {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// saveKeyThroughDialog — НАСТОЯЩИЙ диалог «Сохранить ключ?»: поля
// заполняются, «Сохранить» нажимается, ответ ждётся. Возвращает строку
// состояния главного окна и путь нового файла.
func saveKeyThroughDialog(t *testing.T, dir string) (status, saved string) {
	t.Helper()
	before := map[string]bool{}
	if es, err := os.ReadDir(dir); err == nil {
		for _, e := range es {
			before[e.Name()] = true
		}
	}
	u := focusTestUI(t)
	u.status = widget.NewLabel("")
	u.offerSaveKey("vpn://не-настоящий", "A1б", "")
	over := u.win.Canvas().Overlays().List()
	if len(over) == 0 {
		t.Fatal("диалог сохранения ключа не открылся")
	}
	var entries []*widget.Entry
	var saveBtn *widget.Button
	walkObjects(over[len(over)-1], func(o fyne.CanvasObject) {
		switch w := o.(type) {
		case *widget.Entry:
			entries = append(entries, w)
		case *widget.Button:
			if w.Text == "Сохранить" {
				saveBtn = w
			}
		}
	})
	if len(entries) < 3 || saveBtn == nil {
		t.Fatalf("тест перестал что-либо проверять: в диалоге %d полей, кнопка «Сохранить» найдена: %v",
			len(entries), saveBtn != nil)
	}
	const pin = "a1b-test-pin-2026"
	entries[1].SetText(pin)
	entries[2].SetText(pin)
	test.Tap(saveBtn)
	waitGUIGoroutines(t)
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("каталог хранилищ после сохранения: %v", err)
	}
	for _, e := range es {
		if !before[e.Name()] {
			saved = filepath.Join(dir, e.Name())
		}
	}
	if saved == "" {
		t.Fatalf("тест перестал что-либо проверять: файл не сохранён (статус диалога неизвестен, главный — %q)", u.status.Text)
	}
	t.Cleanup(func() { os.Remove(saved) })
	return u.status.Text, saved
}

// withVaultFiles — каталог хранилищ тестового бинарника с файлами names
// (содержимое не важно: номер «Сервер N» — позиция в списке по имени).
func withVaultFiles(t *testing.T, names ...string) string {
	t.Helper()
	dir := vaultDirForTest(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// shownNumber — под каким «Сервер N» файл path показан на экране
// подключения (savedVaultsBlock нумерует по порядку ListVaults).
func shownNumber(t *testing.T, dir, path string) int {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range es { // os.ReadDir отдаёт имена отсортированными
		if strings.EqualFold(filepath.Ext(e.Name()), ".avlt") && !e.IsDir() {
			n++
			if e.Name() == filepath.Base(path) {
				return n
			}
		}
	}
	t.Fatalf("файла %s нет в списке", path)
	return 0
}

// TestA1bSavedKeyNumberReachesStatus — ТЕСТ ДОЕЗДА: новый файл встаёт
// ПЕРВЫМ в списке (имена «ffffffff», «fffffffe» больше любого случайного), а
// строка состояния на f0febbd называла «Сервер 3» — число файлов, то есть
// чужой сервер.
func TestA1bSavedKeyNumberReachesStatus(t *testing.T) {
	dir := withVaultFiles(t, "fffffffe.avlt", "ffffffff.avlt")
	status, saved := saveKeyThroughDialog(t, dir)
	want := fmt.Sprintf("Ключ сохранён (Сервер %d).", shownNumber(t, dir, saved))
	if status != want {
		t.Errorf("строка состояния %q, ожидалось %q — назван номер, под которым на экране "+
			"подключения виден ДРУГОЙ сервер", status, want)
	}
}

// TestA1bSavedKeyNumberIsPositionNotCount — ТЕСТ РАЗЛИЧЕНИЯ: позиция
// сохранённого файла и число файлов — разные величины; когда новый файл
// встаёт в середину списка, строка обязана назвать позицию.
func TestA1bSavedKeyNumberIsPositionNotCount(t *testing.T) {
	dir := withVaultFiles(t, "00000000.avlt", "ffffffff.avlt")
	status, saved := saveKeyThroughDialog(t, dir)
	pos := shownNumber(t, dir, saved)
	if pos == 3 {
		t.Skip("случайное имя совпало с краем диапазона — различать нечего (вероятность 2⁻³²)")
	}
	if status == "Ключ сохранён (Сервер 3)." {
		t.Errorf("строка состояния называет число файлов (3), а файл виден как «Сервер %d»", pos)
	}
	if want := fmt.Sprintf("Ключ сохранён (Сервер %d).", pos); status != want {
		t.Errorf("строка состояния %q, ожидалось %q", status, want)
	}
}

// countingRunner — fakesrv, считающий запросы `wg show` и отказывающий на
// всех, кроме первых okWgShow.
type countingRunner struct {
	inner    *fakesrv.Server
	mu       sync.Mutex
	wgShow   int
	okWgShow int
}

func (r *countingRunner) Run(cmd string, stdin []byte) (string, error) {
	if strings.Contains(cmd, "wg show wg0 dump") {
		r.mu.Lock()
		r.wgShow++
		n := r.wgShow
		r.mu.Unlock()
		if n > r.okWgShow {
			return "", fmt.Errorf("команда %q: имитированный обрыв связи", cmd)
		}
	}
	return r.inner.Run(cmd, stdin)
}

// cellText — что ячейка (row, col) ПОКАЗЫВАЕТ (настоящий UpdateCell).
func cellText(u *ui, row, col int) string {
	cell := newTableCell()
	u.table.UpdateCell(widget.TableCellID{Row: row, Col: col}, cell)
	return cell.Text
}

// TestA1bActivityAndTrafficFromOneReading — ТЕСТ ДОЕЗДА долга
// «u.handshakes — договорённость, а не тип»: сервер ответил на первый
// `wg show` и оборвал связь на втором. На f0febbd refresh() спрашивал
// дважды (GetHandshakes, затем GetPeerStats), и одна строка таблицы
// утверждала сразу «измерено» (время в «Активности») и «не знаем» («?» в
// «Трафике»). Теперь обе колонки — одно показание.
func TestA1bActivityAndTrafficFromOneReading(t *testing.T) {
	r := &countingRunner{inner: fakesrv.New(), okWgShow: 1}
	sess := core.NewSessionWithRunner(r, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
	c := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Support: core.SupportYes}
	u := refreshedUI(t, sess, c)
	if r.wgShow != 1 {
		t.Errorf("refresh() спросил `wg show` %d раз(а), ожидался один запрос на обе колонки", r.wgShow)
	}
	for row := range u.clients {
		act, traffic := cellText(u, row, 3), cellText(u, row, trafficCol)
		if (act == "?") != (traffic == "?") {
			t.Errorf("строка %d: «Активность» %q и «Трафик» %q — одна строка утверждает и «измерено», "+
				"и «не знаем»: колонки прочитаны из разных ответов сервера", row+1, act, traffic)
		}
	}
}

// TestA1bActivityUnknownWhenStatsFail — ТЕСТ РАЗЛИЧЕНИЯ для той же
// правки на боевом пути: единственный запрос не удался — «Активность» «?»,
// а не «—» (не подключался); сервер ответил — «—» у клиента без
// рукопожатий.
//
// НА f0febbd ОН ПРОХОДИТ, и это честно, а не недосмотр: там это состояние
// уже показывалось верно — долг был в том, что «нет в ответе» держалось
// договорённостью о пустой строке и вторым запросом, а не ложным ответом.
// Падение на f0febbd доказывает TestA1bActivityAndTrafficFromOneReading.
// Этот тест держит НОВЫЙ тип: подмена в guiview.ActivityText «!ok → "—"»
// роняет его (и TestActivityTextThreeStates) — проверено, см. отчёт.
func TestA1bActivityUnknownWhenStatsFail(t *testing.T) {
	c := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Support: core.SupportYes}
	creds := &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"}
	failed := refreshedUI(t, core.NewSessionWithRunner(&countingRunner{inner: fakesrv.New(), okWgShow: 0}, creds), c)
	ok := refreshedUI(t, core.NewSessionWithRunner(fakesrv.New(), creds), c)
	for row := range failed.clients {
		if got := cellText(failed, row, 3); got != "?" {
			t.Errorf("статистика не получена, а «Активность» строки %d — %q, ожидалось «?»", row+1, got)
		}
	}
	for row := range ok.clients {
		if got := cellText(ok, row, 3); got != "—" {
			t.Errorf("сервер ответил «рукопожатий не было», а «Активность» строки %d — %q, ожидалось «—»", row+1, got)
		}
	}
}
