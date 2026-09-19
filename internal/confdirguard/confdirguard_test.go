package confdirguard

// Структурный сторож A4в: имя каталога клиентских конфигов не пишется буквой
// в cmd/.
//
// ЗАЧЕМ. Мест, где «Конфигурации» стояло относительным путём, было два
// (cmd/cli/main.go и cmd/gui/main.go), оба починены: имя осталось ровно в
// одном месте продукта — core/configdir.go, и путь оттуда абсолютный. Но
// «сегодня их нет» — СОСТОЯНИЕ, а не свойство: третье место заведут одной
// строкой os.MkdirAll("Конфигурации", 0700), оно снова окажется относительным,
// и GUI с CLI разъедутся по каталогам. Сторож делает отсутствие свойством.
//
// ЦЕНА ВОПРОСА. Разъехавшиеся места сохранения хуже прежнего единого плохого:
// человек ищет файл там, где его сохранил вчера другой половиной программы.
//
// СТОРОЖ ПРЕДЪЯВЛЯЕТ КАНАРЕЙКУ, и каждую — ОТДЕЛЬНОЙ подменой, реагирующей
// именно на своё (урок A4: трижды канарейка краснела не по заявленной
// причине и потому молчала на настоящей подмене):
//   - TestGuardCatchesPlantedLiteral — заведомый дефект: литерал в cmd/;
//   - «честный файл» — код, берущий каталог из core, красить НЕ должен;
//   - TestGuardCatchesEmptyRoot — пустой корень (сторож смотрит не туда)
//     обязан ронять прогон, а не зеленеть молча.
//
// ЧЕГО СТОРОЖ НЕ ЛОВИТ, поимённо:
//   - ТОЛЬКО cmd/. core/ намеренно вне охвата: именно там имя и обязано
//     лежать (core/configdir.go). internal/ и scripts/ не смотрятся вовсе;
//   - имя, собранное из кусков ("Конфи"+"гурации"), из переменной или из
//     ресурса. Сторож ловит форму, которой пишут на самом деле, — литерал;
//   - относительный путь ДРУГОГО каталога: сторож про имя, а не про
//     относительность вообще;
//   - комментарии и строки в _test.go: они на диск ничего не пишут.
//     Комментарий про «Конфигурации» в cmd/ — законный и краснеть не должен.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// scannedRoot — дерево под охраной. Один корень, и он назван буквой.
var scannedRoot = filepath.Join("..", "..", "cmd")

// minFiles — сколько .go-файлов сторож обязан разобрать в корне. Меньше —
// значит он смотрит не туда (переезд, опечатка в scannedRoot), и это падение,
// а не зелень.
const minFiles = 5

// forbiddenDirLiteral — имя, которого в cmd/ быть не должно. Оно живёт в
// core/configdir.go (clientConfigsDirName) и берётся оттуда функцией
// core.UserConfigsDir.
const forbiddenDirLiteral = "Конфигурации"

type finding struct {
	pos  string
	text string
}

// scanTree разбирает дерево и возвращает находки и число разобранных файлов.
// Ошибку разбора отдаёт наружу: молча пропущенный файл выглядит так же, как
// файл без нарушений.
func scanTree(root string) ([]finding, int, error) {
	fset := token.NewFileSet()
	var out []finding
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		// _test.go не смотрим: тестовые каталоги временные, и подмена пути в
		// тесте — приём, а не нарушение.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		files++
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			if strings.Contains(v, forbiddenDirLiteral) {
				out = append(out, finding{
					pos: fset.Position(lit.Pos()).String(),
					text: "строковый литерал " + lit.Value + " в cmd/: имя каталога конфигов " +
						"пишется буквой только в core/configdir.go, а путь берётся из " +
						"core.UserConfigsDir() — иначе он снова окажется относительным текущему каталогу (A4в)",
				})
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, files, err
	}
	return out, files, nil
}

func TestNoRelativeConfigsDirLiteralInCmd(t *testing.T) {
	found, files, err := scanTree(scannedRoot)
	if err != nil {
		t.Fatalf("обход %s: %v", scannedRoot, err)
	}
	for _, f := range found {
		t.Errorf("%s: %s", f.pos, f.text)
	}
	if files < minFiles {
		t.Fatalf("в %s разобрано всего %d .go-файлов (минимум %d) — сторож смотрит не туда; проверьте scannedRoot", scannedRoot, files, minFiles)
	}
	t.Logf("разобрано файлов: %d", files)
}

// --- канарейки -------------------------------------------------------------

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatalf("каталог для %s: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(src), 0600); err != nil {
			t.Fatalf("подложить %s: %v", name, err)
		}
	}
	return dir
}

const badSrc = `package main

import "os"

func save(cfg string) error { return os.MkdirAll("Конфигурации", 0700) }
`

const goodSrc = `package main

import "amnezia-admin/core"

// Каталог «Конфигурации» выбирается в core — тут только вызов.
func save(name, cfg string) (string, bool, error) {
	dir, err := core.UserConfigsDir()
	if err != nil {
		return "", false, err
	}
	return core.WriteClientConfig(dir, name, cfg)
}
`

// TestGuardCatchesPlantedLiteral — заведомый дефект, на котором сторож обязан
// споткнуться; и рядом честный файл, на котором он обязан молчать. Одной
// половины мало: сторож, красящий всё подряд, прошёл бы первую.
func TestGuardCatchesPlantedLiteral(t *testing.T) {
	t.Run("литерал в cmd/", func(t *testing.T) {
		dir := writeTree(t, map[string]string{"cli/main.go": badSrc})
		found, files, err := scanTree(dir)
		if err != nil {
			t.Fatalf("scanTree: %v", err)
		}
		if files != 1 {
			t.Fatalf("разобрано файлов %d, want 1", files)
		}
		if len(found) == 0 {
			t.Fatal("сторож НЕ споткнулся на os.MkdirAll(\"Конфигурации\", …) — он вечнозелёный")
		}
		// Сверяем НЕ текст находки (он собран из тех же констант, что и сама
		// проверка, — такая сверка тавтологична; замечание SEC-01 по ревью), а
		// МЕСТО: строка и колонка обязаны указывать на подложенный литерал,
		// то есть на строку 5 файла cli/main.go. Сторож, нашедший «что-то
		// где-то», не помог бы найти нарушение.
		if !strings.Contains(found[0].pos, filepath.Join("cli", "main.go")+":5:") {
			t.Fatalf("находка указывает не на подложенный литерал (cli/main.go:5): %s", found[0].pos)
		}
	})

	t.Run("честный файл не краснеет", func(t *testing.T) {
		dir := writeTree(t, map[string]string{
			"cli/main.go": goodSrc,
			// Комментарий с тем же словом — законен и краснеть не должен.
			"gui/aux.go": "package main\n\n// Конфигурации сохраняются в каталог данных пользователя.\nfunc aux() {}\n",
		})
		found, files, err := scanTree(dir)
		if err != nil {
			t.Fatalf("scanTree: %v", err)
		}
		if files != 2 {
			t.Fatalf("разобрано файлов %d, want 2", files)
		}
		if len(found) != 0 {
			var lines []string
			for _, f := range found {
				lines = append(lines, f.pos+": "+f.text)
			}
			t.Fatalf("сторож покраснел на честном коде:\n%s", strings.Join(lines, "\n"))
		}
	})
}

// TestGuardCatchesEmptyRoot — вторая нога канарейки, ОТДЕЛЬНАЯ: сторож,
// разобравший ноль файлов, обязан отличаться от сторожа без находок. Дефект
// здесь другой (не литерал, а пустой корень), и реагировать обязана другая
// проверка — порог minFiles.
func TestGuardCatchesEmptyRoot(t *testing.T) {
	dir := writeTree(t, map[string]string{"readme.txt": "не Go"})
	found, files, err := scanTree(dir)
	if err != nil {
		t.Fatalf("scanTree: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("находки на дереве без Go-файлов: %+v", found)
	}
	if files >= minFiles {
		t.Fatalf("разобрано %d файлов — подложено дерево без Go, ожидалось меньше порога %d", files, minFiles)
	}
	// Именно этот случай TestNoRelativeConfigsDirLiteralInCmd превращает в
	// t.Fatalf: ноль находок при нуле разобранных файлов — не зелень.
}

// TestGuardFailsOnUnparsableInput — неразобранный вход обязан быть ошибкой.
func TestGuardFailsOnUnparsableInput(t *testing.T) {
	dir := writeTree(t, map[string]string{"cli/broken.go": "package main\nfunc ("})
	if _, _, err := scanTree(dir); err == nil {
		t.Fatal("сторож молча проглотил неразбираемый файл")
	}
}

// --- одноразовая подсказка о смене места (ревью UX-01, блокирующее 3) ------
//
// Подсказку обязаны показывать ОБА места записи. Проверка структурная и живёт
// здесь по той же причине, что и сторож guiview: cmd/gui нельзя проверить
// поведенчески без дисплея, а текст подсказки — ровно то, что человек увидит.
// Требуется ИМЕНОВАННАЯ ссылка на core.FirstSaveHint, а не похожий текст,
// набранный заново: два разошедшихся текста одного события — это то, что
// UX-01 и нашёл в паре «Сохранено» / «Конфиг сохранён».

// hintUsers — файлы, обязанные ссылаться на core.FirstSaveHint.
var hintUsers = []string{
	filepath.Join("..", "..", "cmd", "cli", "main.go"),
	filepath.Join("..", "..", "cmd", "gui", "main.go"),
}

// usesFirstSaveHint — есть ли в файле селектор core.FirstSaveHint.
func usesFirstSaveHint(path string) (bool, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return false, err
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "FirstSaveHint" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "core" {
			found = true
		}
		return true
	})
	return found, nil
}

func TestBothWritersShowFirstSaveHint(t *testing.T) {
	for _, path := range hintUsers {
		ok, err := usesFirstSaveHint(path)
		if err != nil {
			t.Fatalf("разбор %s: %v", path, err)
		}
		if !ok {
			t.Errorf("%s не ссылается на core.FirstSaveHint — человек, впервые сохраняющий "+
				"конфиг в новое место, не узнает о переезде (ревью UX-01)", path)
		}
	}
}

// TestHintGuardCatchesPlanted — канарейка ИМЕННО этой проверки: на файле без
// ссылки она обязана сказать «нет», на файле со ссылкой — «да». Реагирует
// своё: это не сканер литералов и не порог minFiles.
func TestHintGuardCatchesPlanted(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"without.go": "package main\n\nfunc save() string { return \"это новое место\" }\n",
		"with.go":    "package main\n\nimport \"amnezia-admin/core\"\n\nfunc save() string { return core.FirstSaveHint }\n",
	})
	if ok, err := usesFirstSaveHint(filepath.Join(dir, "without.go")); err != nil || ok {
		t.Fatalf("проверка засчитала похожий текст за подсказку (ok=%v, err=%v) — она вечнозелёная", ok, err)
	}
	if ok, err := usesFirstSaveHint(filepath.Join(dir, "with.go")); err != nil || !ok {
		t.Fatalf("проверка не увидела настоящую ссылку core.FirstSaveHint (ok=%v, err=%v)", ok, err)
	}
}
