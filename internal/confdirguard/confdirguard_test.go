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
func save(name, cfg string) (string, error) {
	dir, err := core.UserConfigsDir()
	if err != nil {
		return "", err
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
		// Требуется формулировка ИМЕННО этой ветви, иначе канарейка зазеленела
		// бы от находки соседней причины (как трижды вышло в A4).
		if !strings.Contains(found[0].text, "строковый литерал") {
			t.Fatalf("находка не про литерал: %s", found[0].text)
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
