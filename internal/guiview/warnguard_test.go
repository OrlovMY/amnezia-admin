package guiview

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Сторож против возврата текста предупреждения в cmd/gui и против потери
// вызова в одном из обработчиков (задание A3а, Г5).
//
// ЗАЧЕМ. Требование "в cmd/gui не остаётся ни одного литерала текста
// предупреждения" без сторожа — пожелание: через месяц кто-нибудь допишет
// строку прямо в диалоге, и это никто не заметит, потому что в cmd/gui нет
// ни одного теста и запуск GUI требует дисплея. Отдельно — "хотя бы один
// вызов" НЕ отличает шесть от одного: предупреждение, подключённое к удалению
// и забытое у перевыпуска, прошло бы зелёным, а увидеть это можно только на
// живом GUI.
//
// ГРАНИЦЫ СТОРОЖА, признанные прямо, а не замалчиваемые:
//   - он не видит текста, собранного из частей ("Сейчас будет " + "изменение
//     на сервере") или вынесенного в константу с другим именем в cmd/gui;
//   - он не видит текста, пришедшего из внешнего файла или ресурса;
//   - он доказывает, что вызов НАПИСАН в каждом обработчике, и не доказывает,
//     что диалог СРАБАТЫВАЕТ: это проверка на живом экране, у владельца;
//   - он разбирает исходник, а не поведение: обработчик, который вызывает
//     предупреждение и игнорирует его ответ, для сторожа неотличим от
//     правильного. Это читает человек в ревью диффа.
//
// Приём тот же, что в A5: перечисляем ДОПУСТИМОЕ — текст живёт в одном месте,
// вызов обязан быть в шести названных обработчиках, — а не описываем способы
// обойти. Завышенное достижение опаснее скромного.

// guiMainPath — путь к разбираемому файлу от каталога пакета.
const guiMainPath = "../../cmd/gui/main.go"

// warnHelperName — имя метода cmd/gui, который показывает предупреждение.
// Единственная точка, где cmd/gui обращается к этому предмету guiview.
const warnHelperName = "confirmRaceWarning"

// guiHandlers — таблица ожиданий: обработчик необратимой операции → константа
// вида операции, с которой он обязан звать предупреждение. Проверяется и
// наличие вызова, и то, ЧЕМ он позван: скопированный обработчик с чужой
// константой ловится этой же строкой.
var guiHandlers = []struct {
	fn string // имя метода в cmd/gui/main.go
	op string // ожидаемая константа guiview.Op в его теле
	// name — как операция называется человеку в сообщении об ошибке
	name string
}{
	{"addDialog", "guiview.OpAddUser", "создание"},
	{"renameSelected", "guiview.OpRenameUser", "переименование"},
	{"toggleSelected", "guiview.OpToggleUser", "включение/выключение"},
	{"regenerateSelected", "guiview.OpRekeyUser", "перевыпуск конфига"},
	{"deleteSelected", "guiview.OpDeleteUser", "удаление"},
	// Шестая строка — не шестая операция, а шестая ТОЧКА ЗАПИСИ: окно
	// "Изменения перед применением" общее для всех пяти операций, и кнопка
	// "Применить" в нём пишет на сервер через sess.Apply. Сторож обязан
	// отличать шесть от пяти: без этой строки путь "сначала посмотреть, что
	// изменится, потом применить" — путь самого осторожного человека —
	// остался бы без предупреждения при зелёном стороже.
	{"showDiffWindow", "guiview.OpApplyPlan", "применение подготовленного плана из окна изменений"},
}

// warnTextAnchors — фрагменты текста предупреждения (Г1). Появление любого из
// них в cmd/gui/main.go означает, что текст вернулся туда, где его не видит
// ни один тест.
var warnTextAnchors = []string{
	"Сейчас будет изменение на сервере",
	"с этим сервером работает другая программа или другое окно",
	"будут потеряны молча",
	"«готово» увидят оба",
	"Работайте с сервером из одного места за раз",
}

// readGUIMain читает и разбирает cmd/gui/main.go. Неразобранный вход роняет
// тест словами "перестал что-либо проверять": не найден файл или не разобран
// — значит сверять стало не с чем, и молчаливо зелёный сторож хуже, чем
// отсутствующий.
func readGUIMain(t *testing.T) (raw []byte, file *ast.File, fset *token.FileSet) {
	t.Helper()
	raw, err := os.ReadFile(guiMainPath)
	if err != nil {
		t.Fatalf("сторож Г5 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: не удалось прочитать %s: %v", guiMainPath, err)
	}
	fset = token.NewFileSet()
	file, err = parser.ParseFile(fset, guiMainPath, raw, parser.ParseComments)
	if err != nil {
		t.Fatalf("сторож Г5 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: %s не разбирается как Go: %v", guiMainPath, err)
	}
	return raw, file, fset
}

// TestGUIHasNoWarningLiterals — пункт 1 Г5: литералов текста предупреждения в
// cmd/gui/main.go нет. С именем файла и номером строки, чтобы правку было
// куда нести.
func TestGUIHasNoWarningLiterals(t *testing.T) {
	raw, _, _ := readGUIMain(t)
	lines := strings.Split(string(raw), "\n")
	found := false
	for i, line := range lines {
		for _, anchor := range warnTextAnchors {
			if strings.Contains(line, anchor) {
				found = true
				t.Errorf("%s:%d: литерал текста предупреждения вернулся в cmd/gui — фрагмент %q.\n"+
					"Текст живёт в internal/guiview (WarningText), потому что в cmd/gui нет ни одного теста "+
					"и запуск GUI требует дисплея: литерал здесь — строка, которую не видит ни один тест.",
					guiMainPath, i+1, anchor)
			}
		}
	}
	if found {
		t.Log("починка: убрать литерал, показывать guiview.WarningText()")
	}
}

// TestGUICallsWarningInEveryHandler — пункты 2 и 3 Г5: вызов предупреждения
// присутствует в КАЖДОЙ из шести точек записи (пять обработчиков операций и
// общее окно "Изменения перед применением"), и вход
// разобран. Обработчик из таблицы без вызова роняет тест С ИМЕНЕМ ОПЕРАЦИИ.
func TestGUICallsWarningInEveryHandler(t *testing.T) {
	raw, file, fset := readGUIMain(t)

	// bodies — исходный текст тела каждого метода верхнего уровня.
	bodies := map[string]string{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		start := fset.Position(fn.Body.Pos()).Offset
		end := fset.Position(fn.Body.End()).Offset
		if start < 0 || end > len(raw) || start >= end {
			continue
		}
		bodies[fn.Name.Name] = string(raw[start:end])
	}

	// Пункт 3: ни одного из шести обработчиков не нашли — структура файла
	// изменилась, и сверять стало не с чем.
	seen := 0
	for _, h := range guiHandlers {
		if _, ok := bodies[h.fn]; ok {
			seen++
		}
	}
	if seen == 0 {
		t.Fatalf("сторож Г5 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: в %s не найден НИ ОДИН из шести обработчиков %v — "+
			"структура файла изменилась, таблицу ожиданий надо приводить в соответствие, а не удалять",
			guiMainPath, handlerNames())
	}

	// Помощник, показывающий предупреждение, обязан существовать и обязан
	// спрашивать у guiview, а не решать сам.
	helper, ok := bodies[warnHelperName]
	if !ok {
		t.Fatalf("сторож Г5 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: в %s нет метода %s — "+
			"предупреждение показывать нечем", guiMainPath, warnHelperName)
	}
	// WarningTitle и WarningBody, а не WarningText: заголовок диалога и его
	// тело — разные виджеты Fyne, одной строкой их не показать. Что эти две
	// части в сумме и есть эталонный текст, доказывает TestWarningTextGolden
	// (сравнение склейки), поэтому проверка "текст пришёл из guiview целиком"
	// остаётся полной.
	for _, need := range []string{"guiview.WarnDecision", "guiview.WarningTitle", "guiview.WarningBody", "guiview.AfterWarned"} {
		if !strings.Contains(helper, need) {
			t.Errorf("%s не вызывает %s — решение о показе или текст взялись не из guiview", warnHelperName, need)
		}
	}

	// Пункт 2: вызов в каждом обработчике, поимённо.
	for _, h := range guiHandlers {
		body, ok := bodies[h.fn]
		if !ok {
			t.Errorf("у операции %s нет вызова предупреждения — обработчик %s не найден в %s: "+
				"либо его переименовали, либо операцию переписали так, что сторож её не видит",
				h.name, h.fn, guiMainPath)
			continue
		}
		if !strings.Contains(body, warnHelperName+"(") {
			t.Errorf("у операции %s нет вызова предупреждения — либо его убрали, либо переписали так, "+
				"что сторож его не видит (ожидался вызов %s в обработчике %s)",
				h.name, warnHelperName, h.fn)
			continue
		}
		if !strings.Contains(body, h.op) {
			t.Errorf("у операции %s предупреждение вызвано, но не с %s — обработчик сообщает guiview чужой вид операции "+
				"(обработчик %s)", h.name, h.op, h.fn)
		}
	}
}

func handlerNames() []string {
	names := make([]string, 0, len(guiHandlers))
	for _, h := range guiHandlers {
		names = append(names, h.fn)
	}
	return names
}
