package guiview

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
	"testing"
)

// Сторож A1: карточка удаления в GUI спрашивает сервер ПРИ ОТКРЫТИИ диалога,
// а не читает снимок, и тексты незнания берутся из этого пакета.
//
// ЗАЧЕМ ОН. Главное покраснение нового решения (задание A1, Д3 строка 2б):
// правдоподобнейшая будущая правка — «зачем лишний запрос, данные же есть в
// u.handshakes» — вернула бы ровно тот дефект, ради которого написан весь PR,
// и не уронила бы ни один тест: в cmd/gui нет ни одного исполняемого теста,
// запуск GUI требует дисплея и холодной сборки с cgo. Без сторожа прямой
// вызов держится на честном слове и уйдёт при первой «оптимизации».
//
// ПОЧЕМУ СТОРОЖ ЗДЕСЬ, А НЕ В cmd/gui. Тот же приём и то же место, что у
// сторожа A3а (warnguard_test.go): пакет без Fyne и без cgo разбирает
// cmd/gui/main.go как текст, поэтому проверка идёт в обычном `go test`, а не
// только там, где стоит gcc.
//
// ГРАНИЦЫ, признанные прямо:
//   - он разбирает исходник, а не поведение: что диалог ДЕЙСТВИТЕЛЬНО
//     показывает три разных текста, доказывают тесты DeleteCardActivity плюс
//     живая проверка у владельца;
//   - он не видит вызова, спрятанного в другой метод (u.freshHandshakes()):
//     это цена того, что сверка идёт по телу одной функции, и она названа
//     здесь, а не умолчана;
//   - он не доказывает, что кнопка действительно недоступна на экране, —
//     только что Disable() написан до запроса, а Enable() внутри ответа;
//   - он сверяет КОД, а не комментарии: разбор печатается из AST (go/printer),
//     поэтому слово «u.handshakes» в пояснении рядом с правкой его не
//     краснит. Иначе сторож требовал бы молчать о том, что чинит, — и был бы
//     ослаблен первой же правкой комментария.

// deleteHandlerName — обработчик, собирающий карточку перед необратимым
// удалением.
const deleteHandlerName = "deleteSelected"

// guiBody возвращает исходный текст тела метода cmd/gui/main.go. Не найден
// метод — тест падает словами «перестал что-либо проверять»: молчаливо
// зелёный сторож хуже отсутствующего.
func guiBody(t *testing.T, name string) string {
	t.Helper()
	_, file, fset := readGUIMain(t)
	var body string
	found := false
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name.Name != name {
			continue
		}
		var b strings.Builder
		if err := printer.Fprint(&b, fset, fn.Body); err != nil {
			t.Fatalf("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: тело %s не печатается: %v", name, err)
		}
		body, found = b.String(), true
	}
	if !found {
		t.Fatalf("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: в %s нет метода %s — "+
			"либо его переименовали, либо карточку удаления собирают где-то ещё; "+
			"таблицу ожиданий надо приводить в соответствие, а не удалять", guiMainPath, name)
	}
	return body
}

// TestDeleteCardAsksServerOnOpen — карточка удаления строится ПРЯМЫМ вызовом
// GetHandshakes и не читает снимок u.handshakes.
func TestDeleteCardAsksServerOnOpen(t *testing.T) {
	body := guiBody(t, deleteHandlerName)

	if !strings.Contains(body, "u.sess.GetHandshakes(") {
		t.Errorf("%s: карточка удаления НЕ спрашивает сервер при открытии диалога — "+
			"нет вызова u.sess.GetHandshakes. Решение принимается перед необратимым действием, "+
			"и данные для него берутся свежими, а не из снимка неизвестной давности (A1, Г4)",
			deleteHandlerName)
	}
	if strings.Contains(body, "u.handshakes") {
		t.Errorf("%s: карточка удаления снова читает снимок u.handshakes. "+
			"При ошибке чтения refresh() выходит рано и оставляет снимок старым, "+
			"а Plan* перечитывает существование клиента, а не его активность: "+
			"клиент, подключившийся после последнего успешного чтения, будет удалён "+
			"под словами «Подключений не было»", deleteHandlerName)
	}
	if !strings.Contains(body, "guiview.DeleteCardActivity(") {
		t.Errorf("%s: текст активности собирается не через guiview.DeleteCardActivity — "+
			"значит три состояния снова описаны строками в cmd/gui, где их не проверяет ни один тест",
			deleteHandlerName)
	}
}

// TestDeleteCardPassesServerError — ОШИБКА ЗАПРОСА ДОЕЗЖАЕТ ДО КАРТОЧКИ.
// Без этой проверки обход стоит одной клавиши и выглядит безобидно: прямой
// вызов на месте, DeleteCardActivity вызвана, а третьим аргументом передан
// nil — и отказ сервера снова печатается как «Подключений не было». Сверка
// идёт по AST: третий аргумент обязан быть ровно тем именем, которому
// присвоена ошибка вызова GetHandshakes в этой же функции.
func TestDeleteCardPassesServerError(t *testing.T) {
	_, file, _ := readGUIMain(t)

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		d, ok := decl.(*ast.FuncDecl)
		if ok && d.Body != nil && d.Name.Name == deleteHandlerName {
			fn = d
		}
	}
	if fn == nil {
		t.Fatalf("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: в %s нет метода %s", guiMainPath, deleteHandlerName)
	}

	// Имя, которому присвоена ошибка вызова GetHandshakes.
	errName := ""
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 || len(as.Lhs) != 2 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "GetHandshakes" {
			return true
		}
		if id, ok := as.Lhs[1].(*ast.Ident); ok {
			errName = id.Name
		}
		return true
	})
	if errName == "" || errName == "_" {
		t.Fatalf("%s: ошибка вызова GetHandshakes не сохраняется (получатель %q) — "+
			"отказ сервера отброшен в самом месте, ради которого написан PR", deleteHandlerName, errName)
	}

	// И она же передана третьим аргументом в DeleteCardActivity.
	passed := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "DeleteCardActivity" || len(call.Args) != 3 {
			return true
		}
		if id, ok := call.Args[2].(*ast.Ident); ok && id.Name == errName {
			passed = true
		}
		return true
	})
	if !passed {
		t.Errorf("%s: в guiview.DeleteCardActivity передана не ошибка запроса (ожидалось %q третьим "+
			"аргументом) — прямой вызов есть, но отказ сервера снова печатается как «Подключений не было»: "+
			"третье состояние, сведённое к «нет»", deleteHandlerName, errName)
	}
}

// TestDeleteConfirmDisabledUntilAnswer — кнопка подтверждения недоступна,
// пока не пришёл ответ сервера. Иначе появляется окно, где подтвердить можно
// раньше ответа, — то же «уверенно при отсутствии данных», только в другом
// месте.
func TestDeleteConfirmDisabledUntilAnswer(t *testing.T) {
	body := guiBody(t, deleteHandlerName)

	iDisable := strings.Index(body, "okBtn.Disable()")
	iCall := strings.Index(body, "u.sess.GetHandshakes(")
	iEnable := strings.Index(body, "okBtn.Enable()")

	if iDisable < 0 {
		t.Fatalf("%s: нет okBtn.Disable() — кнопку «Удалить» можно нажать до ответа сервера", deleteHandlerName)
	}
	if iEnable < 0 {
		t.Fatalf("%s: нет okBtn.Enable() — кнопка не включится никогда ни при каком ответе", deleteHandlerName)
	}
	if iCall < 0 {
		t.Fatalf("%s: нет вызова u.sess.GetHandshakes — проверять порядок не с чем", deleteHandlerName)
	}
	if !(iDisable < iCall && iCall < iEnable) {
		t.Errorf("%s: порядок Disable → запрос → Enable нарушен (Disable@%d, запрос@%d, Enable@%d)",
			deleteHandlerName, iDisable, iCall, iEnable)
	}
	if !strings.Contains(body, "fyne.Do(") {
		t.Errorf("%s: ответ применяется не через fyne.Do — работа с виджетами не из потока GUI", deleteHandlerName)
	}
}

// TestTrafficCellUsesGuiview — ячейка трафика собирается функцией этого
// пакета, а не строкой в cmd/gui: иначе «0 B / 0 B» при недоступной
// статистике вернётся туда, где его не проверяет ни один тест.
func TestTrafficCellUsesGuiview(t *testing.T) {
	raw, _, _ := readGUIMain(t)
	// Разбор БЕЗ parser.ParseComments: печать *ast.File выводит и список
	// комментариев файла, а сторож сверяет код.
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, guiMainPath, raw, 0)
	if err != nil {
		t.Fatalf("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: %s не разбирается: %v", guiMainPath, err)
	}
	var b strings.Builder
	if err := printer.Fprint(&b, fset, file); err != nil {
		t.Fatalf("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: %s не печатается: %v", guiMainPath, err)
	}
	text := b.String()

	if !strings.Contains(text, "guiview.TrafficText(") {
		t.Errorf("%s: ячейка трафика собирается не через guiview.TrafficText", guiMainPath)
	}
	if strings.Contains(text, "HumanBytes(") {
		t.Errorf("%s: core.HumanBytes снова вызывается прямо в cmd/gui — "+
			"числа печатаются мимо проверки «получена ли статистика», и недоступная статистика "+
			"снова выглядит измеренным нулём", guiMainPath)
	}
	if strings.Contains(text, "statErr == nil") {
		t.Errorf("%s: вернулось отбрасывание ошибки статистики (if … statErr == nil) — "+
			"ветви на ошибку снова нет", guiMainPath)
	}
}
