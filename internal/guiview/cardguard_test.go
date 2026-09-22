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
//   - он не доказывает, что кнопка действительно недоступна НА ЭКРАНЕ, —
//     только что Disable() стоит отдельным оператором в теле обработчика, а
//     Enable() лежит внутри узла fyne.Do внутри goSafe. Это проверка
//     управления потоком по AST, а не порядка подстрок: прежняя редакция
//     сверяла смещения (iDisable < iCall < iEnable) и пропускала подмену
//     «поднять Enable из замыкания» (найдено ревью BE-01);
//   - «включается по ответу» означает «где-то в поддереве обработчика
//     ответа», а не «на всех его путях»: подмена `if hsErr == nil {
//     okBtn.Enable(); diffBtn.Enable() }` сторожа проходит (найдено ревью
//     BE-01). Сегодняшний код включает кнопки безусловно, но при такой
//     правке при отказе сервера обе кнопки остались бы мёртвыми навсегда,
//     и человеку осталась бы «Отмена». Закрыть это значило бы разбирать
//     все пути исполнения замыкания — то есть строить в стороже мини-CFG;
//     цена названа здесь, а выбор оставлен ядру;
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

	// Имена, которым присвоены карта и ошибка вызова GetHandshakes.
	mapName, errName := "", ""
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
		if id, ok := as.Lhs[0].(*ast.Ident); ok {
			mapName = id.Name
		}
		if id, ok := as.Lhs[1].(*ast.Ident); ok {
			errName = id.Name
		}
		return true
	})
	if mapName == "" || mapName == "_" {
		t.Fatalf("%s: результат GetHandshakes не сохраняется (получатель %q) — спрашивать сервер "+
			"и выбрасывать ответ хуже, чем не спрашивать", deleteHandlerName, mapName)
	}
	if errName == "" || errName == "_" {
		t.Fatalf("%s: ошибка вызова GetHandshakes не сохраняется (получатель %q) — "+
			"отказ сервера отброшен в самом месте, ради которого написан PR", deleteHandlerName, errName)
	}

	// И ОБА результата вызова переданы в DeleteCardActivity: карта первым
	// аргументом, ошибка третьим. Одной ошибки мало: карту можно было бы
	// взять любую другую (например, чужой снимок), и карточка печатала бы
	// свежесть, которой нет.
	passedMap, passedErr := false, false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "DeleteCardActivity" || len(call.Args) != 3 {
			return true
		}
		if id, ok := call.Args[0].(*ast.Ident); ok && id.Name == mapName {
			passedMap = true
		}
		if id, ok := call.Args[2].(*ast.Ident); ok && id.Name == errName {
			passedErr = true
		}
		return true
	})
	if !passedMap {
		t.Errorf("%s: в guiview.DeleteCardActivity передана не та карта, что вернул запрос "+
			"(ожидалось %q первым аргументом) — данные в карточке снова неизвестной свежести",
			deleteHandlerName, mapName)
	}
	if !passedErr {
		t.Errorf("%s: в guiview.DeleteCardActivity передана не ошибка запроса (ожидалось %q третьим "+
			"аргументом) — прямой вызов есть, но отказ сервера снова печатается как «Подключений не было»: "+
			"третье состояние, сведённое к «нет»", deleteHandlerName, errName)
	}
}

// deleteBlockedButtons — кнопки диалога удаления, каждая из которых ведёт к
// НЕОБРАТИМОМУ действию и потому обязана быть недоступна, пока не пришёл
// ответ сервера об активности.
//
// ПОЧЕМУ ИХ ДВЕ, А НЕ ОДНА (ревью BE-01, найдено чтением на этой ветке).
// Прежняя редакция блокировала только okBtn, и это была проверка формы: за
// diffBtn стоят PlanDelete → окно изменений → «Применить» → sess.Apply, то
// есть удаление завершается ЦЕЛИКОМ, пока метка ещё говорит «Узнаю,
// подключался ли клиент...». Это та же ШЕСТАЯ ТОЧКА ЗАПИСИ, которую нашёл
// и закрыл A3а, — путь самого осторожного человека. Новая кнопка в этом
// диалоге вносится сюда видимой строкой диффа.
var deleteBlockedButtons = []struct {
	varName string
	human   string
}{
	{"okBtn", "«Удалить»"},
	{"diffBtn", "«Показать изменения» (за ней PlanDelete → окно изменений → «Применить» → sess.Apply)"},
}

// dotted разворачивает a.b.c в "a.b.c"; пусто, если основание — не
// идентификатор (вызов, литерал).
func dotted(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		if base := dotted(x.X); base != "" {
			return base + "." + x.Sel.Name
		}
	}
	return ""
}

// callsIn собирает полные имена вызовов (u.sess.GetHandshakes, fyne.Do,
// okBtn.Enable) в поддереве.
func callsIn(n ast.Node) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(n, func(x ast.Node) bool {
		if call, ok := x.(*ast.CallExpr); ok {
			if name := dotted(call.Fun); name != "" {
				out[name] = true
			}
		}
		return true
	})
	return out
}

// deleteResponseHandler — тело fyne.Do внутри goSafe внутри deleteSelected,
// то есть код, исполняемый ПО ОТВЕТУ сервера на запрос активности.
// Возвращает nil, если такого узла нет.
func deleteResponseHandler(t *testing.T) *ast.FuncLit {
	t.Helper()
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

	var found *ast.FuncLit
	// Ищем goSafe(func(){ … GetHandshakes … fyne.Do(func(){ ←ЭТО }) })
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != "goSafe" {
			return true
		}
		outer, ok := call.Args[0].(*ast.FuncLit)
		if !ok || !callsIn(outer)["u.sess.GetHandshakes"] {
			return true
		}
		ast.Inspect(outer.Body, func(m ast.Node) bool {
			inner, ok := m.(*ast.CallExpr)
			if !ok || len(inner.Args) != 1 {
				return true
			}
			sel, ok := inner.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Do" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "fyne" {
				return true
			}
			if lit, ok := inner.Args[0].(*ast.FuncLit); ok {
				found = lit
			}
			return true
		})
		return true
	})
	return found
}

// directCalls — вызовы, стоящие ОТДЕЛЬНЫМИ ОПЕРАТОРАМИ прямо в теле
// deleteSelected, без вложения в if/for/замыкание. Именно они исполняются
// безусловно при открытии диалога.
func directCalls(t *testing.T) []string {
	t.Helper()
	_, file, _ := readGUIMain(t)
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || fn.Name.Name != deleteHandlerName {
			continue
		}
		for _, st := range fn.Body.List {
			es, ok := st.(*ast.ExprStmt)
			if !ok {
				continue
			}
			if call, ok := es.X.(*ast.CallExpr); ok {
				if name := dotted(call.Fun); name != "" {
					out = append(out, name)
				}
			}
		}
	}
	return out
}

// TestDeleteButtonsDisabledUntilAnswer — ВСЕ кнопки, ведущие к необратимому
// действию, недоступны, пока не пришёл ответ, и включаются РОВНО в
// обработчике ответа.
//
// ЧЕМ ЭТА РЕДАКЦИЯ ОТЛИЧАЕТСЯ ОТ ПРЕЖНЕЙ (ревью BE-01). Прежняя сверяла
// смещения подстрок: iDisable < iCall < iEnable. Порядка в исходнике мало —
// управления потоком он не выражает: подмена «поднять okBtn.Enable() из
// замыкания наверх, сразу после запроса» сохраняла порядок смещений,
// проходила ЗЕЛЁНОЙ и делала кнопку доступной немедленно. Теперь Enable
// ищется ВНУТРИ узла fyne.Do внутри goSafe — по AST, а не по тексту.
func TestDeleteButtonsDisabledUntilAnswer(t *testing.T) {
	resp := deleteResponseHandler(t)
	if resp == nil {
		t.Fatalf("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: в %s не найден обработчик ответа "+
			"(fyne.Do внутри goSafe с вызовом u.sess.GetHandshakes) — сверять «включается по ответу» не с чем",
			deleteHandlerName)
	}
	inResponse := callsIn(resp.Body)

	// Disable ищется среди ОПЕРАТОРОВ ВЕРХНЕГО УРОВНЯ тела обработчика, а не
	// поиском подстроки: `if false { okBtn.Disable() }` и Disable внутри
	// чужого замыкания удовлетворяли бы подстроке, не блокируя ничего.
	onOpen := map[string]bool{}
	for _, st := range directCalls(t) {
		onOpen[st] = true
	}

	for _, b := range deleteBlockedButtons {
		if !onOpen[b.varName+".Disable"] {
			t.Errorf("%s: кнопка %s не блокируется на время запроса — необратимое действие можно "+
				"завершить раньше, чем пришёл ответ об активности клиента", deleteHandlerName, b.human)
		}
		if !inResponse[b.varName+".Enable"] {
			t.Errorf("%s: кнопка %s включается НЕ в обработчике ответа сервера (fyne.Do внутри goSafe) — "+
				"блокировка на время запроса существует только на бумаге", deleteHandlerName, b.human)
		}
	}
}

// TestDeleteResponseSetsActivityText — в том же обработчике ответа
// выставляется текст активности. Иначе «включается по ответу» могло бы
// означать «включается по какому-нибудь ответу».
func TestDeleteResponseSetsActivityText(t *testing.T) {
	resp := deleteResponseHandler(t)
	if resp == nil {
		t.Fatal("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: обработчик ответа не найден")
	}
	got := false
	ast.Inspect(resp.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "DeleteCardActivity" {
			got = true
		}
		return true
	})
	if !got {
		t.Errorf("%s: текст активности выставляется не в обработчике ответа — метка и кнопки "+
			"рассинхронизированы", deleteHandlerName)
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

	// GUI-КОПИРОВАНИЕ: с этой ревизии cmd/gui не зовёт ActivityText и
	// TrafficText напрямую — текст ЛЮБОЙ ячейки собирает guiview.CellText,
	// которая зовёт их внутри. Это не ослабление сторожа, а перенос точки
	// сверки: именно из CellText берётся и то, что видно, и то, что
	// копируется в буфер, — разъехаться они не могут.
	if !strings.Contains(text, "guiview.CellText(") {
		t.Errorf("%s: текст ячеек таблицы собирается не через guiview.CellText — "+
			"ветка «запрос не удался» снова описана строкой в cmd/gui, где её не проверяет "+
			"ни один тест без дисплея, и «что видно» разъезжается с «что копируется»", guiMainPath)
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

// rowFieldSource — ПОЛЯ guiview.Row, собираемого в cmd/gui.rowFor, и
// выражения, из которых они обязаны браться. Перечень поимённый: строка
// «ActivityFailed: false» — обход стоимостью одной клавиши, после которого
// отказ сервера снова печатается и КОПИРУЕТСЯ как измеренная величина.
var rowFieldSource = map[string]string{
	"Num":     "row + 1",
	"Name":    "cl.Name()",
	"Created": "cl.Created()",
	// Disabled найдено ревью QA-01: без него подмена `Disabled: false`
	// оставляла оба пакета зелёными, а на экране у отключённого клиента в
	// «Активности» показалось бы и скопировалось рукопожатие, и имя
	// перестало бы быть курсивом.
	"Disabled":       "cl.Disabled()",
	"CanManage":      "u.canManage",
	"ActivityFailed": "u.activityFailed",
	"StatsFailed":    "u.statsFailed",
	"Handshake":      "u.handshakes[cl.ClientID]",
	"Stats":          "u.peerStats[cl.ClientID]",
	"ClientID":       "cl.ClientID",
}

// TestCellsReceiveTheFailureFlag — ПРИЗНАК ДОЕЗЖАЕТ ДО ЯЧЕЙКИ И ДО БУФЕРА.
//
// ЧЕГО НЕ ХВАТАЛО ПРЕЖНЕЙ РЕДАКЦИИ (ревью BE-01). Она проверяла только
// ПРИСУТСТВИЕ вызова guiview.TrafficText — то есть форму. Обход стоил одной
// клавиши и выглядел как упрощение: `guiview.TrafficText(u.canManage,
// false, …)` — вызов на месте, тесты guiview зелёные, а на экране снова
// «0 B / 0 B» при недоступной статистике.
//
// ЧТО ИЗМЕНИЛОСЬ (GUI-КОПИРОВАНИЕ). Признаки теперь едут в ячейку не
// аргументами, а полями guiview.Row, который собирает cmd/gui.rowFor, —
// и из того же Row берётся текст для буфера обмена. Поэтому сверка
// перенесена на составной литерал: каждое поле перечня обязано браться из
// названного выражения, а не из константы.
func TestCellsReceiveTheFailureFlag(t *testing.T) {
	raw, _, _ := readGUIMain(t)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, guiMainPath, raw, 0)
	if err != nil {
		t.Fatalf("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: %s не разбирается: %v", guiMainPath, err)
	}

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		d, ok := decl.(*ast.FuncDecl)
		if ok && d.Body != nil && d.Name.Name == "rowFor" {
			fn = d
		}
	}
	if fn == nil {
		t.Fatalf("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: в %s нет метода rowFor — "+
			"данные строки превращают в видимое и копируемое где-то ещё; перечень надо "+
			"приводить в соответствие, а не удалять", guiMainPath)
	}

	got := map[string]string{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || dotted(lit.Type) != "guiview.Row" {
			return true
		}
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			var b strings.Builder
			if err := printer.Fprint(&b, fset, kv.Value); err != nil {
				t.Fatalf("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: значение поля не печатается: %v", err)
			}
			got[key.Name] = b.String()
		}
		return true
	})
	if len(got) == 0 {
		t.Fatalf("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: в rowFor нет составного литерала guiview.Row " +
			"с именованными полями — сверять нечего")
	}
	for field, want := range rowFieldSource {
		switch have, ok := got[field]; {
		case !ok:
			t.Errorf("rowFor: поле guiview.Row.%s не заполняется (ожидалось %q) — "+
				"в ячейку и в буфер уедет нулевое значение вместо данных сервера", field, want)
		case have != want:
			t.Errorf("rowFor: поле guiview.Row.%s берётся из %q вместо %q — признак «узнать не удалось» "+
				"до ячейки не доезжает, и отказ сервера снова печатается и копируется как измеренная величина",
				field, have, want)
		}
	}
}

// TestCellTextComesFromRowFor — ДОЕЗД ДО МЕСТА ПЕЧАТИ: текст ячейки строится
// из того самого Row, который вернул rowFor, а не из отдельно собранного
// литерала рядом. Без этой проверки rowFor мог бы остаться безупречным и
// никем не используемым.
func TestCellTextComesFromRowFor(t *testing.T) {
	body := guiBody(t, "buildTable")
	if !strings.Contains(body, "u.rowFor(id.Row)") {
		t.Errorf("buildTable: ячейка строится не из u.rowFor(id.Row) — данные для показа " +
			"собирают вторым способом, и он разойдётся с копированием")
	}
	if !strings.Contains(body, "guiview.CellText(r, id.Col)") {
		t.Errorf("buildTable: нет вызова guiview.CellText(r, id.Col) — текст ячейки берётся " +
			"не из общего с буфером обмена места")
	}
}

// TestRefreshFeedsTheFailureFlags — и сами признаки берутся из ошибок
// запросов, а не выставляются константой. Без этого ячейка честно получала
// бы поле, в которое никто не пишет.
func TestRefreshFeedsTheFailureFlags(t *testing.T) {
	body := guiBody(t, "refresh")
	for _, want := range []string{
		"u.activityFailed = hsErr != nil",
		"u.statsFailed = statsErr != nil",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("refresh(): нет присваивания %q — признак «не удалось» ниоткуда не берётся, "+
				"и ячейка получает вечное false", want)
		}
	}
}

// TestRefreshRecomputesKeyColumnWidth — СТРУКТУРНЫЙ сторож пересчёта ширины
// колонки ключа при смене состава таблицы.
//
// ПОЧЕМУ СТОРОЖ, А НЕ ПОВЕДЕНЧЕСКИЙ ТЕСТ. Сам пересчёт (keyColumnWidth) и его
// доезд до таблицы проверены поведенчески в cmd/gui без дисплея. Но ВЫЗОВ из
// refresh() поведенчески не достать: refresh() ходит на сервер по SSH, а
// тесты к серверам не подключаются. Граница признана прямо: сторож
// утверждает, что вызов стоит в теле refresh(), и не утверждает, что он
// исполняется на всех её путях.
//
// ЗАЧЕМ. Без него удаление одной строки из refresh() не роняет ничего:
// ширина колонки останется от первого состава таблицы, и у клиента с более
// широким ключом подсветка снова обрежет ключ — ровно та жалоба, ради
// которой всё это сделано.
func TestRefreshRecomputesKeyColumnWidth(t *testing.T) {
	body := guiBody(t, "refresh")
	if !strings.Contains(body, "u.applyKeyColumnWidth()") {
		t.Errorf("refresh(): нет вызова u.applyKeyColumnWidth() — состав таблицы меняется, " +
			"а ширина колонки ключа остаётся от прежнего списка; у клиента с более широким " +
			"ключом подсветка снова обрежет ключ")
	}
}

// ---------- сторож самой починки гонки (ревью BE-01, пятое замечание) ----------
//
// ЗАЧЕМ ОН. Четыре починки этого PR получили сторожа, пятая — снимок
// контейнера — держалась на честном слове: обе подмены («снять сверку
// снимка», «спрашивать по u.cur вместо cur») проходили зелёными. По
// собственному доводу PR правка без сторожа устаревает с первым коммитом,
// и исключений для неё нет.
//
// ЧТО ОН УТВЕРЖДАЕТ: всё, что уходит в goroutine из диалога удаления,
// берёт СНИМОК cur, а ответ сверяется с текущим u.cur до того, как
// попадёт на экран.

// deleteSnapshotCalls — вызовы сервера из диалога удаления, каждый из
// которых обязан получать контейнер снимком. Перечень поимённый: новый
// вызов роняет TestDeleteDialogCallsUseSnapshot и вносится сюда видимой
// строкой диффа.
//
// Перечень ВЫВЕДЕН РАЗБОРОМ (а не по памяти): все вызовы u.sess.* в теле
// deleteSelected, у которых первый аргумент — контейнер. Их три:
// GetHandshakes (карточка), PlanDelete (предпросмотр) и DeleteByID (запись
// на сервер). Третий был пропущен первой редакцией правки, и пропущен
// оказался ровно необратимый.
var deleteSnapshotCalls = []string{
	"u.sess.GetHandshakes",
	"u.sess.PlanDelete",
	"u.sess.DeleteByID",
}

// TestDeleteDialogCallsUseSnapshot — первый аргумент каждого серверного
// вызова диалога — идентификатор cur (снимок), а не селектор u.cur,
// прочитанный из другого потока.
func TestDeleteDialogCallsUseSnapshot(t *testing.T) {
	_, file, fset := readGUIMain(t)

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

	// Снимок обязан существовать и быть взят из u.cur.
	snapshot := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		if id, ok := as.Lhs[0].(*ast.Ident); !ok || id.Name != "cur" {
			return true
		}
		if dotted(as.Rhs[0]) == "u.cur" {
			snapshot = true
		}
		return true
	})
	if !snapshot {
		t.Fatalf("%s: нет снимка `cur := u.cur` — всё, что уходит в goroutine, читает поле, "+
			"которое может смениться под ним", deleteHandlerName)
	}

	seen := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		name := dotted(call.Fun)
		guarded := false
		for _, want := range deleteSnapshotCalls {
			if name == want {
				guarded = true
			}
		}
		if !guarded {
			return true
		}
		seen[name] = true
		var got strings.Builder
		if err := printer.Fprint(&got, fset, call.Args[0]); err != nil {
			t.Fatalf("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: аргумент не печатается: %v", err)
		}
		if got.String() != "cur" {
			t.Errorf("%s:%d: %s получает контейнер как %q вместо снимка \"cur\" — "+
				"поле u.cur читается из другой goroutine и может смениться, пока летит запрос; "+
				"ответ придёт про ДРУГОЙ контейнер, ключа victim в нём не будет, и это напечатается "+
				"как «Подключений не было»",
				guiMainPath, fset.Position(call.Pos()).Line, name, got.String())
		}
		return true
	})

	for _, want := range deleteSnapshotCalls {
		if !seen[want] {
			t.Errorf("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: в %s нет вызова %s — "+
				"перечень надо приводить в соответствие, а не удалять", deleteHandlerName, want)
		}
	}
}

// TestDeleteResponseRechecksSnapshot — ответ сверяется со снимком ДО того,
// как попадёт на экран: устаревший ответ — это «узнать не удалось», а не
// «подключений не было».
func TestDeleteResponseRechecksSnapshot(t *testing.T) {
	resp := deleteResponseHandler(t)
	if resp == nil {
		t.Fatal("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: обработчик ответа не найден")
	}
	rechecked := false
	ast.Inspect(resp.Body, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || bin.Op != token.NEQ {
			return true
		}
		if dotted(bin.X) == "cur" && dotted(bin.Y) == "u.cur" {
			rechecked = true
		}
		return true
	})
	if !rechecked {
		t.Errorf("%s: в обработчике ответа нет сверки `cur != u.cur` — ответ про другой контейнер "+
			"попадёт в карточку как ответ про этот, и отсутствие ключа victim напечатается как "+
			"«Подключений не было». Это конвенция файла: так делает refresh()", deleteHandlerName)
	}
}
