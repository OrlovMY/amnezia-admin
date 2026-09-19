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

	if !strings.Contains(text, "guiview.TrafficText(") {
		t.Errorf("%s: ячейка трафика собирается не через guiview.TrafficText", guiMainPath)
	}
	if strings.Contains(text, "HumanBytes(") {
		t.Errorf("%s: core.HumanBytes снова вызывается прямо в cmd/gui — "+
			"числа печатаются мимо проверки «получена ли статистика», и недоступная статистика "+
			"снова выглядит измеренным нулём", guiMainPath)
	}
	if !strings.Contains(text, "guiview.ActivityText(") {
		t.Errorf("%s: ячейка активности собирается не через guiview.ActivityText — "+
			"ветка «запрос не удался» снова описана строкой в cmd/gui, где её не проверяет ни один тест",
			guiMainPath)
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

// cellFailFlagArg — вторым (индекс 1) аргументом ячейки идёт ПРИЗНАК
// «запрос не удался». Перечень: функция → ожидаемое выражение признака.
var cellFailFlagArg = map[string]string{
	"ActivityText": "u.activityFailed",
	"TrafficText":  "u.statsFailed",
}

// TestCellsReceiveTheFailureFlag — ПРИЗНАК ДОЕЗЖАЕТ ДО ЯЧЕЙКИ.
//
// ЧЕГО НЕ ХВАТАЛО ПРЕЖНЕЙ РЕДАКЦИИ (ревью BE-01). Она проверяла только
// ПРИСУТСТВИЕ вызова guiview.TrafficText — то есть форму. Обход стоил одной
// клавиши и выглядел как упрощение: `guiview.TrafficText(u.canManage,
// false, …)` — вызов на месте, тесты guiview зелёные, а на экране снова
// «0 B / 0 B» при недоступной статистике. Для карточки такая сверка уже
// была (TestDeleteCardPassesServerError); здесь тот же приём применён к
// обеим ячейкам таблицы.
func TestCellsReceiveTheFailureFlag(t *testing.T) {
	raw, _, _ := readGUIMain(t)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, guiMainPath, raw, 0)
	if err != nil {
		t.Fatalf("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: %s не разбирается: %v", guiMainPath, err)
	}

	seen := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		want, guarded := cellFailFlagArg[sel.Sel.Name]
		if !guarded {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "guiview" {
			return true
		}
		seen[sel.Sel.Name] = true
		if len(call.Args) < 2 {
			t.Errorf("%s:%d: guiview.%s вызвана с %d аргументами — признак «запрос не удался» передать нечем",
				guiMainPath, fset.Position(call.Pos()).Line, sel.Sel.Name, len(call.Args))
			return true
		}
		var got strings.Builder
		if err := printer.Fprint(&got, fset, call.Args[1]); err != nil {
			t.Fatalf("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: аргумент не печатается: %v", err)
		}
		if got.String() != want {
			t.Errorf("%s:%d: guiview.%s получает вторым аргументом %q вместо %q — "+
				"признак «статистику получить не удалось» до ячейки не доезжает, и отказ сервера "+
				"снова печатается как измеренная величина",
				guiMainPath, fset.Position(call.Pos()).Line, sel.Sel.Name, got.String(), want)
		}
		return true
	})

	for name := range cellFailFlagArg {
		if !seen[name] {
			t.Errorf("сторож A1 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: в %s нет ни одного вызова guiview.%s — "+
				"ячейку собирают чем-то другим, и перечень надо приводить в соответствие, а не удалять",
				guiMainPath, name)
		}
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
