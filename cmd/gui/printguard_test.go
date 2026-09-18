package main

// Структурный сторож на непопадание СЕРВЕРНОГО конфига и его держателей в
// вывод cmd/gui (A2б; ревью SEC-01 главным).
//
// ЗАЧЕМ ОН, ЕСЛИ СЕГОДНЯ КОНФИГ НЕ ПЕЧАТАЕТСЯ. Probe-0 (трассировка от входа
// данных в пакет — поле ввода ключа, чтение ключа из хранилища, параметр key,
// поле Key записи хранилища) печати серверного конфига в cmd/gui НЕ НАШЁЛ. Но
// "сегодня не печатает" — это СОСТОЯНИЕ, а не свойство: оно устаревает с
// первым же коммитом. Сторож делает его свойством.
//
// ЦЕНА ВОПРОСА. В конфиге лежит поле password, а в нём пароль root либо
// приватный SSH-ключ (core/hostkey.go выбирает способ входа по
// strings.Contains(creds.Password, "PRIVATE KEY")). Напечатанный однажды, он
// уходит в файл, в журнал, в скриншот, и отозвать его нельзя — сервер надо
// перенастраивать.
//
// ЧЕМ ЭТОТ СТОРОЖ ОТЛИЧАЕТСЯ ОТ cmd/cli/printguard_test.go. Там запрещено
// ВСЯКОЕ кодирование через encoding/json, кроме одной функции, — и это
// работает, потому что пакет больше ничего не кодирует. Здесь так нельзя:
// cmd/gui ЗАКОННО кодирует и читает ui.json (состояние интерфейса). Сторож,
// скопированный оттуда буквально, покраснел бы на честном коде, и его
// ослабили бы первым же действием. Поэтому запрещено не "кодирование", а
// ПОПАДАНИЕ КОНФИГА И ЕГО ДЕРЖАТЕЛЕЙ В ВЫВОД, а точки кодирования
// перечислены поимённо (allowedEncodePoints).
//
// ЗАЩИТА СТОИТ НА ДВУХ НОГАХ, и ни одна не заменяет другую:
//  1. ПЕРЕЧЕНЬ ДЕРЖАТЕЛЕЙ — закрывает путь через ПОЛЕ СТРУКТУРЫ. Конфиг в
//     cmd/gui живёт не в переменной: ui хранит sess *core.Session, Session
//     хранит Creds *ServerCreds, ServerCreds хранит Password, — и до пароля
//     дотягиваются из любой функции без единого присваивания.
//     fmt.Sprintf("%v", u.sess.Creds) печатает пароль ЦЕЛИКОМ (fmt для
//     указателя на структуру печатает &{…} с содержимым полей — проверено
//     координатором прогоном: &{1.2.3.4 root СЕКРЕТ-ПАРОЛЬ 22}) и не
//     совпадает ни с одним локальным именем. Путь не гипотетический: в файле
//     УЖЕ есть законное widget.NewLabel(fmt.Sprintf("Сервер: %s@%s",
//     u.sess.Creds.User, u.sess.Creds.Host)) — тот же держатель, то же
//     форматирование, другая функция.
//  2. ЦЕПОЧКА ПРИСВАИВАНИЙ В ПРЕДЕЛАХ ФУНКЦИИ — закрывает ЛОКАЛЬНЫЙ обход
//     (p := cfg["password"]; print(p)). Она не ловит и не может ловить путь
//     через поле структуры: u.sess присвоено в одной функции, а раскрывается
//     в другой, и никакой цепочки в пределах второй функции нет.
//
// ВХОД БЫВАЕТ НЕВИДИМЫМ. Первая редакция этого сторожа охраняла вход, который
// видно на экране, — поле ввода keyEntry. Но ключ попадает в программу и
// МИМО экрана: os.Getenv("AMNEZIA_KEY") (:125) читает его из окружения и
// кладёт в то же поле ввода. Этого корня не было ни в одном из трёх
// перечней, составленных до работы, — все трое взяли за вход то, что видно.
// Предъявлено прогоном: правдоподобная строка
// keyEntry.SetPlaceHolder("ключ из окружения: " + k) проходила сторож
// ЗЕЛЁНОЙ, потому что заражение намеренно не идёт через возвращаемое
// значение функции (п. 4 границы ниже), а имя k не совпадает ни с одним
// охраняемым. Ключ vpn://… — весь конфиг целиком, то есть утечка шире всех
// прочих. Закрыто keyEnvNames + envVarsIn (строка 9 таблицы покраснений).
// ОБЩЕЕ ПРАВИЛО, ради которого это записано: корень трассировки — не «поле
// ввода», а ЛЮБОЕ место, где значение появляется в пакете, включая
// окружение, файл и аргумент командной строки.
//
// САМЫЙ БОГАТЫЙ ДЕРЖАТЕЛЬ — САМА СТРОКА КЛЮЧА. В строке vpn://… лежит ВЕСЬ
// конфиг целиком, то есть надмножество всего, что охраняется ниже по
// течению: напечатав её, утекает не пароль, а всё сразу. Она живёт
// ПАРАМЕТРОМ через границы функций без единого присваивания
// (key := strings.TrimSpace(keyEntry.Text) → u.attemptConnect(key, …) →
// core.DecodeVpnKey(key)) и попадает в поле Key записи хранилища. Поэтому
// корни охраны начинаются со ВХОДА (keyEntry, key, .Key), а не с разбора
// (DecodeVpnKey): перечень, начатый с РЕЗУЛЬТАТА DecodeVpnKey, пропускает её
// АРГУМЕНТ.
//
// ГРАНИЦА СТОРОЖА — здесь, в коде, а не в отчёте: завышенное достижение
// опаснее скромного, потому что читатель, уверенный, что сторож ловит всё,
// перестанет искать обход. Сторож НЕ ВИДИТ:
//  1. печати не через перечисленные имена и не через encoding/json — ручной
//     склейки строк, шаблона, значения, собранного посимвольно;
//  2. передачи держателя в другой пакет, который печатает сам; и обратно —
//     текста ошибки, пришедшего из другого пакета (err.Error() печатается
//     законно во многих местах, и что в нём лежит, решает тот пакет);
//  3. МЕТОДА ДЕРЖАТЕЛЯ, ПЕЧАТАЮЩЕГО СЕБЯ (String(), Format(), MarshalJSON()):
//     вызов выглядит обычным вызовом метода и конфигом по имени не является.
//     Сегодня таких методов у ServerCreds/Session/VaultPayload НЕТ (проверено
//     grep по core/) — путь закрыт СОСТОЯНИЕМ КОДА, А НЕ СТОРОЖЕМ;
//  4. ПОТОКА ЧЕРЕЗ ВЫЗОВ: заражение не идёт через возвращаемое значение
//     функции (x := f(cfg) не делает x держателем). Это сделано намеренно:
//     иначе sess, err := core.ConnectWithHostKey(creds, …) пометил бы и err,
//     и каждое законное err.Error() покраснело бы — сторож, краснеющий на
//     честном коде, ослабляют первым же действием. ИСКЛЮЧЕНИЕ ровно одно и
//     названо поимённо: os.Getenv/os.LookupEnv (envVarsIn) — невидимый вход
//     ключа, ради которого пришлось пробить эту границу в одном месте;
//  5. потока через несколько функций без поля структуры: значение, переданное
//     параметром в третью функцию и напечатанное там под другим именем;
//  6. КЛИЕНТСКОГО конфига (core.NewUser.Config). Он охраной НЕ ПОКРЫТ и
//     покрыт быть не должен: в нём приватный ключ и PSK клиента, и он
//     печатается ЗАКОННО И НАМЕРЕННО — диалог "Конфиг готов", QR-код,
//     сохранение .conf: ради этого продукт и существует. Зелёный сторож
//     говорит "СЕРВЕРНЫЙ конфиг в вывод не попадает", а НЕ "секретов в
//     выводе нет";
//  7. пин-кода хранилища (pin, pinEntry): это секрет другого предмета —
//     доступ к файлу .avlt, а не к серверу. Сегодня он никуда не печатается
//     (проверено Probe-0), но сторожем это не закреплено.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// guiPkgDir — каталог пакета, который сторож разбирает.
const guiPkgDir = "."

const jsonImportPath = "encoding/json"

// ---------- 1. Перечень ДОПУСТИМЫХ точек кодирования ----------

// encPoint — разрешённая точка кодирования/разбора JSON: функция, метод
// пакета encoding/json и то, ЧТО она кодирует. Новая точка роняет тест и
// вносится сюда ВИДИМОЙ СТРОКОЙ ДИФФА, с утверждением SEC-01. Это свойство,
// а не неудобство.
type encPoint struct {
	fn     string
	method string
	what   string
}

var allowedEncodePoints = []encPoint{
	{"loadSortState", "Unmarshal", "состояние интерфейса из ui.json (sortStateJSON: четыре поля сортировки, полей конфига нет)"},
	{"saveSortState", "MarshalIndent", "то же состояние интерфейса в ui.json"},
}

// jsonMethods — методы encoding/json, считающиеся точкой кодирования/разбора.
var jsonMethods = map[string]bool{
	"Marshal": true, "MarshalIndent": true, "Unmarshal": true,
	"NewEncoder": true, "NewDecoder": true,
}

// ---------- 2. Перечень ОХРАНЯЕМЫХ держателей ----------

// holderRoots — имена, которые сами по себе являются держателем конфига или
// его надмножества. key/keyEntry — ВХОД (строка vpn://… целиком), cfg —
// разобранный конфиг, creds — извлечённые доступы, sess/payload — поля и
// записи, живущие всё время работы программы.
var holderRoots = map[string]bool{
	"cfg":      true,
	"creds":    true,
	"key":      true,
	"keyEntry": true,
	"sess":     true,
	"payload":  true,
}

// keyEnvNames — переменные окружения, из которых приходит КЛЮЧ. Перечислены
// поимённо, как и всё остальное допустимое/охраняемое в этом стороже: новая
// вносится видимой строкой диффа. Чтение ЛЮБОЙ другой переменной окружения
// держателем не считается и краснеть не должно — в cmd/cli есть законный
// os.Getenv("NO_COLOR"), и сторож, краснеющий на таком, ослабляют первым же
// действием (это уже случалось в круге 1 на замыканиях-обработчиках).
var keyEnvNames = map[string]bool{
	"AMNEZIA_KEY": true,
}

// keyInputFields — поля ввода, В КОТОРЫХ ключ живёт по своему назначению.
// Запись ключа в собственное поле ввода — не раскрытие (см. isSink).
var keyInputFields = map[string]bool{
	"keyEntry": true,
}

// keyEnvNameHint — страховка на случай новой переменной, которую забудут
// внести в keyEnvNames: имя, содержащее KEY или VPN, считается несущим ключ.
// Ложное срабатывание чинится строкой в перечне, пропуск секрета — заново
// настроенным сервером; цена несимметрична.
func keyEnvNameHint(name string) bool {
	up := strings.ToUpper(name)
	return strings.Contains(up, "KEY") || strings.Contains(up, "VPN")
}

// holderFields — поля, путь через которые делает выражение держателем, где бы
// это выражение ни начиналось: u.sess.Creds, vc.payload.Key, x.Password.
var holderFields = map[string]bool{
	"Creds":    true,
	"Password": true,
	"Key":      true,
	"sess":     true,
	"payload":  true,
}

// allowedSelectorSuffixes — ИСКЛЮЧЕНИЯ, перечисленные поимённо, потому что
// законный код уже есть. Разрешено ровно то, что не секрет:
//   - .Creds.User / .Creds.Host — подпись "Сервер: user@host" на главном
//     экране (пользователь и хост не секрет, пароль — секрет);
//   - .HostKeyFingerprint — отпечаток ключа хоста: он и так показывается
//     человеку в диалогах доверия ключу;
//   - .Label / .Created — метка и дата записи хранилища.
//
// ВСЁ ОСТАЛЬНОЕ под .Creds, включая сам .Creds целиком и %v/%+v от него, —
// запрещено. Новый разрешённый селектор вносится сюда ВИДИМОЙ СТРОКОЙ ДИФФА
// и утверждается SEC-01, как и новая точка кодирования.
var allowedSelectorSuffixes = []string{
	".Creds.User",
	".Creds.Host",
	".HostKeyFingerprint",
	".Label",
	".Created",
}

// ---------- 3. Точки вывода (sink) ----------

// isSink отвечает, является ли вызов местом, откуда значение уходит к
// человеку или в файл: кодирование, форматирование и печать, запись файла,
// тексты виджетов и диалогов, паника (её текст уходит в crash.log через
// logPanic). Возвращает читаемое имя вызова.
func isSink(call *ast.CallExpr, jsonNames map[string]bool) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		switch fun.Name {
		case "panic", "print", "println":
			return fun.Name
		}
	case *ast.SelectorExpr:
		name := fun.Sel.Name
		// ИСКЛЮЧЕНИЕ, перечисленное поимённо: keyEntry.SetText(<ключ>) — это
		// заполнение САМОГО ПОЛЯ ВВОДА ключа, то есть возврат значения туда,
		// откуда оно и приходит (:125-126 подставляет ключ из AMNEZIA_KEY в
		// поле, куда его иначе вставляет человек). Новым раскрытием это не
		// является. Всё остальное с тем же значением — включая
		// keyEntry.SetPlaceHolder, подпись, заголовок и любой другой виджет —
		// запрещено: это уже вынос ключа за пределы его собственного поля.
		if name == "SetText" {
			if recv, ok := fun.X.(*ast.Ident); ok && keyInputFields[recv.Name] {
				return ""
			}
		}
		// Методы-приёмники текста: у любого получателя.
		switch name {
		case "SetText", "SetTitle", "SetPlaceHolder", "SetContent":
			return "." + name
		}
		pkg, ok := fun.X.(*ast.Ident)
		if !ok {
			return ""
		}
		if jsonNames[pkg.Name] && jsonMethods[name] {
			return pkg.Name + "." + name
		}
		switch pkg.Name {
		case "fmt", "log":
			return pkg.Name + "." + name
		case "os":
			if name == "WriteFile" {
				return "os.WriteFile"
			}
		// container.* намеренно НЕ sink: раскладка принимает готовые
		// CanvasObject'ы, и container.NewVBox(keyEntry) — это размещение
		// поля ввода на экране, а не печать его содержимого. Сторож,
		// краснеющий на этом, ослабляют первым же действием.
		case "widget", "canvas":
			if strings.HasPrefix(name, "New") {
				return pkg.Name + "." + name
			}
		case "dialog":
			if strings.HasPrefix(name, "Show") || strings.HasPrefix(name, "New") {
				return "dialog." + name
			}
		}
	}
	return ""
}

// ---------- 4. Разбор выражений ----------

// selectorPath разворачивает a.b.c в ".b.c" с корневым идентификатором "a".
// ok == false, если основание — не идентификатор (вызов, литерал и т.п.).
func selectorPath(e ast.Expr) (root string, path string, ok bool) {
	var parts []string
	cur := e
	for {
		switch x := cur.(type) {
		case *ast.SelectorExpr:
			parts = append([]string{x.Sel.Name}, parts...)
			cur = x.X
		case *ast.Ident:
			return x.Name, "." + strings.Join(parts, "."), true
		case *ast.ParenExpr:
			cur = x.X
		case *ast.StarExpr:
			cur = x.X
		case *ast.IndexExpr:
			cur = x.X
		default:
			return "", "." + strings.Join(parts, "."), false
		}
	}
}

// holderVerdict — вердикт по одному выражению.
type holderVerdict int

const (
	verdictNeutral   holderVerdict = iota // к конфигу отношения не имеет
	verdictAllowed                        // держатель, но разрешённый селектор
	verdictForbidden                      // держатель, печатать нельзя
)

// classify судит выражение: держатель ли оно и разрешено ли.
// tainted — имена, заражённые цепочкой присваиваний в этой функции.
func classify(e ast.Expr, tainted map[string]bool) holderVerdict {
	switch x := e.(type) {
	case *ast.Ident:
		if holderRoots[x.Name] || tainted[x.Name] {
			return verdictForbidden
		}
		return verdictNeutral
	case *ast.SelectorExpr:
		root, path, rootIsIdent := selectorPath(x)
		isHolder := false
		if rootIsIdent && (holderRoots[root] || tainted[root]) {
			isHolder = true
		}
		for _, seg := range strings.Split(strings.TrimPrefix(path, "."), ".") {
			if holderFields[seg] {
				isHolder = true
			}
		}
		if !isHolder {
			return verdictNeutral
		}
		for _, suf := range allowedSelectorSuffixes {
			if strings.HasSuffix(path, suf) {
				return verdictAllowed
			}
		}
		return verdictForbidden
	}
	return verdictNeutral
}

// findHolders обходит поддерево выражения и возвращает записи запрещённых
// держателей. В РАЗРЕШЁННЫЙ селектор обход НЕ СПУСКАЕТСЯ: иначе законное
// u.sess.Creds.User покраснело бы своим же префиксом u.sess.Creds.
func findHolders(e ast.Expr, tainted map[string]bool) []string {
	var found []string
	var walk func(ast.Node) bool
	walk = func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			// Тело замыкания, переданного АРГУМЕНТОМ (обработчик кнопки), —
			// не вывод: widget.NewButton("…", func(){ … key … }) не печатает
			// key, он только регистрирует обработчик. Сами вызовы внутри
			// этого тела сторож всё равно видит: внешний обход идёт по всему
			// телу функции, включая ast.FuncLit (строка 7 таблицы
			// покраснений — печать держателя в замыкании — краснеет именно
			// им).
			_ = x
			return false
		case *ast.SelectorExpr:
			switch classify(x, tainted) {
			case verdictAllowed:
				return false // разрешено целиком — внутрь не спускаемся
			case verdictForbidden:
				_, path, _ := selectorPath(x)
				root, _, _ := selectorPath(x)
				found = append(found, root+path)
				return false
			}
			return true
		case *ast.Ident:
			if classify(x, tainted) == verdictForbidden {
				found = append(found, x.Name)
			}
			return false
		case *ast.CallExpr:
			// Имя вызываемой функции держателем не считаем — только аргументы
			// и получателя, если он сам держатель.
			for _, a := range x.Args {
				ast.Inspect(a, walk)
			}
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				ast.Inspect(sel.X, walk)
			}
			return false
		}
		return true
	}
	ast.Inspect(e, walk)
	return found
}

// envVarsIn — ТРЕТЬЯ НОГА: невидимый вход. Возвращает локальные имена,
// получившие значение из os.Getenv/os.LookupEnv, которое несёт ключ. Несущим
// ключ чтение считается по ДВУМ независимым признакам, потому что одного
// мало:
//  1. ПО ИМЕНИ ПЕРЕМЕННОЙ ОКРУЖЕНИЯ — keyEnvNames (поимённо) либо подсказка
//     keyEnvNameHint (KEY/VPN в имени);
//  2. ПО НАЗНАЧЕНИЮ — прочитанное значение уходит в держатель: присваивается
//     имени-держателю (key = k) или подаётся в текст поля ввода ключа
//     (keyEntry.SetText(k)). Это ловит переменную, названную как угодно
//     ("AMN_CONN", "ADMIN_STRING"), — имя обмануть легко, назначение нет.
func envVarsIn(fn ast.Node) map[string]bool {
	candidates := map[string]bool{} // имя → прочитано из окружения
	byName := map[string]bool{}     // и само имя переменной окружения выдаёт ключ

	ast.Inspect(fn, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, rhs := range as.Rhs {
			call, ok := rhs.(*ast.CallExpr)
			if !ok {
				continue
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "os" ||
				(sel.Sel.Name != "Getenv" && sel.Sel.Name != "LookupEnv") {
				continue
			}
			if i >= len(as.Lhs) {
				continue
			}
			id, ok := as.Lhs[i].(*ast.Ident)
			if !ok || id.Name == "_" {
				continue
			}
			candidates[id.Name] = true
			if len(call.Args) > 0 {
				if lit, ok := call.Args[0].(*ast.BasicLit); ok {
					if envName, err := strconv.Unquote(lit.Value); err == nil &&
						(keyEnvNames[envName] || keyEnvNameHint(envName)) {
						byName[id.Name] = true
					}
				}
			}
		}
		return true
	})

	if len(candidates) == 0 {
		return byName
	}

	// Признак 2: значение уходит в держатель.
	out := byName
	ast.Inspect(fn, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for i, rhs := range x.Rhs {
				id, ok := rhs.(*ast.Ident)
				if !ok || !candidates[id.Name] || i >= len(x.Lhs) {
					continue
				}
				if lhs, ok := x.Lhs[i].(*ast.Ident); ok && holderRoots[lhs.Name] {
					out[id.Name] = true
				}
			}
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "SetText" {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok || !holderRoots[recv.Name] {
				return true
			}
			for _, a := range x.Args {
				ast.Inspect(a, func(n ast.Node) bool {
					if id, ok := n.(*ast.Ident); ok && candidates[id.Name] {
						out[id.Name] = true
					}
					return true
				})
			}
		}
		return true
	})
	return out
}

// taintedIn — ВТОРАЯ НОГА: цепочка присваиваний в пределах функции. Ловит
// локальный обход (p := cfg["password"]; c := u.sess.Creds). Заражение НЕ
// идёт через вызов функции — см. п. 4 границы в шапке.
func taintedIn(fn ast.Node) map[string]bool {
	tainted := envVarsIn(fn) // невидимый вход — тоже держатель, с первого круга
	// Несколько проходов: c := u.sess.Creds; p := c — второе видно только
	// после первого.
	for round := 0; round < 4; round++ {
		before := len(tainted)
		ast.Inspect(fn, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != len(as.Rhs) {
				return true
			}
			for i, rhs := range as.Rhs {
				src := rhs
				for {
					switch x := src.(type) {
					case *ast.ParenExpr:
						src = x.X
					case *ast.StarExpr:
						src = x.X
					case *ast.UnaryExpr:
						src = x.X
					case *ast.IndexExpr:
						src = x.X
					default:
						goto done
					}
				}
			done:
				switch src.(type) {
				case *ast.Ident, *ast.SelectorExpr:
				default:
					continue // вызов, литерал, композит — не цепочка
				}
				if classify(src, tainted) != verdictForbidden {
					continue
				}
				if id, ok := as.Lhs[i].(*ast.Ident); ok && id.Name != "_" {
					tainted[id.Name] = true
				}
			}
			return true
		})
		if len(tainted) == before {
			break
		}
	}
	return tainted
}

// ---------- 5. Импорты ----------

// jsonNamesIn возвращает имена, под которыми в файле импортирован
// encoding/json, и нарушения правил импорта. Имя берётся ИЗ ИМПОРТОВ, а не
// сравнивается с литералом "json": иначе import js "encoding/json" обходил бы
// перечень точек кодирования целиком (тот же приём, что в
// cmd/cli/printguard_test.go).
func jsonNamesIn(f *ast.File) (names map[string]bool, problems []string) {
	names = map[string]bool{}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			problems = append(problems, "не разобран путь импорта "+imp.Path.Value)
			continue
		}
		local := ""
		if imp.Name != nil {
			local = imp.Name.Name
		}
		if path == jsonImportPath {
			switch local {
			case ".":
				problems = append(problems, "точечный импорт "+jsonImportPath+
					" запрещён: сторож не разбирает безымянные вызовы Marshal/Unmarshal")
			case "_":
			case "":
				names["json"] = true
			default:
				names[local] = true
			}
			continue
		}
		if strings.Contains(strings.ToLower(path), "json") {
			problems = append(problems, "сторонний пакет кодирования JSON запрещён в cmd/gui: "+path+
				" — сторож знает только "+jsonImportPath)
		}
	}
	return names, problems
}

// ---------- 6. Сбор ----------

type encSite struct {
	fn, file, method string
	expr             string // как записано в коде: "json.MarshalIndent", "js.Unmarshal"
	line             int
}

type holderSite struct {
	fn, file, sink, expr string
	line                 int
}

func scanPackage(t *testing.T) (encs []encSite, holders []holderSite, importProblems []string) {
	t.Helper()

	entries, err := os.ReadDir(guiPkgDir)
	if err != nil {
		t.Fatalf("не удалось прочитать каталог пакета %q: %v — сторож перестал что-либо проверять", guiPkgDir, err)
	}
	fset := token.NewFileSet()
	scanned := 0

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(guiPkgDir, name), nil, 0)
		if err != nil {
			t.Fatalf("не удалось разобрать %s: %v — сторож перестал что-либо проверять", name, err)
		}
		scanned++

		jsonNames, probs := jsonNamesIn(f)
		for _, p := range probs {
			importProblems = append(importProblems, name+": "+p)
		}

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// Обход идёт по ВСЕМУ телу функции, включая тела замыканий
			// (ast.FuncLit): в cmd/gui обработчики написаны замыканиями, и
			// обход только по объявленным функциям пропустил бы почти весь
			// файл.
			tainted := taintedIn(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok && jsonNames[pkg.Name] && jsonMethods[sel.Sel.Name] {
						pos := fset.Position(call.Pos())
						encs = append(encs, encSite{fn: fn.Name.Name, file: filepath.Base(pos.Filename),
							line: pos.Line, method: sel.Sel.Name, expr: pkg.Name + "." + sel.Sel.Name})
					}
				}
				sink := isSink(call, jsonNames)
				if sink == "" {
					return true
				}
				for _, arg := range call.Args {
					for _, h := range findHolders(arg, tainted) {
						pos := fset.Position(call.Pos())
						holders = append(holders, holderSite{fn: fn.Name.Name,
							file: filepath.Base(pos.Filename), line: pos.Line, sink: sink, expr: h})
					}
				}
				return true
			})
		}
	}

	if scanned == 0 {
		t.Fatalf("в %q не разобрано ни одного не-тестового .go-файла — сторож перестал что-либо проверять", guiPkgDir)
	}
	return encs, holders, importProblems
}

// ---------- 7. Сами проверки ----------

// TestGuiConfigHoldersNotPrinted — ГОЛОВНАЯ проверка: держатель серверного
// конфига не появляется в аргументах печати, форматирования, кодирования,
// записи файла и текстов виджетов.
func TestGuiConfigHoldersNotPrinted(t *testing.T) {
	_, holders, importProblems := scanPackage(t)

	for _, p := range importProblems {
		t.Errorf("нарушение правила импорта JSON в cmd/gui: %s", p)
	}

	for _, h := range holders {
		t.Errorf("держатель серверного конфига %q попадает в вывод: %s:%d, функция %s, вызов %s. "+
			"Через него достижим пароль root либо приватный SSH-ключ владельца (ключ vpn://… — это ВЕСЬ "+
			"конфиг целиком). Напечатанный однажды, он уходит в файл, в журнал, в скриншот, и отозвать "+
			"его нельзя — сервер надо перенастраивать. Разрешены поимённо только %v; новый разрешённый "+
			"селектор вносится в этот перечень видимой строкой диффа и утверждается SEC-01.",
			h.expr, h.file, h.line, h.fn, h.sink, allowedSelectorSuffixes)
	}
}

// TestGuiEncodePointsListed — перечень допустимых точек кодирования. Новая
// точка роняет тест и вносится в allowedEncodePoints видимой строкой диффа.
//
// Падает словами "перестал что-либо проверять" на двух входах: точек
// кодирования не найдено вовсе, либо не найдено ни одной из перечисленных —
// исчезновение искомого есть "сверять перестало быть возможным", а не
// "всё чисто".
func TestGuiEncodePointsListed(t *testing.T) {
	encs, _, _ := scanPackage(t)

	if len(encs) == 0 {
		t.Fatalf("в пакете cmd/gui не найдено ни одного места кодирования/разбора JSON — "+
			"образец исчез, сверять нечего; сторож перестал что-либо проверять "+
			"(ожидались точки %v)", allowedEncodePoints)
	}

	allowed := func(fn, method string) (encPoint, bool) {
		for _, p := range allowedEncodePoints {
			if p.fn == fn && p.method == method {
				return p, true
			}
		}
		return encPoint{}, false
	}

	seen := map[string]bool{}
	for _, s := range encs {
		p, ok := allowed(s.fn, s.method)
		if !ok {
			t.Errorf("кодирование/разбор JSON вне перечня допустимых точек: %s:%d, функция %s (%s). "+
				"В cmd/gui запрещено не кодирование, а попадание конфига в вывод, — поэтому допустимые "+
				"точки перечислены поимённо. Если точка законна, внесите её в allowedEncodePoints "+
				"видимой строкой диффа (с указанием, ЧТО она кодирует) и утвердите у SEC-01.",
				s.file, s.line, s.fn, s.expr)
			continue
		}
		seen[p.fn+"."+p.method] = true
	}

	for _, p := range allowedEncodePoints {
		if !seen[p.fn+"."+p.method] {
			t.Fatalf("допустимая точка кодирования %s/json.%s (%s) в пакете не найдена — "+
				"она исчезла или переименована; сторож перестал что-либо проверять. "+
				"Уберите её из allowedEncodePoints видимой строкой диффа, если это намеренно.",
				p.fn, p.method, p.what)
		}
	}
}

// TestGuiGuardRulesThemselves проверяет сами правила сторожа на образцах —
// на тех формах, которыми защита обходится. Эти подтесты не требуют правки
// main.go и держат правила от тихой деградации.
func TestGuiGuardRulesThemselves(t *testing.T) {
	noTaint := map[string]bool{}

	cases := []struct {
		name string
		expr string
		want holderVerdict
	}{
		{"держатель целиком", "u.sess.Creds", verdictForbidden},
		{"поле сессии", "u.sess", verdictForbidden},
		{"пароль", "c.Password", verdictForbidden},
		{"строка ключа", "key", verdictForbidden},
		{"поле ввода ключа", "keyEntry.Text", verdictForbidden},
		{"поле Key записи хранилища", "vc.payload.Key", verdictForbidden},
		{"разрешённый селектор User", "u.sess.Creds.User", verdictAllowed},
		{"разрешённый селектор Host", "u.sess.Creds.Host", verdictAllowed},
		{"отпечаток ключа хоста", "vc.payload.HostKeyFingerprint", verdictAllowed},
		{"постороннее выражение", "victim.Name()", verdictNeutral},
		{"состояние интерфейса", "st.Primary", verdictNeutral},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := parser.ParseExpr(c.expr)
			if err != nil {
				t.Fatalf("разбор образца %q: %v", c.expr, err)
			}
			if got := classify(e, noTaint); got != c.want {
				t.Errorf("classify(%q) = %d, ожидалось %d", c.expr, got, c.want)
			}
		})
	}

	t.Run("цепочка присваиваний в пределах функции", func(t *testing.T) {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", `package main
func f() {
	c := u.sess.Creds
	p := cfg["password"]
	_ = c
	_ = p
}`, 0)
		if err != nil {
			t.Fatalf("разбор образца: %v", err)
		}
		tainted := taintedIn(f)
		for _, name := range []string{"c", "p"} {
			if !tainted[name] {
				t.Errorf("локальная переменная %q не помечена держателем — цепочка присваиваний не работает: %v", name, tainted)
			}
		}
	})

	t.Run("заражение не идёт через вызов функции", func(t *testing.T) {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", `package main
func f() {
	sess, err := core.ConnectWithHostKey(creds, nil)
	_, _ = sess, err
}`, 0)
		if err != nil {
			t.Fatalf("разбор образца: %v", err)
		}
		if taintedIn(f)["err"] {
			t.Error("err помечен держателем — сторож покраснеет на каждом законном err.Error(); " +
				"это ровно тот случай, когда сторожа ослабляют первым же действием")
		}
	})

	t.Run("невидимый вход: ключ из окружения — держатель", func(t *testing.T) {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", `package main
func f() {
	if k := os.Getenv("AMNEZIA_KEY"); k != "" {
		keyEntry.SetText(k)
	}
}`, 0)
		if err != nil {
			t.Fatalf("разбор образца: %v", err)
		}
		if !taintedIn(f)["k"] {
			t.Error("значение из os.Getenv(\"AMNEZIA_KEY\") не помечено держателем — " +
				"в нём ключ vpn://… целиком, то есть весь конфиг сразу")
		}
	})

	t.Run("невидимый вход по назначению, а не по имени переменной", func(t *testing.T) {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", `package main
func f() {
	v := os.Getenv("AMN_CONN")
	keyEntry.SetText(v)
}`, 0)
		if err != nil {
			t.Fatalf("разбор образца: %v", err)
		}
		if !taintedIn(f)["v"] {
			t.Error("значение из окружения, уходящее в поле ввода ключа, не помечено держателем — " +
				"имя переменной окружения обмануть легко, назначение нет")
		}
	})

	t.Run("законное чтение окружения держателем не считается", func(t *testing.T) {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", `package main
func f() {
	if os.Getenv("NO_COLOR") != "" {
		return
	}
	n := os.Getenv("NO_COLOR")
	fmt.Println(n)
}`, 0)
		if err != nil {
			t.Fatalf("разбор образца: %v", err)
		}
		if taintedIn(f)["n"] {
			t.Error("NO_COLOR помечен держателем — сторож покраснеет на законном коде " +
				"(такой os.Getenv есть в cmd/cli), и его ослабят первым же действием")
		}
	})

	t.Run("алиас encoding/json распознаётся", func(t *testing.T) {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", `package main
import js "encoding/json"
`, 0)
		if err != nil {
			t.Fatalf("разбор образца: %v", err)
		}
		names, probs := jsonNamesIn(f)
		if !names["js"] {
			t.Errorf("алиас js не распознан: %v", names)
		}
		if len(probs) != 0 {
			t.Errorf("алиас — не нарушение: %v", probs)
		}
	})

	t.Run("точечный импорт encoding/json запрещён", func(t *testing.T) {
		f, _ := parser.ParseFile(token.NewFileSet(), "x.go", `package main
import . "encoding/json"
`, 0)
		if _, probs := jsonNamesIn(f); len(probs) == 0 {
			t.Error("точечный импорт не помечен нарушением — сторож не разбирает безымянные вызовы, и это обход")
		}
	})

	t.Run("сторонний пакет кодирования JSON запрещён", func(t *testing.T) {
		f, _ := parser.ParseFile(token.NewFileSet(), "x.go", `package main
import jsoniter "github.com/json-iterator/go"
`, 0)
		if _, probs := jsonNamesIn(f); len(probs) == 0 {
			t.Error("сторонний пакет кодирования JSON не помечен нарушением — сторож знает только encoding/json")
		}
	})
}
