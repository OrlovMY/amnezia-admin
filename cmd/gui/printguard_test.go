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
//  2. ПЕРЕНОС ДЕРЖАТЕЛЯ В ЛОКАЛЬНОЕ ИМЯ — закрывает ЛОКАЛЬНЫЙ обход
//     (p := cfg["password"]; print(p)). Она не ловит и не может ловить путь
//     через поле структуры: u.sess присвоено в одной функции, а раскрывается
//     в другой, и никакой цепочки в пределах второй функции нет.
//
// КАК ОБЕ НОГИ ОБХОДИЛИ В КРУГЕ 2 И ЧЕМУ ЭТО УЧИТ (ревью SEC-01). Обе дыры
// были ОДНОГО ВИДА: мы описали, что сторож ловит, в терминах ЯЗЫКОВОЙ
// КОНСТРУКЦИИ («присваивание», «вызов»), а обходились они ДРУГОЙ
// конструкцией с тем же смыслом, ценой одной клавиши:
//   - нога 2 разбирала только ast.AssignStmt → `var c = u.sess.Creds`
//     (ast.ValueSpec) и `for _, c := range …` (ast.RangeStmt) проходили
//     зелёными, делая ровно то же самое;
//   - вывод искался только среди ast.CallExpr → `lbl.Text = key` и
//     `&widget.Entry{Text: key}` показывали ключ на экране, не будучи
//     вызовом; `f.WriteString(key)` писал его в файл мимо os.WriteFile.
// Это тот же дефект, что у признаков «ветка else» и «будущее время»:
// правило описывает ФОРМУ последнего примера, а не свойство класса.
// ПОЭТОМУ К КАЖДОЙ ЗАПИСИ ЭТОЙ ШАПКИ ЗАДАЁТСЯ ВОПРОС: «А ЕСЛИ ТО ЖЕ САМОЕ
// НАПИСАТЬ ИНАЧЕ?» Где ответ «пройдёт» — это либо починка, либо строка
// границы ниже, но не умолчание.
//
// ЧТО ОБОШЛИ В КРУГЕ 3 И ЧЕМУ ЭТО УЧИТ (ревью SEC-01). Три обхода, и все три
// одного корня — ПЕРЕЧЕНЬ, СОСТАВЛЕННЫЙ ПО ПАМЯТИ, А НЕ ВЫВЕДЕННЫЙ:
//   - исключение для поля ввода ключа проверяло значение ПО ИМЕНИ, а имя
//     назначает автор правки: key := u.sess.Creds.Password; keyEntry.SetText(key)
//     удовлетворял всем трём условиям исключения и показывал пароль root на
//     экране. Закрыто четвёртым условием — reboundNames;
//   - точки вывода перечислялись четырьмя именами методов и тремя полями,
//     встреченными в коде: cd.SetSubTitle(key), &widget.Card{Subtitle: key} и
//     fyne.NewNotification("k", key) проходили зелёными. Закрыто не дописью
//     трёх имён, а РАЗБОРОМ САМОГО ПАКЕТА ВИДЖЕТОВ (см. widgetTextFields и
//     isSink): перечень получен обходом go/ast по исходникам fyne и сведён к
//     признаку (префиксы Set*/Append*), чтобы следующая версия fyne закрылась
//     сама;
//   - перенос имени шёл только из Ident и SelectorExpr, и КОНТЕЙНЕР терял
//     заражение: map/срез/структура с ключом внутри и склейка в имя. Закрыто в
//     carry.
// ОБЩЕЕ ПРАВИЛО, ради которого это записано: если защита перечисляет ИМЕНА,
// спрашивать надо не «какого имени не хватает» (их всегда не хватает), а
// «ЧЕМ ЭТИ ИМЕНА ПОРОЖДАЮТСЯ» — и выводить перечень оттуда.
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
//     параметром в третью функцию и напечатанное там под другим именем.
//     ЖИВОЙ ПРИМЕР В ЭТОМ ФАЙЛЕ, предъявленный прогоном (ревью SEC-01):
//     u.connectFail(btn, info, kk) с держателем kk проходит ЗЕЛЁНЫМ —
//     connectFail не в перечне точек вывода, а печать (info.SetText) стоит
//     внутри неё. Расширять перечень на все методы ui значило бы краснеть на
//     каждом законном вызове; это цена, а не недосмотр, и она названа здесь;
//  5а. СБОРКИ ЗНАЧЕНИЯ ЧЕРЕЗ ВЫЗОВ — следствие п. 4, но названо отдельно,
//     потому что из трёх известных форм она самая правдоподобная:
//     parts = append(parts, u.sess.Creds.Password) + strings.Join(parts, " ")
//     и печать результата. Держатель исчезает в возвращаемом значении
//     strings.Join, и ни одна нога его там не видит;
//  5б. ПЕРЕПРИСВОЕНИЯ ИМЕНИ ЗА ГРАНИЦЕЙ ФУНКЦИИ. Четвёртое условие исключения
//     для поля ввода (reboundNames) смотрит ТОЛЬКО В ТУ ЖЕ ФУНКЦИЮ. Если
//     параметр с именем key приходит в функцию уже содержащим не ключ, а
//     пароль, исключение сработает. Это частный случай п. 5 (поток через
//     несколько функций), но назван отдельно, потому что относится к
//     ЕДИНСТВЕННОМУ послаблению сторожа;
//  5в. ТОЧЕК ВЫВОДА ЗА ПРЕДЕЛАМИ РАЗОБРАННЫХ ПАКЕТОВ. Перечень выведен
//     разбором fyne.io/fyne/v2@v2.7.4 (widget, canvas, dialog, корневой fyne)
//     и признаками Set*/Append*. Виджет из СТОРОННЕГО пакета, принимающий
//     текст методом без такого префикса, сторож не увидит; обновление fyne —
//     повод перегнать разбор заново, автоматически это не происходит;
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
var keyInputFields = map[string]bool{
	"keyEntry": true,
}

// widgetTextFields — поля виджетов, запись в которые есть вывод на экран.
// Присваивание в них и композитный литерал с ними — не вызовы, и прежний
// обход по ast.CallExpr их не видел (ревью SEC-01, круг 2).
//
// ОТКУДА ВЗЯТ ЭТОТ ПЕРЕЧЕНЬ — И ПОЧЕМУ НЕ ИЗ ГОЛОВЫ (ревью SEC-01, круг 3).
// Первая редакция перечисляла три поля — Text/Title/PlaceHolder, — то есть те,
// что встретились в коде. SEC-01 обошёл его полем Subtitle виджета Card ценой
// одного слова. Дописать Subtitle значило бы повторить ошибку: перечень имён
// всегда неполон, если имена придумывают, а не ВЫВОДЯТ. Поэтому перечень
// получен РАЗБОРОМ САМОГО ПАКЕТА ВИДЖЕТОВ: экспортированные поля типа string
// у экспортированных структур fyne.io/fyne/v2@v2.7.4 в пакетах widget, canvas,
// dialog и в корневом fyne (обход go/ast по исходникам модуля):
//
//	widget:  Text (Button Check Entry FormItem Hyperlink HyperlinkSegment
//	         Label TextSegment), Title (AccordionItem Card ImageSegment),
//	         Subtitle (Card), PlaceHolder (Entry Select), Selected (RadioGroup
//	         Select), CancelText/SubmitText (Form), HintText (FormItem)
//	canvas:  Text (Text)
//	fyne:    Title/Content (Notification — уведомление ОС), Label (Menu,
//	         MenuItem)
//
// Отброшены как не текст на экране: AppMetadata.{ID,Name,Version},
// Image.File, StaticResource.StaticName. Обновление fyne — повод перегнать
// разбор заново; новое поле вносится сюда видимой строкой диффа.
var widgetTextFields = map[string]bool{
	"Text":        true,
	"Title":       true,
	"Subtitle":    true,
	"PlaceHolder": true,
	"Content":     true,
	"Selected":    true,
	"CancelText":  true,
	"SubmitText":  true,
	"HintText":    true,
	"Label":       true,
}

// allowedKeyRoundTrip — ЕДИНСТВЕННОЕ исключение для поля ввода ключа, и оно
// сужено ПО ЗНАЧЕНИЮ, а не по получателю.
//
// РЕГРЕСС, ИЗ-ЗА КОТОРОГО ЭТО ПЕРЕПИСАНО (ревью SEC-01, круг 2). В круге 1б
// исключение стояло в isSink и было устроено ПО ПОЛУЧАТЕЛЮ: «SetText у
// keyEntry — не вывод». Значит в поле ввода можно было положить ЧТО УГОДНО:
// keyEntry.SetText(u.sess.Creds.Password) проходил ЗЕЛЁНЫМ и выводил пароль
// root в видимое поле на экране. На предыдущей ревизии эта подмена краснела —
// то есть правка, закрывшая девятый корень, открыла восьмую дыру.
// Теперь разрешено ровно одно: вернуть в поле ввода ТО ЖЕ САМОЕ значение,
// которое им и является, — строку ключа (key, keyEntry.Text или значение,
// прочитанное из переменной окружения с ключом). Всё прочее, включая пароль,
// краснеет.
// Проверяется ЧЕТВЁРКА: получатель — поле ввода ключа, вызов — SetText,
// значение — сама строка ключа, И ЭТО ИМЯ НЕ ПЕРЕПРИСВОЕНО ЧУЖИМ ЗНАЧЕНИЕМ
// внутри функции. Ослабь любое из четырёх, и исключение снова станет дырой.
//
// ЧЕТВЁРТОЕ УСЛОВИЕ И ЗАЧЕМ ОНО (ревью SEC-01, круг 3). Три условия
// удовлетворялись одновременно — СЕКРЕТОМ. Прогон SEC-01:
//
//	key := u.sess.Creds.Password
//	keyEntry.SetText(key)          → ЗЕЛЁНО, а на экране пароль root
//
// Получатель — keyEntry, вызов — SetText, «значение» — имя key: все три
// выполнены, потому что значение проверялось ПО ИМЕНИ, а имя назначает автор
// правки. В этом продукте так пишут естественно: в Password лежит либо пароль,
// либо приватный ключ, и назвать его key — не диверсия, а описка.
// Поэтому имя больше не принимается на веру: reboundNames называет имена,
// которым внутри этой функции присвоили ЧТО-ТО, КРОМЕ строки ключа, и для них
// исключение не действует. Заметьте, что перечисленная в шапке обратная
// сторона при этом сохранена: keyEntry.Text = …Password (присваивание) и
// key := u.sess.Creds + Sprint краснеют по-прежнему.
func allowedKeyRoundTrip(sink, recv, holder string, envVars, rebound map[string]bool) bool {
	if sink != ".SetText" || !keyInputFields[recv] {
		return false
	}
	if rebound[holder] {
		// Имя присвоено внутри функции не строкой ключа: смотреть надо на
		// значение, а не на то, как автор его назвал.
		return false
	}
	switch holder {
	case "key", "keyEntry.Text":
		return true
	}
	// Значение из os.Getenv, признанное ключом (envVarsIn), — это та же
	// строка ключа, просто пришедшая невидимым входом. Локальные имена,
	// заражённые ЦЕПОЧКОЙ (c := u.sess.Creds), сюда НЕ попадают: в envVars
	// только имена, прочитанные из окружения.
	return envVars[holder]
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
		// Методы-приёмники текста: у любого получателя.
		//
		// ПОЧЕМУ ЗДЕСЬ ПРИЗНАК, А НЕ ЧЕТЫРЕ ИМЕНИ (ревью SEC-01, круг 3).
		// Прежняя редакция перечисляла SetText/SetTitle/SetPlaceHolder/
		// SetContent — имена, встреченные в коде, — и обходилась методом
		// cd.SetSubTitle(key) виджета Card: то же действие, другое имя.
		// Перечень имён, придуманный по памяти, неполон всегда. Разбор
		// исходников fyne.io/fyne/v2@v2.7.4 (go/ast по widget, canvas, dialog
		// и корневому fyne: экспортированные методы с параметром string) даёт
		// ровно два способа, которыми виджет принимает текст:
		//   Set*    — SetText, SetTitle, SetSubTitle, SetPlaceHolder/
		//             SetPlaceholder, SetContent, SetSelected, SetURLFromString,
		//             SetConfirmText, SetDismissText, SetFileName, SetTitleText;
		//   Append* — Append (CheckGroup, Entry, Form, RadioGroup, TextGrid),
		//             AppendMarkdown (RichText).
		// Поэтому проверяется ПРЕФИКС, а не имя: новый Set-метод в следующей
		// версии fyne закроется сам. Вне обоих признаков остался единственный
		// метод — ParseMarkdown, — он назван отдельно.
		if strings.HasPrefix(name, "Set") || strings.HasPrefix(name, "Append") ||
			name == "ParseMarkdown" || name == "SendNotification" {
			return "." + name
		}
		// Запись в файл или поток мимо os.WriteFile (ревью SEC-01, круг 2):
		// f, _ := os.Create(…); f.WriteString(key) уходил в файл, а сторож
		// знал только os.WriteFile.
		switch name {
		case "Write", "WriteString":
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
		case "fmt", "log", "io":
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
		// КОРНЕВОЙ ПАКЕТ fyne — точка вывода, которой в прежнем перечне не
		// было вовсе (ревью SEC-01, круг 3):
		// fyne.CurrentApp().SendNotification(fyne.NewNotification("k", key))
		// показывает текст УВЕДОМЛЕНИЕМ ОПЕРАЦИОННОЙ СИСТЕМЫ — мимо окна
		// программы и мимо всех виджетов. Разбор исходников даёт здесь
		// конструкторы New* (NewNotification, NewMenu, NewMenuItem,
		// NewStaticResource, LoadResourceFromURLString) и журнал LogError.
		case "fyne":
			if strings.HasPrefix(name, "New") || strings.HasPrefix(name, "Log") ||
				strings.HasPrefix(name, "LoadResource") {
				return "fyne." + name
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

// isKeySourceExpr — является ли выражение САМОЙ СТРОКОЙ КЛЮЧА: имя key,
// keyEntry.Text, поле .Key записи хранилища, значение из переменной окружения
// с ключом, либо любое из перечисленного, обёрнутое вызовом (в коде это
// strings.TrimSpace(keyEntry.Text)). Всё прочее ключом не считается — в том
// числе .Password, даже если ему дали имя key.
func isKeySourceExpr(e ast.Expr, envVars map[string]bool) bool {
	e = unwrapSrc(e)
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name == "key" || envVars[x.Name]
	case *ast.SelectorExpr:
		root, path, rootIsIdent := selectorPath(x)
		if rootIsIdent && keyInputFields[root] && path == ".Text" {
			return true
		}
		return strings.HasSuffix(path, ".Key")
	case *ast.CallExpr:
		// Невидимый вход: k := os.Getenv("AMNEZIA_KEY") — это сама строка
		// ключа, просто пришедшая мимо экрана. Без этой ветки живой код
		// connectScreenWithStatus покраснел бы (проверено прогоном).
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "os" &&
				(sel.Sel.Name == "Getenv" || sel.Sel.Name == "LookupEnv") && len(x.Args) > 0 {
				if lit, ok := x.Args[0].(*ast.BasicLit); ok {
					if name, err := strconv.Unquote(lit.Value); err == nil &&
						(keyEnvNames[name] || keyEnvNameHint(name)) {
						return true
					}
				}
			}
		}
		// strings.TrimSpace(keyEntry.Text), string(b) — обёртка, не смена
		// предмета. Ключом считаем, только если ключ есть среди аргументов.
		for _, a := range x.Args {
			if isKeySourceExpr(a, envVars) {
				return true
			}
		}
	}
	return false
}

// reboundNames — имена, которым внутри функции присвоили значение, НЕ
// являющееся строкой ключа. Для таких имён исключение allowedKeyRoundTrip не
// действует: проверка значения идёт по имени, а имя назначает автор правки.
// Достаточно ОДНОГО такого присваивания в функции — это намеренно строго:
// ложное срабатывание чинится переименованием переменной, пропуск секрета —
// заново настроенным сервером.
func reboundNames(fn ast.Node, envVars map[string]bool) map[string]bool {
	out := map[string]bool{}
	mark := func(lhs, rhs ast.Expr) {
		id, ok := lhs.(*ast.Ident)
		if !ok || id.Name == "_" {
			return
		}
		if !isKeySourceExpr(rhs, envVars) {
			out[id.Name] = true
		}
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Lhs) != len(x.Rhs) {
				return true
			}
			for i, rhs := range x.Rhs {
				mark(x.Lhs[i], rhs)
			}
		case *ast.ValueSpec:
			if len(x.Names) != len(x.Values) {
				return true
			}
			for i, v := range x.Values {
				mark(x.Names[i], v)
			}
		case *ast.RangeStmt:
			if x.Value != nil {
				mark(x.Value, x.X)
			}
		}
		return true
	})
	return out
}

// holdersNoCall — поиск держателей, НЕ СПУСКАЮЩИЙСЯ В ВЫЗОВ. Нужен carry для
// контейнера и склейки: внутри них заражение переносится, но если там стоит
// вызов, его результат держателем не считается (граница, п. 4 и 5а шапки).
func holdersNoCall(e ast.Expr, tainted map[string]bool) []string {
	var found []string
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr, *ast.FuncLit:
			return false
		case *ast.SelectorExpr:
			if classify(x, tainted) == verdictForbidden {
				root, path, _ := selectorPath(x)
				found = append(found, root+path)
			}
			return false
		case *ast.Ident:
			if classify(x, tainted) == verdictForbidden {
				found = append(found, x.Name)
			}
			return false
		}
		return true
	})
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

// unwrapSrc снимает обёртки, не меняющие держателя: (x), *x, &x, x[i].
func unwrapSrc(e ast.Expr) ast.Expr {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.UnaryExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		default:
			return e
		}
	}
}

// taintedIn — ВТОРАЯ НОГА: перенос держателя в локальное имя, В ЛЮБОЙ ФОРМЕ
// ЗАПИСИ. Ловит локальный обход (p := cfg["password"]; c := u.sess.Creds).
//
// ПОЧЕМУ «В ЛЮБОЙ ФОРМЕ ЗАПИСИ» НАПИСАНО ТАК НАСТОЙЧИВО (ревью SEC-01,
// круг 2). Прежняя редакция разбирала только ast.AssignStmt, то есть только
// запись через `:=` и `=`. Обход — одна клавиша: `var c = u.sess.Creds`
// (ast.ValueSpec) проходил ЗЕЛЁНЫМ, делая то же самое. Это тот же дефект,
// что нашли у признаков «ветка else» и «будущее время»: правило описывало
// ФОРМУ последнего примера, а не свойство класса. Поэтому здесь разбираются
// все три формы, которыми значение попадает в новое имя: присваивание,
// объявление переменной и переменная цикла range. При добавлении новой
// формы вопрос задаётся тот же: «а если то же самое написать иначе?»
func taintedIn(fn ast.Node) map[string]bool {
	tainted := envVarsIn(fn) // невидимый вход — тоже держатель, с первого круга

	// carry помечает имя lhs, если значение src — держатель.
	//
	// ПОЧЕМУ СЮДА ДОБАВЛЕНЫ КОНТЕЙНЕР И СКЛЕЙКА (ревью SEC-01, круг 3).
	// Прежняя редакция переносила имя только из Ident и SelectorExpr, и
	// составное выражение теряло заражение целиком. Четыре обхода ценой одной
	// строки, все синтаксически безупречные:
	//   m := map[string]string{"k": key};  info.SetText(m["k"])
	//   s := []string{key};                info.SetText(s[0])
	//   box := struct{ S string }{S: key}; info.SetText(box.S)
	//   var kk = "ключ- " + key            (склейка В ИМЯ; прямая склейка
	//                                      в аргументе печати уже краснела)
	// Это тот же дефект, что закрывали в круге 2 у формы записи: правило
	// описывало ФОРМУ выражения, а не его смысл — «значение держателя
	// оказалось под новым именем». Контейнер и склейка ничего не вычисляют,
	// они только ПЕРЕУПАКОВЫВАЮТ; вынуть обратно можно тем же селектором или
	// индексом, а findHolders уже умеет спускаться в оба.
	//
	// ЧЕМ КОНТЕЙНЕР ОТЛИЧАЕТСЯ ОТ ВЫЗОВА, который ОСТАЛСЯ в границе (п. 4
	// шапки). Вызов — это чужой код: что он вернёт, сторож не знает, и
	// sess, err := core.ConnectWithHostKey(creds, …) пометил бы err, а за ним
	// покраснело бы каждое законное err.Error(). Контейнер и склейка — не
	// чужой код, а та же память под другим именем, видимая в этой же строке.
	// Поэтому источник разбирается holdersNoCall — поиском, который В ВЫЗОВ НЕ
	// СПУСКАЕТСЯ: strings.Join(parts, " ") не заразит имя и здесь (п. 5а
	// границы остаётся в силе — это цена, а не недосмотр).
	carry := func(lhs ast.Expr, src ast.Expr) {
		src = unwrapSrc(src)
		switch src.(type) {
		case *ast.Ident, *ast.SelectorExpr:
			if classify(src, tainted) != verdictForbidden {
				return
			}
		case *ast.CompositeLit, *ast.BinaryExpr:
			// Контейнер (map/slice/struct) и склейка строк: держатель внутри
			// них никуда не делся, он лишь переупакован.
			if len(holdersNoCall(src, tainted)) == 0 {
				return
			}
		default:
			return // вызов и литерал — не перенос имени (границы п. 4, 5а)
		}
		if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
			tainted[id.Name] = true
		}
	}

	// Несколько проходов: c := u.sess.Creds; p := c — второе видно только
	// после первого.
	for round := 0; round < 5; round++ {
		before := len(tainted)
		ast.Inspect(fn, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt: // c := u.sess.Creds  /  c = u.sess.Creds
				if len(x.Lhs) != len(x.Rhs) {
					return true
				}
				for i, rhs := range x.Rhs {
					carry(x.Lhs[i], rhs)
				}
			case *ast.ValueSpec: // var c = u.sess.Creds  /  var c T = …
				if len(x.Names) != len(x.Values) {
					return true
				}
				for i, v := range x.Values {
					carry(x.Names[i], v)
				}
			case *ast.RangeStmt: // for _, c := range []*ServerCreds{u.sess.Creds}
				if classifySubtree(x.X, tainted) && x.Value != nil {
					if id, ok := x.Value.(*ast.Ident); ok && id.Name != "_" {
						tainted[id.Name] = true
					}
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

// classifySubtree — есть ли в поддереве хоть один запрещённый держатель.
// Нужен для range: держатель прячется внутри литерала-среза.
func classifySubtree(e ast.Expr, tainted map[string]bool) bool {
	return len(findHolders(e, tainted)) > 0
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
			envVars := envVarsIn(fn)
			rebound := reboundNames(fn, envVars)
			report := func(n ast.Node, sink, recv string, args []ast.Expr) {
				for _, arg := range args {
					for _, h := range findHolders(arg, tainted) {
						if allowedKeyRoundTrip(sink, recv, h, envVars, rebound) {
							continue
						}
						pos := fset.Position(n.Pos())
						holders = append(holders, holderSite{fn: fn.Name.Name,
							file: filepath.Base(pos.Filename), line: pos.Line, sink: sink, expr: h})
					}
				}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
						if pkg, ok := sel.X.(*ast.Ident); ok && jsonNames[pkg.Name] && jsonMethods[sel.Sel.Name] {
							pos := fset.Position(x.Pos())
							encs = append(encs, encSite{fn: fn.Name.Name, file: filepath.Base(pos.Filename),
								line: pos.Line, method: sel.Sel.Name, expr: pkg.Name + "." + sel.Sel.Name})
						}
					}
					if sink := isSink(x, jsonNames); sink != "" {
						recv := ""
						if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
							if id, ok := sel.X.(*ast.Ident); ok {
								recv = id.Name
							}
						}
						report(x, sink, recv, x.Args)
					}
				case *ast.AssignStmt:
					// ПРИСВАИВАНИЕ В ПОЛЕ ВИДЖЕТА — не вызов, а вывод (ревью
					// SEC-01, круг 2): lbl.Text = key показывает ключ на
					// экране ровно так же, как lbl.SetText(key), но прежний
					// обход смотрел только ast.CallExpr и проходил зелёным.
					for i, lhs := range x.Lhs {
						sel, ok := lhs.(*ast.SelectorExpr)
						if !ok || !widgetTextFields[sel.Sel.Name] || i >= len(x.Rhs) {
							continue
						}
						report(x, "присваивание ."+sel.Sel.Name, "", []ast.Expr{x.Rhs[i]})
					}
				case *ast.CompositeLit:
					// КОМПОЗИТНЫЙ ЛИТЕРАЛ — по той же причине:
					// &widget.Entry{Text: key} выводит ключ и вызовом не
					// является.
					for _, el := range x.Elts {
						kv, ok := el.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						k, ok := kv.Key.(*ast.Ident)
						if !ok || !widgetTextFields[k.Name] {
							continue
						}
						report(x, "литерал с полем "+k.Name, "", []ast.Expr{kv.Value})
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

	t.Run("перенос держателя в любой форме записи", func(t *testing.T) {
		// Ревью SEC-01, круг 2: прежняя редакция знала только `:=`/`=`.
		for _, src := range []struct{ name, code string }{
			{"присваивание", "c := u.sess.Creds"},
			{"объявление var", "var c = u.sess.Creds"},
			{"var с типом", "var c *core.ServerCreds = u.sess.Creds"},
			{"range по срезу держателей", "for _, c := range []*core.ServerCreds{u.sess.Creds} { _ = c }"},
		} {
			t.Run(src.name, func(t *testing.T) {
				f, err := parser.ParseFile(token.NewFileSet(), "x.go",
					"package main\nfunc f() {\n"+src.code+"\n_ = c\n}", 0)
				if err != nil {
					t.Fatalf("разбор образца: %v", err)
				}
				if !taintedIn(f)["c"] {
					t.Errorf("держатель, перенесённый записью %q, не помечен — "+
						"обход одной клавишей: та же конструкция, другая форма записи", src.code)
				}
			})
		}
	})

	t.Run("исключение для поля ввода ключа сужено по значению", func(t *testing.T) {
		env := map[string]bool{"k": true}
		noReb := map[string]bool{}
		if !allowedKeyRoundTrip(".SetText", "keyEntry", "key", env, noReb) {
			t.Error("возврат самой строки ключа в своё поле ввода должен быть разрешён")
		}
		if !allowedKeyRoundTrip(".SetText", "keyEntry", "k", env, noReb) {
			t.Error("ключ из окружения в своё поле ввода должен быть разрешён")
		}
		if allowedKeyRoundTrip(".SetText", "keyEntry", "u.sess.Creds.Password", env, noReb) {
			t.Error("РЕГРЕСС круга 1б: пароль root в поле ввода ключа разрешён — " +
				"исключение снова построено по получателю, а не по значению")
		}
		if allowedKeyRoundTrip(".SetText", "statusLabel", "key", env, noReb) {
			t.Error("ключ разрешён в ЧУЖОЙ виджет — проверяется тройка (получатель, вызов, значение)")
		}
		if allowedKeyRoundTrip(".SetPlaceHolder", "keyEntry", "key", env, noReb) {
			t.Error("ключ разрешён в подсказку поля — исключение только для SetText")
		}
		if allowedKeyRoundTrip(".SetText", "keyEntry", "key", env, map[string]bool{"key": true}) {
			t.Error("РЕГРЕСС круга 2: имя key, переприсвоенное чужим значением, всё ещё " +
				"пользуется исключением — значение проверяется по имени, а имя назначает автор правки")
		}
	})

	t.Run("имя key, присвоенное паролем, теряет исключение", func(t *testing.T) {
		// Прогон SEC-01, круг 3: все три прежних условия исключения
		// выполнены, а на экране пароль root.
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", `package main
func f() {
	key := u.sess.Creds.Password
	keyEntry.SetText(key)
}`, 0)
		if err != nil {
			t.Fatalf("разбор образца: %v", err)
		}
		fd := f.Decls[0].(*ast.FuncDecl)
		if !reboundNames(fd, envVarsIn(fd))["key"] {
			t.Error("имя key, которому присвоили .Password, не помечено переприсвоенным — " +
				"исключение для поля ввода снова удовлетворимо секретом")
		}
	})

	t.Run("законный ключ исключения не теряет", func(t *testing.T) {
		// Обратная сторона той же правки: имя key, присвоенное самой строкой
		// ключа (в коде — через strings.TrimSpace), краснеть не должно.
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", `package main
func f() {
	key := strings.TrimSpace(keyEntry.Text)
	keyEntry.SetText(key)
}`, 0)
		if err != nil {
			t.Fatalf("разбор образца: %v", err)
		}
		fd := f.Decls[0].(*ast.FuncDecl)
		if reboundNames(fd, envVarsIn(fd))["key"] {
			t.Error("key := strings.TrimSpace(keyEntry.Text) помечен переприсвоенным — " +
				"сторож покраснеет на живом коде подключения")
		}
	})

	t.Run("перенос держателя через контейнер и склейку", func(t *testing.T) {
		// Ревью SEC-01, круг 3: составное выражение теряло заражение.
		for _, src := range []struct{ name, code, want string }{
			{"map", `m := map[string]string{"k": key}`, "m"},
			{"срез", `s := []string{key}`, "s"},
			{"структура", `box := struct{ S string }{S: key}`, "box"},
			{"склейка в имя", `kk := "ключ- " + key`, "kk"},
			{"var со склейкой", `var kk = "ключ- " + key`, "kk"},
		} {
			t.Run(src.name, func(t *testing.T) {
				f, err := parser.ParseFile(token.NewFileSet(), "x.go",
					"package main\nfunc f() {\n"+src.code+"\n}", 0)
				if err != nil {
					t.Fatalf("разбор образца: %v", err)
				}
				if !taintedIn(f)[src.want] {
					t.Errorf("держатель, переупакованный записью %q, не помечен — "+
						"контейнер и склейка ничего не вычисляют, они только переупаковывают", src.code)
				}
			})
		}
	})

	t.Run("склейка с вызовом заражения не переносит", func(t *testing.T) {
		// Граница п. 4 и 5а шапки остаётся в силе: результат вызова
		// держателем не считается, иначе покраснеет законный err.Error().
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", `package main
func f() {
	msg := "ошибка: " + err.Error()
	_ = msg
}`, 0)
		if err != nil {
			t.Fatalf("разбор образца: %v", err)
		}
		if taintedIn(f)["msg"] {
			t.Error("склейка с результатом вызова заразила имя — сторож покраснеет на честном коде")
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
