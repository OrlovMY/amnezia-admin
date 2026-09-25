package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode"

	"amnezia-admin/core"
)

// ActionCard — то, что человек видит перед необратимым действием: и в
// интерактивном меню (пункты 3/7/8), и в подкомандах del/rekey/toggle.
// Один и тот же текст в обоих местах (Г3) — печатается через renderCard.
type ActionCard struct {
	Action    string // "удалить" | "перевыпустить конфиг" | "отключить"
	Host      string // sess.Creds.Host
	Container string // c.Name
	Name      string // cl.Name()
	Created   string // cl.Created(), обрезанный до 19 символов, как в listUsers (main.go)
	Key       string // cl.ClientID

	// Seen — поле «Последнее подключение» ОДНИМ значением-исходом
	// (core.ClassifyLastSeen): не удалось / отключён / нет в ответе / не
	// подключался / было. Прежде здесь лежали строка LastSeen и два
	// независимых bool (LastSeenUnknown, LastSeenAbsent) — четыре
	// комбинации, и противоречие «—» + «нет в ответе» разрешал только
	// порядок switch при печати (ревью QA-01, задание НЕЗНАНИЕ-ТРАФИК).
	// Состояние не выводится из текста: тест утверждает по исходу.
	Seen core.LastSeen
}

// Дословные тексты поля «Последнее подключение» для исходов без даты.
const (
	textLastSeenUnknown  = "не удалось получить данные"
	textLastSeenDisabled = "неизвестно (клиент отключён)"
	textLastSeenAbsent   = "нет в статистике сервера (сейчас сервер его не принимает)"
	textLastSeenNever    = "—"
)

// capitalizeFirst делает первую букву заглавной, по рунам (не по байтам —
// кириллица многобайтовая, s[:1] отрезал бы половину первой буквы).
func capitalizeFirst(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// trunc19 обрезает строку до 19 рун — тот же лимит, что применяется к
// колонке "Создан" в listUsers (main.go), чтобы карточка показывала то же
// значение, что и таблица пользователей.
func trunc19(s string) string {
	if r := []rune(s); len(r) > 19 {
		return string(r[:19])
	}
	return s
}

// renderCard — единственное место с текстом карточки подтверждения; и меню,
// и подкоманды вызывают только его (TestCardTextSharedBetweenMenuAndSubcommand).
func renderCard(card ActionCard) string {
	var b strings.Builder
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, cHead("Действие: "+card.Action))
	fmt.Fprintln(&b, "  Сервер:                 "+card.Host)
	fmt.Fprintln(&b, "  Контейнер:              "+card.Container)
	fmt.Fprintln(&b, "  Имя:                    "+cHead(card.Name))
	fmt.Fprintln(&b, "  Создан:                 "+card.Created)
	var lastSeen, warn string
	switch card.Seen.State {
	case core.SeenWas:
		lastSeen = card.Seen.When
		warn = "  ⚠ Внимание: у этого клиента была активность."
	case core.SeenNever:
		lastSeen = textLastSeenNever
	case core.SeenDisabled:
		lastSeen = textLastSeenDisabled
	case core.SeenAbsent:
		lastSeen = textLastSeenAbsent
		warn = "  ⚠ Клиента нет в статистике сервера — неизвестно, подключался ли он раньше."
	default: // core.SeenFailed и любое незаполненное значение — незнание
		lastSeen = textLastSeenUnknown
		// Незнание печатается ТАМ ЖЕ, где печаталась бы активность, и той
		// же меткой внимания.
		warn = "  ⚠ Внимание: статистику с сервера получить не удалось — " +
			"неизвестно, пользуется ли клиент этим доступом."
	}
	fmt.Fprintln(&b, "  Последнее подключение:  "+lastSeen)
	fmt.Fprintln(&b, "  Публичный ключ:         "+cDim(card.Key))
	if warn != "" {
		fmt.Fprintln(&b, cWarn(warn))
	}
	if card.Action == "перевыпустить конфиг" {
		// раньше это предупреждение печаталось только в меню (main.go, пункт
		// 8); подкоманда rekey его не показывала вовсе (ревью PR-5, Medium-2).
		// В GUI такое предупреждение уже есть — CLI молчал.
		fmt.Fprintln(&b, cWarn("  ⚠ Старый конфиг перестанет работать, пользователю нужно установить новый."))
	}
	return b.String()
}

// buildCard собирает ActionCard из текущего состояния сессии — единая точка
// сборки, чтобы поля карточки в меню и в подкомандах не расходились.
func buildCard(sess *core.Session, cur *core.Container, cl core.ClientEntry, action string) ActionCard {
	// Прямой вызов при сборке карточки (как и было): данные свежие в момент
	// принятия решения. Ошибка НЕ отбрасывается — она и есть третье
	// состояние (A1, место № 5).
	hs, err := sess.GetHandshakes(cur)
	return ActionCard{
		Action:    action,
		Host:      sess.Creds.Host,
		Container: cur.Name,
		Name:      cl.Name(),
		Created:   trunc19(cl.Created()),
		Seen:      core.ClassifyLastSeen(hs, err, cl.ClientID, cl.Disabled()),
		Key:       cl.ClientID,
	}
}

// readLine читает одну строку из in. Если in уже *bufio.Reader (как in в
// interactive() — общий на весь цикл меню), читаем прямо через него, а не
// оборачиваем в новый bufio.NewReader: второй слой съел бы вставленные
// заранее строки (пайп, ввод в несколько строк подряд) в свой собственный
// буфер, и следующий ask() в меню их бы не увидел (ревью PR-5, Low-6).
func readLine(in io.Reader) string {
	if br, ok := in.(*bufio.Reader); ok {
		line, _ := br.ReadString('\n')
		return line
	}
	line, _ := bufio.NewReader(in).ReadString('\n')
	return line
}

// needsConfirm — нужен ли вопрос для подкоманды cmd над записью cl.
// del → true; rekey → true; toggle → true, если cl активен (то есть будет
// ОТКЛЮЧЁН); toggle над отключённым (включение) → false; rename, add, list
// и всё прочее → false.
func needsConfirm(cmd string, cl core.ClientEntry) bool {
	switch cmd {
	case "del", "rekey":
		return true
	case "toggle":
		return !cl.Disabled()
	default:
		return false
	}
}

// confirmSubcommand — обвязка "нужен ли вопрос → карточка → confirmOrExit"
// для CLI-подкоманд (del/rekey/toggle в main()). Вынесена из трёх одинаковых
// копий в case-ветках (ревью PR-5, Medium-4; по образцу runDryRun) — раньше
// пропажа os.Exit(code) в любой из трёх копий не давила ни один тест, а цена
// такой пропажи — необратимое действие вопреки отказу. os.Exit — на стороне
// вызывающего (main()), не здесь: os.Exit убил бы тестовый процесс, поэтому
// функция только решает (proceed, code), как и confirmOrExit. Если
// needsConfirm==false — buildCard/confirmOrExit не вызываются вовсе (не
// трогаем GetHandshakes и не печатаем карточку для rename/add и подобных).
func confirmSubcommand(in io.Reader, out, errOut io.Writer, isTTY, yes bool, cmd string, cl core.ClientEntry, sess *core.Session, cur *core.Container, action string) (proceed bool, code int) {
	if !needsConfirm(cmd, cl) {
		return true, 0
	}
	card := buildCard(sess, cur, cl, action)
	return confirmOrExit(in, out, errOut, isTTY, yes, card)
}

// confirmOrExit решает судьбу необратимого действия. Карточка печатается в
// out всегда — даже при yes=true, чтобы действие осталось в журнале скрипта.
//
//	yes=true              → proceed=true без вопроса, code=0; in не читается.
//	isTTY=false && !yes    → "без терминала требуется -yes" в errOut,
//	                         proceed=false, code=2.
//	isTTY=true && !yes     → вопрос "<Действие> %q? (y/n): " в out; читает
//	                         одну строку из in; "y"/"yes" без учёта регистра
//	                         → proceed=true, code=0; иначе — "Отменено." в
//	                         out, proceed=false, code=2 (в т.ч. пустой ответ —
//	                         иначе скрипт не отличит "отменил" от "сделал").
func confirmOrExit(in io.Reader, out, errOut io.Writer, isTTY, yes bool, card ActionCard) (proceed bool, code int) {
	fmt.Fprint(out, renderCard(card))
	if yes {
		return true, 0
	}
	if !isTTY {
		fmt.Fprintln(errOut, "Действие не выполнено: без терминала требуется флаг -yes (для скриптов).")
		return false, 2
	}
	fmt.Fprintf(out, "%s %q? (y/n): ", capitalizeFirst(card.Action), card.Name)
	answer := strings.ToLower(strings.TrimSpace(readLine(in)))
	if answer == "y" || answer == "yes" {
		return true, 0
	}
	fmt.Fprintln(out, "Отменено.")
	return false, 2
}
