// amnezia-admin — консольная утилита администрирования сервера Amnezia VPN.
//
// Запуск без аргументов — интерактивный режим: вводите ключ vpn://,
// утилита определяет сервер, протоколы и показывает меню доступных команд.
//
// Также поддерживаются подкоманды для скриптов:
//
//	amnezia-admin decode -key vpn://...
//	amnezia-admin list   -key vpn://...
//	amnezia-admin add    -key vpn://... -name Vasya
//	amnezia-admin del    -key vpn://... -name Vasya
//	amnezia-admin rename -key vpn://... -name Vasya -newname "Vasya Ivanov"
//	amnezia-admin toggle -key vpn://... -name Vasya
//	amnezia-admin rekey  -key vpn://... -name Vasya
//	amnezia-admin version
//	amnezia-admin check
//
// Подкоманда check печатает признаки окружения (ОС, архитектура, библиотека
// C, библиотеки графики, графическая сессия) и говорит заранее, запустится
// ли графическая версия; ключ, сеть и права администратора ей не нужны.
//
// Флаг -dry-run (для add/del/rename/toggle/rekey) показывает diff wg0.conf и
// clientsTable, которые получились бы после операции, ничего не записывая на
// сервер:
//
//	amnezia-admin add -key vpn://... -name Vasya -dry-run
//
// Необратимые команды (del, rekey и toggle в сторону отключения) требуют
// подтверждения: у терминала печатают карточку (сервер/контейнер/имя/дата
// создания/последнее подключение/ключ) и спрашивают "y/n"; без терминала —
// только флаг -yes (для скриптов), без него — отказ. -dry-run побеждает
// -yes: план печатается, ничего не пишется, вопрос не задаётся.
//
//	amnezia-admin del -key vpn://... -name Vasya -yes
//
// Коды возврата: 0 — успех; 1 — ошибка; 2 — отказ из-за отсутствия
// подтверждения (нет терминала и нет -yes, либо явный отказ "n" у терминала).
// Подкоманда check возвращает 0 всегда — в том числе когда графическая
// версия не запустится и когда что-то определить не удалось: это факт об
// окружении, а не ошибка утилиты.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"amnezia-admin/core"
	"amnezia-admin/internal/envcheck"
	"amnezia-admin/internal/version"
)

// ---------- печать конфига vpn:// (A2, SEC-01) ----------
//
// Раньше decode и пункт меню «5» печатали json.MarshalIndent(cfg) целиком.
// В конфиге лежит ключ "password", и в нём — ПАРОЛЬ ROOT ЛИБО ПРИВАТНЫЙ
// SSH-КЛЮЧ: core/hostkey.go:144 выбирает способ входа по
// strings.Contains(creds.Password, "PRIVATE KEY"), то есть одно из двух там
// всегда. Напечатанный пароль root отозвать нельзя — он уходит в
// перенаправленный вывод, в журнал, в запись терминала и в скриншот.
//
// Приём — перечислять ДОПУСТИМОЕ, а не недопустимое: список способов утечь
// бесконечен, список полей, которые человеку имеет право показать, конечен.
// Вывод строится ИЗ КОНФИГА (печатается имя каждого фактического ключа,
// сколько бы их ни было), а списки управляют ТОЛЬКО значениями — человек,
// читающий decode, должен видеть, какие поля в ключе есть: это и есть
// диагностика. Что в них лежит, мы не знаем, и потому не показываем:
// «не знаем, секретное ли» → не «наверное, нет», а «показываем факт
// существования, скрываем содержимое».
//
// ДВА СПИСКА, И ЗАПРЕЩАЮЩИЙ СИЛЬНЕЕ РАЗРЕШАЮЩЕГО. Проверка на
// configDeniedKeys идёт ДО проверки на configAllowedKeys. Если бы "password"
// скрывался лишь потому, что его нет в разрешающем списке, защитой было бы
// ОТСУТСТВИЕ строки, а отсутствие строки никто не охраняет: одно слово,
// когда-нибудь дописанное в разрешающий список «для диагностики», открыло бы
// пароль root, и в диффе это выглядело бы невинно. При двух списках такое
// добавление не даёт эффекта, а удаление "password" из запрещающего — видимое
// удаление строки, и его ловит тест TestDecodeMasksPassword.
//
// Формат вывода НЕ меняется: это по-прежнему отступованный JSON-объект,
// разбираемый как JSON. decode объявлен подкомандой для скриптов (шапка
// файла), и его вывод — договор, а не украшение; меняются только значения.
// Порядок ключей детерминирован: encoding/json сортирует ключи map по имени.
var (
	// configAllowedKeys — закрытый список ключей, значения которых печатаются
	// как есть. Ровно то, что продукт вообще умеет читать из конфига
	// (core/core.go:104–107) за вычетом password; containers обнаруживаются
	// НА СЕРВЕРЕ (core.FindContainers), а не берутся из ключа. Расширяется
	// только решением ядра — одной видимой строкой диффа.
	configAllowedKeys = map[string]bool{
		"hostName": true,
		"userName": true,
		"port":     true,
	}
	// configDeniedKeys — явный запрещающий список. В "password" лежит пароль
	// root либо приватный SSH-ключ (core/hostkey.go:144).
	configDeniedKeys = map[string]bool{
		"password": true,
	}
)

// configHiddenPlaceholder — та же форма, что в core/txn.go:maskSecrets,
// чтобы в продукте не завелось двух разных плейсхолдеров.
const configHiddenPlaceholder = "<скрыто>"

// redactConfig возвращает копию конфига, пригодную к печати: имена всех
// фактических ключей сохранены, значения — по спискам выше.
//
// Три состояния поля различимы, и это требование, а не вкус: «скрыто» и
// «пусто» — разные факты, и человек, читающий вывод, обязан их различать,
// иначе он решит, что пароля в ключе нет, и пойдёт искать несуществующую
// проблему.
//
//	поле отсутствует в конфиге → строки нет вовсе;
//	поле есть и пусто          → "password": "";
//	поле есть и скрыто         → "password": "<скрыто>".
//
// Маскированное значение — строка независимо от исходного типа: если поле
// было массивом или объектом, оно становится строкой. Это осознанно —
// показать структуру значения значит показать часть значения.
func redactConfig(cfg map[string]any) map[string]any {
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		// Пустая строка — не секрет (скрывать нечего), и она обязана
		// отличаться от скрытого значения: см. три состояния выше.
		if s, ok := v.(string); ok && s == "" {
			out[k] = ""
			continue
		}
		switch {
		case configDeniedKeys[k]: // ДО проверки на разрешённость — см. шапку
			out[k] = configHiddenPlaceholder
		case configAllowedKeys[k]:
			out[k] = v
		default:
			out[k] = configHiddenPlaceholder
		}
	}
	return out
}

// printConfig печатает конфиг через redactConfig. Единственная точка печати
// конфига в CLI: и decode, и пункт меню «5» идут через неё.
// json.Encoder с SetEscapeHTML(false), а не json.MarshalIndent: последний
// экранирует "<" и ">" в </>, и плейсхолдер печатался бы как
// "<скрыто>" — не та форма, что в core/txn.go:maskSecrets, и не та,
// что утверждена UI-01. Отступ прежний (два пробела), вывод остаётся
// разбираемым JSON: обе формы разбираются в одну и ту же строку.
func printConfig(w io.Writer, cfg map[string]any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(redactConfig(cfg)); err != nil {
		// Молчаливое «ничего не напечатали» неотличимо от пустого конфига —
		// говорим прямо, но без содержимого конфига в тексте ошибки.
		fmt.Fprintln(w, "не удалось собрать вывод конфига")
	}
}

func pad(s string, n int) string {
	if d := n - len([]rune(s)); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// listUsers печатает таблицу пользователей в w и возвращает отсортированный
// по активности slice — тот же порядок, что показан в таблице (нумерация
// "#" в выводе соответствует индексам этого slice), чтобы вызывающий код мог
// резолвить номер строки без повторного LoadClients. w — параметр (не
// os.Stdout напрямую) начиная с PR-4 (Е3): interactive() передаёт os.Stdout,
// run() — свой stdout io.Writer, чтобы TestNonTTYUnknownHostNeedsHostkey мог
// перехватить вывод подкоманды list без чтения реального os.Stdout.
func listUsers(w io.Writer, s *core.Session, c *core.Container) ([]core.ClientEntry, error) {
	if !c.Managed {
		return nil, fmt.Errorf("для протокола %s управление пользователями не реализовано (поддерживаются AmneziaWG и WireGuard)", c.Proto)
	}
	clients, err := s.LoadClients(c)
	if err != nil {
		return nil, err
	}
	stats, err := s.GetPeerStats(c)
	if err != nil {
		stats = map[string]core.PeerStat{}
	}
	core.SortByActivity(clients, stats)

	if len(clients) == 0 {
		fmt.Fprintln(w, "В clientsTable записей нет.")
	} else {
		fmt.Fprintln(w)
		fmt.Fprintln(w, cHead(pad("#", 4)+pad("Имя", 34)+pad("Создан", 21)+pad("Активность", 18)+pad("Трафик ↓/↑", 24)+"Публичный ключ"))
		fmt.Fprintln(w, cDim(strings.Repeat("─", 4+34+21+18+24+44)))
		for i, cl := range clients {
			created := cl.Created()
			if r := []rune(created); len(r) > 19 {
				created = string(r[:19])
			}
			var hs string
			if cl.Disabled() {
				hs = cDim(pad("(откл.)", 18))
			} else {
				st := stats[cl.ClientID]
				if st.LastHandshake.IsZero() {
					hs = cDim(pad("—", 18))
				} else {
					hs = cOK(pad(st.LastHandshake.Format("2006-01-02 15:04"), 18))
				}
			}
			st := stats[cl.ClientID]
			traffic := core.HumanBytes(st.RxBytes) + " / " + core.HumanBytes(st.TxBytes)
			name := cl.Name()
			if cl.Disabled() {
				name = cDim(pad(name, 34))
			} else {
				name = pad(name, 34)
			}
			fmt.Fprintln(w, cNum(pad(strconv.Itoa(i+1), 4))+name+cDim(pad(created, 21))+hs+pad(traffic, 24)+cDim(cl.ClientID))
		}
		fmt.Fprintln(w, cDim("Трафик и активность — с момента перезапуска сервера."))
	}

	if orphans := s.OrphanPeers(c, clients); len(orphans) > 0 {
		fmt.Fprintf(w, "\nPeers в wg0.conf без имени в clientsTable: %d\n", len(orphans))
		for _, o := range orphans {
			fmt.Fprintln(w, "  ", o)
		}
	}
	return clients, nil
}

// saveUserConfig — см. listUsers про параметр w (Е3).
func saveUserConfig(w io.Writer, u *core.NewUser, proto string) error {
	if err := os.MkdirAll("Конфигурации", 0755); err != nil {
		return err
	}
	fileName := filepath.Join("Конфигурации", core.SanitizeName(u.Name)+".conf")
	if err := os.WriteFile(fileName, []byte(u.Config), 0600); err != nil {
		return err
	}
	abs, _ := filepath.Abs(fileName)
	fmt.Fprintln(w)
	fmt.Fprintln(w, cOK(fmt.Sprintf("Пользователь %q создан (IP %s, протокол %s).", u.Name, u.IP, proto)))
	fmt.Fprintln(w, "Конфиг сохранён: "+cAccent(abs))
	fmt.Fprintln(w, "Импортируйте файл в приложение AmneziaWG или Amnezia (Импорт → выбрать .conf).")
	return nil
}

func printContainers(containers []core.Container, withNotes bool) {
	for i, c := range containers {
		note := ""
		if withNotes && !c.Managed {
			note = cDim(" (только просмотр, управление не поддерживается)")
		}
		fmt.Printf("  %s %s %s%s\n", cNum(strconv.Itoa(i+1)+"."), c.Proto, cDim("["+c.Name+"]"), note)
	}
}

// printPlan печатает построчный diff по обоим файлам плана в формате
// "--- <path> (было) / +++ <path> (станет)" — общая функция для -dry-run
// (Е1) и её регресс-теста (Е4: TestDryRunFlagPrintsDiffAndWritesNothing),
// который вызывает её напрямую на плане, собранном на fakesrv.
func printPlan(w io.Writer, p *core.Plan) {
	wgDiff, tblDiff := p.Diff()
	dir := p.Container.Dir
	printFileDiff(w, dir+"/wg0.conf", wgDiff)
	printFileDiff(w, dir+"/clientsTable", tblDiff)
}

func printFileDiff(w io.Writer, path, diff string) {
	fmt.Fprintf(w, "--- %s (было)\n+++ %s (станет)\n", path, path)
	if diff == "" {
		fmt.Fprintln(w, "(без изменений)")
		return
	}
	fmt.Fprint(w, diff)
}

// runDryRun строит план для cmd (add/del/rename/toggle/rekey) и печатает его
// diff через printPlan, ничего не записывая на сервер — тело -dry-run веток
// main() (Е1), вынесенное в отдельную функцию (ревью BE-01, круг 2, Medium):
// сама обвязка флага (разбор, пять веток, break после печати) раньше ничем
// не стереглась, тест звал только printPlan напрямую. Для add/rekey конфиг
// с приватным ключом (plan.result.Config) не печатается и не сохраняется —
// план ещё не применён, конфиг с ним мог бы и не заработать.
func runDryRun(w io.Writer, sess *core.Session, cur *core.Container, cmd, name, newname string) error {
	printAndDone := func(plan *core.Plan) error {
		printPlan(w, plan)
		fmt.Fprintln(w, "Ничего не записано (dry-run).")
		return nil
	}
	switch cmd {
	case "add":
		plan, err := sess.PlanAddUser(cur, name)
		if err != nil {
			return err
		}
		return printAndDone(plan)
	case "del":
		// вне интерактивного списка номер строки ничего не значит —
		// принимаем только имя или публичный ключ (см. core.ResolveNonNumeric)
		clients, err := sess.LoadClients(cur)
		if err != nil {
			return err
		}
		idx, err := core.ResolveNonNumeric(clients, name)
		if err != nil {
			return err
		}
		plan, err := sess.PlanDelete(cur, clients[idx].ClientID)
		if err != nil {
			return err
		}
		return printAndDone(plan)
	case "rename":
		clients, err := sess.LoadClients(cur)
		if err != nil {
			return err
		}
		idx, err := core.ResolveNonNumeric(clients, name)
		if err != nil {
			return err
		}
		plan, err := sess.PlanRename(cur, clients[idx].ClientID, newname)
		if err != nil {
			return err
		}
		return printAndDone(plan)
	case "toggle":
		clients, err := sess.LoadClients(cur)
		if err != nil {
			return err
		}
		idx, err := core.ResolveNonNumeric(clients, name)
		if err != nil {
			return err
		}
		enable := clients[idx].Disabled()
		plan, err := sess.PlanSetEnabled(cur, clients[idx].ClientID, enable)
		if err != nil {
			return err
		}
		return printAndDone(plan)
	case "rekey":
		clients, err := sess.LoadClients(cur)
		if err != nil {
			return err
		}
		idx, err := core.ResolveNonNumeric(clients, name)
		if err != nil {
			return err
		}
		plan, err := sess.PlanRekey(cur, clients[idx].ClientID)
		if err != nil {
			return err
		}
		return printAndDone(plan)
	default:
		return fmt.Errorf("-dry-run не поддержан для команды %q", cmd)
	}
}

// ---------- интерактивный режим ----------

func interactive() {
	in := bufio.NewReader(os.Stdin)
	ask := func(prompt string) string {
		fmt.Print(prompt)
		line, _ := in.ReadString('\n')
		return strings.TrimSpace(line)
	}

	fmt.Println(cTitle("=== Amnezia Admin " + version.String() + " ==="))
	key := os.Getenv("AMNEZIA_KEY")
	if key == "" {
		key = ask("Вставьте админский ключ (vpn://...): ")
	} else {
		fmt.Println("Ключ взят из переменной окружения AMNEZIA_KEY.")
	}
	cfg, err := core.DecodeVpnKey(key)
	if err != nil {
		fmt.Println(cErr("Ошибка декодирования ключа: ") + err.Error())
		pause(in)
		return
	}
	creds, err := core.CredsFromConfig(cfg)
	if err != nil {
		printErr(err)
		pause(in)
		return
	}

	fmt.Printf("Сервер: %s@%s:%s — подключаюсь...\n", creds.User, creds.Host, creds.Port)
	knownHostsPath := filepath.Join(core.DefaultVaultDir(), "known_hosts")
	sess, err := core.ConnectWithHostKey(creds, core.HostKeyPolicy{
		KnownHostsPath: knownHostsPath,
		Prompt:         cliHostKeyPrompt(in, os.Stdout),
		OnChanged:      cliHostKeyChanged(os.Stdout, knownHostsPath),
	})
	if err != nil {
		fmt.Println(cErr("SSH не удался: ") + err.Error())
		pause(in)
		return
	}
	defer sess.Close()

	containers, err := sess.FindContainers()
	if err != nil {
		printErr(err)
		pause(in)
		return
	}
	fmt.Println()
	fmt.Println(cHead("Установленные протоколы:"))
	printContainers(containers, true)

	cur := &containers[0]
	for i := range containers {
		if containers[i].Managed {
			cur = &containers[i]
			break
		}
	}

	for {
		title := fmt.Sprintf(" Протокол: %s ", cur.Proto)
		width := 58
		side := (width - len([]rune(title))) / 2
		if side < 3 {
			side = 3
		}
		fmt.Println()
		fmt.Println()
		fmt.Println(cDim(strings.Repeat("═", side)) + cTitle(title) + cDim(strings.Repeat("═", side)))
		item := func(n, text string) { fmt.Println("  " + cNum(n+".") + " " + text) }
		item("1", "Показать пользователей")
		if cur.Managed {
			item("2", "Создать пользователя")
			item("3", "Удалить пользователя")
			item("6", "Переименовать пользователя")
			item("7", "Отключить/включить пользователя")
			item("8", "Перевыпустить конфиг")
		}
		if len(containers) > 1 {
			item("4", "Сменить протокол/контейнер")
		}
		item("5", "Показать данные ключа (JSON)")
		item("0", "Выход")
		fmt.Println(cDim(strings.Repeat("─", width)))

		switch ask("Выбор: ") {
		case "1":
			if _, err := listUsers(os.Stdout, sess, cur); err != nil {
				printErr(err)
			}
		case "2":
			name := ask("Имя нового пользователя: ")
			u, err := sess.AddUser(cur, name)
			if err != nil {
				printErr(err)
				break
			}
			if err := saveUserConfig(os.Stdout, u, cur.Proto); err != nil {
				printErr(err)
			}
		case "3":
			if !cur.Managed {
				printErr(fmt.Errorf("удаление пользователей для %s не поддерживается этой утилитой", cur.Proto))
				break
			}
			// listUsers возвращает список в том же (отсортированном) порядке,
			// что и напечатанная таблица — номер строки резолвится по нему же,
			// без повторного LoadClients (иначе порядок/индексы могут разъехаться).
			clients, err := listUsers(os.Stdout, sess, cur)
			if err != nil {
				printErr(err)
				break
			}
			ident := ask("\nКого удалить (номер, имя или публичный ключ): ")
			if ident == "" {
				break
			}
			idx := core.ResolveClient(clients, ident)
			if idx < 0 {
				printErr(fmt.Errorf("пользователь %q не найден", ident))
				break
			}
			victim := clients[idx]
			card := buildCard(sess, cur, victim, "удалить")
			proceed, _ := confirmOrExit(in, os.Stdout, os.Stderr, true, false, card)
			if !proceed {
				break
			}
			if err := sess.DeleteByID(cur, victim.ClientID); err != nil {
				printErr(err)
			} else {
				fmt.Println(cOK(fmt.Sprintf("Пользователь %q удалён.", victim.Name())))
			}
		case "6":
			if !cur.Managed {
				printErr(fmt.Errorf("переименование пользователей для %s не поддерживается этой утилитой", cur.Proto))
				break
			}
			clients, err := listUsers(os.Stdout, sess, cur)
			if err != nil {
				printErr(err)
				break
			}
			ident := ask("\nКого переименовать (номер, имя или публичный ключ): ")
			if ident == "" {
				break
			}
			idx := core.ResolveClient(clients, ident)
			if idx < 0 {
				printErr(fmt.Errorf("пользователь %q не найден", ident))
				break
			}
			victim := clients[idx]
			newName := ask(fmt.Sprintf("Новое имя для %q: ", victim.Name()))
			if newName == "" {
				break
			}
			if err := sess.RenameUser(cur, victim.ClientID, newName); err != nil {
				printErr(err)
			} else {
				fmt.Println(cOK(fmt.Sprintf("Пользователь %q переименован в %q.", victim.Name(), strings.TrimSpace(newName))))
			}
		case "7":
			if !cur.Managed {
				printErr(fmt.Errorf("управление пользователями для %s не поддерживается этой утилитой", cur.Proto))
				break
			}
			clients, err := listUsers(os.Stdout, sess, cur)
			if err != nil {
				printErr(err)
				break
			}
			ident := ask("\nКого отключить/включить (номер, имя или публичный ключ): ")
			if ident == "" {
				break
			}
			idx := core.ResolveClient(clients, ident)
			if idx < 0 {
				printErr(fmt.Errorf("пользователь %q не найден", ident))
				break
			}
			victim := clients[idx]
			enable := victim.Disabled()
			if enable {
				// включение — вопрос как раньше, без карточки (Г3: вопрос
				// при включении не трогаем, владелец им уже пользуется).
				verb := "включить"
				if ask(fmt.Sprintf("%s пользователя %q? (y/n): ", capitalizeFirst(verb), victim.Name())) != "y" {
					fmt.Println("Отменено.")
					break
				}
			} else {
				card := buildCard(sess, cur, victim, "отключить")
				proceed, _ := confirmOrExit(in, os.Stdout, os.Stderr, true, false, card)
				if !proceed {
					break
				}
			}
			if err := sess.SetEnabled(cur, victim.ClientID, enable); err != nil {
				printErr(err)
			} else if enable {
				fmt.Println(cOK(fmt.Sprintf("Пользователь %q включён.", victim.Name())))
			} else {
				fmt.Println(cOK(fmt.Sprintf("Пользователь %q отключён.", victim.Name())))
			}
		case "8":
			if !cur.Managed {
				printErr(fmt.Errorf("перевыпуск конфигов для %s не поддерживается этой утилитой", cur.Proto))
				break
			}
			clients, err := listUsers(os.Stdout, sess, cur)
			if err != nil {
				printErr(err)
				break
			}
			ident := ask("\nКому перевыпустить конфиг (номер, имя или публичный ключ): ")
			if ident == "" {
				break
			}
			idx := core.ResolveClient(clients, ident)
			if idx < 0 {
				printErr(fmt.Errorf("пользователь %q не найден", ident))
				break
			}
			victim := clients[idx]
			card := buildCard(sess, cur, victim, "перевыпустить конфиг")
			proceed, _ := confirmOrExit(in, os.Stdout, os.Stderr, true, false, card)
			if !proceed {
				break
			}
			u, err := sess.RegenerateUser(cur, victim.ClientID)
			if err != nil {
				printErr(err)
				break
			}
			if err := saveUserConfig(os.Stdout, u, cur.Proto); err != nil {
				printErr(err)
			}
		case "4":
			printContainers(containers, false)
			if n, e := strconv.Atoi(ask("Номер: ")); e == nil && n >= 1 && n <= len(containers) {
				cur = &containers[n-1]
			}
		case "5":
			printConfig(os.Stdout, cfg)
		case "0", "q", "exit":
			return
		}
	}
}

func pause(in *bufio.Reader) {
	fmt.Print("Нажмите Enter для выхода...")
	in.ReadString('\n')
}

// ---------- CLI-режим ----------

func main() {
	if len(os.Args) < 2 {
		interactive()
		return
	}
	knownHostsPath := filepath.Join(core.DefaultVaultDir(), "known_hosts")
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, knownHostsPath))
}

// run — точка входа CLI-подкоманд (Е3 задания PR-4, правка 4.15 PQ-01):
// вынесена из main(), чтобы её можно было прогнать в тесте
// (TestNonTTYUnknownHostNeedsHostkey — сценарий без TTY против fakesrv)
// без os.Exit, который убил бы тестовый процесс. main() вызывает run() с
// os.Args[1:]/os.Stdin/os.Stdout/os.Stderr и реальным known_hosts
// (core.DefaultVaultDir()); все os.Exit(code) внутри веток switch заменены
// на return code, а confirmOrExit/confirmSubcommand (PR-5) получают потоки
// run() (stdin/stdout/stderr), а не os.Stdin/os.Stdout/os.Stderr напрямую —
// тесты PR-5 (TestNonTTYWithoutYesExit2 и др.) это не трогает, они и раньше
// звали confirmOrExit/confirmSubcommand напрямую со своими буферами.
//
// stdinIsTTY() по-прежнему проверяет РЕАЛЬНЫЙ os.Stdin (единственный
// TTY-детектор пакета — confirm.go, PR-5, второй не заводим) — это НЕ то же
// самое, что переданный сюда stdin io.Reader: последний источник для чтения
// ответов на вопросы (в тестах — bytes.Buffer/strings.Reader), а
// stdinIsTTY() решает, задавать ли вопрос вообще. В тестовом процессе
// os.Stdin не терминал, поэтому stdinIsTTY() там всегда false — как и было
// в TestNonTTYWithoutYesExit2 до этого рефакторинга.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, knownHostsPath string) int {
	cmd := args[0]

	// version/-version/--version — до flag.NewFlagSet и до любой работы с
	// ключом/сетью/known_hosts (ПР-6а, Г2): run() иначе требует -key ради
	// печати номера версии. Лишние аргументы игнорируются (П19).
	if cmd == "version" || cmd == "-version" || cmd == "--version" {
		fmt.Fprintln(stdout, "amnezia-admin "+version.String())
		return 0
	}

	// check — по тем же причинам здесь же: проверка окружения, требующая
	// административного ключа, бессмысленна, а ниже run() требует -key.
	// Код всегда 0: «графический интерфейс не запустится» — не ошибка
	// утилиты, а факт об окружении, и коды 1/2 остаются договором со
	// скриптами (PR-4-Б, PR-5). Лишние аргументы игнорируются — как у
	// version.
	if cmd == "check" {
		envcheck.Report(envcheck.Detect(envcheck.OSDeps()), stdout)
		return 0
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	key := fs.String("key", os.Getenv("AMNEZIA_KEY"), "админский ключ vpn://...")
	name := fs.String("name", "", "имя пользователя (для add/del/rename/toggle)")
	newname := fs.String("newname", "", "новое имя (для rename)")
	dryRun := fs.Bool("dry-run", false, "показать изменения wg0.conf и clientsTable, ничего не записывая")
	yes := fs.Bool("yes", false, "выполнить необратимое действие (del/rekey/toggle-отключение) без вопроса (для скриптов)")
	hostkey := fs.String("hostkey", "", "ожидаемый отпечаток ключа сервера SHA256:… (обязателен без терминала для нового сервера)")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		// Код 1 — обычная ошибка (флаг ошибся, а не "не подтверждено");
		// 2 занят решением PR-5 "нет терминала и нет -yes"/"y/n ответил
		// нет" — смешивать эти два смысла нельзя (ревью PR-4-Б, круг 1,
		// BE-01 Low: скрипт, различающий "неверные аргументы" от "человек
		// сознательно отказался", не должен получать один и тот же код для
		// обоих случаев).
		return 1
	}

	if *key == "" {
		fmt.Fprintln(stderr, "Не задан ключ: -key vpn://... или переменная AMNEZIA_KEY")
		return 1
	}
	cfg, err := core.DecodeVpnKey(*key)
	if err != nil {
		fmt.Fprintln(stderr, "Ошибка декодирования ключа:", err)
		return 1
	}
	if cmd == "decode" {
		printConfig(stdout, cfg)
		return 0
	}

	creds, err := core.CredsFromConfig(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "Ошибка:", err)
		return 1
	}

	isTTY := stdinIsTTY()
	sess, err := core.ConnectWithHostKey(creds, hostKeyPolicyForCLI(stdin, stdout, stderr, isTTY, *hostkey, knownHostsPath))
	if err != nil {
		if !isTTY && errors.Is(err, core.ErrHostKeyUnknown) {
			fmt.Fprintln(stderr, "SSH:", err)
			fmt.Fprintln(stderr, "Без терминала подключение к новому серверу требует явного отпечатка: -hostkey SHA256:...")
			return 2
		}
		fmt.Fprintln(stderr, "SSH:", err)
		return 1
	}
	defer sess.Close()

	containers, err := sess.FindContainers()
	if err != nil {
		fmt.Fprintln(stderr, "Ошибка:", err)
		return 1
	}
	cur := &containers[0]
	for i := range containers {
		if containers[i].Managed {
			cur = &containers[i]
			break
		}
	}

	switch cmd {
	case "list":
		_, err = listUsers(stdout, sess, cur)
	case "add":
		if *dryRun {
			err = runDryRun(stdout, sess, cur, cmd, *name, *newname)
			break
		}
		u, e := sess.AddUser(cur, *name)
		if e == nil {
			e = saveUserConfig(stdout, u, cur.Proto)
		}
		err = e
	case "del":
		if *dryRun {
			err = runDryRun(stdout, sess, cur, cmd, *name, *newname)
			break
		}
		// вне интерактивного списка номер строки ничего не значит —
		// принимаем только имя или публичный ключ (см. core.ResolveNonNumeric)
		clients, e := sess.LoadClients(cur)
		if e != nil {
			err = e
			break
		}
		idx, e := core.ResolveNonNumeric(clients, *name)
		if e != nil {
			err = e
			break
		}
		if proceed, code := confirmSubcommand(stdin, stdout, stderr, isTTY, *yes, cmd, clients[idx], sess, cur, "удалить"); !proceed {
			return code
		}
		err = sess.DeleteByID(cur, clients[idx].ClientID)
		if err == nil {
			fmt.Fprintf(stdout, "Пользователь %q удалён.\n", *name)
		}
	case "rename":
		if *dryRun {
			err = runDryRun(stdout, sess, cur, cmd, *name, *newname)
			break
		}
		// вне интерактивного списка номер строки ничего не значит —
		// принимаем только имя или публичный ключ (см. core.ResolveNonNumeric)
		clients, e := sess.LoadClients(cur)
		if e != nil {
			err = e
			break
		}
		idx, e := core.ResolveNonNumeric(clients, *name)
		if e != nil {
			err = e
			break
		}
		err = sess.RenameUser(cur, clients[idx].ClientID, *newname)
		if err == nil {
			fmt.Fprintf(stdout, "Пользователь %q переименован в %q.\n", *name, strings.TrimSpace(*newname))
		}
	case "toggle":
		if *dryRun {
			err = runDryRun(stdout, sess, cur, cmd, *name, *newname)
			break
		}
		// вне интерактивного списка номер строки ничего не значит —
		// принимаем только имя или публичный ключ (см. core.ResolveNonNumeric)
		clients, e := sess.LoadClients(cur)
		if e != nil {
			err = e
			break
		}
		idx, e := core.ResolveNonNumeric(clients, *name)
		if e != nil {
			err = e
			break
		}
		enable := clients[idx].Disabled()
		if proceed, code := confirmSubcommand(stdin, stdout, stderr, isTTY, *yes, cmd, clients[idx], sess, cur, "отключить"); !proceed {
			return code
		}
		err = sess.SetEnabled(cur, clients[idx].ClientID, enable)
		if err == nil {
			if enable {
				fmt.Fprintf(stdout, "Пользователь %q включён.\n", *name)
			} else {
				fmt.Fprintf(stdout, "Пользователь %q отключён.\n", *name)
			}
		}
	case "rekey":
		if *dryRun {
			err = runDryRun(stdout, sess, cur, cmd, *name, *newname)
			break
		}
		// вне интерактивного списка номер строки ничего не значит —
		// принимаем только имя или публичный ключ (см. core.ResolveNonNumeric)
		clients, e := sess.LoadClients(cur)
		if e != nil {
			err = e
			break
		}
		idx, e := core.ResolveNonNumeric(clients, *name)
		if e != nil {
			err = e
			break
		}
		if proceed, code := confirmSubcommand(stdin, stdout, stderr, isTTY, *yes, cmd, clients[idx], sess, cur, "перевыпустить конфиг"); !proceed {
			return code
		}
		u, e := sess.RegenerateUser(cur, clients[idx].ClientID)
		if e == nil {
			e = saveUserConfig(stdout, u, cur.Proto)
		}
		err = e
	default:
		err = fmt.Errorf("неизвестная команда %q (decode | list | add | del | rename | toggle | rekey)", cmd)
	}
	if err != nil {
		fmt.Fprintln(stderr, "Ошибка:", err)
		return 1
	}
	return 0
}
