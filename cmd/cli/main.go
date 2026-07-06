// amnezia-admin — консольная утилита администрирования сервера Amnezia VPN.
//
// Запуск без аргументов — интерактивный режим: вводите ключ vpn://,
// утилита определяет сервер, протоколы и показывает меню доступных команд.
//
// Также поддерживаются подкоманды для скриптов:
//   amnezia-admin decode -key vpn://...
//   amnezia-admin list   -key vpn://...
//   amnezia-admin add    -key vpn://... -name Vasya
//   amnezia-admin del    -key vpn://... -name Vasya
//   amnezia-admin rename -key vpn://... -name Vasya -newname "Vasya Ivanov"
//   amnezia-admin toggle -key vpn://... -name Vasya
//   amnezia-admin rekey  -key vpn://... -name Vasya
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"amnezia-admin/core"
)

func pad(s string, n int) string {
	if d := n - len([]rune(s)); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// listUsers печатает таблицу пользователей и возвращает отсортированный по
// активности slice — тот же порядок, что показан в таблице (нумерация "#"
// в выводе соответствует индексам этого slice), чтобы вызывающий код мог
// резолвить номер строки без повторного LoadClients.
func listUsers(s *core.Session, c *core.Container) ([]core.ClientEntry, error) {
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
		fmt.Println("В clientsTable записей нет.")
	} else {
		fmt.Println()
		fmt.Println(cHead(pad("#", 4) + pad("Имя", 34) + pad("Создан", 21) + pad("Активность", 18) + pad("Трафик ↓/↑", 24) + "Публичный ключ"))
		fmt.Println(cDim(strings.Repeat("─", 4+34+21+18+24+44)))
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
			fmt.Println(cNum(pad(strconv.Itoa(i+1), 4)) + name + cDim(pad(created, 21)) + hs + pad(traffic, 24) + cDim(cl.ClientID))
		}
		fmt.Println(cDim("Трафик и активность — с момента перезапуска сервера."))
	}

	if orphans := s.OrphanPeers(c, clients); len(orphans) > 0 {
		fmt.Printf("\nPeers в wg0.conf без имени в clientsTable: %d\n", len(orphans))
		for _, o := range orphans {
			fmt.Println("  ", o)
		}
	}
	return clients, nil
}

func saveUserConfig(u *core.NewUser, proto string) error {
	if err := os.MkdirAll("Конфигурации", 0755); err != nil {
		return err
	}
	fileName := filepath.Join("Конфигурации", core.SanitizeName(u.Name)+".conf")
	if err := os.WriteFile(fileName, []byte(u.Config), 0600); err != nil {
		return err
	}
	abs, _ := filepath.Abs(fileName)
	fmt.Println()
	fmt.Println(cOK(fmt.Sprintf("Пользователь %q создан (IP %s, протокол %s).", u.Name, u.IP, proto)))
	fmt.Println("Конфиг сохранён: " + cAccent(abs))
	fmt.Println("Импортируйте файл в приложение AmneziaWG или Amnezia (Импорт → выбрать .conf).")
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

// ---------- интерактивный режим ----------

func interactive() {
	in := bufio.NewReader(os.Stdin)
	ask := func(prompt string) string {
		fmt.Print(prompt)
		line, _ := in.ReadString('\n')
		return strings.TrimSpace(line)
	}

	fmt.Println(cTitle("=== Amnezia Admin ==="))
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
	sess, err := core.Connect(creds)
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
			if _, err := listUsers(sess, cur); err != nil {
				printErr(err)
			}
		case "2":
			name := ask("Имя нового пользователя: ")
			u, err := sess.AddUser(cur, name)
			if err != nil {
				printErr(err)
				break
			}
			if err := saveUserConfig(u, cur.Proto); err != nil {
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
			clients, err := listUsers(sess, cur)
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
			fmt.Println()
			fmt.Println(cHead("Будет удалён:"))
			fmt.Println("  Имя:            " + cHead(victim.Name()))
			fmt.Println("  Создан:         " + victim.Created())
			fmt.Println("  Публичный ключ: " + cDim(victim.ClientID))
			hs := sess.GetHandshakes(cur)[victim.ClientID]
			if hs != "" && hs != "—" {
				fmt.Println(cWarn("  ⚠ Внимание: у этого клиента была активность, последнее подключение: " + hs))
			} else {
				fmt.Println(cDim("  Подключений не было."))
			}
			if ask(fmt.Sprintf("Точно удалить %q? (y/n): ", victim.Name())) == "y" {
				if err := sess.DeleteByID(cur, victim.ClientID); err != nil {
					printErr(err)
				} else {
					fmt.Println(cOK(fmt.Sprintf("Пользователь %q удалён.", victim.Name())))
				}
			} else {
				fmt.Println("Отменено.")
			}
		case "6":
			if !cur.Managed {
				printErr(fmt.Errorf("переименование пользователей для %s не поддерживается этой утилитой", cur.Proto))
				break
			}
			clients, err := listUsers(sess, cur)
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
			clients, err := listUsers(sess, cur)
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
			verb := "отключить"
			if enable {
				verb = "включить"
			}
			if ask(fmt.Sprintf("%s пользователя %q? (y/n): ", strings.ToUpper(verb[:1])+verb[1:], victim.Name())) != "y" {
				fmt.Println("Отменено.")
				break
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
			clients, err := listUsers(sess, cur)
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
			fmt.Println(cWarn(fmt.Sprintf("Старый конфиг %q перестанет работать после перевыпуска.", victim.Name())))
			if ask(fmt.Sprintf("Перевыпустить конфиг для %q? (y/n): ", victim.Name())) != "y" {
				fmt.Println("Отменено.")
				break
			}
			u, err := sess.RegenerateUser(cur, victim.ClientID)
			if err != nil {
				printErr(err)
				break
			}
			if err := saveUserConfig(u, cur.Proto); err != nil {
				printErr(err)
			}
		case "4":
			printContainers(containers, false)
			if n, e := strconv.Atoi(ask("Номер: ")); e == nil && n >= 1 && n <= len(containers) {
				cur = &containers[n-1]
			}
		case "5":
			pretty, _ := json.MarshalIndent(cfg, "", "  ")
			fmt.Println(string(pretty))
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
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	key := fs.String("key", os.Getenv("AMNEZIA_KEY"), "админский ключ vpn://...")
	name := fs.String("name", "", "имя пользователя (для add/del/rename/toggle)")
	newname := fs.String("newname", "", "новое имя (для rename)")
	fs.Parse(os.Args[2:])

	if *key == "" {
		fmt.Fprintln(os.Stderr, "Не задан ключ: -key vpn://... или переменная AMNEZIA_KEY")
		os.Exit(1)
	}
	cfg, err := core.DecodeVpnKey(*key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка декодирования ключа:", err)
		os.Exit(1)
	}
	if cmd == "decode" {
		pretty, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(pretty))
		return
	}

	creds, err := core.CredsFromConfig(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}
	sess, err := core.Connect(creds)
	if err != nil {
		fmt.Fprintln(os.Stderr, "SSH:", err)
		os.Exit(1)
	}
	defer sess.Close()

	containers, err := sess.FindContainers()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
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
		_, err = listUsers(sess, cur)
	case "add":
		u, e := sess.AddUser(cur, *name)
		if e == nil {
			e = saveUserConfig(u, cur.Proto)
		}
		err = e
	case "del":
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
		err = sess.DeleteByID(cur, clients[idx].ClientID)
		if err == nil {
			fmt.Printf("Пользователь %q удалён.\n", *name)
		}
	case "rename":
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
			fmt.Printf("Пользователь %q переименован в %q.\n", *name, strings.TrimSpace(*newname))
		}
	case "toggle":
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
		err = sess.SetEnabled(cur, clients[idx].ClientID, enable)
		if err == nil {
			if enable {
				fmt.Printf("Пользователь %q включён.\n", *name)
			} else {
				fmt.Printf("Пользователь %q отключён.\n", *name)
			}
		}
	case "rekey":
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
		u, e := sess.RegenerateUser(cur, clients[idx].ClientID)
		if e == nil {
			e = saveUserConfig(u, cur.Proto)
		}
		err = e
	default:
		err = fmt.Errorf("неизвестная команда %q (decode | list | add | del | rename | toggle | rekey)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}
}
