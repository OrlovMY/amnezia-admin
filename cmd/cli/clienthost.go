package main

import (
	"fmt"
	"io"
	"strings"

	"amnezia-admin/core"
)

// clientHostResolver — резолвер для сверки имени с сервером (шов для тестов).
var clientHostResolver core.Resolver = core.SystemResolver

// clientHostServerIP — адрес подключения для сверки (шов для тестов: стенд
// fakesrv слушает 127.0.0.1, а это непубличный адрес — «сравнивать не с чем»).
var clientHostServerIP = func(s *core.Session) string { return s.ServerIP() }

// applyClientHost — адрес сервера в конфигах клиентов перед выдачей
// (add/rekey). У CLI нет хранилища настроек: выбор — флаг -client-host
// (или переменная AMNEZIA_CLIENT_HOST) на каждый запуск.
//
//	имени нет, в ключе имя → как прежде, ничего не печатаем;
//	имени нет, в ключе IP  → конфиг с IP + громкое предупреждение в stderr;
//	имя задано и совпало   → конфиг с именем;
//	другие адреса / проверить не удалось → нужен y/N в терминале или
//	                         -client-host-confirm; без них — отказ, код 2.
//
// Предупреждение об IP возвращается (warn), а печатается вызывающим ПОСЛЕ
// выдачи конфига: не выдан — предупреждать не о чем, а первая строка
// stderr остаётся причиной отказа.
func applyClientHost(in io.Reader, out, errOut io.Writer, isTTY bool, flagHost string, confirmed bool, sess *core.Session) (proceed bool, code int, warn string) {
	if strings.TrimSpace(flagHost) == "" {
		if sess.Creds != nil && core.IsIPHost(sess.Creds.Host) {
			warn = core.ClientHostIPWarning(sess.Creds.Host)
		}
		return true, 0, warn
	}
	if strings.EqualFold(strings.TrimSpace(flagHost), "keep-ip") {
		// явное «оставить IP»: выбор сделан (копия знает адрес выдачи)
		sess.ClientHostDecided = true
		if sess.Creds != nil && core.IsIPHost(sess.Creds.Host) {
			warn = core.ClientHostIPWarning(sess.Creds.Host)
		}
		return true, 0, warn
	}
	name, err := core.NormalizeClientHost(flagHost)
	if err != nil {
		fmt.Fprintln(errOut, "Ошибка -client-host:", err)
		return false, 1, ""
	}
	chk := core.CheckClientHost(name, clientHostServerIP(sess), clientHostResolver)
	if chk.Status == core.ClientHostMatch {
		fmt.Fprintln(out, cOK(chk.Text()))
		sess.ClientHost, sess.ClientHostDecided = name, true
		return true, 0, ""
	}
	fmt.Fprintln(errOut, cWarn(chk.Text()))
	if !confirmed {
		if !isTTY {
			fmt.Fprintln(errOut, "Конфиг не выдан: без терминала имя, не совпавшее с сервером или не проверенное, принимается только с флагом -client-host-confirm.")
			return false, 2, ""
		}
		fmt.Fprintf(out, "Всё равно выдать конфиг с именем %s? (y/n): ", name)
		ans := strings.ToLower(strings.TrimSpace(readLine(in)))
		if ans != "y" && ans != "yes" {
			fmt.Fprintln(out, "Отменено.")
			return false, 2, ""
		}
	}
	sess.ClientHost, sess.ClientHostDecided = name, true
	return true, 0, ""
}

// interactiveClientHost — меню: один раз за сеанс перед первой выдачей
// конфига, если в ключе IP. Пустой ответ — «оставить IP» (запоминается до
// конца сеанса).
func interactiveClientHost(ask func(string) string, sess *core.Session, decided *bool) {
	if *decided || sess.Creds == nil || !core.IsIPHost(sess.Creds.Host) || sess.ClientHost != "" {
		*decided = true
		return
	}
	fmt.Println(cWarn("В админском ключе адрес сервера — IP " + sess.Creds.Host + "."))
	fmt.Println("Конфиг клиента с IP при переезде сервера придётся перевыпускать каждому; с DNS-именем достаточно перевести DNS.")
	for {
		v := ask("DNS-имя сервера для конфигов клиентов (Enter — оставить IP): ")
		if v == "" {
			fmt.Println(cWarn(core.ClientHostIPWarning(sess.Creds.Host)))
			sess.ClientHostDecided = true
			*decided = true
			return
		}
		name, err := core.NormalizeClientHost(v)
		if err != nil {
			printErr(err)
			continue
		}
		chk := core.CheckClientHost(name, clientHostServerIP(sess), clientHostResolver)
		if chk.Status == core.ClientHostMatch {
			fmt.Println(cOK(chk.Text()))
		} else {
			fmt.Println(cWarn(chk.Text()))
			a := strings.ToLower(ask("Всё равно использовать это имя? (y/n): "))
			if a != "y" && a != "yes" {
				continue
			}
		}
		sess.ClientHost, sess.ClientHostDecided = name, true
		*decided = true
		return
	}
}
