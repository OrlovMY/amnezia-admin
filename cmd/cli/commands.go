package main

// Закрытый список подкоманд CLI: один на справку и на «неизвестная
// команда». Новая подкоманда без строки здесь отвергается ранней проверкой
// в run() как неизвестная — забыть её внести незаметно нельзя. У каждой —
// строка вызова для общей справки (help): команда без строки или строка
// без команды роняет TestCLIHelpListsEveryCommand.

import (
	"fmt"
	"io"
	"strings"
)

var cliCommands = []string{
	"decode", "list", "add", "del", "rename", "toggle", "rekey", "show-config",
	"backup", "backup-info", "restore", "migrate", "provision-check", "diagnose",
	"version", "check", "stats", "admin-key",
}

var cliCommandList = strings.Join(cliCommands, " | ")

// cliUsage — строки вызова для общей справки (ключ — подкоманда).
var cliUsage = map[string][]string{
	"decode":      {"decode -key vpn://...  — разобрать ключ (секреты скрыты)"},
	"list":        {"list -key vpn://...  — пользователи"},
	"add":         {"add -key vpn://... -name Имя [-client-host имя]"},
	"del":         {"del -key vpn://... -name Имя [-yes]"},
	"rename":      {"rename -key vpn://... -name Имя -newname НовоеИмя"},
	"toggle":      {"toggle -key vpn://... -name Имя [-yes]"},
	"rekey":       {"rekey -key vpn://... -name Имя [-yes]"},
	"show-config": {"show-config -key vpn://... -name Имя [-print]"},
	"backup":      {"backup -key vpn://... [-o файл.aabk] (-password-file файл | -no-password)"},
	"backup-info": {"backup-info [-password-file файл] файл.aabk"},
	"restore":     {"restore -key vpn://НОВОГО... -file файл.aabk [-apply] [-yes]"},
	"migrate": {
		"migrate -key vpn://ИСТОЧНИКА... -to-key vpn://ЦЕЛИ... (-password-file файл | -no-password) [-apply] [-yes]",
		"migrate -key-file файл -to-host IP|имя [-to-port 22] [-to-user root] [-key-out файл] (-password-file файл | -no-password) [-apply]  — перенос на чистый сервер",
	},
	"provision-check": {"provision-check -to-key vpn://ЦЕЛИ... [-to-hostkey SHA256:...]"},
	"diagnose":        {"diagnose -key vpn://... [-fix [-yes]]"},
	"version":         {"version"},
	"check":           {"check  — запустится ли графическая версия"},
	"stats":           {"stats [status|install|uninstall] -key vpn://... [-from ГГГГ-ММ-ДД] [-to ГГГГ-ММ-ДД] [-csv файл]"},
	"admin-key": {
		"admin-key (-key-file файл | -key vpn://...) -out файл [-include-password] [-allow-partial]  — выдать ключ vpn:// заново",
		"admin-key -host IP|имя [-port 22] [-user root] -out файл [-include-password] [-allow-partial]",
	},
}

// printCLIHelp — общая справка: все подкоманды со строками вызова.
func printCLIHelp(w io.Writer) {
	fmt.Fprintln(w, "Команды: "+cliCommandList)
	fmt.Fprintln(w)
	for _, c := range cliCommands {
		for _, u := range cliUsage[c] {
			fmt.Fprintln(w, "  amnezia-admin "+u)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Справка по флагам: amnezia-admin <команда> -h")
}

func knownCLICommand(cmd string) bool {
	for _, c := range cliCommands {
		if c == cmd {
			return true
		}
	}
	return false
}
