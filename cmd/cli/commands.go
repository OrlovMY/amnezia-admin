package main

// Закрытый список подкоманд CLI: один на справку и на «неизвестная
// команда». Новая подкоманда без строки здесь отвергается ранней проверкой
// в run() как неизвестная — забыть её внести незаметно нельзя.

import "strings"

var cliCommands = []string{
	"decode", "list", "add", "del", "rename", "toggle", "rekey", "show-config",
	"backup", "backup-info", "restore", "migrate", "provision-check", "diagnose",
	"version", "check", "stats",
}

var cliCommandList = strings.Join(cliCommands, " | ")

func knownCLICommand(cmd string) bool {
	for _, c := range cliCommands {
		if c == cmd {
			return true
		}
	}
	return false
}
