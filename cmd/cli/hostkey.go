// Файл hostkey.go — CLI-обвязка над core.HostKeyPolicy (PR-4, часть Б, Е2):
// TTY-вопрос при неизвестном сервере, вывод при смене ключа, флаг -hostkey
// для скриптов без терминала. Обходного флага "не проверять ключ хоста" нет
// и не будет (В2 п.3) — единственный путь для скрипта без TTY на НОВЫЙ
// сервер это -hostkey SHA256:… с отпечатком, полученным заранее.
//
// У CLI нет собственного хранилища (.avlt) — оно только в cmd/gui, поэтому
// подкоманды "забыть ключ сервера" здесь нет (SEC-01, handoff-2026-09-14/
// С3-позиция-ядра.md: "CLI: хранилища нет — точная инструкция в тексте
// ErrHostKeyChanged; подкоманду forget-hostkey не заводить"). Единственное
// восстановление доступа после легитимной переустановки сервера — вручную
// удалить строку адреса из known_hosts (см. текст ошибки в core/hostkey.go
// и README, раздел "Ключ сервера").
package main

import (
	"fmt"
	"io"
	"strings"

	"amnezia-admin/core"
)

// cliHostKeyPrompt — core.HostKeyPolicy.Prompt для CLI при наличии
// терминала: печатает адрес и отпечаток, спрашивает подтверждение. Ответ
// читает через readLine (confirm.go) — тот же способ чтения строки, что и
// confirmOrExit, единый на пакет.
func cliHostKeyPrompt(in io.Reader, out io.Writer) func(host, fingerprint string) bool {
	return func(host, fingerprint string) bool {
		fmt.Fprintf(out, "\nНеизвестный сервер: %s\n", host)
		fmt.Fprintf(out, "Отпечаток ключа: %s\n", fingerprint)
		fmt.Fprint(out, "Доверять этому серверу и запомнить ключ? (y/n): ")
		answer := strings.ToLower(strings.TrimSpace(readLine(in)))
		return answer == "y" || answer == "yes"
	}
}

// cliHostKeyChanged — core.HostKeyPolicy.OnChanged для CLI: печатает оба
// отпечатка и инструкцию по восстановлению доступа; ничего не спрашивает —
// смена ключа отказ ВСЕГДА (правка 4.5 PQ-01), кнопки/флага "принять" нет.
// Пишет в errOut — соединение уже отклоняется, это диагностика ошибки.
func cliHostKeyChanged(errOut io.Writer, knownHostsPath string) func(host, knownFp, presentedFp string) {
	return func(host, knownFp, presentedFp string) {
		fmt.Fprintf(errOut, "\nКлюч сервера ИЗМЕНИЛСЯ: %s\n", host)
		fmt.Fprintf(errOut, "  Был:  %s\n", knownFp)
		fmt.Fprintf(errOut, "  Стал: %s\n", presentedFp)
		fmt.Fprintf(errOut, "Если сервер переустанавливали: удалите строку %q из %s и подключитесь заново — увидите новый отпечаток и решите, доверять ли ему.\n", host, knownHostsPath)
		fmt.Fprintln(errOut, "Если не переустанавливали — возможна подмена: не подключайтесь. Кнопки/флага \"всё равно подключиться\" нет.")
	}
}

// hostKeyPolicyForCLI собирает core.HostKeyPolicy для одного запуска CLI.
// С TTY — Prompt печатает вопрос в out и читает ответ из in. Без TTY —
// Prompt == nil: неизвестный сервер без -hostkey отклоняется без вопроса
// (см. run(), ветка ErrHostKeyUnknown, код выхода 2).
func hostKeyPolicyForCLI(in io.Reader, out, errOut io.Writer, isTTY bool, hostkey, knownHostsPath string) core.HostKeyPolicy {
	pol := core.HostKeyPolicy{
		KnownHostsPath:      knownHostsPath,
		OnChanged:           cliHostKeyChanged(errOut, knownHostsPath),
		ExpectedFingerprint: strings.TrimSpace(hostkey),
	}
	if isTTY {
		pol.Prompt = cliHostKeyPrompt(in, out)
	}
	return pol
}
