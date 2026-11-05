package main

// provision-check (А1): предпроверка ЦЕЛЕВОГО сервера перед установкой
// Amnezia «с нуля». Только чтение. Ядро — core/provision_check.go.
//
// Коды выхода: 0 — можно ставить; 1 — нельзя (есть пункт «не годится»);
// 2 — ошибка использования или подключения; 4 — неизвестно (пунктов «не
// годится» нет, но часть узнать не удалось). Код 4 — по смыслу как у
// migrate (exitRestoreStopped): «проверка не дала идти дальше».
// ОТЛИЧИЕ от migrate: там ошибка подключения — 1, здесь — 2, потому что 1
// занят измеренным «нельзя» и смешивать его с «не подключились» нельзя.

import (
	"fmt"
	"io"
	"strings"

	"amnezia-admin/core"
)

const (
	exitProvNo      = 1
	exitProvUsage   = 2
	exitProvUnknown = exitRestoreStopped // 4
)

// runProvisionCheckCmd — разбор ключа цели и подключение. Ключ — -to-key
// (как цель у migrate), иначе -key; отпечаток — -to-hostkey, иначе -hostkey.
func runProvisionCheckCmd(in io.Reader, w, errOut io.Writer, isTTY bool, key, toKey, hostkey, toHostkey, knownHostsPath string) int {
	key, toKey = strings.TrimSpace(key), strings.TrimSpace(toKey)
	if key != "" && toKey != "" && key != toKey {
		fmt.Fprintln(errOut, "provision-check проверяет один сервер: заданы -key и -to-key с разными ключами. Оставьте один.")
		return exitProvUsage
	}
	k := toKey
	if k == "" {
		k = key
	}
	if k == "" {
		fmt.Fprintln(errOut, "Не задан ключ проверяемого сервера: -to-key vpn://... (или -key; переменные AMNEZIA_TO_KEY / AMNEZIA_KEY)")
		return exitProvUsage
	}
	hk := toHostkey
	if hk == "" {
		hk = hostkey
	}
	sess, code := migrateConnect("цель", k, hk, "-to-hostkey", knownHostsPath, in, w, errOut, isTTY)
	if code != 0 {
		return exitProvUsage
	}
	defer sess.Close()
	return runProvisionCheck(w, sess)
}

// runProvisionCheck — печать отчёта и код выхода.
func runProvisionCheck(w io.Writer, sess *core.Session) int {
	fmt.Fprintln(w, sideLine("Проверяемый сервер (только чтение)", sess))
	r := sess.ProvisionCheck()
	for _, it := range r.Items {
		fmt.Fprintf(w, "  %s: %s — %s\n", it.What, it.State, it.Reason)
	}
	v := r.Verdict()
	fmt.Fprintln(w, "Итог: "+v.String()+". На сервере ничего не изменено.")
	switch v {
	case core.ProvVerdictYes:
		return 0
	case core.ProvVerdictNo:
		return exitProvNo
	}
	fmt.Fprintln(w, "Часть пунктов узнать не удалось — это не «годится»: проверьте их вручную или повторите под root.")
	return exitProvUnknown
}
