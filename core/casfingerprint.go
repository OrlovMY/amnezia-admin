package core

import (
	"crypto/sha256"
	"encoding/hex"
)

// Постоянные заглушки для отпечатка команды записи: проходят те же проверки,
// что настоящие значения, и не зависят ни от сервера, ни от плана.
const (
	casFPContainer = "fingerprint"
	casFPDir       = "/fingerprint"
	casFPSum       = "0000000000000000000000000000000000000000000000000000000000000000"
)

// CASFingerprint — отпечаток текста записи этой сборки: sha256 скрипта
// (CASWriteScript) и шаблонов внешней команды в обеих формах (CASWriteCommand,
// CASWriteCommandSudo) с постоянными заглушками вместо контейнера, каталога
// и сумм. Детерминирован: одна и та же ревизия даёт одни и те же три суммы
// на любой машине. Канарейка A3б печатает его в П2; перед выпуском суммы
// выпускаемой ревизии сверяются с присланными владельцем (RELEASING.md).
func CASFingerprint() (script, command, sudoCommand string) {
	return casFingerprintWith(casWriteCommand, CASWriteScript)
}

// casFingerprintWith — отпечаток по построителю команды (шов для теста:
// изменённый шаблон обязан менять сумму).
func casFingerprintWith(build func(label, container, dir, wantWg, wantTbl string, sudo bool) (string, error), scriptText string) (script, command, sudoCommand string) {
	h := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	cmd, err := build(CASLabelApply, casFPContainer, casFPDir, casFPSum, CASAbsent, false)
	if err != nil {
		panic("CASFingerprint: заглушки не прошли проверку: " + err.Error())
	}
	sudo, err := build(CASLabelApply, casFPContainer, casFPDir, casFPSum, CASAbsent, true)
	if err != nil {
		panic("CASFingerprint: заглушки не прошли проверку: " + err.Error())
	}
	return h(scriptText), h(cmd), h(sudo)
}
