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
	casFPFile      = "server.json" // имя файла — аргумент $4 (PR-W1); при нём допустимы дополнительные файлы (Р-4)
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
func casFingerprintWith(build func(label, container, dir, file, wantWg, wantTbl string, sudo bool, extras ...CASExtra) (string, error), scriptText string) (script, command, sudoCommand string) {
	h := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	// Р-4: заглушки дополнительных файлов — хвост команды тоже под отпечатком.
	xs := casFPExtras()
	cmd, err := build(CASLabelApply, casFPContainer, casFPDir, casFPFile, casFPSum, CASAbsent, false, xs...)
	if err != nil {
		panic("CASFingerprint: заглушки не прошли проверку: " + err.Error())
	}
	sudo, err := build(CASLabelApply, casFPContainer, casFPDir, casFPFile, casFPSum, CASAbsent, true, xs...)
	if err != nil {
		panic("CASFingerprint: заглушки не прошли проверку: " + err.Error())
	}
	return h(scriptText), h(cmd), h(sudo)
}

// casFPExtras — все дополнительные файлы закрытого списка в постоянном
// порядке, с заглушкой суммы.
func casFPExtras() []CASExtra {
	return []CASExtra{
		{"xray_uuid.key", casFPSum}, {"xray_short_id.key", CASAbsent},
		{"xray_public.key", casFPSum}, {"xray_private.key", casFPSum},
	}
}
