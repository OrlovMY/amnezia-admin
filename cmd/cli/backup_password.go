package main

// Пароль копии (решение владельца по Р-1: оба режима, выбор при
// сохранении). Пароль — только из файла (-password-file) или с терминала
// без эха; аргументом командной строки его не передать (виден другим
// процессам и остаётся в истории оболочки). Внутри — core.Secret.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"amnezia-admin/core"
)

// readPasswordTTY — ввод без эха с терминала (шов теста).
var readPasswordTTY = func(w io.Writer, prompt string) ([]byte, error) {
	fmt.Fprint(w, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(w)
	return b, err
}

// readPasswordFile — пароль из файла: содержимое без одного завершающего
// перевода строки.
func readPasswordFile(path string) (core.Secret, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return core.Secret{}, fmt.Errorf("файл пароля не прочитан: %w", err)
	}
	b = bytes.TrimSuffix(bytes.TrimSuffix(b, []byte("\n")), []byte("\r"))
	return core.NewSecret(b), nil
}

var errNeedPasswordChoice = errors.New("без терминала укажите -password-file <файл> (копия с паролем) или -no-password (без пароля)")

// backupLayerChoice — слой новой копии и предупреждение к нему. code != 0 —
// отказ (2 — не выбрано без терминала, 1 — ошибка).
func backupLayerChoice(in io.Reader, w, errOut io.Writer, isTTY bool, pwFile string, noPw bool) (core.BackupLayer, string, int) {
	switch {
	case pwFile != "" && noPw:
		fmt.Fprintln(errOut, "Укажите что-то одно: -password-file или -no-password.")
		return nil, "", 1
	case noPw:
		return core.PlainLayer{}, core.BackupUnencryptedWarning, 0
	case pwFile != "":
		pw, err := readPasswordFile(pwFile)
		if err == nil {
			err = core.ValidateBackupPassword(pw)
		}
		if err != nil {
			backupErr(errOut, "Копия не снята: ", err)
			return nil, "", 1
		}
		return core.PasswordLayer{Password: pw}, core.BackupPasswordWarning, 0
	case !isTTY:
		fmt.Fprintln(errOut, "Копия не снята: "+errNeedPasswordChoice.Error())
		return nil, "", 2
	}
	fmt.Fprint(w, "Зашифровать копию паролем? (y — с паролем / n — без пароля): ")
	switch strings.ToLower(strings.TrimSpace(readLine(in))) {
	case "y", "yes":
	case "n", "no":
		return core.PlainLayer{}, core.BackupUnencryptedWarning, 0
	default:
		fmt.Fprintln(w, "Отменено.")
		return nil, "", 2
	}
	a, err := readPasswordTTY(w, fmt.Sprintf("Пароль копии (не короче %d символов): ", core.BackupPasswordMin))
	if err != nil {
		backupErr(errOut, "Пароль не прочитан: ", err)
		return nil, "", 1
	}
	b, err := readPasswordTTY(w, "Повторите пароль: ")
	if err != nil {
		backupErr(errOut, "Пароль не прочитан: ", err)
		return nil, "", 1
	}
	pw := core.NewSecret(a)
	if !bytes.Equal(a, b) {
		fmt.Fprintln(errOut, "Пароли не совпали — копия не снята.")
		return nil, "", 1
	}
	if err := core.ValidateBackupPassword(pw); err != nil {
		backupErr(errOut, "Копия не снята: ", err)
		return nil, "", 1
	}
	return core.PasswordLayer{Password: pw}, core.BackupPasswordWarning, 0
}

// readLayers — слои для чтения копии: пароль спрашивается только у
// зашифрованной. code != 0 — отказ.
func readLayers(w, errOut io.Writer, isTTY bool, path, pwFile string) ([]core.BackupLayer, int) {
	name, err := core.BackupLayerOf(path)
	if err != nil {
		backupErr(errOut, "", err)
		return nil, 1
	}
	if name != core.PasswordLayerName {
		return []core.BackupLayer{core.PlainLayer{}}, 0
	}
	var pw core.Secret
	switch {
	case pwFile != "":
		if pw, err = readPasswordFile(pwFile); err != nil {
			backupErr(errOut, "", err)
			return nil, 1
		}
	case isTTY:
		b, err := readPasswordTTY(w, "Копия зашифрована. Пароль: ")
		if err != nil {
			backupErr(errOut, "Пароль не прочитан: ", err)
			return nil, 1
		}
		pw = core.NewSecret(b)
	default:
		fmt.Fprintln(errOut, "Копия зашифрована: без терминала укажите -password-file <файл>.")
		return nil, 2
	}
	return []core.BackupLayer{core.PlainLayer{}, core.PasswordLayer{Password: pw}}, 0
}
