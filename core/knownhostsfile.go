package core

// Запись known_hosts несколькими копиями программы (дефект, найденный
// канарейкой A3б PR-4). Прежде appendKnownHost и removeKnownHostLines писали
// через ОБЩИЙ known_hosts.tmp: на Windows вторая копия падала «файл занят»,
// на Linux одна копия уносила чужой tmp из-под rename другой, а строки
// молча терялись — «прочитал старое, дописал своё, перезаписал» — то же
// потерянное обновление, что A3б на сервере, только локально.
//
// Выбор: межпроцессная блокировка (flock / LockFileEx) на отдельном файле
// known_hosts.lock + перечитывание под замком + уникальный временный файл
// (os.CreateTemp в том же каталоге) + атомарная замена. Слияние без замка
// (перечитать и дописать) потерю не устраняет — окно между перечитыванием и
// rename остаётся; замок закрывает его целиком. Замок держится на время
// одной операции (миллисекунды), освобождается ядром при смерти процесса —
// зависнуть он не может; ожидание ограничено knownHostsLockWait.
//
// Под тем же замком идёт и ЧТЕНИЕ known_hosts (lookupKnownHost): на Windows
// rename поверх файла, открытого другим процессом на чтение, падает
// «файл занят».

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ErrKnownHostsWrite — ключ сервера НЕ сохранён в known_hosts (запись не
// удалась). Не «ключ сохранён» и не «ключ отклонён» — третье состояние.
var ErrKnownHostsWrite = errors.New("ключ сервера не сохранён в known_hosts")

// ErrKnownHostsBusy — known_hosts занят другой копией программы дольше
// knownHostsLockWait.
var ErrKnownHostsBusy = errors.New("known_hosts занят другой копией программы")

const knownHostsLockWait = 10 * time.Second

// withKnownHostsLock выполняет fn под исключительным межпроцессным замком
// на path+".lock". Каталог создаётся с прежними правами appendKnownHost.
func withKnownHostsLock(path string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	lf, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("замок known_hosts: %w", err)
	}
	defer lf.Close()
	deadline := time.Now().Add(knownHostsLockWait)
	for {
		busy, err := tryLockFile(lf)
		if err != nil {
			return fmt.Errorf("замок known_hosts: %w", err)
		}
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w (ждали %v): %s", ErrKnownHostsBusy, knownHostsLockWait, path)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer unlockFile(lf)
	return fn()
}

// replaceFileAtomic пишет data во временный файл с уникальным именем в
// каталоге path (0600) и атомарно переименовывает его в path. Вызывать под
// withKnownHostsLock.
func replaceFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0600); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
