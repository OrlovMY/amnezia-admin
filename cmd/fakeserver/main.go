// Команда cmd/fakeserver — встроенный SSH-сервер Amnezia в памяти,
// запускаемый как отдельный процесс (PR-4, Г3): для ручной проверки QA-02
// диалогов проверки ключа хоста (GUI) и TTY-вопроса/-hostkey (CLI) без
// боевого сервера — владелец сказал прямо: «тестового сервера нет».
//
// В релиз (release.yml) НЕ входит — release.yml собирает только ./cmd/cli
// и ./cmd/gui; этот бинарь существует только для локальной проверки.
//
// Использование:
//
//	go run ./cmd/fakeserver                       # порт 2222, новый ключ хоста каждый раз
//	go run ./cmd/fakeserver -hostkey-file key.bin  # ключ хоста сохраняется/переиспользуется
//	go run ./cmd/fakeserver -hostkey-file key.bin -new-hostkey
//	                                                # тот же адрес/порт, СМЕНИТЬ ключ хоста —
//	                                                # воспроизвести сценарий «ключ сервера изменился»
//
// Печатает адрес, отпечаток ключа хоста и готовый ключ vpn://… — его нужно
// вставить в поле подключения CLI/GUI. Поддерживает только exec-команды,
// которые понимает internal/fakesrv.Server (docker/wg-эмуляция в памяти) —
// как и остальные тесты пакета core.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"

	"golang.org/x/crypto/ssh"

	"amnezia-admin/internal/fakesrv"
)

const (
	fakeUser     = "root"
	fakePassword = "fakeserver-QA-02-only"
)

func main() {
	port := flag.Int("port", 2222, "порт, на котором слушает фейковый SSH-сервер (127.0.0.1:<port>)")
	hostkeyFile := flag.String("hostkey-file", "", "путь к файлу с ключом хоста (seed ed25519, 32 байта); если файл существует — ключ переиспользуется, иначе создаётся и сохраняется туда")
	newHostkey := flag.Bool("new-hostkey", false, "сгенерировать НОВЫЙ ключ хоста и перезаписать -hostkey-file (даже если файл уже существует) — воспроизвести «ключ сервера изменился»: запустите один раз без флага, подключитесь и подтвердите ключ, затем перезапустите с этим флагом на том же порту")
	flag.Parse()

	signer, err := loadOrCreateHostKey(*hostkeyFile, *newHostkey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cmd/fakeserver:", err)
		os.Exit(1)
	}

	exec := fakesrv.New()
	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	srv, err := fakesrv.ListenSSH(addr, fakeUser, fakePassword, signer, exec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cmd/fakeserver: не удалось запустить сервер:", err)
		os.Exit(1)
	}
	defer srv.Close()

	key, err := buildVpnKey(srv.Addr())
	if err != nil {
		fmt.Fprintln(os.Stderr, "cmd/fakeserver:", err)
		os.Exit(1)
	}

	fmt.Println("=== Фейковый SSH-сервер Amnezia (только для локальной проверки QA-02) ===")
	fmt.Println("НИКОГДА не используйте для боевых серверов — это не Amnezia, только эмуляция exec-команд в памяти.")
	fmt.Println()
	fmt.Println("Адрес:     ", srv.Addr())
	fmt.Println("Отпечаток: ", srv.Fingerprint())
	fmt.Println()
	fmt.Println("Ключ vpn:// (вставьте в поле подключения CLI/GUI):")
	fmt.Println(key)
	fmt.Println()
	fmt.Println("Проверка «неизвестный сервер»: первое подключение этим ключом — вопрос с отпечатком выше, подтвердите его.")
	fmt.Println("Проверка «известный сервер»: повторное подключение тем же ключом — без вопроса.")
	fmt.Println("Проверка «ключ сервера изменился»: остановите процесс (Ctrl+C) и запустите заново с")
	fmt.Println("  -hostkey-file <файл> -new-hostkey  (тот же -port) — подключение тем же сохранённым ключом vpn://")
	fmt.Println("  должно быть отклонено с сообщением о смене ключа, без возможности «всё равно подключиться».")
	fmt.Println()
	fmt.Println("Ctrl+C — остановить сервер.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	fmt.Println("\ncmd/fakeserver: остановлено.")
}

// loadOrCreateHostKey — при отсутствии hostkeyPath или forceNew генерирует
// новый ключ хоста; иначе читает 32-байтовый seed ed25519 из файла. Пустой
// hostkeyPath — ключ не сохраняется (каждый запуск новый, как раньше делал
// core.NewHostKey сам по себе).
func loadOrCreateHostKey(hostkeyPath string, forceNew bool) (ssh.Signer, error) {
	if hostkeyPath == "" {
		return fakesrv.NewHostKey()
	}
	if !forceNew {
		if seed, err := os.ReadFile(hostkeyPath); err == nil {
			if len(seed) != ed25519.SeedSize {
				return nil, fmt.Errorf("%s: неверный размер файла ключа (%d байт, want %d) — удалите файл или запустите с -new-hostkey", hostkeyPath, len(seed), ed25519.SeedSize)
			}
			signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", hostkeyPath, err)
			}
			return signer, nil
		}
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("генерация ключа хоста: %w", err)
	}
	if err := os.WriteFile(hostkeyPath, seed, 0600); err != nil {
		return nil, fmt.Errorf("не удалось сохранить ключ хоста в %s: %w", hostkeyPath, err)
	}
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", hostkeyPath, err)
	}
	return signer, nil
}

// buildVpnKey собирает ключ vpn:// в формате "bare JSON base64", который
// понимает core.DecodeVpnKey (core/core_test.go:52-62: base64.RawURLEncoding
// без сжатия) — hostName/userName/password/port.
func buildVpnKey(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("SplitHostPort(%q): %w", addr, err)
	}
	m := map[string]any{
		"hostName": host,
		"userName": fakeUser,
		"password": fakePassword,
		"port":     port,
	}
	data, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return "vpn://" + base64.RawURLEncoding.EncodeToString(data), nil
}
