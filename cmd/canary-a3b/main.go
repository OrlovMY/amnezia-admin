// Команда canary-a3b — проверка A3б на ОТДЕЛЬНОМ сервере владельца (PR-4).
// Не входит в выпуск (scripts/build-release.sh собирает только cmd/cli и
// cmd/gui). Логика и её проверка на fakesrv — internal/canary.
//
// Запуск (инструкция — ИНСТРУКЦИЯ-КАНАРЕЙКА-A3Б.md):
//
//	AMNEZIA_KEY='vpn://…ТЕСТОВОГО сервера…' \
//	go run ./cmd/canary-a3b -not-production ЭТО-НЕ-БОЕВОЙ-СЕРВЕР \
//	    -new ./amnezia-admin-new -old ./amnezia-admin-v0.2.0
//
// Ключ — только из переменной окружения: в командной строке он был бы
// виден другим процессам и попал бы в историю оболочки. В вывод не печатается.
//
// Вся логика — internal/canary.Main (раунд 2 ревью PR #37).
package main

import (
	"os"

	"amnezia-admin/internal/canary"
)

func main() { os.Exit(canary.Main(os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr)) }
