#!/usr/bin/env bash
# Сборка релизных бинарей (CLI + GUI) для одной ОС. Версия и коммит — только
# из окружения (VERSION, COMMIT); скрипт их не вычисляет и не подставляет по
# умолчанию — релиз без версии считается находкой аудита (audit-2026-09-14).
#
# Использование: scripts/build-release.sh <linux|windows|macos>
#   VERSION=v1.2.3 COMMIT=<sha> scripts/build-release.sh windows
set -euo pipefail

os="${1:-}"
case "$os" in
linux | windows | macos) ;;
*)
	echo "СТОП: аргумент должен быть linux|windows|macos, получено: '${os}'" >&2
	exit 1
	;;
esac

if [ -z "${VERSION:-}" ]; then
	echo "СТОП: переменная окружения VERSION пуста или не задана" >&2
	exit 1
fi
if [ -z "${COMMIT:-}" ]; then
	echo "СТОП: переменная окружения COMMIT пуста или не задана" >&2
	exit 1
fi

# Код фейкового SSH-сервера (cmd/fakeserver, internal/fakesrv) не должен
# попасть в релизные бинари ни при каких обстоятельствах (П9): наивный
# `go list ... | grep ...` под `set -euo pipefail` завершил бы скрипт кодом
# 1 (из-за grep без совпадений) даже на чистом дереве, а починка глушением
# кода возврата тихо проглотила бы настоящую ошибку `go list` — поэтому
# вызовы разделены явно.
deps="$(go list -deps ./cmd/cli ./cmd/gui)" # падение go list — падение скрипта
if printf '%s\n' "$deps" | grep -E 'fakesrv|fakeserver'; then
	echo "СТОП: код фейкового сервера в зависимостях релиза" >&2
	exit 1
fi

mkdir -p dist

ldflags="-s -w -X amnezia-admin/internal/version.Version=${VERSION} -X amnezia-admin/internal/version.Commit=${COMMIT}"

case "$os" in
linux)
	CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o dist/amnezia-admin-linux-amd64 ./cmd/cli
	CGO_ENABLED=1 go build -trimpath -ldflags "$ldflags" -o dist/amnezia-admin-gui-linux-amd64 ./cmd/gui
	;;
windows)
	CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o dist/amnezia-admin-windows-amd64.exe ./cmd/cli
	CGO_ENABLED=1 go build -trimpath -ldflags "$ldflags -H windowsgui" -o dist/amnezia-admin-gui-windows-amd64.exe ./cmd/gui
	;;
macos)
	CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o dist/amnezia-admin-macos-arm64 ./cmd/cli
	CGO_ENABLED=1 go build -trimpath -ldflags "$ldflags" -o dist/amnezia-admin-gui-macos-arm64 ./cmd/gui
	;;
esac
