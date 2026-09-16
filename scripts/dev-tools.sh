#!/usr/bin/env bash
# scripts/dev-tools.sh — ОДИН источник версий линтеров: и для CI, и для машины
# разработчика. Причина, а не аккуратность: расхождение версий линтера между
# локальной машиной и CI даёт худший из возможных результатов — «у меня
# зелено» и спор о том, чья правда.
#
# Что делает: кладёт пиновый shellcheck в каталог ВНЕ репозитория и печатает
# его абсолютный путь в stdout (всё остальное — в stderr). Этот путь потом
# передаётся actionlint флагом -shellcheck: PATH шага и PATH, в котором ищет
# actionlint, — не одно и то же, и именно на этой разнице проект уже горел.
#
# Использование:
#   SHELLCHECK_BIN="$(bash scripts/dev-tools.sh)"
# В CI (когда задан GITHUB_ENV) путь дополнительно экспортируется как
# SHELLCHECK_BIN для следующих шагов job.
#
# Идемпотентность: повторный запуск с уже скачанным архивом сумму проверяет,
# но заново не качает. Ни одной формы глушения (|| true, || :, 2>/dev/null,
# set +e) вокруг проверок сумм и наличия файлов здесь нет и быть не должно:
# подменённый линтер проверяет то, что выгодно подменившему.
set -euo pipefail

# --- Версии: единственное место, где они записаны -----------------------------
SHELLCHECK_VERSION="v0.10.0"
# actionlint скачивать нечего — он запускается как
# `go run github.com/rhysd/actionlint/cmd/actionlint@${ACTIONLINT_VERSION}`
# (так уже сделано в release.yml, новых зависимостей в go.mod не появляется).
# Версия зафиксирована здесь, чтобы источник версий был один; .github/workflows/ci.yml
# обязан использовать ровно её.
ACTIONLINT_VERSION="v1.7.12"

# --- Контрольные суммы --------------------------------------------------------
# Источник: страница релиза https://github.com/koalaman/shellcheck/releases/tag/v0.10.0,
# загрузка по HTTPS координатором 2026-09-16 (agent-mailbox/shellcheck-sums.txt).
# ГРАНИЦА ДОКАЗАТЕЛЬСТВА: источник ОДИН. Проект shellcheck файла с суммами к
# релизу не публикует, независимого второго источника нет. Эти суммы —
# ЗАКРЕПЛЕНИЕ («всегда берём тот же файл, что взяли в тот день»), а не
# доказательство подлинности. Пересчитать sha256 того, что сам же скачал, —
# не сверка.
#
# ВНИМАНИЕ: на каждую цель ДВЕ РАЗНЫЕ суммы разных объектов — архива и
# исполняемого файла внутри него. Их уже путали, и это стоило времени.
# Проверяются обе, каждая своим объектом.
#
# Цель            | архив                                   | sha256 архива / sha256 бинаря
# linux-x86_64    | shellcheck-v0.10.0.linux.x86_64.tar.xz  | 6c881ab0… / f35ae15a…
# linux-aarch64   | shellcheck-v0.10.0.linux.aarch64.tar.xz | 324a7e89… / 4111c093…
# windows         | shellcheck-v0.10.0.zip                  | eb6cd53a… / 4dd6fb1d…

# Цель определяется по машине; DEV_TOOLS_TARGET переопределяет её вручную —
# это нужно, чтобы с Windows-машины можно было проверить ровно ту ветку,
# которая исполняется в CI (linux-x86_64). Суммы проверяются в любом случае.
detect_target() {
	local sys arch
	sys="$(uname -s)"
	arch="$(uname -m)"
	case "$sys" in
	Linux)
		case "$arch" in
		x86_64 | amd64) echo "linux-x86_64" ;;
		aarch64 | arm64) echo "linux-aarch64" ;;
		*)
			echo "СТОП: архитектура Linux '$arch' не поддержана: суммы есть только для x86_64 и aarch64" >&2
			exit 1
			;;
		esac
		;;
	MINGW* | MSYS* | CYGWIN*) echo "windows" ;;
	Darwin)
		# Суммы для macOS намеренно не заводились (решение ядра, П9 задания
		# CI-PR): в CI shellcheck нужен только на ubuntu-24.04, где живёт
		# единственный запуск actionlint. Сборка 0.10.0 под macOS публикуется
		# как darwin.x86_64, а раннер macos-26 — arm64 (тот же случай Rosetta,
		# что в BUILD-MATRIX). Пин без суммы завести нельзя, поэтому — СТОП.
		echo "СТОП: macOS не поддержан — пиновой суммы для darwin-сборки shellcheck 0.10.0 у нас нет (решение ядра)" >&2
		exit 1
		;;
	*)
		echo "СТОП: неизвестная система '$sys'" >&2
		exit 1
		;;
	esac
}

target="${DEV_TOOLS_TARGET:-$(detect_target)}"

# Ветка windows исполняется ТОЛЬКО на машине разработчика: скрипт по замыслу
# один и для CI, и для локальной работы. В CI (ci.yml, job lint) вызывается
# только ubuntu-24.04, то есть ветка linux-x86_64. Ветка windows не мёртвая —
# она живёт локально, и потому её суммы здесь тоже пиновые.
case "$target" in
linux-x86_64)
	archive="shellcheck-${SHELLCHECK_VERSION}.linux.x86_64.tar.xz"
	archive_sha256="6c881ab0698e4e6ea235245f22832860544f17ba386442fe7e9d629f8cbedf87"
	bin_sha256="f35ae15a4677945428bdfe61ccc297490d89dd1e544cc06317102637638c6deb"
	bin_rel="shellcheck-${SHELLCHECK_VERSION}/shellcheck"
	;;
linux-aarch64)
	archive="shellcheck-${SHELLCHECK_VERSION}.linux.aarch64.tar.xz"
	archive_sha256="324a7e89de8fa2aed0d0c28f3dab59cf84c6d74264022c00c22af665ed1a09bb"
	bin_sha256="4111c09318d10b93653a42179381273f31061b34987978346fbd19a6e81a74c3"
	bin_rel="shellcheck-${SHELLCHECK_VERSION}/shellcheck"
	;;
windows)
	archive="shellcheck-${SHELLCHECK_VERSION}.zip"
	archive_sha256="eb6cd53a54ea97a56540e9d296ce7e2fa68715aa507ff23574646c1e12b2e143"
	bin_sha256="4dd6fb1debca8ac71a24f932abcbed3e55d3078af71ac7c6dad98633020b7a97"
	bin_rel="shellcheck.exe"
	;;
*)
	echo "СТОП: неизвестная цель '$target' (ожидалось linux-x86_64|linux-aarch64|windows)" >&2
	exit 1
	;;
esac

url="https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/${archive}"

# Каталог назначения — ВНЕ репозитория, чтобы ни один скачанный байт не попал
# в дерево: в CI это $RUNNER_TEMP, локально — временный каталог машины.
# Поэтому в .gitignore ничего добавлять не нужно; проверяется это не верой,
# а `git status --short` после прогона.
tools_dir="${DEV_TOOLS_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/amnezia-admin-dev-tools}"
dest="${tools_dir}/${target}"
mkdir -p "$dest"

sha256_of() {
	# sha256sum есть и в Git Bash, и на ubuntu-раннере. Отсутствие — падение,
	# а не «пропустим проверку».
	sha256sum "$1" | awk '{print $1}'
}

check_sha256() {
	local file="$1" want="$2" what="$3" got
	test -f "$file" || {
		echo "СТОП: нет файла $file — проверять нечего" >&2
		exit 1
	}
	got="$(sha256_of "$file")"
	if [ "$got" != "$want" ]; then
		echo "СТОП: не совпала sha256 ${what}: ${file}" >&2
		echo "  ожидалось: $want" >&2
		echo "  получено:  $got" >&2
		echo "  Повторная загрузка НЕ выполняется: подменённый линтер проверяет то, что выгодно подменившему." >&2
		# Ревью, З5: в CI каталог умирает вместе с раннером, а на машине
		# разработчика повреждённый (не оборванный) файл остался бы лежать и
		# блокировал бы шаг навсегда — скрипт видит файл на месте и качать
		# заново отказывается. Поэтому выход из тупика называется здесь, а не
		# угадывается.
		echo "  Если файл повреждён при загрузке — удалите его и повторите:" >&2
		echo "    rm -f \"$file\" && bash scripts/dev-tools.sh" >&2
		echo "  Если после повторной загрузки сумма снова не та — это не сбой сети: не обходите проверку, идите к ядру." >&2
		exit 1
	fi
	echo "sha256 OK (${what}): $got  ${file##*/}" >&2
}

archive_path="${dest}/${archive}"
bin_path="${dest}/${bin_rel}"

if [ -f "$archive_path" ]; then
	echo "Архив уже есть, повторная загрузка не нужна: $archive_path" >&2
else
	echo "Загрузка $url" >&2
	curl --fail --location --silent --show-error --output "${archive_path}.part" "$url"
	mv "${archive_path}.part" "$archive_path"
fi

check_sha256 "$archive_path" "$archive_sha256" "АРХИВА"

# Распаковка — каждый раз заново из архива с уже проверенной суммой: так
# подменённый после распаковки бинарь не переживёт повторный запуск.
#
# Распаковка идёт из каталога назначения по ОТНОСИТЕЛЬНОМУ имени архива:
# GNU tar принимает абсолютный путь вида C:/... за спецификацию удалённой
# машины («Cannot connect to C: resolve failed») — на Windows-машине
# разработчика это ломало бы ветку, которую иначе нечем проверить.
case "$archive" in
*.tar.xz) (cd "$dest" && tar -xJf "$archive") ;;
*.zip) (cd "$dest" && unzip -o -q "$archive") ;;
*)
	echo "СТОП: неизвестный вид архива $archive" >&2
	exit 1
	;;
esac

check_sha256 "$bin_path" "$bin_sha256" "ИСПОЛНЯЕМОГО ФАЙЛА"
chmod +x "$bin_path"

echo "shellcheck ${SHELLCHECK_VERSION}: $bin_path" >&2
echo "actionlint ${ACTIONLINT_VERSION}: через go run, устанавливать нечего" >&2

# В CI отдаём путь следующим шагам job; локально его забирает вызывающий из
# stdout. Обе формы дают ОДИН И ТОТ ЖЕ бинарь — тот, что скачан и проверен
# здесь, а не первый найденный в PATH: версия из образа раннера не
# используется никогда, даже при совпадении номера (образ обновляется
# еженедельно, и «берём из образа, если совпало» делает выбор линтера
# зависимым от недели прогона).
if [ -n "${GITHUB_ENV:-}" ]; then
	printf 'SHELLCHECK_BIN=%s\n' "$bin_path" >>"$GITHUB_ENV"
	printf 'ACTIONLINT_VERSION=%s\n' "$ACTIONLINT_VERSION" >>"$GITHUB_ENV"
fi

printf '%s\n' "$bin_path"
