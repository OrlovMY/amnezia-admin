#!/usr/bin/env bash
# Строгий рост версии релизного тега (ядро, 15.09.2026 10:35).
#
# Использование: scripts/check-version-growth.sh <новый-тег>
#   список существующих тегов — построчно на stdin (без текущего/нового тега
#   в списке — это обязанность вызывающего, см. .github/workflows/release.yml,
#   фильтр `awk -v t="$GITHUB_REF_NAME" '$0 != t'`).
#
# Код возврата: 0 — новый тег строго больше максимума среди существующих
# (или список пуст — первый релиз); 1 — отказ, причина на stderr.
# Скрипт НЕ вызывает git — только текстовые данные из аргумента и stdin.
#
# Эталонный ключ сравнения: vX.Y.Z -> X.Y.Z.2 ; vX.Y.Z-rc.N -> X.Y.Z.1.N ;
# затем `sort -V`. Финальный релиз (.2) всегда больше любого rc той же
# X.Y.Z (.1.N), потому что 2 > 1 в четвёртом поле ключа.
set -euo pipefail

new_tag="${1:-}"
if [ -z "$new_tag" ]; then
	echo "СТОП: не передан новый тег первым аргументом" >&2
	exit 1
fi

# Печатает ключ сравнения тега в stdout и возвращает 0, либо возвращает 1
# без вывода, если тег не проходит semver-шаблон
# ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$.
to_key() {
	local tag="$1"
	if [[ "$tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)-rc\.([0-9]+)$ ]]; then
		printf '%s.%s.%s.1.%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"
		return 0
	elif [[ "$tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
		printf '%s.%s.%s.2\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
		return 0
	fi
	return 1
}

new_key="$(to_key "$new_tag")" || {
	echo "СТОП: новый тег '$new_tag' не проходит semver-шаблон" >&2
	exit 1
}

max_key=""
while IFS= read -r line || [ -n "$line" ]; do
	line="${line%$'\r'}"
	[ -z "$line" ] && continue
	case "$line" in
	v[0-9]*) ;;
	*) continue ;; # не по шаблону ^v[0-9] (например, archive/v0.0.1-pre-audit) — игнорируется
	esac
	key="$(to_key "$line")" || continue # не semver — игнорируется тоже
	if [ -z "$max_key" ]; then
		max_key="$key"
	else
		max_key="$(printf '%s\n%s\n' "$max_key" "$key" | sort -V | tail -1)"
	fi
done

if [ -z "$max_key" ]; then
	# Существующих валидных тегов нет — это первый релиз, новый тег проходит.
	exit 0
fi

top="$(printf '%s\n%s\n' "$max_key" "$new_key" | sort -V | tail -1)"
if [ "$max_key" = "$new_key" ] || [ "$top" != "$new_key" ]; then
	echo "СТОП: тег '$new_tag' не строго больше существующего максимума ('$max_key' по ключу сравнения)" >&2
	exit 1
fi

exit 0
