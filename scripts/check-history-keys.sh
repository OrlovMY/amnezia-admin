#!/usr/bin/env bash
# scripts/check-history-keys.sh — есть ли в истории git секреты: настоящий
# приватный ключ PEM или длинная ссылка vpn:// (шаг 1 RELEASING.md).
#
# Зачем скрипт, а не grep -c в инструкции. Прежняя проверка считала
# PEM-заголовки и ждала 0. С тестов маскировки (core/runner_mask_test.go)
# заголовков в истории больше десятка: это синтетические строки внутри
# Go-литералов с телами `test-pem-body-…`. Инструкция ложно кричала «не
# публиковать» на каждом релизе. Поднять ожидаемое число значило бы ослабить
# проверку, поэтому различение идёт по существу.
#
# КАК РАЗЛИЧАЕТСЯ (ревью SEC-01). От заголовка BEGIN … PRIVATE KEY до строки
# END … PRIVATE KEY, но не дальше 100 строк, собираются все отрезки, похожие
# на тело ключа. Отрезок — это строка вывода git log или кусок между
# escape-последовательностями \n внутри неё. После снятия пробелов, кавычек и
# хвостовых `,` `+` в нём должно остаться только [A-Za-z0-9+/] (и до двух
# `=` в конце), не меньше 16 символов. Блок не переходит границу коммита
# или файла. Строки Proc-Type:/DEK-Info: и пустая строка зашифрованного
# PEM отрезками не считаются (в них `:`, `,`, `-`), но и не обрывают блок,
# поэтому тело за ними собирается. Если отрезков в сумме 100 символов и больше,
# блок подозрителен. Порог 100, а не 200: тело ключа EC P-256 (SEC1) —
# около 160 символов. Подсчёт суммой, а не длиной одной строки, поэтому
# перенос по 40 символов и пробелы внутри тела его не обходят. Код тестов
# отрезком не считается: в нём есть `(`, `.`, `-`, `:` и прочее, а
# синтетические тела `test-pem-body-…` содержат `-`.
#
# ЧИСЛО ЗАГОЛОВКОВ сравнивается с KNOWN_HEADERS ниже. Если оно отличается,
# скрипт выходит с кодом 3: появился новый заголовок (или история не та),
# и смотреть на это обязан человек. Отдельный код нужен, чтобы это не
# оставалось на глаз. После просмотра число обновляется здесь отдельным
# коммитом. ВНИМАНИЕ (ревью SEC-01): настоящий ключ с телом строками короче
# 16 символов или в base64url (`-`/`_`) даёт не 1, а 3 — код 3 не означает
# «просто сменились тесты».
#
# ОБЛАСТЬ — `git log --all`, как и у проверки имён файлов в RELEASING.md.
#
# НЕ ПОКРЫТО (названо и в RELEASING.md): ключ без заголовка BEGIN (голое
# тело, PuTTY .ppk и другие форматы), бинарные файлы (git log -p пишет
# «Binary files differ»), содержимое, которое есть только в диффе
# merge-коммита (git log -p диффов слияний не показывает).
#
# Канарейка. До разбора истории та же функция scan прогоняется на образцах,
# собранных на лету (в тексте скрипта ключа нет, иначе он нашёл бы сам
# себя). Если что-то опознано не так, как ожидалось, — выход 2.
#
# Выход: 0 — чисто; 1 — подозрительный блок или vpn://; 2 — канарейка;
# 3 — число заголовков отличается от записанного. Тела ключей не печатаются
# никогда: печатаются заголовок и номер строки вывода git log.
#
# Использование:  bash scripts/check-history-keys.sh
set -euo pipefail

# Записано 29.09.2026 (A6) по `git log --all -p` на 787137c. Все 14 —
# синтетика из core/runner_mask_test.go и одна строка сообщения коммита.
KNOWN_HEADERS=14

scan() {
	awk '
	function seg_len(s,   t) {
		t = s
		gsub(/[ \t"\047]/, "", t)
		sub(/[,+]+$/, "", t)
		if (t == "") return 0
		if (t !~ /^[A-Za-z0-9+\/]+=?=?$/) return 0
		if (length(t) < 16) return 0
		return length(t)
	}
	function feed(s,   n, i, parts) {
		# Куски между escape-последовательностями \n — отдельные строки тела.
		n = split(s, parts, /\\[rn]/)
		for (i = 1; i <= n; i++) {
			if (!inblock) return
			if (parts[i] ~ /END [A-Z ]*PRIVATE KEY/) { close_block(); return }
			acc += seg_len(parts[i])
		}
	}
	function close_block() {
		if (inblock && acc >= 100) print "SUSPECT " hdr_nr ": " hdr " (тело " acc " символов base64)"
		inblock = 0
	}
	{
		# Граница коммита или файла закрывает блок: тело ключа не может
		# продолжаться в чужом коммите или в соседнем файле.
		if ($0 ~ /^commit [0-9a-f]+/ || $0 ~ /^diff --git /) close_block()
		line = $0
		sub(/\r$/, "", line)
		sub(/^[-+ ]/, "", line)
		if (match(line, /BEGIN [A-Z ]*PRIVATE KEY-----/)) {
			close_block()
			headers++
			hdr_nr = NR
			hdr = substr(line, RSTART, RLENGTH)
			inblock = 1; acc = 0; left = 100
			feed(substr(line, RSTART + RLENGTH))
			next
		}
		if (inblock) {
			feed(line)
			if (inblock && --left <= 0) close_block()
		}
	}
	END { close_block(); print "HEADERS " headers + 0 }
	'
}

count_suspects() { grep -c '^SUSPECT ' || true; }

# --- канарейка ---------------------------------------------------------------
kb="-----BEGIN RSA PRIVATE"" KEY-----"
ke="-----END RSA PRIVATE"" KEY-----"
b64="$(head -c 900 /dev/zero | base64 | tr -d '\n')"   # 1200 символов
small="${b64:0:164}"                                    # размер тела EC P-256

sample_file() { printf '+%s\n' "$kb"; printf '%s\n' "$1" | fold -w "$2" | sed 's/^/+/'; printf '+%s\n' "$ke"; }

declare -a names wants gots
check() { names+=("$1"); wants+=("$2"); gots+=("$(scan | count_suspects)"); } # stdin — образец

check "ключ файлом, строки по 64" 1 < <(sample_file "$b64" 64)
check "тело строками по 40" 1 < <(sample_file "$b64" 40)
check "короткое тело EC (164 символа)" 1 < <(sample_file "$small" 64)
check "зашифрованный PEM" 1 < <(printf '+%s\n' "$kb" "Proc-Type: 4,ENCRYPTED" "DEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF" "" | cat - <(printf '%s\n' "$b64" | fold -w 64 | sed 's/^/+/') <(printf '+%s\n' "$ke"))
check "тело с пробелами каждые 20" 1 < <({ printf '+%s\n' "$kb"; printf '%s\n' "$b64" | fold -w 60 | sed 's/.\{20\}/& /g; s/^/+/'; printf '+%s\n' "$ke"; })
check "ключ одной строкой (Go-литерал)" 1 < <(printf '+\tkey := "%s\\n%s\\n%s"\n' "$kb" "$b64" "$ke")
check "синтетический заголовок из теста" 0 < <(printf '+\t\tin := "ssh: ключ отвергнут:\\n%s\\n" + body\n+\t\tgot := maskFreeText(in)\n+\t\tif !strings.Contains(got, "x") {\n+\t\t\tt.Fatalf("утечка: %%q", got)\n+\t\t}\n' "$kb")
check "заголовок без END в сообщении, base64 в следующем коммите" 0 < <(printf '    OUT: "%s<скрыто>"\ncommit 0123456789abcdef0123456789abcdef01234567\n+\t\t"%s",\n' "$kb" "${b64:0:120}")

bad=0
for i in "${!names[@]}"; do
	if [ "${gots[$i]}" != "${wants[$i]}" ]; then
		echo "СТОП: канарейка «${names[$i]}»: подозрительных ${gots[$i]}, ждали ${wants[$i]}" >&2
		bad=1
	fi
done
if [ "$bad" != 0 ]; then
	echo "Проверка не доказала, что различает ключ и синтетику; её результату верить нельзя." >&2
	exit 2
fi
echo "канарейка: ${#names[@]} образцов опознаны как ожидалось"

# --- история -----------------------------------------------------------------
log="$(git -c core.quotePath=false log --all -p)"
out="$(printf '%s\n' "$log" | scan)"
headers="$(printf '%s\n' "$out" | sed -n 's/^HEADERS //p')"
suspects="$(printf '%s\n' "$out" | count_suspects)"
vpn="$(printf '%s\n' "$log" | grep -cE 'vpn://[A-Za-z0-9_-]{60,}' || true)"
echo "область: git log --all -p"
echo "PEM-заголовков приватного ключа: $headers (записано: $KNOWN_HEADERS)"
echo "блоков с телом ключа (подозрительных): $suspects"
echo "длинных ссылок vpn://: $vpn"
if [ "$suspects" != 0 ] || [ "$vpn" != 0 ]; then
	printf '%s\n' "$out" | grep '^SUSPECT ' >&2 || true
	echo "СТОП: найдено тело ключа или длинная ссылка vpn://. Не публиковать, звать ядро." >&2
	exit 1
fi
if [ "$headers" != "$KNOWN_HEADERS" ]; then
	echo "СТОП: заголовков $headers, а записано $KNOWN_HEADERS. Новые места надо посмотреть глазами (RELEASING.md, шаг 1); тел рядом скрипт не нашёл, но ключ, который он не узнаёт, выглядит так же." >&2
	exit 3
fi
