package core

// СБОРЩИК СТАТИСТИКИ ТРАФИКА НА СЕРВЕРЕ (задание TRAFFIC-STATS, решения
// владельца 05.11.2026). Счётчики wg/awg обнуляются при перезапуске
// контейнера или сервера, поэтому «за всё время» копит сам сервер: таймер
// systemd раз в 5 минут запускает collect.sh, и тот дописывает снимок
// счётчиков в свой каталог. Программа только ставит/снимает сборщик (с
// подтверждением) и читает накопленное.
//
// ЧТО ПИШЕТСЯ НА СЕРВЕР (и больше ничего):
//
//	/opt/amnezia/traffic-stats/collect.sh                  — этот скрипт
//	/etc/systemd/system/amnezia-traffic-stats.service      — oneshot-служба
//	/etc/systemd/system/amnezia-traffic-stats.timer        — таймер 5 мин
//
// и данные, которые пишет сам скрипт — только в /opt/amnezia/traffic-stats:
// snapshots.log (снимки), daily.log (суточные итоги после ротации),
// служебные block.tmp, daily.new, snap.new и метка FULL.
//
// ФОРМАТ snapshots.log (текст, строка — запись, поля через пробел):
//
//	H v1 <поколение>                         первая строка файла
//	                                          пустая строка перед блоком
//	S <unix-время> <контейнер> <число peer'ов> <boot_id|-> <StartedAt|->
//	                                          (старый формат — без двух последних)
//	P <публичный ключ> <принято> <отправлено> <рукопожатие unix>
//	…
//	E <unix-время> <контейнер> <число peer'ов>
//	F <unix-время> <контейнер> exec|parse     снять счётчики не удалось
//
// Блок S…E — один снимок одного контейнера. Блок целиком собирается во
// временном файле и дописывается одним cat >>; читатель принимает блок,
// только если E совпадает с S (время, контейнер) и число строк P равно
// заявленному. Оборванный блок — пропуск снимка, а не ноль: счётчики
// накопительные, и следующий целый блок даёт ту же разницу.
//
// ФОРМАТ daily.log (суточные итоги, пишутся только ротацией):
//
//	D <поколение> <сутки UTC> <контейнер> <ключ> <принято> <отправлено> <рукопожатие> <интервалов> <из них частично потерянных>
//	N <поколение> <сутки UTC> <контейнер> <учтённых снимков> <из них без признака запуска>
//
// «Сутки UTC» — номер суток от 1970-01-01 (unix-время / 86400): awk без
// strftime (mawk, busybox) считает его одинаково, и Go — тоже.
//
// РОТАЦИЯ (предел владельца — 100 МБ на всё). Когда snapshots.log больше
// statsRotateBytes, скрипт сворачивает его в суточные итоги (awkAgg) и
// начинает новый журнал с контрольной точки — последнего целого снимка
// каждого контейнера (awkCheckpoint), чтобы разница через ротацию не
// потерялась. Поколение защищает читателя от двойного счёта в окне между
// двумя mv: журнал снимков учитывается, только если его поколение не
// меньше наибольшего поколения в daily.log. Если ротация не удаётся и
// журнал вырос до statsRawCapBytes, или daily.log больше statsDailyCapBytes,
// скрипт создаёт метку FULL и больше ничего не пишет — состояние видно в
// `stats status`.
//
// ОБРЫВ МЕЖДУ ДВУМЯ mv (ревью 1, В1): daily.log уже нового поколения, а
// журнал — старого. В начале каждого запуска сборщик сверяет поколения и
// заменяет такой журнал его контрольной точкой — иначе следующая ротация
// свернула бы тот же журнал второй раз (двойной счёт навсегда).
//
// ПРИЗНАК ЗАПУСКА (ревью 1, С2): в S пишутся boot_id ядра и StartedAt
// контейнера; смена любого — перезапуск, счётчик считается с нуля даже
// если перерос прежний. Без признака (старые снимки) — эвристика
// «уменьшился», и такие интервалы считаются (N, шестое поле; Heuristic).
// Данные пишутся с umask 077 (Н2) — читаются от root.
//
// Пик объёма (журнал 16 МБ + итоги 30 МБ + их копия при
// ротации) ниже 100 МБ.

import (
	"fmt"
	"strings"
)

const (
	StatsDir         = "/opt/amnezia/traffic-stats"
	StatsScriptPath  = StatsDir + "/collect.sh"
	StatsUnit        = "amnezia-traffic-stats"
	StatsServicePath = "/etc/systemd/system/" + StatsUnit + ".service"
	StatsTimerPath   = "/etc/systemd/system/" + StatsUnit + ".timer"

	statsRotateBytes   = 8000000
	statsRawCapBytes   = 16000000
	statsDailyCapBytes = 30000000

	// statsMaxDigits — длина числа в записи. awk хранит числа в double:
	// точны до 2^53; 15 знаков — с запасом. Длиннее — битая строка и в awk,
	// и в Go (одно правило в обоих местах).
	statsMaxDigits = 15
)

// statsSpecs — контейнеры, счётчики которых снимает сборщик: та же
// закрытая таблица семейства WG (wgfamily.go), в форме контейнер:утилита:интерфейс.
func statsSpecs() string {
	var b []string
	for _, f := range wgFamilies {
		b = append(b, f.Container+":"+f.Tool+":"+f.Iface)
	}
	return strings.Join(b, " ")
}

// awkBlock — из `wg show <if> dump` в блок S…E. Любая непонятная строка —
// отказ целиком (exit 1), а скрипт пишет F: частичный блок был бы
// «измерением» по неполным данным.
const awkBlock = `BEGIN { FS = "\t"; n = 0; bad = 0 }
NR == 1 { next }
NF == 0 { next }
{
  if (NF < 8 || $1 !~ /^[A-Za-z0-9+\/=]+$/ || $5 !~ /^[0-9]+$/ || $6 !~ /^[0-9]+$/ || $7 !~ /^[0-9]+$/ || length($5) > 15 || length($6) > 15 || length($7) > 15) { bad = 1; exit 1 }
  n++
  p[n] = "P " $1 " " $6 " " $7 " " $5
}
END {
  if (bad) exit 1
  if (b !~ /^[0-9a-f-]+$/) b = "-"
  if (s !~ /^[0-9A-Za-z:.+-]+$/) s = "-"
  printf "S %s %s %d %s %s\n", ts, c, n, b, s
  for (k = 1; k <= n; k++) print p[k]
  printf "E %s %s %d\n", ts, c, n
}`

// awkParse — общий разбор блоков для awkAgg и awkCheckpoint. Правила те
// же, что в parseTrafficRaw (Go): см. TestAwkMatchesGo.
const awkParse = `function num(v) { return v ~ /^[0-9]+$/ && length(v) <= 15 }
function sig(v) { return v ~ /^[0-9A-Za-z:.+-]+$/ }
NF == 0 { next }
$1 == "S" {
  if ((NF == 4 || (NF == 6 && sig($5) && sig($6))) && num($2) && num($4) && $3 ~ /^[a-z0-9-]+$/) {
    inb = 1; bts = $2; bc = $3; bn = $4 + 0; m = 0; buf = $0; bsig = ""
    if (NF == 6 && $5 != "-" && $6 != "-") bsig = $5 " " $6
  } else { inb = 0 }
  next
}
$1 == "P" {
  if (inb && NF == 5 && $2 ~ /^[A-Za-z0-9+\/=]+$/ && num($3) && num($4) && num($5)) { m++; pk[m] = $2; prx[m] = $3 + 0; ptx[m] = $4 + 0; phs[m] = $5 + 0; buf = buf "\n" $0 } else { inb = 0 }
  next
}
$1 == "E" {
  if (inb && NF == 4 && $2 == bts && $3 == bc && num($4) && $4 + 0 == bn && m == bn) { blk(buf "\n" $0) }
  inb = 0
  next
}
{ inb = 0 }
`

// awkAgg — суточные итоги журнала снимков. Правило разницы (то же в Go,
// trafficState.apply):
//   - ключ был в прошлом целом снимке контейнера: если хоть один счётчик
//     уменьшился — сброс (перезапуск), разница = новое значение; иначе —
//     новое минус прежнее;
//   - ключа не было, но контейнер уже снимался — peer добавлен после
//     прошлого снимка, разница = новое значение;
//   - первый снимок контейнера — точка отсчёта, разницы нет.
//
// Разница относится к суткам снимка, ЗАВЕРШАЮЩЕГО интервал.
const awkAgg = awkParse + `function blk(text,   j, key, has, dx, dt, day, ak, k, a, nd, known, rs, gap, part) {
  blkno++
  day = int(bts / 86400)
  known = (bsig != "" && (bc in psig) && psig[bc] != "")
  rs = (known && psig[bc] != bsig)
  gap = ((bc in plast) && bts - plast[bc] > 660)
  for (j = 1; j <= m; j++) {
    key = bc SUBSEP pk[j]
    has = 0
    part = 0
    if (key in prv) {
      if (rs || prx[j] < prv[key] || ptx[j] < ptv[key]) { dx = prx[j]; dt = ptx[j]; if (gap) part = 1 } else { dx = prx[j] - prv[key]; dt = ptx[j] - ptv[key] }
      has = 1
      if (!known) hc[day SUBSEP bc]++
    } else if (bc in seen) { dx = prx[j]; dt = ptx[j]; has = 1 }
    if (has) {
      ak = day SUBSEP key
      arx[ak] += dx; atx[ak] += dt; an[ak]++; ap[ak] += part
      if (!(ak in ahs) || phs[j] > ahs[ak]) ahs[ak] = phs[j]
    }
    prv[key] = prx[j]; ptv[key] = ptx[j]; cur[key] = blkno
  }
  nd = 0
  for (k in prv) { split(k, a, SUBSEP); if (a[1] == bc && cur[k] != blkno) dl[++nd] = k }
  for (j = 1; j <= nd; j++) { delete prv[dl[j]]; delete ptv[dl[j]] }
  if (bc in seen) cov[day SUBSEP bc]++
  seen[bc] = 1
  psig[bc] = bsig
  plast[bc] = bts
}
END {
  for (ak in arx) { split(ak, a, SUBSEP); printf "D %s %s %s %s %.0f %.0f %.0f %d %d\n", gen, a[1], a[2], a[3], arx[ak], atx[ak], ahs[ak], an[ak], ap[ak] + 0 }
  for (ak in cov) { split(ak, a, SUBSEP); printf "N %s %s %s %d %d\n", gen, a[1], a[2], cov[ak], hc[ak] + 0 }
}`

// awkHead — поколение из заголовка журнала (пусто, если заголовок не наш).
const awkHead = `NR == 1 { if ($1 == "H" && $2 == "v1" && $3 ~ /^[0-9]+$/ && length($3) <= 15) printf "%d\n", $3; exit }`

// awkCheckpoint — последний целый снимок каждого контейнера: с него
// начинается новый журнал после ротации.
const awkCheckpoint = awkParse + `function blk(text) { last[bc] = text }
END { for (c in last) printf "\n%s\n", last[c] }`

// awkGen — наибольшее поколение в daily.log плюс add.
const awkGen = `BEGIN { g = 0 }
($1 == "D" || $1 == "N") && $2 ~ /^[0-9]+$/ && $2 + 0 > g { g = $2 + 0 }
END { printf "%d\n", g + add }`

// StatsCollectorScript — текст collect.sh. Сторож: TestStatsScriptClosedList
// (только чтение счётчиков и запись в свой каталог).
func StatsCollectorScript() string {
	return fmt.Sprintf(`#!/bin/sh
# amnezia-admin: сборщик статистики трафика VPN, формат v1.
# Читает счётчики wg/awg и дописывает снимок в /opt/amnezia/traffic-stats.
# Снять: amnezia-admin stats uninstall
set -u
umask 077
cd %[1]s || exit 1
if [ -e FULL ]; then exit 0; fi
dg=0
if [ -e daily.log ]; then dg=$(awk -v add=0 '%[2]s' daily.log) || exit 1; fi
if [ ! -e snapshots.log ]; then
  printf 'H v1 %%s\n' "$dg" > snapshots.log
fi
rg=$(awk '%[10]s' snapshots.log) || exit 1
if [ -n "$rg" ] && [ "$rg" -lt "$dg" ]; then
  rm -f snap.new
  printf 'H v1 %%s\n' "$dg" > snap.new
  if ! awk '%[9]s' snapshots.log >> snap.new; then
    rm -f snap.new
    exit 1
  fi
  mv snap.new snapshots.log
fi
ts=$(date +%%s)
rm -f block.tmp
boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || boot="-"
if names=$(timeout 30 docker ps --format "{{.Names}}" 2>/dev/null); then
  :
else
  names=""
  printf '\nF %%s - ps\n' "$ts" >> block.tmp
fi
all=$(timeout 30 docker ps -a --format "{{.Names}}" 2>/dev/null) || all=""
for spec in %[3]s; do
  c=${spec%%%%:*}
  r=${spec#*:}
  t=${r%%%%:*}
  i=${r#*:}
  found=0
  for x in $names; do
    if [ "$x" = "$c" ]; then found=1; fi
  done
  if [ "$found" = 0 ]; then
    for x in $all; do
      if [ "$x" = "$c" ]; then found=2; fi
    done
    if [ "$found" = 2 ]; then printf '\nF %%s %%s stopped\n' "$ts" "$c" >> block.tmp; fi
    continue
  fi
  st=$(timeout 30 docker inspect -f "{{.State.StartedAt}}" "$c" 2>/dev/null) || st="-"
  if out=$(timeout 30 docker exec "$c" "$t" show "$i" dump 2>/dev/null); then
    if blk=$(printf '%%s\n' "$out" | awk -v ts="$ts" -v c="$c" -v b="$boot" -v s="$st" '%[4]s'); then
      printf '\n%%s\n' "$blk" >> block.tmp
    else
      printf '\nF %%s %%s parse\n' "$ts" "$c" >> block.tmp
    fi
  else
    printf '\nF %%s %%s exec\n' "$ts" "$c" >> block.tmp
  fi
done
if [ -s block.tmp ]; then cat block.tmp >> snapshots.log; fi
rm -f block.tmp
sz=$(wc -c < snapshots.log) || exit 1
if [ "$sz" -gt %[5]d ]; then
  printf 'raw\n' > FULL
  exit 0
fi
if [ "$sz" -gt %[6]d ]; then
  ds=0
  if [ -e daily.log ]; then ds=$(wc -c < daily.log) || exit 1; fi
  if [ "$ds" -gt %[7]d ]; then
    printf 'daily\n' > FULL
    exit 0
  fi
  gen=1
  if [ -e daily.log ]; then gen=$(awk -v add=1 '%[2]s' daily.log) || exit 1; fi
  rm -f daily.new snap.new
  if [ -e daily.log ]; then cat daily.log > daily.new || exit 1; fi
  if ! awk -v gen="$gen" '%[8]s' snapshots.log >> daily.new; then
    rm -f daily.new
    exit 1
  fi
  printf 'H v1 %%s\n' "$gen" > snap.new
  if ! awk '%[9]s' snapshots.log >> snap.new; then
    rm -f daily.new snap.new
    exit 1
  fi
  mv daily.new daily.log
  mv snap.new snapshots.log
fi
`, StatsDir, awkGen, statsSpecs(), awkBlock, statsRawCapBytes, statsRotateBytes, statsDailyCapBytes, awkAgg, awkCheckpoint, awkHead)
}

// Бюджет времени одного запуска (аудит AU-1, Н5). Каждый вызов docker —
// под `timeout statsDockerTimeout`; в худшем случае все висят до конца:
// docker ps + docker ps -a + (inspect + exec) на каждый контейнер семейства
// WG = 30 × (2 + 2×3) = 240 с; плюс запас на awk, cat и ротацию журнала до
// 16 МБ — statsRunSlackSec. TimeoutStartSec службы = сумма (300 с), чтобы
// systemd не обрывал запуск, который укладывается в собственные таймауты.
const (
	statsDockerTimeout = 30
	statsRunSlackSec   = 60
)

// statsStartTimeoutSec — TimeoutStartSec службы (TestStatsTimeouts сверяет
// его с числом вызовов docker в скрипте).
func statsStartTimeoutSec() int {
	return statsDockerTimeout*(2+2*len(wgFamilies)) + statsRunSlackSec
}

// StatsServiceUnit — текст службы.
func StatsServiceUnit() string {
	return `[Unit]
Description=amnezia-admin traffic statistics snapshot
After=docker.service

[Service]
Type=oneshot
Nice=10
TimeoutStartSec=` + fmt.Sprint(statsStartTimeoutSec()) + `s
ExecStart=/bin/sh ` + StatsScriptPath + `
`
}

// StatsTimerUnit — текст таймера: раз в 5 минут.
func StatsTimerUnit() string {
	return `[Unit]
Description=amnezia-admin traffic statistics every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
`
}

// StatsInstallFile — один файл, который пишет установка.
type StatsInstallFile struct {
	Path, Mode, Content string
}

// StatsInstallFiles — всё, что `stats install` записывает на сервер.
func StatsInstallFiles() []StatsInstallFile {
	return []StatsInstallFile{
		{StatsScriptPath, "0755", StatsCollectorScript()},
		{StatsServicePath, "0644", StatsServiceUnit()},
		{StatsTimerPath, "0644", StatsTimerUnit()},
	}
}

const statsHeredoc = "AA_TRAFFIC_STATS_EOF"

// statsInstallScript — подаётся на stdin `sh -s`. Идемпотентен: файлы
// переписываются целиком (через .new и mv), enable --now повторно ничего
// не меняет, данные (snapshots.log, daily.log) не трогаются.
func statsInstallScript() string {
	var b strings.Builder
	b.WriteString("set -e\numask 022\n" + statsDirCheck())
	for _, f := range StatsInstallFiles() {
		b.WriteString("cat > " + f.Path + ".new <<'" + statsHeredoc + "'\n")
		b.WriteString(f.Content)
		b.WriteString(statsHeredoc + "\n")
		b.WriteString("chmod " + f.Mode + " " + f.Path + ".new\n")
		b.WriteString("mv " + f.Path + ".new " + f.Path + "\n")
	}
	b.WriteString("systemctl daemon-reload\nsystemctl enable --now " + StatsUnit + ".timer\necho AA_STATS_INSTALLED\n")
	return b.String()
}

// statsDirCheck — каталог данных (аудит AU-1, Н1): не симлинк, после
// mkdir — владелец root и права 0700, иначе отказ с причиной
// (AA_STATS_BADDIR …) — root не пишет в каталог, который может подменить
// кто-то другой.
func statsDirCheck() string {
	return "if [ -L " + StatsDir + " ]; then echo \"AA_STATS_BADDIR symlink\"; exit 3; fi\n" +
		"mkdir -p " + StatsDir + "\n" +
		"chown root:root " + StatsDir + "\n" +
		"chmod 0700 " + StatsDir + "\n" +
		"m=$(stat -c %u:%a " + StatsDir + ")\n" +
		"if [ \"$m\" != \"0:700\" ]; then echo \"AA_STATS_BADDIR $m\"; exit 3; fi\n"
}

// statsUninstallScript — снимает таймер, службу и скрипт (и *.new от
// прерванной установки); ДАННЫЕ ОСТАВЛЯЕТ (история «за всё время»).
// Маркер — только если файлов действительно нет (аудит AU-1, Н2).
func statsUninstallScript() string {
	all := ""
	check := ""
	for _, p := range []string{StatsTimerPath, StatsServicePath, StatsScriptPath} {
		all += " " + p + " " + p + ".new"
		check += "[ ! -e " + p + " ] && [ ! -e " + p + ".new ] && "
	}
	return "systemctl disable --now " + StatsUnit + ".timer 2>/dev/null || true\n" +
		"systemctl stop " + StatsUnit + ".service 2>/dev/null || true\n" +
		"rm -f" + all + "\n" +
		"systemctl reset-failed " + StatsUnit + ".service " + StatsUnit + ".timer 2>/dev/null || true\n" +
		"systemctl daemon-reload\n" +
		"if " + check + "true; then echo AA_STATS_REMOVED; fi\n"
}

// statsStatusScript — только чтение: суммы файлов, состояние таймера,
// метка FULL.
func statsStatusScript() string {
	return "for f in " + StatsScriptPath + " " + StatsServicePath + " " + StatsTimerPath + "; do\n" +
		"  if [ -e \"$f\" ]; then echo \"AA_F $f $(cksum < \"$f\")\"; else echo \"AA_F $f -\"; fi\n" +
		"done\n" +
		"echo \"AA_ACTIVE $(systemctl is-active " + StatsUnit + ".timer 2>/dev/null)\"\n" +
		// Аудит AU-1, С2: «работает» — не по таймеру, а по исходу службы и
		// свежести последнего снимка.
		"systemctl show -p Result -p ActiveState -p SubState -p ExecMainStartTimestampMonotonic " + StatsUnit + ".service 2>/dev/null\n" +
		// Аудит AU-1, Н4: когда сработает таймер — для «первый снимок ожидается до …».
		"systemctl show -p NextElapseUSecRealtime " + StatsUnit + ".timer 2>/dev/null\n" +
		"echo \"AA_NOW $(date +%s)\"\n" +
		"if [ -e " + StatsDir + "/snapshots.log ]; then echo AA_TAIL_BEGIN; tail -n 50 " + StatsDir + "/snapshots.log; echo; echo AA_TAIL_END; fi\n" +
		"if [ -e " + StatsDir + "/FULL ]; then echo \"AA_FULL $(cat " + StatsDir + "/FULL)\"; fi\n" +
		"echo AA_STATUS_END\n"
}

// statsReadScript — только чтение данных. Маркеры AA_* с начала строки не
// совпадают ни с одной записью (H, S, P, E, F, D, N).
func statsReadScript() string {
	return "for f in daily.log snapshots.log; do\n" +
		"  p=" + StatsDir + "/$f\n" +
		"  if [ -e \"$p\" ]; then\n" +
		"    echo \"AA_FILE $f\"\n" +
		"    if cat \"$p\"; then echo; echo \"AA_EOF $f\"; else echo; echo \"AA_ERR $f\"; fi\n" +
		"  else\n" +
		"    echo \"AA_NOFILE $f\"\n" +
		"  fi\n" +
		"done\n" +
		"echo AA_READ_END\n"
}
