// Package canary — проверка A3б на ОТДЕЛЬНОМ сервере владельца (PR-4,
// шаги К1–К7 проекта БК-A3Б-ГОНКА-CAS.md и пункты «Для PR-4» из
// ОТЧЁТ-A3Б-PR1.md). Запускает владелец со своего компьютера
// (cmd/canary-a3b), против арендованного на сутки VPS с Amnezia.
//
// Главное правило вывода: у каждого шага три исхода — ПРОЙДЕН, НЕ ПРОЙДЕН,
// НЕ ПРОВЕРЕНО. «Не удалось проверить» никогда не становится «пройден»:
// команда не выполнилась, вывод не разобрался, человек не ответил — всё это
// НЕ ПРОВЕРЕНО. Итог ПРОЙДЕН — только если нет ни одного НЕ ПРОЙДЕН и ни
// одного НЕ ПРОВЕРЕНО.
//
// Секреты: ключ vpn:// приходит только из переменной окружения, передаётся
// дочерним процессам (две версии программы) только через окружение, в вывод
// не попадает. Вывод программ (в нём — приватные ключи выданных клиентов)
// не печатается: только код выхода, заголовок исхода и путь к .conf.
package canary

import (
	"bytes"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"amnezia-admin/core"
	"amnezia-admin/internal/writeoutcome"
)

// Status — исход шага.
type Status int

const (
	NotChecked Status = iota // по умолчанию: пока не доказано — не проверено
	Pass
	Fail
	// NotApplicable — шаг для этого контейнера не имеет смысла (К7 на
	// amnezia-awg2: v0.2.0 его не знает). Причина — в Detail. Не «пройдено»
	// и не «не проверено»: итог по нему не меняется.
	NotApplicable
)

func (s Status) String() string {
	switch s {
	case Pass:
		return "ПРОЙДЕН"
	case Fail:
		return "НЕ ПРОЙДЕН"
	case NotApplicable:
		return "НЕ ПРИМЕНИМО"
	}
	return "НЕ ПРОВЕРЕНО"
}

// Result — один шаг.
type Result struct {
	ID, Name string
	Status   Status
	Detail   string
}

// Answer — ответ человека на вопрос о том, что программа проверить не может.
type Answer int

const (
	AnswerSkip Answer = iota
	AnswerYes
	AnswerNo
)

// Env — всё, с чем работает канарейка. Поля-функции — швы для проверки
// самой канарейки на fakesrv (internal/canary/canary_test.go).
type Env struct {
	// Remote — команда на ХОСТЕ сервера по SSH; ошибка — не выполнилась или
	// вернула ненулевой код.
	Remote func(cmd string) (string, error)
	Sess   *core.Session
	Ctr    *core.Container

	NewBin, OldBin string   // пути к собранным CLI: новая и v0.2.0 ("" — нет)
	KeyEnv         []string // окружение с AMNEZIA_KEY тестового сервера
	SudoKeyEnv     []string // второй ключ — пользователь, которому docker доступен через sudo (nil — нет)
	HostKey        string   // отпечаток SHA256:… — передаётся программам через -hostkey

	// MakeSudoKey — создаёт на ТЕСТОВОМ сервере временного пользователя без
	// root, которому docker доступен только через sudo, и отдаёт окружение с
	// его ключом; undo — удалить пользователя. nil — не умеем (PR4.2 тогда
	// НЕ ПРОВЕРЕНО).
	MakeSudoKey func() (env []string, undo func() error, err error)

	Ask func(question string) Answer
	Out io.Writer

	// RaceRounds — сколько добавлений делает каждый из двух писателей в К4.
	RaceRounds int

	// SelfBuild — сведения о сборке самой канарейки (nil — debug.ReadBuildInfo).
	SelfBuild func() (*debug.BuildInfo, bool)

	cleanMu  sync.Mutex
	cleanups []func() error

	sudoUndo func() error // удалить временного пользователя (nil — не создавали)

	docker    string // "docker" или "sudo -n docker"
	dockerErr error  // docker ps не выполнился — К2.8 НЕ ПРОВЕРЕНО

	// RemoteIn — команда на хосте со stdin (К4: прежняя запись без замка
	// в роли старой версии). nil — К4 контроль НЕ ПРОВЕРЕНО.
	RemoteIn func(cmd string, stdin []byte) (string, error)

	fam core.WGFamily // файл, утилита, интерфейс контейнера Ctr (PR-W1)

	// oldRace — шов теста для контроля К4 (nil — oldWriterRace).
	oldRace func() (lost, total int, err error)

	awgVariant string // К8: какой вариант AWG проверен вживую ("" — не дошли)
}

// conf — путь к файлу конфигурации сервера контейнера.
func (e *Env) conf() string { return e.Ctr.Dir + "/" + e.fam.File }

// RequiredConfirmation — дословный текст подтверждения, без которого
// канарейка не работает (cmd/canary-a3b, флаг -not-production).
const RequiredConfirmation = "ЭТО-НЕ-БОЕВОЙ-СЕРВЕР"

// ErrStop — работа остановлена до записи (клиенты на сервере и т.п.).
var ErrStop = errors.New("канарейка остановлена")

// Run — все шаги по порядку. Возвращает результаты; ErrStop — если сервер
// не годится для проверки (на нём есть клиенты): тогда не выполнено НИЧЕГО.
func Run(e *Env) ([]Result, error) {
	var rs []Result
	add := func(r Result) {
		rs = append(rs, r)
		fmt.Fprintf(e.Out, "[%s] %s %s — %s\n", r.Status, r.ID, r.Name, r.Detail)
	}
	if e.RaceRounds == 0 {
		e.RaceRounds = 20
	}
	fam, ferr := core.WGFamilyOf(e.Ctr)
	if ferr != nil {
		add(Result{"П3", "контейнер семейства WG", NotChecked, ferr.Error()})
		return rs, fmt.Errorf("%w: %v", ErrStop, ferr)
	}
	e.fam = fam
	e.docker = "docker"
	if out, err := e.Remote("docker ps -q 2>&1"); err != nil && strings.Contains(strings.ToLower(out+err.Error()), "permission denied") {
		e.docker = "sudo -n docker"
		_, e.dockerErr = e.Remote("sudo -n docker ps -q")
	} else {
		e.dockerErr = err
	}

	// П0. Сервер пуст — иначе это может оказаться боевой сервер. Раунд 2
	// (SEC S1): «clientsTable пуста или её нет» ≠ «клиентов нет». Пусто должно
	// быть ВСЁ: таблица, [Peer] в wg0.conf и работающий сервер. Любое
	// непрочитанное — СТОП.
	// П2 (раунд 4, AU-LOGIC M2): чья сборка проверяется. Грязное дерево,
	// разные ревизии канарейки и -new, текст команды записи не найден в -new —
	// НЕ ПРОВЕРЕНО, а значит, и итог не ПРОЙДЕН.
	add(e.buildCheck())

	if r := e.serverEmpty(); r.Status != Pass {
		add(r)
		return rs, fmt.Errorf("%w: не удалось убедиться, что на сервере нет клиентов", ErrStop)
	} else {
		add(r)
	}

	// К2 — предусловия записи. Любое не ПРОЙДЕН — запись не выполняется
	// (раунд 2, QA блокер 2б: и утилиты, и время docker exec, и следы
	// прошлого прогона — без них выводы шагов записи бессмысленны).
	pre := []Result{e.traces(), e.lockDir(), e.busybox(), e.timeoutSyntax(), e.lslocks()}
	pre = append(pre, e.k2Tools()...)
	pre = append(pre, e.execTiming(), e.sudoTiming())
	for _, r := range pre {
		add(r)
	}
	for _, r := range e.k2Info() {
		add(r)
	}
	gateOK := true
	for _, r := range pre {
		if r.Status != Pass {
			gateOK = false
		}
	}
	lockBefore, _ := e.Remote("ls -ld /run/lock")

	writes := []struct {
		id, name string
		fn       func() Result
	}{
		{"К3", "обычная работа новой версии", e.k3},
		{"PR4.4", "права 0600 после записи", e.perms},
		{"PR4.1", "откат через подмену wg-quick", e.rollback},
		{"PR4.2", "sudo в обоих порядках", e.sudoOrders},
		{"К4", "гонка: новая версия без потерь, прежняя запись без замка — с потерей", e.race},
		{"К5", "обрыв: замок не зависает, файлы целиком", e.breakWrite},
		{"К6", "приложение Amnezia: «изменён другим»", e.amneziaApp},
		{"К7", "v0.2.0 после всего работает", func() Result { return e.oldWorks(lockBefore) }},
	}
	for _, w := range writes {
		if !gateOK {
			add(Result{w.id, w.name, NotChecked, "запись не выполнялась: предусловие К2 не подтверждено"})
			continue
		}
		r := w.fn()
		r.ID, r.Name = w.id, w.name
		add(r)
	}
	// Раунд 4 (AU-LOGIC L2): неубранные canary-* — не строка в журнале, а
	// шаг итога.
	u := Result{ID: "У", Name: "уборка canary-*"}
	if !gateOK {
		u.Detail = "записей не было — убирать нечего проверять"
	} else if err := e.cleanup(); err != nil {
		u.Status, u.Detail = Fail, err.Error()
	} else {
		u.Status, u.Detail = Pass, "canary-* удалены, пользователь из приложения Amnezia оставлен"
	}
	add(u)
	if e.sudoUndo != nil {
		su := Result{ID: "У2", Name: "временный пользователь " + TempUser + " удалён"}
		if err := e.dropSudoUser(); err != nil {
			su.Status, su.Detail = Fail, err.Error()
		} else {
			su.Status, su.Detail = Pass, "удалён и проверено"
		}
		add(su)
	}
	return rs, nil
}

// ensureSudoUser — временный пользователь PR4.2 (нужен уже в К2.10). Один
// на прогон; удаление — в конце Run (шаг «У2») и по сигналу.
func (e *Env) ensureSudoUser() error {
	if e.SudoKeyEnv != nil {
		return nil
	}
	if e.MakeSudoKey == nil {
		return errors.New("не задан AMNEZIA_KEY_SUDO и временного пользователя создать нечем (ключ не root)")
	}
	env, undo, err := e.MakeSudoKey()
	if err != nil {
		return err
	}
	done := false
	once := func() error {
		if done {
			return nil
		}
		if err := undo(); err != nil {
			return fmt.Errorf("ВНИМАНИЕ: временный пользователь НЕ удалён — удалите вручную на сервере: userdel %s; rm -f /etc/sudoers.d/%s (%v)", TempUser, TempUser, err)
		}
		done = true
		return nil
	}
	e.Cleanup(once)
	e.sudoUndo = once
	e.SudoKeyEnv = env
	return nil
}

func (e *Env) dropSudoUser() error {
	if e.sudoUndo == nil {
		return nil
	}
	err := e.sudoUndo()
	e.SudoKeyEnv = nil
	return err
}

// sudoTiming — К2.10 (AU-LOGIC L-1 к H1): после H1 под замком идёт
// `env LC_ALL=C sudo -n docker exec …`, и запуск sudo тоже съедает запас 10 с внешнего
// таймаута. Мерится от того же временного пользователя (su от root), та же
// сумма «запуск до конца `true`» против запаса. su добавляет своё время —
// замер с запасом в осторожную сторону. Не измерено — НЕ ПРОВЕРЕНО (шлюз).
func (e *Env) sudoTiming() Result {
	r := Result{ID: "К2.10", Name: "запуск sudo + docker exec < 10 с (sudo-пользователь)"}
	if e.MakeSudoKey == nil {
		if e.docker == "sudo -n docker" {
			r.Status, r.Detail = Pass, "ключ не root: К2.9 уже мерил запуск через sudo -n docker exec"
			return r
		}
		r.Detail = "временного sudo-пользователя создать нечем (ключ не root, docker без sudo) — запуск через sudo не измерен"
		return r
	}
	if err := e.ensureSudoUser(); err != nil {
		r.Detail = "временный пользователь не создан: " + err.Error()
		return r
	}
	var times []string
	for _, which := range []string{"холодный", "тёплый"} {
		out, err := e.Remote(`su -s /bin/sh ` + TempUser + ` -c 's=$(date +%s%N); env LC_ALL=C sudo -n docker exec ` + e.Ctr.Name + ` timeout 50 sh -c true; rc=$?; e=$(date +%s%N); echo "rc=$rc ns=$((e-s))"'`)
		if err != nil {
			r.Detail = which + ": не выполнилось: " + err.Error()
			return r
		}
		var rc int
		var ns int64
		if n, _ := fmt.Sscanf(strings.TrimSpace(out), "rc=%d ns=%d", &rc, &ns); n != 2 {
			r.Detail = which + ": вывод не разобран: " + oneLine(out)
			return r
		}
		if rc != 0 {
			r.Detail = fmt.Sprintf("%s: sudo -n docker exec от %s вернул %d — время не измерено", which, TempUser, rc)
			return r
		}
		d := time.Duration(ns)
		times = append(times, fmt.Sprintf("%s %.2f с", which, d.Seconds()))
		if d >= 10*time.Second {
			r.Status, r.Detail = Fail, strings.Join(times, ", ")+" — запаса 10 с не хватает при записи через sudo"
			return r
		}
	}
	r.Status, r.Detail = Pass, strings.Join(times, ", ")+" (от "+TempUser+", через su)"
	return r
}

// buildCheck — П2: ревизия и чистота сборки -new, совпадение с ревизией
// канарейки, sha256 текста команды записи (core.CASWriteScript) и его
// наличие в -new дословно.
func (e *Env) buildCheck() Result {
	self := e.SelfBuild
	if self == nil {
		self = debug.ReadBuildInfo
	}
	si, sok := self()
	var ni *debug.BuildInfo
	var nerr error
	var bin []byte
	if e.NewBin != "" {
		ni, nerr = buildinfo.ReadFile(e.NewBin)
		bin, _ = os.ReadFile(e.NewBin)
	}
	return judgeBuild(ni, nerr, si, sok, bin, core.CASWriteScript)
}

func vcsOf(bi *debug.BuildInfo) (rev, modified string) {
	if bi == nil {
		return "", ""
	}
	for _, kv := range bi.Settings {
		switch kv.Key {
		case "vcs.revision":
			rev = kv.Value
		case "vcs.modified":
			modified = kv.Value
		}
	}
	return rev, modified
}

// judgeBuild — чистая часть П2 (таблица в тестах).
func judgeBuild(ni *debug.BuildInfo, nerr error, si *debug.BuildInfo, sok bool, bin []byte, script string) Result {
	r := Result{ID: "П2", Name: "сборка -new: ревизия и текст команды записи"}
	hsum := FingerprintLine()
	if ni == nil {
		r.Detail = fmt.Sprintf("сведения о сборке -new не прочитаны: %v; канарейка: %s", nerr, hsum)
		return r
	}
	rev, mod := vcsOf(ni)
	srev, smod := "", ""
	if sok {
		srev, smod = vcsOf(si)
	}
	head := fmt.Sprintf("-new: vcs.revision=%s vcs.modified=%s; канарейка: vcs.revision=%s vcs.modified=%s; %s", orQ(rev), orQ(mod), orQ(srev), orQ(smod), hsum)
	switch {
	case rev == "" || mod == "":
		r.Detail = head + " — ревизия -new неизвестна (собрано без git?)"
	case mod != "false":
		r.Detail = head + " — -new собрана из ИЗМЕНЁННОГО дерева: что проверено, не совпадёт ни с одной ревизией"
	case srev == "" || smod != "false":
		r.Detail = head + " — ревизия канарейки неизвестна или дерево изменено"
	case srev != rev:
		r.Detail = head + " — канарейка и -new из РАЗНЫХ ревизий"
	case !bytes.Contains(bin, []byte(script)):
		r.Detail = head + " — текст команды записи канарейки в -new не найден дословно"
	default:
		r.Status, r.Detail = Pass, head+"; текст команды записи в -new найден дословно"
	}
	return r
}

// FingerprintLine — три суммы отпечатка записи этой сборки (core.CASFingerprint)
// одной строкой: так же печатает `canary-a3b -print-fingerprint`, и перед
// выпуском строки сверяются посимвольно (RELEASING.md).
func FingerprintLine() string {
	s, c, u := core.CASFingerprint()
	return fmt.Sprintf("sha256(CASWriteScript)=%s sha256(CASWriteCommand)=%s sha256(CASWriteCommandSudo)=%s", s, c, u)
}

func orQ(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

// Summary — итоговая строка: ПРОЙДЕН только без НЕ ПРОЙДЕН и НЕ ПРОВЕРЕНО.
func Summary(rs []Result, runErr error) (Status, string) {
	var pass, fail, nc, na int
	for _, r := range rs {
		switch r.Status {
		case Pass:
			pass++
		case Fail:
			fail++
		case NotApplicable:
			na++
		default:
			nc++
		}
	}
	counts := fmt.Sprintf("пройдено %d, не пройдено %d, не проверено %d", pass, fail, nc)
	if na > 0 {
		counts += fmt.Sprintf(", не применимо %d", na)
	}
	switch {
	case runErr != nil:
		return Fail, "ИТОГ: НЕ ПРОЙДЕН — " + runErr.Error() + " (" + counts + ")"
	case fail > 0:
		return Fail, "ИТОГ: НЕ ПРОЙДЕН (" + counts + ")"
	case nc > 0 || pass == 0:
		return NotChecked, "ИТОГ: НЕ ПРОВЕРЕНО — выпуск по этой канарейке НЕЛЬЗЯ (" + counts + ")"
	}
	return Pass, "ИТОГ: ПРОЙДЕН (" + counts + ")"
}

// ---------- К2: предусловия и сведения ----------

// dexec — команда внутри контейнера (без одинарных кавычек в cmd).
func (e *Env) dexec(cmd string) (string, error) {
	return e.Remote(e.docker + " exec " + e.Ctr.Name + " sh -c '" + cmd + "'")
}

// lockDir — ОТЧЁТ PR1, п. 6: /run/lock — каталог root, drwxrwxrwt.
func (e *Env) lockDir() Result {
	r := Result{ID: "К2.1", Name: "/run/lock — каталог root 1777"}
	out, err := e.Remote("ls -ld /run/lock")
	if err != nil {
		r.Detail = "не выполнилось: " + err.Error()
		return r
	}
	f := strings.Fields(out)
	if len(f) < 3 {
		r.Detail = "вывод не разобран: " + strings.TrimSpace(out)
		return r
	}
	r.Detail = strings.TrimSpace(out)
	if f[0] == "drwxrwxrwt" && f[2] == "root" {
		r.Status = Pass
	} else {
		r.Status = Fail
		r.Detail += " — ожидалось drwxrwxrwt root; запись НЕ выполнять"
	}
	return r
}

var reBusybox = regexp.MustCompile(`v(\d+)\.(\d+)`)

// busybox — РЕВЬЮ PR2 SEC, п. 3: версия < 1.30 — СТОП до решения ядра.
func (e *Env) busybox() Result {
	r := Result{ID: "К2.2", Name: "busybox в контейнере ≥ 1.30"}
	out, err := e.dexec(`command -v busybox >/dev/null 2>&1 || { echo NO-BUSYBOX; exit 0; }; busybox | head -1`)
	if err != nil {
		r.Detail = "не выполнилось: " + err.Error()
		return r
	}
	out = strings.TrimSpace(out)
	if out == "NO-BUSYBOX" {
		r.Status, r.Detail = Pass, "busybox в контейнере нет — ограничение старого busybox не относится; синтаксис timeout проверяет К2.3"
		return r
	}
	m := reBusybox.FindStringSubmatch(out)
	if m == nil {
		r.Detail = "версия не разобрана: " + out
		return r
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	r.Detail = out
	if maj > 1 || (maj == 1 && min >= 30) {
		r.Status = Pass
	} else {
		r.Status = Fail
		r.Detail += " — версия < 1.30: СТОП до решения ядра о форме вызова timeout"
	}
	return r
}

// timeoutSyntax — ОТЧЁТ PR1, п. 5, и SEC PR2: `timeout 50 sh -c true` в
// контейнере даёт 0; `timeout --help` — в подробности.
func (e *Env) timeoutSyntax() Result {
	r := Result{ID: "К2.3", Name: "синтаксис timeout в контейнере"}
	help, _ := e.dexec(`timeout --help 2>&1 | head -3`)
	out, err := e.dexec(`timeout 50 sh -c true; echo "rc=$?"`)
	if err != nil {
		r.Detail = "не выполнилось: " + err.Error()
		return r
	}
	r.Detail = strings.TrimSpace(out) + "; timeout --help: " + oneLine(help)
	if strings.Contains(out, "rc=0") {
		r.Status = Pass
	} else if strings.Contains(out, "rc=") {
		r.Status = Fail
	}
	return r
}

// lslocks — ОТЧЁТ PR1, п. 7: посторонний держатель замка на /run/lock.
func (e *Env) lslocks() Result {
	r := Result{ID: "К2.4", Name: "никто не держит замок /run/lock до прогона"}
	holders, known, why := e.lockHolders()
	switch {
	case !known:
		r.Detail = why
	case len(holders) == 0:
		r.Status, r.Detail = Pass, "держателей замка на каталоге /run/lock нет"
	default:
		r.Status, r.Detail = Fail, "замок держит: "+strings.Join(holders, "; ")+" — запись будет получать «занято»"
	}
	return r
}

// lslocksCmd — вывод lslocks с кодом возврата ОТДЕЛЬНО (раунд 2, QA блокер
// 2а): прежнее `… | grep … || echo NO-HOLDER` превращало отказ lslocks в
// «держателей нет».
const lslocksCmd = `command -v lslocks >/dev/null || { echo NO-LSLOCKS; exit 0; }; out=$(lslocks -o COMMAND,PID,TYPE,PATH 2>&1); echo "rc=$?"; printf '%s\n' "$out"`

// lockHolders — кто держит замок ИМЕННО на каталоге /run/lock (так замок
// берёт команда записи после PR-1, H1). Замки на файлах ВНУТРИ /run/lock —
// чужие и нашей записи не мешают. known=false — узнать не удалось.
func (e *Env) lockHolders() (holders []string, known bool, why string) {
	out, err := e.Remote(lslocksCmd)
	if err != nil {
		return nil, false, "lslocks не выполнился: " + err.Error()
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) > 0 && strings.TrimSpace(lines[0]) == "NO-LSLOCKS" {
		return nil, false, "lslocks на хосте нет — держателя не узнать"
	}
	if len(lines) < 2 || strings.TrimSpace(lines[0]) != "rc=0" {
		return nil, false, "lslocks отказал: " + oneLine(out)
	}
	head := strings.Fields(lines[1])
	pathCol := -1
	for i, h := range head {
		if h == "PATH" {
			pathCol = i
		}
	}
	if pathCol < 0 || len(head) < 4 {
		return nil, false, "заголовок lslocks не разобран: " + oneLine(lines[1])
	}
	for _, l := range lines[2:] {
		f := strings.Fields(l)
		if len(f) <= pathCol {
			continue
		}
		if p := strings.TrimSuffix(f[len(f)-1], "/"); p == "/run/lock" {
			holders = append(holders, oneLine(l))
		}
	}
	return holders, true, ""
}

// serverEmpty — П0: нет записей в clientsTable, нет [Peer] в wg0.conf и нет
// peer'ов в работающем сервере. Любое непрочитанное — НЕ ПРОВЕРЕНО (СТОП).
func (e *Env) serverEmpty() Result {
	r := Result{ID: "П0", Name: "на сервере нет клиентов"}
	clients, err := e.Sess.LoadClients(e.Ctr)
	if err != nil {
		r.Detail = "clientsTable не прочитана: " + err.Error() + " — СТОП"
		return r
	}
	wg, err := e.Remote(e.docker + " exec " + e.Ctr.Name + " cat " + e.conf())
	if err != nil {
		r.Detail = e.fam.File + " не прочитан: " + err.Error() + " — СТОП"
		return r
	}
	peersInConf := strings.Count(wg, "[Peer]")
	rt, err := e.Sess.GetPeerStats(e.Ctr)
	if err != nil {
		r.Detail = "работающий сервер не опрошен (wg show): " + err.Error() + " — СТОП"
		return r
	}
	if len(clients) != 0 || peersInConf != 0 || len(rt) != 0 {
		r.Status = Fail
		r.Detail = fmt.Sprintf("клиентов в таблице %d, [Peer] в %s %d, peer'ов в работающем сервере %d — СТОП: канарейка запускается только на пустом тестовом сервере", len(clients), e.fam.File, peersInConf, len(rt))
		return r
	}
	r.Status, r.Detail = Pass, "таблица, "+e.fam.File+" и работающий сервер — без клиентов"
	return r
}

// traces — следы прошлого прогона (раунд 2, SEC S3/S4): временный
// пользователь, его sudoers, подменённый wg-quick. Есть — запись не идёт,
// пользователя «до нас» НЕ удаляем.
func (e *Env) traces() Result {
	r := Result{ID: "П1", Name: "следов прошлого прогона нет"}
	host, err := e.Remote(`id ` + TempUser + ` >/dev/null 2>&1 && echo USER; test -e /etc/sudoers.d/` + TempUser + ` && echo SUDOERS; echo DONE`)
	if err != nil || !strings.Contains(host, "DONE") {
		r.Detail = "хост не проверен: " + fmt.Sprint(err)
		return r
	}
	ctr, err := e.dexec(`for t in ` + e.fam.Tool + ` ` + e.fam.Tool + `-quick; do p=$(command -v $t) && test -e "$p.canary-orig" && echo "ORIG $p"; done; echo DONE`)
	if err != nil || !strings.Contains(ctr, "DONE") {
		r.Detail = "контейнер не проверен: " + fmt.Sprint(err)
		return r
	}
	var found []string
	if strings.Contains(host, "USER") {
		found = append(found, "пользователь "+TempUser+" уже есть (удалите вручную: userdel "+TempUser+")")
	}
	if strings.Contains(host, "SUDOERS") {
		found = append(found, "/etc/sudoers.d/"+TempUser+" уже есть (rm -f /etc/sudoers.d/"+TempUser+")")
	}
	if strings.Contains(ctr, "ORIG") {
		found = append(found, "в контейнере лежит *.canary-orig ("+oneLine(strings.ReplaceAll(ctr, "DONE", ""))+") — wg или wg-quick, возможно, подменён (верните: mv <путь>.canary-orig <путь>)")
	}
	if len(found) > 0 {
		r.Status, r.Detail = Fail, strings.Join(found, "; ")+" — запись НЕ выполняется"
		return r
	}
	r.Status, r.Detail = Pass, "нет"
	return r
}

// TempUser — временный пользователь PR4.2.
const TempUser = "amnezia-canary"

// Cleanup — регистрирует уборку (возврат wg-quick, удаление пользователя);
// RunCleanups выполняет все, в том числе по сигналу (cmd/canary-a3b).
func (e *Env) Cleanup(f func() error) {
	e.cleanMu.Lock()
	e.cleanups = append(e.cleanups, f)
	e.cleanMu.Unlock()
}

// RunCleanups — выполнить зарегистрированные уборки (в обратном порядке) и
// вернуть ошибки. Повторный вызов ничего не делает.
func (e *Env) RunCleanups() []error {
	e.cleanMu.Lock()
	fs := e.cleanups
	e.cleanups = nil
	e.cleanMu.Unlock()
	var errs []error
	for i := len(fs) - 1; i >= 0; i-- {
		if err := fs[i](); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// k2Info — сведения, которые записываются дословно (К2, ОТЧЁТ PR1 п. 2).
func (e *Env) k2Tools() []Result {
	var rs []Result
	tools := func(id, name, cmd string, inCtr bool) {
		var out string
		var err error
		if inCtr {
			out, err = e.dexec(cmd)
		} else {
			out, err = e.Remote(cmd)
		}
		r := Result{ID: id, Name: name}
		switch {
		case err != nil:
			r.Detail = "не выполнилось: " + err.Error()
		case strings.Contains(out, "MISSING"):
			r.Status, r.Detail = Fail, oneLine(out)
		case !strings.Contains(out, "DONE"):
			r.Detail = "вывод не разобран: " + oneLine(out)
		default:
			r.Status, r.Detail = Pass, oneLine(strings.ReplaceAll(out, "DONE", ""))
		}
		rs = append(rs, r)
	}
	tools("К2.5", "flock и timeout на хосте", `for t in flock timeout; do command -v $t || echo "MISSING $t"; done; echo DONE`, false)
	tools("К2.6", "утилиты в контейнере", `for t in sha256sum base64 mv rm sh; do command -v $t || echo "MISSING $t"; done; echo DONE`, true)
	return rs
}

// k2Info — сведения, не входящие в шлюз записи (К2, ОТЧЁТ PR1 п. 2).
func (e *Env) k2Info() []Result {
	var rs []Result
	r := Result{ID: "К2.7", Name: "sysctl fs.protected_regular (сведение)"}
	if out, err := e.Remote(`sysctl fs.protected_regular`); err == nil && strings.Contains(out, "fs.protected_regular =") {
		r.Status, r.Detail = Pass, oneLine(out)
	} else {
		// раунд 2 (QA мелочь 7): «нет» — не ПРОЙДЕН
		r.Detail = "не прочитано: " + oneLine(out) + " " + fmt.Sprint(err)
	}
	rs = append(rs, r)
	dk := Result{ID: "К2.8", Name: "docker без sudo (сведение)", Detail: "docker ps не выполнился: " + fmt.Sprint(e.dockerErr)}
	if e.dockerErr == nil {
		dk.Status, dk.Detail = Pass, "используется: "+e.docker
	}
	rs = append(rs, dk)
	return rs
}

// execTiming — ОТЧЁТ PR1, п. 3: запуск docker exec против запаса 10 с.
func (e *Env) execTiming() Result {
	r := Result{ID: "К2.9", Name: "запуск docker exec < 10 с (запас casOuterMargin)"}
	var times []string
	for _, which := range []string{"холодный", "тёплый"} {
		out, err := e.Remote(`s=$(date +%s%N); ` + e.docker + ` exec ` + e.Ctr.Name + ` timeout 50 sh -c true; e=$(date +%s%N); echo $((e-s))`)
		if err != nil {
			r.Detail = which + ": не выполнилось: " + err.Error()
			return r
		}
		ns, perr := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
		if perr != nil {
			r.Detail = which + ": время не разобрано: " + oneLine(out)
			return r
		}
		d := time.Duration(ns)
		times = append(times, fmt.Sprintf("%s %.2f с", which, d.Seconds()))
		if d >= 10*time.Second {
			r.Status, r.Detail = Fail, strings.Join(times, ", ")+" — запаса 10 с не хватает, окно R2 открыто"
			return r
		}
	}
	r.Status, r.Detail = Pass, strings.Join(times, ", ")
	return r
}

// ---------- записи ----------

// cli — вызов собранной программы; ключ — только через окружение. Вывод
// наружу не отдаётся: только код, заголовок исхода (первая строка stderr) и
// путь к .conf.
type cliRun struct {
	code        int
	title, conf string
	errText     string
	dur         time.Duration
}

func (e *Env) cli(bin string, env []string, args ...string) cliRun {
	full := append([]string{}, args...)
	full = append(full, "-hostkey", e.HostKey)
	// PR-W1: новая версия получает контейнер явно; v0.2.0 флага -container
	// не знает и выбирает первый управляемый сам (К7 это проверяет).
	if bin == e.NewBin && e.Ctr != nil {
		full = append(full, "-container", e.Ctr.Name)
	}
	cmd := exec.Command(bin, full...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = strings.NewReader("")
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	start := time.Now()
	err := cmd.Run()
	r := cliRun{dur: time.Since(start), errText: se.String()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		r.code = ee.ExitCode()
	default:
		r.code = -1
		r.errText = err.Error()
	}
	r.title = oneLine(firstLine(se.String()))
	for _, l := range strings.Split(so.String(), "\n") {
		if strings.Contains(l, ".conf") {
			r.conf = strings.TrimSpace(l)
		}
	}
	return r
}

func (e *Env) names() (map[string]core.ClientEntry, error) {
	cl, err := e.Sess.LoadClients(e.Ctr)
	if err != nil {
		return nil, err
	}
	m := map[string]core.ClientEntry{}
	for _, c := range cl {
		m[c.Name()] = c
	}
	return m, nil
}

// k3 — К3: добавить, переименовать, отключить, включить, перевыпустить,
// удалить новой версией; после каждого — состав списка по серверу. Сверка с
// приложением Amnezia и подключение с .conf — вопросы человеку.
func (e *Env) k3() Result {
	lastID := "" // ключ canary-k3r до перевыпуска
	steps := []struct {
		args  []string
		check func(map[string]core.ClientEntry) bool
		what  string
	}{
		{[]string{"add", "-name", "canary-k3"}, func(m map[string]core.ClientEntry) bool { _, ok := m["canary-k3"]; return ok }, "добавить"},
		{[]string{"rename", "-name", "canary-k3", "-newname", "canary-k3r"}, func(m map[string]core.ClientEntry) bool {
			_, a := m["canary-k3"]
			_, b := m["canary-k3r"]
			return !a && b
		}, "переименовать"},
		{[]string{"toggle", "-name", "canary-k3r", "-yes"}, func(m map[string]core.ClientEntry) bool { return m["canary-k3r"].Disabled() }, "отключить"},
		{[]string{"toggle", "-name", "canary-k3r", "-yes"}, func(m map[string]core.ClientEntry) bool {
			c, ok := m["canary-k3r"]
			return ok && c.EnabledState() == core.EnabledActive
		}, "включить"},
		// раунд 4 (AU-LOGIC L1): перевыпуск обязан сменить ключ
		{[]string{"rekey", "-name", "canary-k3r", "-yes"}, func(m map[string]core.ClientEntry) bool {
			c, ok := m["canary-k3r"]
			return ok && lastID != "" && c.ClientID != lastID
		}, "перевыпустить"},
	}
	var log []string
	conf := ""
	for _, s := range steps {
		r := e.cli(e.NewBin, e.KeyEnv, s.args...)
		if r.code != 0 {
			return Result{Status: Fail, Detail: fmt.Sprintf("%s: код %d: %s", s.what, r.code, r.title)}
		}
		if r.conf != "" {
			conf = r.conf
		}
		m, err := e.names()
		if err != nil {
			return Result{Detail: s.what + ": список после не прочитан: " + err.Error()}
		}
		if !s.check(m) {
			return Result{Status: Fail, Detail: s.what + ": состав списка на сервере не тот"}
		}
		lastID = m["canary-k3r"].ClientID
		log = append(log, s.what)
	}
	// удаление — после вопросов, чтобы человек успел проверить подключение
	ans1 := e.Ask("К3: откройте приложение Amnezia и обновите список пользователей этого сервера. Есть ли там «canary-k3r» и совпадает ли список с программой?")
	ans2 := e.Ask("К3: импортируйте в клиент AmneziaWG файл " + conf + " и подключитесь. Работает ли подключение (открывается сайт)?")
	d := e.cli(e.NewBin, e.KeyEnv, "del", "-name", "canary-k3r", "-yes")
	if d.code != 0 {
		return Result{Status: Fail, Detail: "удалить: код " + strconv.Itoa(d.code) + ": " + d.title}
	}
	if m, err := e.names(); err != nil || len(m) != 0 {
		return Result{Status: Fail, Detail: "удалить: список после удаления не пуст или не прочитан"}
	}
	log = append(log, "удалить")
	res := Result{Status: Pass, Detail: "по серверу: " + strings.Join(log, ", ") + " — состав верный"}
	for _, a := range []Answer{ans1, ans2} {
		switch a {
		case AnswerNo:
			res.Status = Fail
		case AnswerSkip:
			if res.Status == Pass {
				res.Status = NotChecked
			}
		}
	}
	if res.Status != Pass {
		res.Detail += fmt.Sprintf("; ответы человека: список в Amnezia — %s, подключение — %s", ans1, ans2)
	}
	return res
}

func (a Answer) String() string {
	switch a {
	case AnswerYes:
		return "да"
	case AnswerNo:
		return "нет"
	}
	return "не проверено"
}

// perms — ОТЧЁТ PR1, п. 4: после записи оба файла — 0600.
func (e *Env) perms() Result {
	if r := e.cli(e.NewBin, e.KeyEnv, "add", "-name", "canary-perm"); r.code != 0 {
		return Result{Status: Fail, Detail: "добавить: код " + strconv.Itoa(r.code) + ": " + r.title}
	}
	out, err := e.dexec(`ls -l ` + e.conf() + ` ` + e.Ctr.Dir + `/clientsTable`)
	if err != nil {
		return Result{Detail: "ls не выполнился: " + err.Error()}
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		return Result{Detail: "вывод ls не разобран: " + oneLine(out)}
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "-rw-------") {
			return Result{Status: Fail, Detail: "права не 0600: " + oneLine(l)}
		}
	}
	return Result{Status: Pass, Detail: "оба файла -rw-------"}
}

func (e *Env) fileSums() (string, error) {
	out, err := e.dexec(`sha256sum ` + e.conf() + ` ` + e.Ctr.Dir + `/clientsTable`)
	return strings.TrimSpace(out), err
}

// rollback — ОТЧЁТ PR1, п. 1; раунд 4 (AU-LOGIC M1). Проверяет ИМЕННО
// ветку отката ядра:
//   - перед шагом на сервере нет canary-* (иначе исход зависел бы от
//     оставшихся от PR4.4 клиентов); затем добавляется опорный canary-rb0 —
//     работающий сервер НЕ пуст, и «вернулся к прежнему» не выполняется
//     тривиально;
//   - ломается `wg`, а не wg-quick: обёртка отвечает `exit 1` ТОЛЬКО на
//     `wg syncconf` и передаёт всё прочее (`wg show` для проверки) настоящему
//     wg. Прежняя подмена wg-quick отдавала syncconf ПУСТОЙ ввод, и настоящий
//     wg мог принять его и снять с сервера всех peer'ов — тогда откат не
//     возвращает рабочее состояние, и исход не «отменено», хотя продукт прав;
//   - путь ядра при этом: casWrite записал → syncconf упал, рантайм не тронут
//     (обёртка не доходит до ядра wg) → restore: casWrite отката по нашим
//     байтам → повторный syncconf снова упал → файлы измерены «совпали»,
//     рантайм измерен «совпал» → клетка {Same, Same} → ErrRolledBack →
//     «Не применено: изменения отменены».
//
// wg возвращается ВСЕГДА (defer и уборка по сигналу).
func (e *Env) rollback() (res Result) {
	if err := e.cleanup(); err != nil {
		return Result{Detail: "перед откатом canary-* не убраны: " + err.Error()}
	}
	if m, err := e.names(); err != nil || len(m) != 0 {
		return Result{Detail: fmt.Sprintf("перед откатом список не пуст (%d) или не прочитан (%v)", len(m), err)}
	}
	if r := e.cli(e.NewBin, e.KeyEnv, "add", "-name", "canary-rb0"); r.code != 0 {
		return Result{Status: Fail, Detail: "опорный клиент canary-rb0: код " + strconv.Itoa(r.code) + ": " + r.title}
	}
	peersBefore, err := e.Sess.GetPeerStats(e.Ctr)
	if err != nil {
		return Result{Detail: "работающий сервер до отката не опрошен: " + err.Error()}
	}
	if len(peersBefore) != 1 {
		return Result{Status: Fail, Detail: fmt.Sprintf("после «готово» для canary-rb0 peer'ов в работающем сервере %d, ожидался 1", len(peersBefore))}
	}
	p, err := e.dexec(`command -v ` + e.fam.Tool)
	p = strings.TrimSpace(p)
	if err != nil || p == "" || strings.ContainsAny(p, " '\"$`\\") {
		return Result{Detail: e.fam.Tool + " в контейнере не найден: " + fmt.Sprint(err)}
	}
	before, err := e.fileSums()
	if err != nil {
		return Result{Detail: "суммы файлов до не получены: " + err.Error()}
	}
	// mv, а не cp: если wg — символическая ссылка, запись поверх неё
	// испортила бы настоящий файл.
	if _, err := e.dexec(`mv ` + p + ` ` + p + `.canary-orig`); err != nil {
		return Result{Detail: "wg не отодвинут: " + err.Error()}
	}
	// Возврат регистрируется СРАЗУ (SEC S4): и в конце шага, и по сигналу.
	restoreDone := false
	restore := func() error {
		if restoreDone {
			return nil
		}
		if _, err := e.dexec(`mv -f ` + p + `.canary-orig ` + p); err != nil {
			return fmt.Errorf("ВНИМАНИЕ: wg НЕ возвращён — верните вручную в контейнере: mv -f %s.canary-orig %s (%v)", p, p, err)
		}
		restoreDone = true
		return nil
	}
	e.Cleanup(restore)
	defer func() {
		if err := restore(); err != nil {
			res.Status = Fail
			res.Detail += "; " + err.Error()
		}
	}()
	if _, err := e.dexec(wgWrapper(p)); err != nil {
		return Result{Detail: "обёртка wg не установлена: " + err.Error()}
	}
	r := e.cli(e.NewBin, e.KeyEnv, "add", "-name", "canary-rb")
	after, err := e.fileSums()
	if err != nil {
		return Result{Detail: "суммы файлов после не получены: " + err.Error()}
	}
	peersAfter, perr := e.Sess.GetPeerStats(e.Ctr)
	want, _ := writeoutcome.TextFor(writeoutcome.RolledBack)
	switch {
	case r.code == 0:
		return Result{Status: Fail, Detail: "добавление прошло, хотя wg syncconf сломан — откат не проверен"}
	case r.code != 1 || want.Title == "" || r.title != want.Title:
		return Result{Status: Fail, Detail: fmt.Sprintf("исход не «%s»: код %d: %s", want.Title, r.code, r.title)}
	case after != before:
		return Result{Status: Fail, Detail: "файлы после отката не совпали с прежними"}
	case perr != nil:
		return Result{Detail: "исход верный, файлы прежние; работающий сервер после не опрошен: " + perr.Error()}
	case !samePeers(peersBefore, peersAfter):
		return Result{Status: Fail, Detail: fmt.Sprintf("работающий сервер после отката не прежний: peer'ов было %d, стало %d", len(peersBefore), len(peersAfter))}
	}
	return Result{Status: Pass, Detail: "«" + want.Title + "», файлы байт в байт прежние, работающий сервер прежний (canary-rb0 на месте); wg возвращён"}
}

// wgWrapper — команда установки обёртки: `wg syncconf` → exit 1, всё прочее
// — настоящему wg (он лежит рядом как *.canary-orig).
func wgWrapper(p string) string {
	return `echo "#!/bin/sh" > ` + p +
		` && echo "[ \"\$1\" = syncconf ] && { echo canary: syncconf disabled >&2; exit 1; }" >> ` + p +
		` && echo "exec ` + p + `.canary-orig \"\$@\"" >> ` + p +
		` && chmod +x ` + p
}

func samePeers(a, b map[string]core.PeerStat) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// sudoOrders — ОТЧЁТ PR1, п. 2: запись от root, затем от пользователя с
// docker через sudo, и наоборот; ни одного «код 66».
func (e *Env) sudoOrders() (res Result) {
	// пользователь создан в К2.10 (или задан AMNEZIA_KEY_SUDO); удаляется
	// в конце Run — шаг «У2»
	if err := e.ensureSudoUser(); err != nil {
		return Result{Detail: "второго ключа (пользователь без root, docker через sudo) нет: " + err.Error()}
	}
	order := []struct {
		env  []string
		name string
	}{{e.KeyEnv, "canary-su-1"}, {e.SudoKeyEnv, "canary-su-2"}, {e.SudoKeyEnv, "canary-su-3"}, {e.KeyEnv, "canary-su-4"}}
	for _, o := range order {
		r := e.cli(e.NewBin, o.env, "add", "-name", o.name)
		if r.code != 0 || strings.Contains(r.errText, "66") {
			res = Result{Status: Fail, Detail: o.name + ": код " + strconv.Itoa(r.code) + ": " + r.title}
			return res
		}
	}
	res = Result{Status: Pass, Detail: "root → sudo и sudo → root: все четыре записи прошли"}
	return res
}

// race — К4: два писателя одновременно по RaceRounds добавлений.
// Раунд 3 (решение ядра): новая версия ПРОЙДЕН, только если (1) каждое
// «готово» есть на сервере, (2) всё прочее — только «изменили в другом
// месте» или «занято» (код выхода 1 и заголовок исхода дословно), (3)
// «готово» ≥ 1, (4) исходы всех 2*RaceRounds попыток учтены. Контроль на
// v0.2.0 ОБЯЗАН показать потерю, иначе стенд гонку не воспроизводит.
func (e *Env) race() Result {
	st, err := e.raceWith(e.NewBin, "canary-n")
	if err != nil {
		return Result{Detail: "новая версия: " + err.Error()}
	}
	if err := e.cleanup(); err != nil {
		return Result{Detail: "после гонки новой версии canary-* не убраны: " + err.Error()}
	}
	if r, ok := judgeNew(st, 2*e.RaceRounds); !ok {
		return r
	}
	// Контроль (PR-W1, Р3-4): роль старой версии играет сама канарейка —
	// прежней командой записи без замка (`cat > tmp && mv`, как v0.2.0).
	// v0.2.0 amnezia-awg2 не знает, а гонку надо воспроизвести на каждом
	// контейнере.
	oldRace := e.oldRace
	if oldRace == nil {
		oldRace = e.oldWriterRace
	}
	lost, total, err := oldRace()
	if err != nil {
		return Result{Detail: "новая версия: " + st.summary() + "; контроль (прежняя запись без замка): " + err.Error()}
	}
	if lost == 0 {
		return Result{Detail: fmt.Sprintf("новая версия: %s; контроль прежней записью без замка потери НЕ показал (%d записей) — гонку не удалось вызвать, проверка недействительна", st.summary(), total)}
	}
	return Result{Status: Pass, Detail: fmt.Sprintf("новая версия: %s; прежняя запись без замка: потеряно %d из %d — стенд гонку воспроизводит", st.summary(), lost, total)}
}

// raceStats — исходы гонки: попытки, «готово», пропавшие из них, остальные
// исходы по виду.
type raceStats struct {
	attempts int
	done     []string
	lost     int
	changed  int // код 1, «Не записано: сервер изменили в другом месте»
	busy     int // код 1, «Не записано: сервер занят»
	// unconfirmed — код 1, «Записано, но работа изменений не подтверждена —
	// откат не выполнен» (решение ядра 02.10.2026): в гонке это честно —
	// вторая копия записала поверх до проверки первой. Допустимо, только
	// если запись есть на сервере (считается в lost вместе с done).
	unconfirmed []string
	other       map[string]int // всё иное: «код N «заголовок»»
}

// countLost — сколько записей, о которых сказано «готово» или «записано,
// не подтверждено», на сервере после гонки НЕТ.
func countLost(st raceStats, onServer map[string]core.ClientEntry) int {
	n := 0
	for _, name := range append(append([]string(nil), st.done...), st.unconfirmed...) {
		if _, in := onServer[name]; !in {
			n++
		}
	}
	return n
}

func (st raceStats) otherCount() int {
	n := 0
	for _, v := range st.other {
		n += v
	}
	return n
}

func (st raceStats) summary() string {
	s := fmt.Sprintf("попыток %d: «готово» %d, «записано, не подтверждено» %d (потеряно из них %d), «изменили в другом месте» %d, «занято» %d", st.attempts, len(st.done), len(st.unconfirmed), st.lost, st.changed, st.busy)
	if len(st.other) > 0 {
		var parts []string
		for k, v := range st.other {
			parts = append(parts, fmt.Sprintf("%s × %d", k, v))
		}
		sort.Strings(parts)
		s += ", иные: " + strings.Join(parts, "; ")
	}
	return s
}

// judgeNew — приговор новой версии; ok=false — вернуть r (НЕ ПРОЙДЕН).
func judgeNew(st raceStats, want int) (Result, bool) {
	fail := func(why string) (Result, bool) {
		return Result{Status: Fail, Detail: "новая версия: " + why + " — " + st.summary()}, false
	}
	switch {
	case st.attempts != want || len(st.done)+len(st.unconfirmed)+st.changed+st.busy+st.otherCount() != want:
		return fail(fmt.Sprintf("исходы учтены не для всех %d попыток", want))
	case st.lost > 0:
		return fail(fmt.Sprintf("из «готово» и «записано, не подтверждено» пропало %d", st.lost))
	case st.otherCount() > 0:
		return fail("есть исходы, кроме «изменили в другом месте» и «занято»")
	case len(st.done) == 0:
		return fail("ни одного «готово»")
	}
	return Result{}, true
}

// raceOutcome — вид исхода одной попытки по коду выхода и заголовку исхода.
func classifyRace(st *raceStats, name string, code int, title string) {
	chg, _ := writeoutcome.TextFor(writeoutcome.Changed)
	bsy, _ := writeoutcome.TextFor(writeoutcome.Busy)
	unc, _ := writeoutcome.TextFor(writeoutcome.RollbackForeign)
	switch {
	case code == 1 && chg.Title != "" && title == chg.Title:
		st.changed++
	case code == 1 && unc.Title != "" && title == unc.Title:
		st.unconfirmed = append(st.unconfirmed, name)
	case code == 1 && bsy.Title != "" && title == bsy.Title:
		st.busy++
	default:
		if st.other == nil {
			st.other = map[string]int{}
		}
		st.other[fmt.Sprintf("код %d «%s»", code, title)]++
	}
}

func (e *Env) raceWith(bin, prefix string) (st raceStats, err error) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	// Прогрев: одно чтение списка ДО гонки, чтобы ключ сервера уже был в
	// known_hosts этой программы. Иначе два первых одновременных подключения
	// дописывают known_hosts через общий known_hosts.tmp, и на Windows один из
	// них падает «файл занят» (раунд 3: поймано настоящей гонкой на fakesrv).
	// Это не исход записи, а К4 меряет запись. Исход прогрева не судится:
	// программа, которая не работает вовсе, провалит и саму гонку.
	e.cli(bin, e.KeyEnv, "list")
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < e.RaceRounds; i++ {
				name := fmt.Sprintf("%s-%d-%02d", prefix, w, i)
				r := e.cli(bin, e.KeyEnv, "add", "-name", name)
				mu.Lock()
				st.attempts++
				if r.code == 0 {
					st.done = append(st.done, name)
				} else {
					classifyRace(&st, name, r.code, r.title)
				}
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	m, lerr := e.names()
	if lerr != nil {
		return st, fmt.Errorf("список после гонки не прочитан: %w", lerr)
	}
	st.lost = countLost(st, m)
	return st, nil
}

// breakWrite — К5 и ОТЧЁТ PR1, п. 8: запись обрывается (процесс убит, SSH
// рвётся); замок в это время держится, следующая запись ждёт или получает
// «занято», файлы — целиком старые или целиком новые, а затем запись идёт.
func (e *Env) breakWrite() Result {
	cmd := exec.Command(e.NewBin, "add", "-name", "canary-k5a", "-hostkey", e.HostKey)
	cmd.Env = append(os.Environ(), e.KeyEnv...)
	if err := cmd.Start(); err != nil {
		return Result{Detail: "первая запись не запущена: " + err.Error()}
	}
	time.Sleep(300 * time.Millisecond)
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	holders, known, why := e.lockHolders()
	holder := strings.Join(holders, "; ")
	if !known {
		holder = why
	} else if holder == "" {
		holder = "нет"
	}
	second := e.cli(e.NewBin, e.KeyEnv, "add", "-name", "canary-k5b")
	consistent, why := e.consistent()
	third := e.cli(e.NewBin, e.KeyEnv, "add", "-name", "canary-k5c")
	detail := fmt.Sprintf("держатель замка сразу после обрыва: %s; вторая запись: код %d за %.1f с (%s); третья: код %d; файлы: %s",
		oneLine(holder), second.code, second.dur.Seconds(), second.title, third.code, why)
	switch {
	case !consistent:
		return Result{Status: Fail, Detail: detail}
	case third.code != 0:
		return Result{Status: Fail, Detail: detail + " — замок завис"}
	case !known:
		return Result{Detail: detail + " — держателя замка на /run/lock узнать не удалось: ожидание второй записи не проверено"}
	case len(holders) == 0:
		return Result{Detail: detail + " — обрыв пришёлся не на запись под замком (или lslocks нет): ожидание второй записи не проверено"}
	case second.code != 0 && !isBusy(second):
		return Result{Status: Fail, Detail: detail + " — вторая запись не прошла и не «занято»"}
	}
	return Result{Status: Pass, Detail: detail}
}

// isBusy — «занято» так же, как в К4: код 1 и заголовок дословно (раунд 4,
// AU-LOGIC L3).
func isBusy(r cliRun) bool {
	b, _ := writeoutcome.TextFor(writeoutcome.Busy)
	return r.code == 1 && b.Title != "" && r.title == b.Title
}

// consistent — файлы согласованы: каждый включённый клиент таблицы есть в
// wg0.conf и наоборот (ни «смеси», ни половины записи).
func (e *Env) consistent() (bool, string) {
	cl, err := e.Sess.LoadClients(e.Ctr)
	if err != nil {
		return false, "список не прочитан: " + err.Error()
	}
	wg, err := e.dexec(`cat ` + e.conf())
	if err != nil {
		return false, e.fam.File + " не прочитан: " + err.Error()
	}
	peers := map[string]bool{}
	for _, l := range strings.Split(wg, "\n") {
		if kv := strings.SplitN(l, "=", 2); len(kv) == 2 && strings.TrimSpace(kv[0]) == "PublicKey" {
			peers[strings.TrimSpace(kv[1])] = true
		}
	}
	active := 0
	for _, c := range cl {
		if c.EnabledState() != core.EnabledActive {
			continue
		}
		active++
		if !peers[c.ClientID] {
			return false, "клиент " + c.Name() + " в таблице, но не в " + e.fam.File
		}
	}
	if active != len(peers) {
		return false, fmt.Sprintf("в %s peer'ов %d, активных в таблице %d", e.fam.File, len(peers), active)
	}
	return true, "согласованы"
}

// amneziaApp — К6: план добавления построен, в приложении Amnezia добавлен
// пользователь, план применён — ожидается «изменён другим», пользователь из
// приложения на месте.
func (e *Env) amneziaApp() Result {
	before, err := e.names()
	if err != nil {
		return Result{Detail: "список не прочитан: " + err.Error()}
	}
	plan, err := e.Sess.PlanAddUser(e.Ctr, "canary-k6")
	if err != nil {
		return Result{Detail: "план не построен: " + err.Error()}
	}
	if e.Ask("К6: добавьте сейчас одного пользователя в приложении Amnezia на этом сервере. Добавили?") != AnswerYes {
		return Result{Detail: "пользователь в приложении Amnezia не добавлен"}
	}
	_, err = e.Sess.Apply(plan)
	after, lerr := e.names()
	switch {
	case !errors.Is(err, core.ErrCASMismatch):
		return Result{Status: Fail, Detail: "исход не «изменён другим»: " + fmt.Sprint(err)}
	case lerr != nil:
		return Result{Detail: "список после не прочитан: " + lerr.Error()}
	case len(after) != len(before)+1:
		return Result{Status: Fail, Detail: fmt.Sprintf("пользователей было %d, стало %d — пользователь из приложения не на месте", len(before), len(after))}
	}
	return Result{Status: Pass, Detail: "«изменён другим», пользователь из приложения на месте"}
}

// oldWorks — К7: v0.2.0 работает после всего; каталог замка не изменился.
func (e *Env) oldWorks(lockBefore string) Result {
	if e.fam.File != "wg0.conf" {
		return Result{Status: NotApplicable, Detail: "v0.2.0 не знает " + e.Ctr.Name + " (" + e.fam.File + ") — работать на нём и не должна"}
	}
	if e.OldBin == "" {
		return Result{Detail: "программа v0.2.0 не задана"}
	}
	if r := e.cli(e.OldBin, e.KeyEnv, "list"); r.code != 0 {
		return Result{Status: Fail, Detail: "v0.2.0 list: код " + strconv.Itoa(r.code) + ": " + r.title}
	}
	if r := e.cli(e.OldBin, e.KeyEnv, "add", "-name", "canary-k7"); r.code != 0 {
		return Result{Status: Fail, Detail: "v0.2.0 add: код " + strconv.Itoa(r.code) + ": " + r.title}
	}
	// v0.2.0 выбирает контейнер сам (первый управляемый): запись обязана
	// оказаться в ЭТОМ контейнере, иначе К7 проверил другой протокол.
	if m, err := e.names(); err != nil {
		return Result{Detail: "v0.2.0 add прошёл; список " + e.Ctr.Name + " не прочитан: " + err.Error()}
	} else if _, ok := m["canary-k7"]; !ok {
		return Result{Detail: "v0.2.0 add прошёл, но не в " + e.Ctr.Name + " — v0.2.0 выбрала другой контейнер; К7 для этого контейнера не проверен"}
	}
	if r := e.cli(e.OldBin, e.KeyEnv, "del", "-name", "canary-k7", "-yes"); r.code != 0 {
		return Result{Status: Fail, Detail: "v0.2.0 del: код " + strconv.Itoa(r.code) + ": " + r.title}
	}
	now, err := e.Remote("ls -ld /run/lock")
	fn, fb := strings.Fields(now), strings.Fields(lockBefore)
	if err != nil || len(fn) == 0 || len(fb) == 0 {
		return Result{Detail: "v0.2.0 list/add/del прошли; каталог замка сравнить не удалось"}
	}
	if fn[0] != fb[0] {
		return Result{Status: Fail, Detail: "права /run/lock изменились: было " + oneLine(lockBefore) + ", стало " + oneLine(now)}
	}
	return Result{Status: Pass, Detail: "v0.2.0 list/add/del прошли; /run/lock не изменился"}
}

// cleanup — удаляет всех «canary-*», кроме добавленного в приложении
// Amnezia. Раунд 4 (AU-LOGIC L2): ошибка — не только в журнал, а наружу.
func (e *Env) cleanup() error {
	cl, err := e.Sess.LoadClients(e.Ctr)
	if err != nil {
		return fmt.Errorf("уборка: список не прочитан: %w", err)
	}
	var left []string
	for _, c := range cl {
		if strings.HasPrefix(c.Name(), "canary-") {
			if err := e.Sess.DeleteByID(e.Ctr, c.ClientID); err != nil {
				left = append(left, c.Name())
			}
		}
	}
	if len(left) > 0 {
		sort.Strings(left)
		return fmt.Errorf("уборка: не удалены: %s", strings.Join(left, ", "))
	}
	return nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}
