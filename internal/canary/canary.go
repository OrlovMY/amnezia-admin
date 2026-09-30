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
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"amnezia-admin/core"
)

// Status — исход шага.
type Status int

const (
	NotChecked Status = iota // по умолчанию: пока не доказано — не проверено
	Pass
	Fail
)

func (s Status) String() string {
	switch s {
	case Pass:
		return "ПРОЙДЕН"
	case Fail:
		return "НЕ ПРОЙДЕН"
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

	Ask func(question string) Answer
	Out io.Writer

	// RaceRounds — сколько добавлений делает каждый из двух писателей в К4.
	RaceRounds int

	docker    string // "docker" или "sudo -n docker"
	dockerErr error  // docker ps не выполнился — К2.8 НЕ ПРОВЕРЕНО
}

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
	e.docker = "docker"
	if out, err := e.Remote("docker ps -q 2>&1"); err != nil && strings.Contains(strings.ToLower(out+err.Error()), "permission denied") {
		e.docker = "sudo -n docker"
		_, e.dockerErr = e.Remote("sudo -n docker ps -q")
	} else {
		e.dockerErr = err
	}

	// П0. Сервер пуст — иначе это может оказаться боевой сервер.
	clients, err := e.Sess.LoadClients(e.Ctr)
	if err != nil {
		add(Result{"П0", "на сервере нет клиентов", NotChecked, "список не прочитан: " + err.Error()})
		return rs, fmt.Errorf("%w: не удалось убедиться, что на сервере нет клиентов", ErrStop)
	}
	if len(clients) != 0 {
		add(Result{"П0", "на сервере нет клиентов", Fail, fmt.Sprintf("клиентов %d — СТОП: канарейка запускается только на пустом тестовом сервере", len(clients))})
		return rs, fmt.Errorf("%w: на сервере есть клиенты", ErrStop)
	}
	add(Result{"П0", "на сервере нет клиентов", Pass, "clientsTable пуста или отсутствует"})

	// К2 — предусловия записи. Любое не ПРОЙДЕН — запись не выполняется.
	pre := []Result{e.lockDir(), e.busybox(), e.timeoutSyntax(), e.lslocks()}
	for _, r := range pre {
		add(r)
	}
	for _, r := range e.k2Info() {
		add(r)
	}
	add(e.execTiming())
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
		{"К4", "гонка: новая версия без потерь, v0.2.0 с потерей", e.race},
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
	e.cleanup()
	return rs, nil
}

// Summary — итоговая строка: ПРОЙДЕН только без НЕ ПРОЙДЕН и НЕ ПРОВЕРЕНО.
func Summary(rs []Result, runErr error) (Status, string) {
	var pass, fail, nc int
	for _, r := range rs {
		switch r.Status {
		case Pass:
			pass++
		case Fail:
			fail++
		default:
			nc++
		}
	}
	counts := fmt.Sprintf("пройдено %d, не пройдено %d, не проверено %d", pass, fail, nc)
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
	out, err := e.Remote(`command -v lslocks >/dev/null || { echo NO-LSLOCKS; exit 0; }; lslocks -o COMMAND,PID,PATH | grep -F /run/lock || echo NO-HOLDER`)
	if err != nil {
		r.Detail = "не выполнилось: " + err.Error()
		return r
	}
	switch s := strings.TrimSpace(out); s {
	case "NO-LSLOCKS":
		r.Detail = "lslocks на хосте нет — держателя не узнать"
	case "NO-HOLDER":
		r.Status, r.Detail = Pass, "держателей нет"
	default:
		r.Status, r.Detail = Fail, "замок держит: "+oneLine(s)+" — запись будет получать «занято»"
	}
	return r
}

// k2Info — сведения, которые записываются дословно (К2, ОТЧЁТ PR1 п. 2).
func (e *Env) k2Info() []Result {
	var rs []Result
	info := func(id, name, cmd string, inCtr bool) {
		var out string
		var err error
		if inCtr {
			out, err = e.dexec(cmd)
		} else {
			out, err = e.Remote(cmd)
		}
		r := Result{ID: id, Name: name}
		if err != nil {
			r.Detail = "не выполнилось: " + err.Error()
		} else if strings.Contains(out, "MISSING") {
			r.Status, r.Detail = Fail, oneLine(out)
		} else {
			r.Status, r.Detail = Pass, oneLine(out)
		}
		rs = append(rs, r)
	}
	info("К2.5", "flock и timeout на хосте", `for t in flock timeout; do command -v $t || echo "MISSING $t"; done`, false)
	info("К2.6", "утилиты в контейнере", `for t in sha256sum base64 mv rm sh; do command -v $t || echo "MISSING $t"; done`, true)
	info("К2.7", "sysctl fs.protected_regular (сведение)", `sysctl fs.protected_regular 2>&1 || echo нет`, false)
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
		{[]string{"rekey", "-name", "canary-k3r", "-yes"}, func(m map[string]core.ClientEntry) bool { _, ok := m["canary-k3r"]; return ok }, "перевыпустить"},
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
	out, err := e.dexec(`ls -l ` + e.Ctr.Dir + `/wg0.conf ` + e.Ctr.Dir + `/clientsTable`)
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
	out, err := e.dexec(`sha256sum ` + e.Ctr.Dir + `/wg0.conf ` + e.Ctr.Dir + `/clientsTable`)
	return strings.TrimSpace(out), err
}

// rollback — ОТЧЁТ PR1, п. 1: применение ломается (wg-quick → exit 1),
// ожидается «Не применено: изменения отменены», файлы байт в байт прежние.
// wg-quick возвращается ВСЕГДА.
func (e *Env) rollback() (res Result) {
	p, err := e.dexec(`command -v wg-quick`)
	p = strings.TrimSpace(p)
	if err != nil || p == "" || strings.ContainsAny(p, " '\"") {
		return Result{Detail: "wg-quick в контейнере не найден: " + fmt.Sprint(err)}
	}
	before, err := e.fileSums()
	if err != nil {
		return Result{Detail: "суммы файлов до не получены: " + err.Error()}
	}
	if _, err := e.dexec(`cp ` + p + ` ` + p + `.canary-orig && echo "#!/bin/sh" > ` + p + ` && echo "exit 1" >> ` + p + ` && chmod +x ` + p); err != nil {
		return Result{Detail: "подмена wg-quick не удалась: " + err.Error()}
	}
	defer func() {
		if _, err := e.dexec(`mv -f ` + p + `.canary-orig ` + p); err != nil {
			res.Status = Fail
			res.Detail += "; ВНИМАНИЕ: wg-quick НЕ возвращён — верните вручную: mv " + p + ".canary-orig " + p
		}
	}()
	r := e.cli(e.NewBin, e.KeyEnv, "add", "-name", "canary-rb")
	after, err := e.fileSums()
	if err != nil {
		return Result{Detail: "суммы файлов после не получены: " + err.Error()}
	}
	switch {
	case r.code == 0:
		return Result{Status: Fail, Detail: "добавление прошло, хотя wg-quick сломан — откат не проверен"}
	case !strings.Contains(r.errText, "Не применено: изменения отменены"):
		return Result{Status: Fail, Detail: "исход не «Не применено: изменения отменены»: " + r.title}
	case after != before:
		return Result{Status: Fail, Detail: "файлы после отката не совпали с прежними"}
	}
	return Result{Status: Pass, Detail: "«Не применено: изменения отменены», файлы байт в байт прежние; wg-quick возвращён"}
}

// sudoOrders — ОТЧЁТ PR1, п. 2: запись от root, затем от пользователя с
// docker через sudo, и наоборот; ни одного «код 66».
func (e *Env) sudoOrders() Result {
	if e.SudoKeyEnv == nil {
		return Result{Detail: "второй ключ (AMNEZIA_KEY_SUDO — пользователь без root, docker через sudo) не задан"}
	}
	order := []struct {
		env  []string
		name string
	}{{e.KeyEnv, "canary-su-1"}, {e.SudoKeyEnv, "canary-su-2"}, {e.SudoKeyEnv, "canary-su-3"}, {e.KeyEnv, "canary-su-4"}}
	for _, o := range order {
		r := e.cli(e.NewBin, o.env, "add", "-name", o.name)
		if r.code != 0 || strings.Contains(r.errText, "66") {
			return Result{Status: Fail, Detail: o.name + ": код " + strconv.Itoa(r.code) + ": " + r.title}
		}
	}
	return Result{Status: Pass, Detail: "root → sudo и sudo → root: все четыре записи прошли"}
}

// race — К4: два писателя одновременно по RaceRounds добавлений. Новая
// версия — каждый, кому сказано «готово», в списке. Контроль на v0.2.0 —
// ОБЯЗАН показать потерю, иначе стенд гонку не воспроизводит.
func (e *Env) race() Result {
	lostNew, okNew, err := e.raceWith(e.NewBin, "canary-n")
	if err != nil {
		return Result{Detail: "новая версия: " + err.Error()}
	}
	e.cleanup()
	if lostNew > 0 {
		return Result{Status: Fail, Detail: fmt.Sprintf("новая версия: из %d «готово» потеряно %d", okNew, lostNew)}
	}
	if e.OldBin == "" {
		return Result{Detail: fmt.Sprintf("новая версия: %d «готово», потерь 0; контроль на v0.2.0 не выполнен — программа v0.2.0 не задана", okNew)}
	}
	lostOld, okOld, err := e.raceWith(e.OldBin, "canary-o")
	e.cleanup()
	if err != nil {
		return Result{Detail: "контроль v0.2.0: " + err.Error()}
	}
	if lostOld == 0 {
		return Result{Detail: fmt.Sprintf("новая версия без потерь, но контроль на v0.2.0 потери НЕ показал (%d «готово») — стенд не воспроизводит гонку, проверка недействительна", okOld)}
	}
	return Result{Status: Pass, Detail: fmt.Sprintf("новая версия: %d «готово», потерь 0; v0.2.0: потеряно %d из %d — стенд гонку воспроизводит", okNew, lostOld, okOld)}
}

func (e *Env) raceWith(bin, prefix string) (lost, ok int, err error) {
	var mu sync.Mutex
	var done []string
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < e.RaceRounds; i++ {
				name := fmt.Sprintf("%s-%d-%02d", prefix, w, i)
				if r := e.cli(bin, e.KeyEnv, "add", "-name", name); r.code == 0 {
					mu.Lock()
					done = append(done, name)
					mu.Unlock()
				}
			}
		}(w)
	}
	wg.Wait()
	m, lerr := e.names()
	if lerr != nil {
		return 0, 0, fmt.Errorf("список после гонки не прочитан: %w", lerr)
	}
	for _, n := range done {
		if _, in := m[n]; !in {
			lost++
		}
	}
	return lost, len(done), nil
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
	holder, herr := e.Remote(`lslocks -o COMMAND,PID,PATH | grep -F /run/lock || echo NO-HOLDER`)
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
	case herr != nil || strings.TrimSpace(holder) == "NO-HOLDER":
		return Result{Detail: detail + " — обрыв пришёлся не на запись под замком (или lslocks нет): ожидание второй записи не проверено"}
	case second.code != 0 && !strings.Contains(second.errText, "сервер занят"):
		return Result{Status: Fail, Detail: detail + " — вторая запись не прошла и не «занято»"}
	}
	return Result{Status: Pass, Detail: detail}
}

// consistent — файлы согласованы: каждый включённый клиент таблицы есть в
// wg0.conf и наоборот (ни «смеси», ни половины записи).
func (e *Env) consistent() (bool, string) {
	cl, err := e.Sess.LoadClients(e.Ctr)
	if err != nil {
		return false, "список не прочитан: " + err.Error()
	}
	wg, err := e.dexec(`cat ` + e.Ctr.Dir + `/wg0.conf`)
	if err != nil {
		return false, "wg0.conf не прочитан: " + err.Error()
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
			return false, "клиент " + c.Name() + " в таблице, но не в wg0.conf"
		}
	}
	if active != len(peers) {
		return false, fmt.Sprintf("в wg0.conf peer'ов %d, активных в таблице %d", len(peers), active)
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
	if e.OldBin == "" {
		return Result{Detail: "программа v0.2.0 не задана"}
	}
	if r := e.cli(e.OldBin, e.KeyEnv, "list"); r.code != 0 {
		return Result{Status: Fail, Detail: "v0.2.0 list: код " + strconv.Itoa(r.code) + ": " + r.title}
	}
	if r := e.cli(e.OldBin, e.KeyEnv, "add", "-name", "canary-k7"); r.code != 0 {
		return Result{Status: Fail, Detail: "v0.2.0 add: код " + strconv.Itoa(r.code) + ": " + r.title}
	}
	if r := e.cli(e.OldBin, e.KeyEnv, "del", "-name", "canary-k7", "-yes"); r.code != 0 {
		return Result{Status: Fail, Detail: "v0.2.0 del: код " + strconv.Itoa(r.code) + ": " + r.title}
	}
	now, err := e.Remote("ls -ld /run/lock")
	if err != nil || lockBefore == "" {
		return Result{Detail: "v0.2.0 list/add/del прошли; каталог замка сравнить не удалось"}
	}
	if strings.Fields(now)[0] != strings.Fields(lockBefore)[0] {
		return Result{Status: Fail, Detail: "права /run/lock изменились: было " + oneLine(lockBefore) + ", стало " + oneLine(now)}
	}
	return Result{Status: Pass, Detail: "v0.2.0 list/add/del прошли; /run/lock не изменился"}
}

// cleanup — удаляет всех «canary-*», кроме добавленного в приложении Amnezia.
func (e *Env) cleanup() {
	cl, err := e.Sess.LoadClients(e.Ctr)
	if err != nil {
		fmt.Fprintln(e.Out, "уборка: список не прочитан:", err)
		return
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
		fmt.Fprintln(e.Out, "уборка: не удалены:", strings.Join(left, ", "))
	}
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
