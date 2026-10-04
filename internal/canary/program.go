package canary

// Программа canary-a3b целиком (раунд 2 ревью PR #37, решение ядра): логика
// перенесена из cmd/canary-a3b, чтобы сторож прогона программы
// (TestProgramStepsMatchRegistry) шёл в пакете, который уже в списке go test
// CI; cmd/canary-a3b только вызывает Main.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"amnezia-admin/core"
)

// multiFlag — повторяемый флаг (-skip-family a -skip-family b).
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// Main — вся программа canary-a3b; аргументы, окружение и потоки — параметрами, чтобы
// сторож TestProgramStepsMatchRegistry (internal/canary) исполнял ровно её; cmd/canary-a3b — тонкая обёртка.
func Main(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("canary-a3b", flag.ContinueOnError)
	fl.SetOutput(stderr)
	// QA-01 Н1: единственная граница маскировки — всё, что канарейка
	// печатает, идёт через эти писатели (см. internal/canary/mask.go).
	masker := NewMasker(getenv("AMNEZIA_KEY"), getenv("AMNEZIA_KEY_SUDO"))
	out, errOut := masker.Writer(stdout), masker.Writer(stderr)
	confirm := fl.String("not-production", "", "подтверждение, что сервер НЕ боевой: ровно "+RequiredConfirmation)
	newBin := fl.String("new", "", "путь к собранной новой версии (консольная, amnezia-admin)")
	oldBin := fl.String("old", "", "путь к v0.2.0 (консольная) — для контроля гонки и К7")
	hostkey := fl.String("hostkey", "", "отпечаток ключа сервера SHA256:… (иначе программа спросит)")
	rounds := fl.Int("rounds", 20, "добавлений на писателя в К4")
	only := fl.String("container", "", "проверить только этот контейнер семейства WG (amnezia-awg, amnezia-awg2, amnezia-wireguard); по умолчанию — все найденные")
	var skipFam multiFlag
	fl.Var(&skipFam, "skip-family", "осознанно пропустить обязательное семейство WG, которого нет на сервере (повторяемый); итог тогда — «ПРОЙДЕН, БЕЗ ЖИВОЙ ПРОВЕРКИ: …»")
	serverIP := fl.String("server-ip", "", "IP тестового сервера; сверяется с адресом из ключа ДО подключения (не совпал — отказ). С ним П0 допускает до "+fmt.Sprint(MaxExisting)+" уже существующих клиентов (клиент администратора приложения Amnezia) и сверяет в конце, что они не изменились; без него сервер обязан быть пуст")
	printFP := fl.Bool("print-fingerprint", false, "напечатать ревизию сборки и три суммы команды записи и выйти (сервер не нужен)")
	if err := fl.Parse(args); err != nil {
		return 2
	}

	if *printFP {
		rev, mod := "?", "?"
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, kv := range bi.Settings {
				switch kv.Key {
				case "vcs.revision":
					rev = kv.Value
				case "vcs.modified":
					mod = kv.Value
				}
			}
		}
		fmt.Fprintf(out, "vcs.revision=%s vcs.modified=%s\n%s\n", rev, mod, FingerprintLine())
		return 0
	}

	if *confirm != RequiredConfirmation {
		fmt.Fprintln(errOut, "ОТКАЗ: канарейка запускается только на отдельном тестовом сервере.")
		fmt.Fprintln(errOut, "Подтвердите это флагом: -not-production "+RequiredConfirmation)
		return 2
	}
	key := getenv("AMNEZIA_KEY")
	if key == "" || *newBin == "" {
		fmt.Fprintln(errOut, "ОТКАЗ: нужны переменная AMNEZIA_KEY (ключ ТЕСТОВОГО сервера) и флаг -new")
		return 2
	}
	cfg, err := core.DecodeVpnKey(key)
	if err == nil {
		masker.Add(core.Str(cfg, "password"))
	}
	if err != nil {
		fmt.Fprintln(errOut, "ОТКАЗ: ключ не разобран:", err)
		return 2
	}
	// SEC П-3: второй ключ — на тот же тестовый сервер, ДО подключения.
	sudoKey := ""
	if k := getenv("AMNEZIA_KEY_SUDO"); k != "" {
		sk, err := SudoKey(cfg, k, *serverIP, net.LookupIP)
		if err != nil {
			fmt.Fprintln(errOut, "ОТКАЗ:", err)
			return 2
		}
		sudoKey = sk
	}
	// Правка П0: второй фактор против боевого сервера — IP, названный
	// человеком, против адреса из ключа; ДО подключения. SEC П-1: дальше
	// и канарейка, и дочерние программы подключаются ПРЯМО по этому IP —
	// второго разрешения имени нет.
	if *serverIP != "" {
		pinned, err := PinServer(cfg, *serverIP, net.LookupIP)
		if err != nil {
			fmt.Fprintln(errOut, "ОТКАЗ:", err)
			return 2
		}
		ck, err := ChildKey(pinned)
		if err != nil {
			fmt.Fprintln(errOut, "ОТКАЗ: ключ для дочерних программ не собран")
			return 2
		}
		cfg, key = pinned, ck
	}
	creds, err := core.CredsFromConfig(cfg)
	if err != nil {
		fmt.Fprintln(errOut, "ОТКАЗ:", err)
		return 2
	}
	// Долг 02.10: конфиги canary-* дочерние программы сохраняют во
	// временный каталог, а не в настоящий каталог данных пользователя.
	confHome, err := os.MkdirTemp("", "amnezia-canary-data-")
	if err != nil {
		fmt.Fprintln(errOut, "ОТКАЗ: временный каталог для конфигов canary-* не создан:", err)
		return 2
	}
	fmt.Fprintf(out, "Конфиги canary-* сохраняются во временный каталог: %s (настоящий каталог данных не трогается)\n", confHome)
	in := bufio.NewReader(stdin)
	ask := func(q string) Answer {
		fmt.Fprintf(out, "%s (да/нет/пропустить): ", q)
		line, _ := in.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "да", "y", "yes":
			return AnswerYes
		case "нет", "n", "no":
			return AnswerNo
		}
		return AnswerSkip
	}
	fmt.Fprintf(out, "Сервер: %s (канарейка — только для ТЕСТОВОГО сервера)\n", creds.Host)
	kh := filepath.Join(os.TempDir(), "amnezia-canary-a3b-known_hosts")
	sess, err := core.ConnectWithHostKey(creds, core.HostKeyPolicy{
		KnownHostsPath:      kh,
		ExpectedFingerprint: *hostkey,
		Prompt: func(host, fp string) bool {
			return ask("Ключ сервера "+host+": "+fp+". Доверять?") == AnswerYes
		},
	})
	if err != nil {
		fmt.Fprintln(errOut, "ОТКАЗ: подключение:", err)
		return 2
	}
	defer sess.Close()
	cs, err := sess.FindContainers()
	if err != nil {
		fmt.Fprintln(errOut, "ОТКАЗ: контейнеры:", err)
		return 2
	}
	sel, why := SelectWG(cs, *only)
	if len(sel) == 0 {
		fmt.Fprintln(out, why)
		fmt.Fprintln(out, "ИТОГ: НЕ ПРОВЕРЕНО — выпуск по этой канарейке НЕЛЬЗЯ")
		return 1
	}
	// W1 раунд 2 (QA, находка 4): обязательные семейства. Ненайденное — шаг
	// «НЕ ПРОВЕРЕНО» в итоге, если не пропущено флагом -skip-family.
	var selNames []string
	for _, c := range sel {
		selNames = append(selNames, c.Name)
	}
	// Р-4: amnezia-xray (К9) пропускается тем же флагом, но в таблицу
	// семейств WG не входит.
	var skipWG []string
	skipXRay := false
	for _, f := range skipFam {
		if f == XRayFamily {
			skipXRay = true
			continue
		}
		skipWG = append(skipWG, f)
	}
	famRows, skipped, famNotes, ferr := FamilyPlan(selNames, skipWG)
	if skipXRay {
		skipped = append(skipped, XRayFamily)
	}
	if ferr != nil {
		fmt.Fprintln(errOut, "ОТКАЗ:", ferr)
		return 2
	}
	remote := func(cmd string) (string, error) {
		s, err := sess.Client.NewSession()
		if err != nil {
			return "", err
		}
		defer s.Close()
		out, err := s.CombinedOutput(cmd)
		return string(out), err
	}
	remoteIn := func(cmd string, stdin []byte) (string, error) {
		s, err := sess.Client.NewSession()
		if err != nil {
			return "", err
		}
		defer s.Close()
		if stdin != nil {
			s.Stdin = bytes.NewReader(stdin)
		}
		out, err := s.CombinedOutput(cmd)
		return string(out), err
	}
	newEnv := func(ctr *core.Container) *Env {
		env := &Env{
			Remote:   remote,
			RemoteIn: remoteIn,
			Sess:     sess, Ctr: ctr,
			NewBin: *newBin, OldBin: *oldBin,
			KeyEnv:  []string{"AMNEZIA_KEY=" + key},
			HostKey: sess.HostKeyFingerprint,
			Ask:     ask,
			AskIP: func(q string) string {
				fmt.Fprintf(out, "%s\nАдрес: ", q)
				line, _ := in.ReadString('\n')
				return strings.TrimSpace(line)
			},
			Out:        out,
			RaceRounds: *rounds,
			ServerIP:   *serverIP,
			ConfHome:   confHome,
		}
		if sudoKey != "" {
			env.SudoKeyEnv = []string{"AMNEZIA_KEY=" + sudoKey}
		} else if creds.User == "root" {
			// PR4.2: временный пользователь без root на ТЕСТОВОМ сервере;
			// пароль случайный, уходит только через stdin chpasswd (SEC S2).
			env.MakeSudoKey = sudoKeyMaker(remoteIn, creds.Host, creds.Port, func() (string, error) {
				buf := make([]byte, 16)
				if _, err := rand.Read(buf); err != nil {
					return "", err
				}
				return hex.EncodeToString(buf), nil
			})
		}
		return env
	}

	// Уборка по Ctrl+C / kill (SEC S3, S4): вернуть подменённые утилиты,
	// удалить временного пользователя — у текущего контейнера.
	var curMu sync.Mutex
	var cur *Env
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Fprintln(out, "\nПРЕРВАНО — убираю за собой на тестовом сервере…")
		curMu.Lock()
		e := cur
		curMu.Unlock()
		if e != nil {
			for _, err := range e.RunCleanups() {
				fmt.Fprintln(out, err)
			}
		}
		fmt.Fprintln(out, "ИТОГ: НЕ ПРОЙДЕН — проверка прервана. Удалите тестовый сервер у провайдера.")
		os.Exit(130)
	}()

	// PR-W1: канарейка проходит по ВСЕМ контейнерам семейства WG (или по
	// одному — флаг -container); итог — таблица «шаг × контейнер».
	var all []Result
	// SEC W-R2: общий каталог данных awg/awg2 — СТОП до любой записи;
	// отказ inspect — НЕ ПРОВЕРЕНО (шлюз).
	var foundNames []string
	for _, c := range cs {
		foundNames = append(foundNames, c.Name)
	}
	mr := MountsCheck(remote, foundNames)
	fmt.Fprintf(out, "[%s] %s %s — %s\n", mr.Status, mr.ID, mr.Name, mr.Detail)
	if mr.Status != Pass && mr.Status != NotApplicable {
		_, line := Summary([]Result{mr}, nil)
		fmt.Fprintln(out, line)
		return 1
	}
	all = append(all, mr)
	runRows := []Result{mr}
	// SEC П-2: с -server-ip — предпроверка сервера ОДИН раз до первой
	// записи: свежесть всех контейнеров Amnezia и сумма существующих
	// клиентов по всем контейнерам семейства WG. Не пройдена — СТОП.
	envs := map[string]*Env{}
	if *serverIP != "" {
		allWG, _ := SelectWG(cs, "")
		var list []*Env
		for i := range allWG {
			e := newEnv(&allWG[i])
			envs[allWG[i].Name] = e
			list = append(list, e)
		}
		pre := Preflight(remote, list, foundNames, time.Now())
		for _, r := range pre {
			fmt.Fprintf(out, "[%s] %s %s — %s\n", r.Status, r.ID, r.Name, r.Detail)
		}
		for _, r := range pre {
			if r.Status != Pass {
				_, line := Summary(pre, nil)
				fmt.Fprintln(out, line)
				return 1
			}
		}
		all = append(all, pre...)
		runRows = append(runRows, pre...)
	}
	var order []string
	per := map[string][]Result{}
	stopped := map[string]bool{}
	conds := map[string]RunConds{}
	var runErr error
	cleanFailed := false
	for i := range sel {
		ctr := &sel[i]
		fmt.Fprintf(out, "\n===== контейнер %s (%s) =====\n", ctr.Name, ctr.Proto)
		env := envs[ctr.Name]
		if env == nil {
			env = newEnv(ctr)
		}
		curMu.Lock()
		cur = env
		curMu.Unlock()
		rs, err := Run(env)
		for _, cerr := range env.RunCleanups() {
			fmt.Fprintln(out, cerr)
			cleanFailed = true
		}
		if err != nil {
			stopped[ctr.Name] = true
		}
		// условия прогона для сверки с реестром (AU-LOGIC р3 Medium-1)
		conds[ctr.Name] = RunConds{ServerIP: *serverIP != "", SudoUser: env.sudoUndo != nil}
		if err != nil && runErr == nil {
			runErr = fmt.Errorf("%s: %w", ctr.Name, err)
		}
		order = append(order, ctr.Name)
		per[ctr.Name] = rs
		all = append(all, rs...)
	}
	return finish(out, &runState{remote: remote, remoteIn: remoteIn, foundNames: foundNames, sel: sel, skipXRay: skipXRay,
		order: order, per: per, stopped: stopped, conds: conds, runRows: runRows, all: all, famRows: famRows, famNotes: famNotes,
		runErr: runErr, cleanFailed: cleanFailed, skipped: skipped})
}

// sudoKeyMaker — шов теста программы: fakesrv не моделирует useradd.
var sudoKeyMaker = NewSudoKeyMaker

// runState — всё, что run собрал к концу шагов WG, для finish.
type runState struct {
	remote      func(string) (string, error)
	remoteIn    func(string, []byte) (string, error)
	foundNames  []string
	sel         []core.Container
	skipXRay    bool
	order       []string
	per         map[string][]Result
	stopped     map[string]bool
	conds       map[string]RunConds // условия прогона контейнера // Run контейнера вернул ошибку (остановлен)
	runRows     []Result            // строки прогона (П4, П0-свежесть, П0-сервер)
	all         []Result
	famRows     []Result
	famNotes    []string
	runErr      error
	cleanFailed bool
	skipped     []string
}

// finish — К9 (запись с ключами, Р-4), сверка с реестром шагов и итог:
// таблица «шаг × контейнер», семейства, строка ИТОГ. К9 исполняется здесь —
// на amnezia-xray (если найден и не пропущен) и на каждом проверяемом
// контейнере WG. Сверка с реестром (Audit, AU-LOGIC High-1): шаг,
// ожидаемый на контейнере, без строки и строка вне реестра — НЕ ПРОЙДЕН.
func finish(out io.Writer, st *runState) int {
	fmt.Fprintln(out, "\n===== К9: запись с ключами под замком =====")
	xrayFound := false
	for _, n := range st.foundNames {
		xrayFound = xrayFound || n == XRayFamily
	}
	targets := []K9Target{K9XRayTarget}
	found := []bool{xrayFound}
	for i := range st.sel {
		if f, err := core.WGFamilyOf(&st.sel[i]); err == nil {
			targets = append(targets, K9WGTarget(f))
			found = append(found, true)
		}
	}
	k9 := map[string][]Result{}
	for i, tg := range targets {
		skip := i == 0 && st.skipXRay
		var rs []Result
		switch {
		case skip:
		case st.runErr != nil || st.cleanFailed:
			r := Result{ID: "К9", Status: NotChecked, Detail: "не выполнялся: прогон WG не завершён"}
			r.Name = StepName("К9")
			rs = []Result{r}
		default:
			rs = K9(st.remote, st.remoteIn, tg, found[i], false)
		}
		for _, r := range rs {
			fmt.Fprintf(out, "[%s] %s (%s) %s — %s\n", r.Status, r.ID, tg.Container, r.Name, r.Detail)
		}
		if !skip {
			k9[tg.Container] = rs
		}
	}
	// Сверка с реестром.
	var audit []Result
	addAudit := func(where string, rs []Result) {
		for _, r := range rs {
			fmt.Fprintf(out, "[%s] %s (%s) %s — %s\n", r.Status, r.ID, where, r.Name, r.Detail)
			audit = append(audit, r)
			if where != "прогон" {
				st.per[where] = append(st.per[where], r)
			}
		}
	}
	for _, name := range st.order {
		addAudit(name, Audit(name, st.per[name], !st.stopped[name], "wg", st.conds[name]))
	}
	for _, tg := range targets {
		rs, ok := k9[tg.Container]
		if !ok {
			continue
		}
		addAudit(tg.Container, Audit(tg.Container, rs, true, "k9", RunConds{}))
	}
	addAudit("прогон", Audit("прогон", append(append([]Result(nil), st.runRows...), st.famRows...), true, "run", RunConds{}))
	order := st.order
	for _, tg := range targets {
		rs, ok := k9[tg.Container]
		if !ok {
			continue
		}
		if _, had := st.per[tg.Container]; !had {
			order = append(order, tg.Container)
		}
		st.per[tg.Container] = append(st.per[tg.Container], rs...)
		st.all = append(st.all, rs...)
	}
	st.all = append(st.all, audit...)
	fmt.Fprintln(out, "\n"+Table(order, st.per))
	for _, r := range st.famRows {
		fmt.Fprintf(out, "[%s] %s %s — %s\n", r.Status, r.ID, r.Name, r.Detail)
	}
	for _, n := range st.famNotes {
		fmt.Fprintln(out, n)
	}
	st.all = append(st.all, st.famRows...)
	s, line := FinalSummary(st.all, st.runErr, st.skipped)
	if st.cleanFailed {
		s, line = Fail, "ИТОГ: НЕ ПРОЙДЕН — уборка на тестовом сервере не удалась (см. выше)"
	}
	fmt.Fprintln(out, line)
	// 0 — ПРОЙДЕН, 3 — ПРОЙДЕН ЧАСТИЧНО (-skip-family), 1 — прочее.
	return ExitCode(s)
}
