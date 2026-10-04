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
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
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
	"amnezia-admin/internal/canary"
)

func main() { os.Exit(run()) }

// multiFlag — повторяемый флаг (-skip-family a -skip-family b).
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func run() int {
	// QA-01 Н1: единственная граница маскировки — всё, что канарейка
	// печатает, идёт через эти писатели (см. internal/canary/mask.go).
	masker := canary.NewMasker(os.Getenv("AMNEZIA_KEY"), os.Getenv("AMNEZIA_KEY_SUDO"))
	out, errOut := masker.Writer(os.Stdout), masker.Writer(os.Stderr)
	confirm := flag.String("not-production", "", "подтверждение, что сервер НЕ боевой: ровно "+canary.RequiredConfirmation)
	newBin := flag.String("new", "", "путь к собранной новой версии (консольная, amnezia-admin)")
	oldBin := flag.String("old", "", "путь к v0.2.0 (консольная) — для контроля гонки и К7")
	hostkey := flag.String("hostkey", "", "отпечаток ключа сервера SHA256:… (иначе программа спросит)")
	rounds := flag.Int("rounds", 20, "добавлений на писателя в К4")
	only := flag.String("container", "", "проверить только этот контейнер семейства WG (amnezia-awg, amnezia-awg2, amnezia-wireguard); по умолчанию — все найденные")
	var skipFam multiFlag
	flag.Var(&skipFam, "skip-family", "осознанно пропустить обязательное семейство WG, которого нет на сервере (повторяемый); итог тогда — «ПРОЙДЕН, БЕЗ ЖИВОЙ ПРОВЕРКИ: …»")
	serverIP := flag.String("server-ip", "", "IP тестового сервера; сверяется с адресом из ключа ДО подключения (не совпал — отказ). С ним П0 допускает до "+fmt.Sprint(canary.MaxExisting)+" уже существующих клиентов (клиент администратора приложения Amnezia) и сверяет в конце, что они не изменились; без него сервер обязан быть пуст")
	printFP := flag.Bool("print-fingerprint", false, "напечатать ревизию сборки и три суммы команды записи и выйти (сервер не нужен)")
	flag.Parse()

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
		fmt.Fprintf(out, "vcs.revision=%s vcs.modified=%s\n%s\n", rev, mod, canary.FingerprintLine())
		return 0
	}

	if *confirm != canary.RequiredConfirmation {
		fmt.Fprintln(errOut, "ОТКАЗ: канарейка запускается только на отдельном тестовом сервере.")
		fmt.Fprintln(errOut, "Подтвердите это флагом: -not-production "+canary.RequiredConfirmation)
		return 2
	}
	key := os.Getenv("AMNEZIA_KEY")
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
	if k := os.Getenv("AMNEZIA_KEY_SUDO"); k != "" {
		sk, err := canary.SudoKey(cfg, k, *serverIP, net.LookupIP)
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
		pinned, err := canary.PinServer(cfg, *serverIP, net.LookupIP)
		if err != nil {
			fmt.Fprintln(errOut, "ОТКАЗ:", err)
			return 2
		}
		ck, err := canary.ChildKey(pinned)
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
	in := bufio.NewReader(os.Stdin)
	ask := func(q string) canary.Answer {
		fmt.Fprintf(out, "%s (да/нет/пропустить): ", q)
		line, _ := in.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "да", "y", "yes":
			return canary.AnswerYes
		case "нет", "n", "no":
			return canary.AnswerNo
		}
		return canary.AnswerSkip
	}
	fmt.Fprintf(out, "Сервер: %s (канарейка — только для ТЕСТОВОГО сервера)\n", creds.Host)
	kh := filepath.Join(os.TempDir(), "amnezia-canary-a3b-known_hosts")
	sess, err := core.ConnectWithHostKey(creds, core.HostKeyPolicy{
		KnownHostsPath:      kh,
		ExpectedFingerprint: *hostkey,
		Prompt: func(host, fp string) bool {
			return ask("Ключ сервера "+host+": "+fp+". Доверять?") == canary.AnswerYes
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
	sel, why := canary.SelectWG(cs, *only)
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
		if f == canary.XRayFamily {
			skipXRay = true
			continue
		}
		skipWG = append(skipWG, f)
	}
	famRows, skipped, famNotes, ferr := canary.FamilyPlan(selNames, skipWG)
	if skipXRay {
		skipped = append(skipped, canary.XRayFamily)
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
	newEnv := func(ctr *core.Container) *canary.Env {
		env := &canary.Env{
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
			env.MakeSudoKey = canary.NewSudoKeyMaker(remoteIn, creds.Host, creds.Port, func() (string, error) {
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
	var cur *canary.Env
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
	var all []canary.Result
	// SEC W-R2: общий каталог данных awg/awg2 — СТОП до любой записи;
	// отказ inspect — НЕ ПРОВЕРЕНО (шлюз).
	var foundNames []string
	for _, c := range cs {
		foundNames = append(foundNames, c.Name)
	}
	mr := canary.MountsCheck(remote, foundNames)
	fmt.Fprintf(out, "[%s] %s %s — %s\n", mr.Status, mr.ID, mr.Name, mr.Detail)
	if mr.Status != canary.Pass && mr.Status != canary.NotApplicable {
		_, line := canary.Summary([]canary.Result{mr}, nil)
		fmt.Fprintln(out, line)
		return 1
	}
	all = append(all, mr)
	// SEC П-2: с -server-ip — предпроверка сервера ОДИН раз до первой
	// записи: свежесть всех контейнеров Amnezia и сумма существующих
	// клиентов по всем контейнерам семейства WG. Не пройдена — СТОП.
	envs := map[string]*canary.Env{}
	if *serverIP != "" {
		allWG, _ := canary.SelectWG(cs, "")
		var list []*canary.Env
		for i := range allWG {
			e := newEnv(&allWG[i])
			envs[allWG[i].Name] = e
			list = append(list, e)
		}
		pre := canary.Preflight(remote, list, foundNames, time.Now())
		for _, r := range pre {
			fmt.Fprintf(out, "[%s] %s %s — %s\n", r.Status, r.ID, r.Name, r.Detail)
		}
		for _, r := range pre {
			if r.Status != canary.Pass {
				_, line := canary.Summary(pre, nil)
				fmt.Fprintln(out, line)
				return 1
			}
		}
		all = append(all, pre...)
	}
	var order []string
	per := map[string][]canary.Result{}
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
		rs, err := canary.Run(env)
		for _, cerr := range env.RunCleanups() {
			fmt.Fprintln(out, cerr)
			cleanFailed = true
		}
		if err != nil && runErr == nil {
			runErr = fmt.Errorf("%s: %w", ctr.Name, err)
		}
		order = append(order, ctr.Name)
		per[ctr.Name] = rs
		all = append(all, rs...)
	}
	fmt.Fprintln(out, "\n"+canary.Table(order, per))
	for _, r := range famRows {
		fmt.Fprintf(out, "[%s] %s %s — %s\n", r.Status, r.ID, r.Name, r.Detail)
	}
	for _, n := range famNotes {
		fmt.Fprintln(out, n)
	}
	all = append(all, famRows...)
	st, line := canary.FinalSummary(all, runErr, skipped)
	if cleanFailed {
		st, line = canary.Fail, "ИТОГ: НЕ ПРОЙДЕН — уборка на тестовом сервере не удалась (см. выше)"
	}
	fmt.Fprintln(out, line)
	// 0 — ПРОЙДЕН, 3 — ПРОЙДЕН ЧАСТИЧНО (-skip-family), 1 — прочее.
	return canary.ExitCode(st)
}
