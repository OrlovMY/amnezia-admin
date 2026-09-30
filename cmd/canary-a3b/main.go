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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"amnezia-admin/core"
	"amnezia-admin/internal/canary"
)

func main() { os.Exit(run()) }

func run() int {
	confirm := flag.String("not-production", "", "подтверждение, что сервер НЕ боевой: ровно "+canary.RequiredConfirmation)
	newBin := flag.String("new", "", "путь к собранной новой версии (консольная, amnezia-admin)")
	oldBin := flag.String("old", "", "путь к v0.2.0 (консольная) — для контроля гонки и К7")
	hostkey := flag.String("hostkey", "", "отпечаток ключа сервера SHA256:… (иначе программа спросит)")
	rounds := flag.Int("rounds", 20, "добавлений на писателя в К4")
	flag.Parse()

	if *confirm != canary.RequiredConfirmation {
		fmt.Fprintln(os.Stderr, "ОТКАЗ: канарейка запускается только на отдельном тестовом сервере.")
		fmt.Fprintln(os.Stderr, "Подтвердите это флагом: -not-production "+canary.RequiredConfirmation)
		return 2
	}
	key := os.Getenv("AMNEZIA_KEY")
	if key == "" || *newBin == "" {
		fmt.Fprintln(os.Stderr, "ОТКАЗ: нужны переменная AMNEZIA_KEY (ключ ТЕСТОВОГО сервера) и флаг -new")
		return 2
	}
	cfg, err := core.DecodeVpnKey(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ОТКАЗ: ключ не разобран:", err)
		return 2
	}
	creds, err := core.CredsFromConfig(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ОТКАЗ:", err)
		return 2
	}
	in := bufio.NewReader(os.Stdin)
	ask := func(q string) canary.Answer {
		fmt.Printf("%s (да/нет/пропустить): ", q)
		line, _ := in.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "да", "y", "yes":
			return canary.AnswerYes
		case "нет", "n", "no":
			return canary.AnswerNo
		}
		return canary.AnswerSkip
	}
	fmt.Printf("Сервер: %s (канарейка — только для ТЕСТОВОГО сервера)\n", creds.Host)
	kh := filepath.Join(os.TempDir(), "amnezia-canary-a3b-known_hosts")
	sess, err := core.ConnectWithHostKey(creds, core.HostKeyPolicy{
		KnownHostsPath:      kh,
		ExpectedFingerprint: *hostkey,
		Prompt: func(host, fp string) bool {
			return ask("Ключ сервера "+host+": "+fp+". Доверять?") == canary.AnswerYes
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ОТКАЗ: подключение:", err)
		return 2
	}
	defer sess.Close()
	cs, err := sess.FindContainers()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ОТКАЗ: контейнеры:", err)
		return 2
	}
	var ctr *core.Container
	for i := range cs {
		if cs[i].Name == "amnezia-awg" {
			ctr = &cs[i]
		}
	}
	if ctr == nil {
		fmt.Fprintln(os.Stderr, "ОТКАЗ: контейнера amnezia-awg нет — установите протокол AmneziaWG в приложении Amnezia")
		return 2
	}
	env := &canary.Env{
		Remote: func(cmd string) (string, error) {
			s, err := sess.Client.NewSession()
			if err != nil {
				return "", err
			}
			defer s.Close()
			out, err := s.CombinedOutput(cmd)
			return string(out), err
		},
		Sess: sess, Ctr: ctr,
		NewBin: *newBin, OldBin: *oldBin,
		KeyEnv:     []string{"AMNEZIA_KEY=" + key},
		HostKey:    sess.HostKeyFingerprint,
		Ask:        ask,
		Out:        os.Stdout,
		RaceRounds: *rounds,
	}
	if k := os.Getenv("AMNEZIA_KEY_SUDO"); k != "" {
		env.SudoKeyEnv = []string{"AMNEZIA_KEY=" + k}
	}
	rs, runErr := canary.Run(env)
	st, line := canary.Summary(rs, runErr)
	fmt.Println(line)
	if st != canary.Pass {
		return 1
	}
	return 0
}
