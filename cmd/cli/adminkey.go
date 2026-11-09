package main

// admin-key — повторная выдача админского ключа vpn:// для сервера, к
// которому есть доступ:
//
//	admin-key (-key-file файл | -key vpn://...) -out файл [-include-password] [-allow-partial]
//	admin-key -host IP|имя [-port 22] [-user root] [-hostkey SHA256:…] -out файл [-include-password] [-allow-partial]
//
// Ключ собирается из ФАКТИЧЕСКОГО состояния сервера (контейнеры и параметры
// протоколов, прочитанные с него — core.AdminKeyReissuePlan), проверяется
// VerifyAdminKey и пишется ТОЛЬКО в новый файл -out (0600; на Windows —
// права каталога). В stdout/stderr ключ не печатается никогда.
//
// Пароль в ключ — только с явного согласия: флаг -include-password или
// «y» на вопрос в терминале. Источник пароля: при -key — тот же пароль
// (или приватный SSH-ключ), что в текущем ключе; при -host — пароль,
// введённый при входе, а при входе ключами ПК — спрашивается отдельно (как
// в migrate -to-host).
//
// Контейнер, параметры которого не прочитаны (или тип которого в ключ не
// кладётся), молча не пропускается: без -allow-partial ключ не выдаётся,
// с ним — выдаётся с перечнем того, чего в нём нет.
//
// Коды выхода: 0 — ключ выдан и проверен; 1 — ключ не выдан (измерено:
// не совпал, сервер не принял пароль, файл не записан, файл уже есть);
// 2 — ошибка использования/подключения или нет согласия; 4 — неизвестно:
// список контейнеров или параметры протоколов не прочитаны (ключ не
// выдан), либо ключ выдан, но проверить его входом не удалось.

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"

	"amnezia-admin/core"
)

const (
	exitAdminKeyNo      = 1
	exitAdminKeyUsage   = 2
	exitAdminKeyUnknown = 4
)

// Швы теста.
var (
	adminKeyDial       = core.ConnectWithHostKey
	adminKeyConnectNew = core.ConnectNew
	adminKeyPlan       = func(s *core.Session, preferDefault string) (core.AdminKeyReissue, error) {
		return s.AdminKeyReissuePlan(preferDefault)
	}
	adminKeyVerify = core.VerifyAdminKey
)

// adminKeyOpts — разобранные флаги admin-key.
type adminKeyOpts struct {
	key, hostkey        string
	host, port, user    string
	out                 string
	includePw, partial  bool
	knownHostsPath      string
	authKeyDir, agentFS string // шов теста
	noAgent             bool
}

// runAdminKeyCmd — разбор флагов admin-key и запуск.
func runAdminKeyCmd(args []string, stdin io.Reader, stdout, stderr io.Writer, knownHostsPath string) int {
	fs := flag.NewFlagSet("admin-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	key := fs.String("key", "", "текущий админский ключ vpn://... сервера (или переменная AMNEZIA_KEY)")
	keyFile := fs.String("key-file", "", "текущий ключ vpn:// из файла вместо -key")
	hostkey := fs.String("hostkey", "", "ожидаемый отпечаток ключа хоста SHA256:… (обязателен без терминала для нового сервера)")
	host := fs.String("host", "", "IP или DNS-имя сервера вместо ключа: вход ключами ПК, не вышло — пароль с терминала")
	port := fs.String("port", "22", "-host: порт SSH")
	user := fs.String("user", "root", "-host: пользователь SSH")
	out := fs.String("out", "", "файл для ключа vpn:// (обязателен; новый файл, существующий не перезаписывается; на Linux/macOS права 0600, на Windows — права каталога)")
	includePw := fs.Bool("include-password", false, "согласие положить пароль (или приватный SSH-ключ) в выдаваемый ключ; без флага спрашивается в терминале, без терминала ключ не выдаётся")
	partial := fs.Bool("allow-partial", false, "выдать ключ, даже если параметры части контейнеров не прочитаны (их в ключе не будет — перечень печатается)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return exitAdminKeyUsage
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if fs.NArg() > 0 {
		fmt.Fprintln(stderr, core.MaskText("admin-key: лишние аргументы: "+strings.Join(fs.Args(), " ")))
		return exitAdminKeyUsage
	}
	if set["key"] && set["key-file"] {
		fmt.Fprintln(stderr, "-key-file и -key взаимоисключающие — ключ задаётся одним способом.")
		return exitAdminKeyUsage
	}
	k := *key
	if set["key-file"] {
		v, err := readKeyFile(*keyFile, stderr)
		if err != nil {
			fmt.Fprintln(stderr, "-key-file: "+err.Error())
			return exitAdminKeyUsage
		}
		k = v
	}
	if set["host"] {
		if set["key"] || set["key-file"] {
			fmt.Fprintln(stderr, "admin-key: -host и -key взаимоисключающие — сервер задаётся одним способом.")
			return exitAdminKeyUsage
		}
	} else {
		if set["port"] || set["user"] {
			fmt.Fprintln(stderr, "admin-key: -port и -user — только вместе с -host.")
			return exitAdminKeyUsage
		}
		if k == "" {
			k = os.Getenv("AMNEZIA_KEY")
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runAdminKey(ctx, stdin, stdout, stderr, stdinIsTTY(), adminKeyOpts{
		key: k, hostkey: *hostkey, host: *host, port: *port, user: *user, out: *out,
		includePw: *includePw, partial: *partial, knownHostsPath: knownHostsPath})
}

// runAdminKey — подключение, сбор, согласие, сборка, проверка, файл.
func runAdminKey(ctx context.Context, in io.Reader, w, errOut io.Writer, isTTY bool, o adminKeyOpts) int {
	in = bufio.NewReader(in)
	out := strings.TrimSpace(o.out)
	if out == "" {
		fmt.Fprintln(errOut, "admin-key: не задан -out <файл> — ключ пишется только в файл, на экран не печатается.")
		return exitAdminKeyUsage
	}
	if _, err := os.Lstat(out); err == nil {
		abs, _ := filepath.Abs(out)
		fmt.Fprintln(errOut, "admin-key: файл "+abs+" уже есть — не перезаписываю; укажите новый -out.")
		return exitAdminKeyNo
	}
	host := strings.TrimSpace(o.host)
	if host == "" && strings.TrimSpace(o.key) == "" {
		fmt.Fprintln(errOut, "Не задан сервер: -key-file <файл>, -key vpn://..., переменная AMNEZIA_KEY или -host IP|имя")
		return exitAdminKeyUsage
	}

	// --- вход ---
	var sess *core.Session
	var pw core.Secret // пароль для ключа (затирается в конце)
	defer func() { pw.Wipe() }()
	var loginPw core.Secret
	defer func() { loginPw.Wipe() }()
	var port int
	var user, description, dns1, dns2, preferDefault string
	byKeys := false
	if host == "" {
		cfg, err := core.DecodeVpnKey(o.key)
		if err != nil {
			fmt.Fprintln(errOut, "Ошибка декодирования ключа: "+core.MaskText(err.Error()))
			return exitAdminKeyUsage
		}
		creds, err := core.CredsFromConfig(cfg)
		if err != nil {
			fmt.Fprintln(errOut, "Ошибка: "+core.MaskText(err.Error()))
			return exitAdminKeyUsage
		}
		p, err := strconv.Atoi(creds.Port)
		if err != nil || p < 1 || p > 65535 {
			fmt.Fprintln(errOut, "Ошибка: порт SSH в ключе не 1…65535")
			return exitAdminKeyUsage
		}
		s, err := adminKeyDial(creds, hostKeyPolicyForCLI(in, w, errOut, isTTY, o.hostkey, "-hostkey", o.knownHostsPath))
		if err != nil {
			fmt.Fprintln(errOut, "SSH: "+core.MaskText(err.Error()))
			if !isTTY && errors.Is(err, core.ErrHostKeyUnknown) {
				fmt.Fprintln(errOut, "Без терминала подключение к новому серверу требует явного отпечатка: -hostkey SHA256:...")
			}
			return exitAdminKeyUsage
		}
		sess = s
		host, port, user = creds.Host, p, creds.User
		pw = core.NewSecret([]byte(creds.Password))
		description, dns1, dns2 = core.Str(cfg, "description"), core.Str(cfg, "dns1"), core.Str(cfg, "dns2")
		preferDefault = core.Str(cfg, "defaultContainer")
	} else {
		if strings.HasPrefix(strings.ToLower(host), "vpn://") || strings.ContainsAny(host, " /@:") && net.ParseIP(host) == nil {
			fmt.Fprintln(errOut, "-host: укажите IP или DNS-имя сервера (без пользователя и порта — они задаются -user и -port; ключ vpn:// — через -key-file)")
			return exitAdminKeyUsage
		}
		p, err := strconv.Atoi(strings.TrimSpace(o.port))
		if err != nil || p < 1 || p > 65535 {
			fmt.Fprintln(errOut, "-port: порт SSH 1…65535")
			return exitAdminKeyUsage
		}
		port, user = p, strings.TrimSpace(o.user)
		if user == "" {
			fmt.Fprintln(errOut, "-user: не задан пользователь SSH")
			return exitAdminKeyUsage
		}
		auth := core.AuthSource{KeyDir: o.authKeyDir, AgentSocket: o.agentFS, NoAgent: o.noAgent}
		if isTTY {
			auth.Password = func(keys core.KeyAttempt) ([]byte, error) {
				fmt.Fprintln(w, "Вход ключами ПК: "+keys.Reason()+".")
				b, err := toHostPassword(w, "Пароль "+user+"@"+host+" (не отображается; не сохраняется; "+pwCancelHint+"): ")
				if err != nil {
					return nil, err
				}
				if ctx.Err() != nil {
					clear(b)
					return nil, core.ErrPasswordCancelled
				}
				loginPw = core.NewSecret(append([]byte(nil), b...))
				return b, nil
			}
		}
		s, att, err := adminKeyConnectNew(host, strconv.Itoa(port), user, auth, hostKeyPolicyForCLI(in, w, errOut, isTTY, o.hostkey, "-hostkey", o.knownHostsPath))
		if err != nil {
			var ae *core.AuthError
			if errors.As(err, &ae) {
				fmt.Fprintln(errOut, core.MaskText(ae.Error()))
				if !isTTY && !ae.PasswordTried {
					fmt.Fprintln(errOut, "Без терминала пароль не спрашивается: войти можно только ключами ПК (агент или ~/.ssh без парольной фразы).")
				}
			} else {
				fmt.Fprintln(errOut, "SSH: "+core.MaskText(err.Error()))
				if errors.Is(err, core.ErrHostKeyUnknown) && !isTTY {
					fmt.Fprintln(errOut, "Без терминала подключение к новому серверу требует явного отпечатка: -hostkey SHA256:...")
				}
			}
			return exitAdminKeyUsage
		}
		sess = s
		if att.Outcome == core.KeysAccepted {
			byKeys = true
			fmt.Fprintln(w, "Вход: по ключу ПК ("+att.Reason()+").")
		} else {
			fmt.Fprintln(w, "Вход: по паролю. Ключи ПК: "+att.Reason()+". Пароль не сохраняется.")
			pw = core.NewSecret(loginPw.Bytes())
		}
		loginPw.Wipe()
		description = host
	}
	defer sess.Close()
	fmt.Fprintln(w, sideLine("Сервер (только чтение)", sess))

	// --- что можно положить в ключ ---
	plan, err := adminKeyPlan(sess, preferDefault)
	if err != nil {
		backupErr(errOut, "Ключ vpn:// не выдан — состояние сервера неизвестно: ", err)
		return exitAdminKeyUnknown
	}
	if !printAdminKeyPlan(w, errOut, plan, o.partial) {
		return exitAdminKeyUnknown
	}

	// --- согласие на пароль в ключе ---
	// При входе ключами ПК пароля у программы нет — сказать это ДО вопроса
	// о согласии (ревью PR #75, L1).
	if byKeys {
		fmt.Fprintln(w, "Вход был по ключу ПК — пароля для ключа vpn:// у программы нет: его придётся ввести.")
		if !isTTY {
			fmt.Fprintln(errOut, "Ключ не выдан: без терминала пароль для ключа не спрашивается.")
			return exitAdminKeyUsage
		}
	}
	consent := o.includePw
	if !consent {
		if !isTTY {
			fmt.Fprintln(errOut, "Ключ не выдан: в ключ кладётся пароль "+user+" (или приватный SSH-ключ) — согласие даётся флагом -include-password или ответом в терминале.")
			return exitAdminKeyUsage
		}
		fmt.Fprintln(w, "В ключе vpn:// будет пароль "+user+"@"+host+" (или приватный SSH-ключ): кто получит ключ — получит root-доступ к серверу.")
		if !askYes(in, w, "Положить пароль в ключ и выдать ключ? (y/n): ") {
			fmt.Fprintln(w, "Ключ не выдан (нет согласия).")
			return exitAdminKeyUsage
		}
	}
	if byKeys {
		if pw = askKeyPassword(ctx, w, user, host); pw.Len() == 0 {
			fmt.Fprintln(w, "Пароль не введён — ключ не выдан.")
			return exitAdminKeyUsage
		}
	}
	if pw.Len() == 0 {
		fmt.Fprintln(errOut, "Ключ не выдан: в текущем ключе нет пароля SSH — ключ без способа входа бесполезен.")
		return exitAdminKeyNo
	}

	// --- сборка, проверка, файл ---
	for attempt := 1; ; attempt++ {
		in := core.AdminKeyInput{Host: host, Port: port, User: user, Password: pw, PasswordConsent: true,
			Containers: plan.Containers, DefaultContainer: plan.Default, Description: description, DNS1: dns1, DNS2: dns2}
		key, err := core.BuildAdminKey(in)
		if err != nil {
			backupErr(errOut, "Ключ vpn:// не выдан: ", err)
			return exitAdminKeyNo
		}
		verr := adminKeyVerify(key, in, sess.HostKeyFingerprint, o.knownHostsPath)
		switch {
		case errors.Is(verr, core.ErrAdminKeyAuthRejected):
			fmt.Fprintln(w, "Ключ НЕ годится: сервер не принял пароль из ключа — пароль не подошёл или вход по паролю на сервере выключен (PasswordAuthentication no).")
			if o.host == "" || !isTTY || attempt >= toHostKeyAttempts {
				fmt.Fprintln(w, "Ключ vpn:// не выдан.")
				return exitAdminKeyNo
			}
			np := askKeyPassword(ctx, w, user, host)
			if np.Len() == 0 {
				fmt.Fprintln(w, "Ключ vpn:// не выдан: пароль не введён.")
				return exitAdminKeyNo
			}
			pw.Wipe()
			pw = np
			continue
		case errors.Is(verr, core.ErrAdminKeyMismatch):
			backupErr(errOut, "Ключ vpn:// НЕ выдан — собранный ключ не совпал с ожидаемым: ", verr)
			return exitAdminKeyNo
		case verr != nil:
			fmt.Fprintln(w, "Ключ проверить не удалось (это не «ключ плохой» и не «ключ хороший»): "+core.MaskText(verr.Error()))
		}
		path, err := core.WriteAdminKeyFile(out, key)
		if err != nil {
			backupErr(errOut, "Ключ vpn:// не записан: ", err)
			return exitAdminKeyNo
		}
		fmt.Fprintln(w, "Ключ vpn:// записан в файл ("+keyFilePermText(path)+"): "+path)
		fmt.Fprintln(w, "В файле — пароль "+user+" сервера: храните его как пароль, не пересылайте открыто; после импорта в приложение Amnezia удалите файл.")
		if !plan.Complete() {
			fmt.Fprintln(w, "Ключ НЕПОЛНЫЙ: в нём нет "+adminKeyGapNames(plan)+" (см. выше).")
		}
		if verr != nil {
			fmt.Fprintln(w, "Ключ НЕ проверен входом — проверьте его импортом в приложение Amnezia.")
			return exitAdminKeyUnknown
		}
		fmt.Fprintln(w, "Ключ проверен: разобран и вход на сервер по нему выполнен.")
		return 0
	}
}

// adminKeyGapNames — имена контейнеров, которых не будет в ключе.
func adminKeyGapNames(r core.AdminKeyReissue) string {
	var n []string
	for _, g := range r.Gaps {
		n = append(n, g.Container)
	}
	return strings.Join(n, ", ")
}

// printAdminKeyPlan — что войдёт в ключ и чего в нём НЕ будет. false —
// ключ выдавать нельзя (причина напечатана).
func printAdminKeyPlan(w, errOut io.Writer, r core.AdminKeyReissue, partial bool) bool {
	for _, c := range r.Containers {
		fmt.Fprintln(w, "  В ключ: "+c.Name+" — параметры прочитаны с сервера.")
	}
	for _, g := range r.Gaps {
		fmt.Fprintln(w, "  НЕ в ключ: "+g.Container+" — "+core.MaskText(g.Reason))
	}
	for _, n := range r.Notes {
		fmt.Fprintln(w, n)
	}
	switch {
	case len(r.Containers) == 0:
		backupErr(errOut, "Ключ vpn:// не выдан: ", core.ErrAdminKeyNoContainers)
		return false
	case len(r.Gaps) > 0 && !partial:
		fmt.Fprintln(errOut, "Ключ vpn:// не выдан: параметры не прочитаны для "+adminKeyGapNames(r)+" — ключ без этих протоколов был бы неполным. Устраните причину или повторите с -allow-partial (их в ключе не будет).")
		return false
	case len(r.Gaps) > 0:
		fmt.Fprintln(w, "По -allow-partial ключ будет выдан БЕЗ: "+adminKeyGapNames(r)+".")
	}
	return true
}
