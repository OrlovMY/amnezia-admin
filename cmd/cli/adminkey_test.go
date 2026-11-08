package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

const (
	akHost = "203.0.113.77"
	akPw   = "Canary-AK-Pw-91c2!"
)

// akEnv — швы admin-key: сессия поверх fakesrv (настоящий
// AdminKeyReissuePlan), проверка ключа — подменная.
type akEnv struct {
	srv       *fakesrv.Server
	verifyErr error
	verifyN   int
	keyAuth   bool
	pwAsked   int
	pwAnswer  string
}

func newAKEnv(t *testing.T) *akEnv {
	e := &akEnv{srv: fakesrv.NewAWG2(), pwAnswer: akPw}
	d0, d1, d2, d3, d4 := adminKeyDial, adminKeyConnectNew, adminKeyPlan, adminKeyVerify, toHostPassword
	t.Cleanup(func() {
		adminKeyDial, adminKeyConnectNew, adminKeyPlan, adminKeyVerify, toHostPassword = d0, d1, d2, d3, d4
	})
	adminKeyDial = func(c *core.ServerCreds, _ core.HostKeyPolicy) (*core.Session, error) {
		s := core.NewSessionWithRunner(e.srv, c)
		s.HostKeyFingerprint = "SHA256:ak"
		return s, nil
	}
	adminKeyConnectNew = func(host, port, user string, src core.AuthSource, _ core.HostKeyPolicy) (*core.Session, core.KeyAttempt, error) {
		att := core.KeyAttempt{Outcome: core.KeysAccepted}
		if !e.keyAuth {
			att.Outcome = core.KeysRejected
			if src.Password == nil {
				return nil, att, &core.AuthError{Keys: att, Err: errors.New("отказ")}
			}
			b, err := src.Password(att)
			if err != nil || len(b) == 0 {
				return nil, att, &core.AuthError{Keys: att, Err: errors.New("нет пароля")}
			}
			clear(b)
		}
		s := core.NewSessionWithRunner(e.srv, &core.ServerCreds{Host: host, Port: port, User: user})
		s.HostKeyFingerprint = "SHA256:ak"
		return s, att, nil
	}
	adminKeyVerify = func(core.AdminKey, core.AdminKeyInput, string, string) error {
		e.verifyN++
		return e.verifyErr
	}
	toHostPassword = func(io.Writer, string) ([]byte, error) {
		e.pwAsked++
		return []byte(e.pwAnswer), nil
	}
	return e
}

// akCurrentKey — «текущий» ключ сервера (с паролем-канарейкой).
func akCurrentKey(t *testing.T) string {
	t.Helper()
	k, err := core.BuildAdminKey(core.AdminKeyInput{Host: akHost, Port: 22, User: "root", Password: core.NewSecret([]byte(akPw)),
		PasswordConsent: true, Containers: []core.AdminKeyContainer{{Name: "amnezia-awg2", Protocol: thParams()}}, DefaultContainer: "amnezia-awg2"})
	if err != nil {
		t.Fatal(err)
	}
	return k.Reveal()
}

// akKeyBody — vpn:// с телом ключа (слово «ключ vpn://» в тексте — не утечка).
var akKeyBody = regexp.MustCompile(`vpn://[A-Za-z0-9_-]{8}`)

// akNoLeak — ни ключ (старый и выданный), ни пароль не напечатаны.
func akNoLeak(t *testing.T, text string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if s != "" && strings.Contains(text, s) {
			t.Fatalf("секрет (%d байт) напечатан в выводе", len(s))
		}
	}
	if akKeyBody.MatchString(text) {
		t.Fatal("в выводе есть тело ключа vpn://…")
	}
}

func TestAdminKeyCLI(t *testing.T) {
	const conf = "/opt/amnezia/awg/awg0.conf"
	cases := []struct {
		name      string
		setup     func(*akEnv)
		tty       bool
		stdin     string
		host      bool // вход по адресу, а не ключом
		noOut     bool
		outExists bool
		includePw bool
		partial   bool
		wantCode  int
		wantFile  bool
		wantIn    []string // контейнеры в выданном ключе
		wantOut   []string // подстроки stdout+stderr
	}{
		{name: "ключом: выдан и проверен", includePw: true, wantCode: 0, wantFile: true, wantIn: []string{"amnezia-awg2"},
			wantOut: []string{"В ключ: amnezia-awg2", "Ключ проверен"}},
		// Тест доезда: «не прочитан» возникает ошибкой cat с сервера.
		{name: "параметры не прочитаны — ключ не выдан", setup: func(e *akEnv) {
			e.srv.FailRead = map[string]error{conf: errors.New("Permission denied")}
		}, includePw: true, wantCode: exitAdminKeyUnknown, wantOut: []string{"НЕ в ключ: amnezia-awg2", "не выдан"}},
		{name: "параметры не прочитаны — и с -allow-partial протоколов нет", setup: func(e *akEnv) {
			e.srv.FailRead = map[string]error{conf: errors.New("Permission denied")}
		}, includePw: true, partial: true, wantCode: exitAdminKeyUnknown, wantOut: []string{"ни у одного контейнера"}},
		{name: "незнакомый контейнер без -allow-partial", setup: func(e *akEnv) {
			e.srv.Names = []string{"amnezia-awg2", "amnezia-foo"}
		}, includePw: true, wantCode: exitAdminKeyUnknown, wantOut: []string{"НЕ в ключ: amnezia-foo", "-allow-partial"}},
		{name: "незнакомый контейнер с -allow-partial — неполный ключ с перечнем", setup: func(e *akEnv) {
			e.srv.Names = []string{"amnezia-awg2", "amnezia-foo"}
		}, includePw: true, partial: true, wantCode: 0, wantFile: true, wantIn: []string{"amnezia-awg2"},
			wantOut: []string{"БЕЗ: amnezia-foo", "Ключ НЕПОЛНЫЙ: в нём нет amnezia-foo"}},
		{name: "amnezia-dns — ключ полный, без -allow-partial", setup: func(e *akEnv) {
			e.srv.Names = []string{"amnezia-awg2", "amnezia-dns"}
		}, includePw: true, wantCode: 0, wantFile: true, wantIn: []string{"amnezia-awg2"}, wantOut: []string{"amnezia-dns: служба Amnezia без клиентских параметров"}},
		{name: "список контейнеров не прочитан", setup: func(e *akEnv) { e.srv.Names = nil }, includePw: true,
			wantCode: exitAdminKeyUnknown, wantOut: []string{"состояние сервера неизвестно"}},
		{name: "без согласия и без терминала", wantCode: exitAdminKeyUsage, wantOut: []string{"-include-password"}},
		{name: "терминал: ответ n", tty: true, stdin: "n\n", wantCode: exitAdminKeyUsage, wantOut: []string{"нет согласия"}},
		{name: "терминал: ответ y", tty: true, stdin: "y\n", wantCode: 0, wantFile: true, wantIn: []string{"amnezia-awg2"}},
		{name: "-out не задан", noOut: true, includePw: true, wantCode: exitAdminKeyUsage, wantOut: []string{"-out"}},
		{name: "-out уже есть", outExists: true, includePw: true, wantCode: exitAdminKeyNo, wantOut: []string{"не перезаписываю"}},
		{name: "ключ не совпал", setup: func(e *akEnv) { e.verifyErr = core.ErrAdminKeyMismatch }, includePw: true,
			wantCode: exitAdminKeyNo, wantOut: []string{"не совпал"}},
		{name: "сервер не принял пароль", setup: func(e *akEnv) { e.verifyErr = core.ErrAdminKeyAuthRejected }, includePw: true,
			wantCode: exitAdminKeyNo, wantOut: []string{"НЕ годится"}},
		{name: "проверить не удалось — выдан, но код 4", setup: func(e *akEnv) { e.verifyErr = errors.New("сеть") }, includePw: true,
			wantCode: exitAdminKeyUnknown, wantFile: true, wantIn: []string{"amnezia-awg2"}, wantOut: []string{"НЕ проверен"}},
		{name: "адресом: вход по паролю", host: true, tty: true, includePw: true, wantCode: 0, wantFile: true, wantIn: []string{"amnezia-awg2"},
			wantOut: []string{"Вход: по паролю"}},
		{name: "адресом: ключ ПК, без терминала пароля нет", host: true, setup: func(e *akEnv) { e.keyAuth = true }, includePw: true,
			wantCode: exitAdminKeyUsage, wantOut: []string{"пароль для ключа не спрашивается"}},
		{name: "адресом: ключ ПК, пароль спрошен в терминале", host: true, tty: true, setup: func(e *akEnv) { e.keyAuth = true }, includePw: true,
			wantCode: 0, wantFile: true, wantIn: []string{"amnezia-awg2"}, wantOut: []string{"пароля для ключа vpn:// у программы нет"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newAKEnv(t)
			if tc.setup != nil {
				tc.setup(e)
			}
			cur := akCurrentKey(t)
			out := filepath.Join(t.TempDir(), "admin.vpn.txt")
			if tc.outExists {
				if err := os.WriteFile(out, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			o := adminKeyOpts{key: cur, out: out, includePw: tc.includePw, partial: tc.partial, port: "22", user: "root"}
			if tc.host {
				o.key, o.host = "", akHost
			}
			if tc.noOut {
				o.out = ""
			}
			var so, se bytes.Buffer
			code := runAdminKey(context.Background(), strings.NewReader(tc.stdin), &so, &se, tc.tty, o)
			all := so.String() + se.String()
			var issued string
			if b, err := os.ReadFile(out); err == nil && !tc.outExists {
				issued = strings.TrimSpace(string(b))
			}
			akNoLeak(t, all, akPw, cur, issued)
			if code != tc.wantCode {
				t.Fatalf("код %d, ожидался %d; вывод:\n%s", code, tc.wantCode, all)
			}
			for _, w := range tc.wantOut {
				if !strings.Contains(all, w) {
					t.Errorf("нет %q в выводе:\n%s", w, all)
				}
			}
			if (issued != "") != tc.wantFile {
				t.Fatalf("файл ключа: есть=%v, ожидалось %v", issued != "", tc.wantFile)
			}
			if !tc.wantFile {
				return
			}
			cfg, err := core.DecodeVpnKey(issued)
			if err != nil {
				t.Fatal("выданный ключ не разбирается")
			}
			creds, err := core.CredsFromConfig(cfg)
			if err != nil || creds.Host != akHost || creds.Password != akPw {
				t.Fatal("в выданном ключе не тот сервер или пароль")
			}
			var got []string
			for _, c := range cfg["containers"].([]any) {
				m := c.(map[string]any)
				got = append(got, core.Str(m, "container"))
				// параметры — с сервера (fakesrv: H1 = 100-200), а не из старого ключа (H1 = 1)
				if p, _ := m["awg"].(map[string]any); core.Str(p, "H1") != "100-200" {
					t.Fatalf("параметры не с сервера: H1=%q", core.Str(p, "H1"))
				}
			}
			if strings.Join(got, ",") != strings.Join(tc.wantIn, ",") {
				t.Fatalf("в ключе %v, ожидалось %v", got, tc.wantIn)
			}
		})
	}
}

// Ключ не печатается и через run(): сквозной вызов с -key-file.
func TestAdminKeyRunNoKeyInOutput(t *testing.T) {
	newAKEnv(t)
	cur := akCurrentKey(t)
	dir := t.TempDir()
	kf := filepath.Join(dir, "cur.txt")
	if err := os.WriteFile(kf, []byte(cur), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "new.txt")
	var so, se bytes.Buffer
	code := run([]string{"admin-key", "-key-file", kf, "-out", out, "-include-password"}, strings.NewReader(""), &so, &se, filepath.Join(dir, "kh"))
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("код %d, файл не записан: %s", code, so.String()+se.String())
	}
	akNoLeak(t, so.String()+se.String(), akPw, cur, strings.TrimSpace(string(b)))
	if code != 0 {
		t.Fatalf("код %d: %s", code, so.String()+se.String())
	}
}

// Общая справка: у каждой подкоманды закрытого списка есть строка вызова,
// и строк для несуществующих подкоманд нет.
func TestCLIHelpListsEveryCommand(t *testing.T) {
	for _, c := range cliCommands {
		if len(cliUsage[c]) == 0 {
			t.Errorf("у %s нет строки в общей справке", c)
		}
	}
	for c := range cliUsage {
		if !knownCLICommand(c) {
			t.Errorf("строка справки для неизвестной команды %s", c)
		}
	}
	var so bytes.Buffer
	if code := run([]string{"help"}, strings.NewReader(""), &so, io.Discard, ""); code != 0 {
		t.Fatal(code)
	}
	for _, w := range []string{"amnezia-admin migrate -key-file", "amnezia-admin admin-key -host"} {
		if !strings.Contains(so.String(), w) {
			t.Errorf("в справке нет %q", w)
		}
	}
}
