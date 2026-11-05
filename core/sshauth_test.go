package core

// Тесты ConnectNew (PR 2 плана «перенос на чистый сервер»): поддельный
// SSH-сервер на эфемерном порту 127.0.0.1 — никаких реальных серверов, порт
// 22 не используется. Каталог ключей — временный (шов AuthSource.KeyDir),
// настоящий ~/.ssh не читается; агент отключён через SSH_AUTH_SOCK="".

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

const sshPw = "Канарейка-пароль-7f3Q"

// fakeAuthServer — SSH-сервер, принимающий ключи из allowKeys и пароль
// allowPassword ("" — пароль не принимается). Возвращает порт.
type fakeAuthServer struct {
	port      string
	hostKey   ssh.Signer
	allowKeys map[string]bool
	// dropOnPubkey — рвать TCP-соединение, как только клиент спросил про
	// ключ (сбой транспорта внутри validateKey у клиента).
	dropOnPubkey atomic.Bool
}

func startFakeAuthServer(t *testing.T, allowKeys []ssh.PublicKey, allowPassword string) *fakeAuthServer {
	t.Helper()
	return startFakeAuthServerConf(t, allowKeys, allowPassword, nil)
}

// startFakeAuthServerConf — то же, mut правит ServerConfig перед запуском
// (убрать метод publickey, оставить только keyboard-interactive…).
func startFakeAuthServerConf(t *testing.T, allowKeys []ssh.PublicKey, allowPassword string, mut func(*ssh.ServerConfig)) *fakeAuthServer {
	t.Helper()
	hk := mustHostKey(t)
	fs := &fakeAuthServer{hostKey: hk, allowKeys: map[string]bool{}}
	for _, k := range allowKeys {
		fs.allowKeys[string(k.Marshal())] = true
	}
	conf := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if fs.allowKeys[string(k.Marshal())] {
				return nil, nil
			}
			return nil, errors.New("ключ не принят")
		},
		PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if allowPassword != "" && string(p) == allowPassword {
				return nil, nil
			}
			return nil, errors.New("пароль не принят")
		},
	}
	if mut != nil {
		mut(conf)
	}
	conf.AddHostKey(hk)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				cc := conf
				if fs.dropOnPubkey.Load() {
					cp := *conf
					cp.PublicKeyCallback = func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
						_ = c.Close()
						return nil, errors.New("обрыв")
					}
					cc = &cp
				}
				sc, chans, reqs, err := ssh.NewServerConn(c, cc)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "нет")
				}
				_ = sc.Close()
			}(c)
		}
	}()
	fs.port = strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	if fs.port == "22" {
		t.Fatal("эфемерный порт оказался 22")
	}
	return fs
}

// writeKey кладёт ключ в dir/name; passphrase != "" — под фразой.
func writeKey(t *testing.T, dir, name, passphrase string) ssh.PublicKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var blk *pem.Block
	if passphrase == "" {
		blk, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

func trustPolicy(t *testing.T) HostKeyPolicy {
	return HostKeyPolicy{
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		Prompt:         func(string, string) bool { return true },
	}
}

// pwSource — колбэк пароля, запоминающий исход по ключам и выданный срез.
type pwSource struct {
	calls int
	got   KeyAttempt
	bufs  [][]byte
	pw    string
}

func (p *pwSource) fn(k KeyAttempt) ([]byte, error) {
	p.calls++
	p.got = k
	b := []byte(p.pw)
	p.bufs = append(p.bufs, b)
	return b, nil
}

type authScenario struct {
	name      string
	keyInDir  bool // положить ключ в каталог
	serverKey bool // сервер принимает этот ключ
	serverPw  string
	clientPw  string
	noPubkey  bool // сервер не предлагает publickey (PubkeyAuthentication no)
}

func runScenario(t *testing.T, sc authScenario) (*Session, KeyAttempt, *pwSource, error) {
	t.Helper()
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	var allow []ssh.PublicKey
	if sc.keyInDir {
		k := writeKey(t, dir, "id_ed25519", "")
		if sc.serverKey {
			allow = append(allow, k)
		}
	}
	var mut func(*ssh.ServerConfig)
	if sc.noPubkey {
		mut = func(c *ssh.ServerConfig) { c.PublicKeyCallback = nil }
	}
	srv := startFakeAuthServerConf(t, allow, sc.serverPw, mut)
	ps := &pwSource{pw: sc.clientPw}
	sess, att, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: dir, Password: ps.fn}, trustPolicy(t))
	if sess != nil {
		t.Cleanup(func() { _ = sess.Client.Close() })
	}
	return sess, att, ps, err
}

// TestConnectNewDistinguishesThreeOutcomes — тест различения и доезда: три
// исхода по ключам возникают боевым путём ConnectNew и различны.
func TestConnectNewDistinguishesThreeOutcomes(t *testing.T) {
	cases := []struct {
		sc          authScenario
		want        KeyOutcome
		wantPwCalls int
		wantErr     bool
	}{
		{authScenario{name: "ключ принят", keyInDir: true, serverKey: true, clientPw: sshPw}, KeysAccepted, 0, false},
		{authScenario{name: "ключи отвергнуты, пароль принят", keyInDir: true, serverPw: sshPw, clientPw: sshPw}, KeysRejected, 1, false},
		{authScenario{name: "ключей нет, пароль принят", serverPw: sshPw, clientPw: sshPw}, KeysUnavailable, 1, false},
		{authScenario{name: "сервер не принимает ключи, пароль принят", keyInDir: true, serverKey: true, noPubkey: true, serverPw: sshPw, clientPw: sshPw}, KeysNotAllowed, 1, false},
		{authScenario{name: "всё отвергнуто", keyInDir: true, serverPw: "другой", clientPw: sshPw}, KeysRejected, 1, true},
	}
	seen := map[KeyOutcome]bool{}
	for _, c := range cases {
		t.Run(c.sc.name, func(t *testing.T) {
			sess, att, ps, err := runScenario(t, c.sc)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, want err %v", err, c.wantErr)
			}
			if att.Outcome != c.want {
				t.Fatalf("Outcome = %v, want %v (notes %v)", att.Outcome, c.want, att.Notes)
			}
			if ps.calls != c.wantPwCalls {
				t.Fatalf("пароль спрошен %d раз, want %d", ps.calls, c.wantPwCalls)
			}
			if ps.calls > 0 && ps.got.Outcome != c.want {
				t.Fatalf("колбэк пароля получил %v, want %v", ps.got.Outcome, c.want)
			}
			if sess != nil && sess.Creds.Password != "" {
				t.Fatal("пароль сохранён в Session.Creds")
			}
			if err != nil {
				var ae *AuthError
				if !errors.As(err, &ae) || !ae.PasswordTried || ae.Keys.Outcome != c.want {
					t.Fatalf("ожидался *AuthError с паролем и %v, got %#v", c.want, err)
				}
			}
			seen[att.Outcome] = true
		})
	}
	if len(seen) != 4 {
		t.Fatalf("различимых исходов %d, want 4: %v", len(seen), seen)
	}
}

// TestConnectNewNoPasswordCallbackKeysRejected — пароля нет, ключ отвергнут:
// исход «отвергнут», а не «неизвестно» и не «ключей нет».
func TestConnectNewNoPasswordCallbackKeysRejected(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	writeKey(t, dir, "id_ed25519", "")
	srv := startFakeAuthServer(t, nil, sshPw)
	_, att, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: dir}, trustPolicy(t))
	var ae *AuthError
	if !errors.As(err, &ae) || ae.PasswordTried {
		t.Fatalf("ожидался *AuthError без пароля, got %v", err)
	}
	if att.Outcome != KeysRejected {
		t.Fatalf("Outcome = %v, want KeysRejected", att.Outcome)
	}
}

// TestConnectNewNothingToOffer — ни ключей, ни пароля: «ключей нет», без
// подключения.
func TestConnectNewNothingToOffer(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	srv := startFakeAuthServer(t, nil, sshPw)
	_, att, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: t.TempDir()}, trustPolicy(t))
	if err == nil || att.Outcome != KeysUnavailable {
		t.Fatalf("err=%v Outcome=%v, want ошибка и KeysUnavailable", err, att.Outcome)
	}
}

// TestConnectNewPassphraseKeySkipped — ключ под фразой пропущен с причиной.
func TestConnectNewPassphraseKeySkipped(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	writeKey(t, dir, "id_ed25519", "фраза")
	srv := startFakeAuthServer(t, nil, sshPw)
	ps := &pwSource{pw: sshPw}
	sess, att, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: dir, Password: ps.fn}, trustPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Client.Close()
	if att.Outcome != KeysUnavailable {
		t.Fatalf("Outcome = %v, want KeysUnavailable", att.Outcome)
	}
	if !strings.Contains(strings.Join(ps.got.Notes, ";"), "id_ed25519: защищён парольной фразой") {
		t.Fatalf("причина пропуска не сообщена колбэку: %v", ps.got.Notes)
	}
}

// TestConnectNewHostKeyRejectedUndetermined — ключ хоста не подтверждён:
// до ключей входа не дошло → KeysUndetermined, ошибка ключа хоста, пароль
// не спрошен.
func TestConnectNewHostKeyRejectedUndetermined(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	k := writeKey(t, dir, "id_ed25519", "")
	srv := startFakeAuthServer(t, []ssh.PublicKey{k}, "")
	ps := &pwSource{pw: sshPw}
	pol := HostKeyPolicy{KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts")} // Prompt nil
	_, att, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: dir, Password: ps.fn}, pol)
	if !errors.Is(err, ErrHostKeyUnknown) {
		t.Fatalf("err = %v, want ErrHostKeyUnknown", err)
	}
	if att.Outcome != KeysUndetermined || ps.calls != 0 {
		t.Fatalf("Outcome=%v calls=%d, want KeysUndetermined и 0", att.Outcome, ps.calls)
	}
}

// TestConnectNewPasswordZeroed — выданный пароль обнулён после попытки.
func TestConnectNewPasswordZeroed(t *testing.T) {
	for _, ok := range []bool{true, false} {
		t.Run(fmt.Sprint("принят=", ok), func(t *testing.T) {
			sc := authScenario{serverPw: "другой", clientPw: sshPw}
			if ok {
				sc.serverPw = sshPw
			}
			_, _, ps, _ := runScenario(t, sc)
			if len(ps.bufs) != 1 {
				t.Fatalf("буферов %d, want 1", len(ps.bufs))
			}
			if !bytes.Equal(ps.bufs[0], make([]byte, len(sshPw))) {
				t.Fatal("пароль не обнулён после ConnectNew")
			}
		})
	}
}

// leaksPassword — сторож: пароль (целиком или заметный кусок) в тексте.
func leaksPassword(text string) bool {
	return strings.Contains(text, sshPw) || strings.Contains(text, sshPw[len(sshPw)-8:])
}

// TestConnectNewPasswordNotInOutput — пароль не встречается ни в тексте
// ошибки, ни в %+v/%#v ошибки, ни в причине по ключам. Канарейка: сторож
// обязан поймать текст, в котором пароль есть.
func TestConnectNewPasswordNotInOutput(t *testing.T) {
	if !leaksPassword("ошибка: " + sshPw) {
		t.Fatal("канарейка: сторож не видит пароль в тексте")
	}
	_, att, _, err := runScenario(t, authScenario{keyInDir: true, serverPw: "другой", clientPw: sshPw})
	if err == nil {
		t.Fatal("ожидался отказ")
	}
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("ожидался *AuthError, got %T", err)
	}
	for _, s := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err), fmt.Sprintf("%#v", *ae), att.Reason(), fmt.Sprintf("%#v", att)} {
		if leaksPassword(s) {
			t.Fatalf("пароль попал в вывод: %s", s)
		}
	}
}

// TestConnectNewPasswordDeclined — человек отказался вводить пароль (колбэк
// вернул пустой срез): *AuthError с исходом по ключам, PasswordTried=false,
// а не общий *ConnectError.
func TestConnectNewPasswordDeclined(t *testing.T) {
	_, att, ps, err := runScenario(t, authScenario{keyInDir: true, serverPw: sshPw, clientPw: ""})
	var ae *AuthError
	if !errors.As(err, &ae) || ae.PasswordTried || !errors.Is(err, ErrNoPassword) {
		t.Fatalf("ожидался *AuthError(ErrNoPassword) без пароля, got %T %v", err, err)
	}
	if att.Outcome != KeysRejected || ps.calls != 1 {
		t.Fatalf("Outcome=%v calls=%d, want KeysRejected и 1", att.Outcome, ps.calls)
	}
}

// TestConnectNewKbdInteractive — keyboard-interactive: один скрытый вопрос →
// пароль; два вопроса (второй фактор) → пароль НЕ отправлен и не спрошен.
func TestConnectNewKbdInteractive(t *testing.T) {
	kbd := func(qs []string, echos []bool) func(*ssh.ServerConfig) {
		return func(c *ssh.ServerConfig) {
			c.PasswordCallback = nil
			c.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
				ans, err := ch("", "", qs, echos)
				if err != nil {
					return nil, err
				}
				if len(ans) == 1 && ans[0] == sshPw {
					return nil, nil
				}
				return nil, errors.New("нет")
			}
		}
	}
	t.Setenv("SSH_AUTH_SOCK", "")

	srv := startFakeAuthServerConf(t, nil, "", kbd([]string{"Password: "}, []bool{false}))
	ps := &pwSource{pw: sshPw}
	sess, _, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: t.TempDir(), Password: ps.fn}, trustPolicy(t))
	if err != nil {
		t.Fatalf("один вопрос: %v", err)
	}
	_ = sess.Client.Close()

	srv2 := startFakeAuthServerConf(t, nil, "", kbd([]string{"Password: ", "Verification code: "}, []bool{false, false}))
	ps2 := &pwSource{pw: sshPw}
	_, _, err = ConnectNew("127.0.0.1", srv2.port, "root", AuthSource{KeyDir: t.TempDir(), Password: ps2.fn}, trustPolicy(t))
	var ae *AuthError
	if !errors.As(err, &ae) || !errors.Is(err, ErrKbdInteractive) || ps2.calls != 0 {
		t.Fatalf("два вопроса: err=%v calls=%d, want *AuthError(ErrKbdInteractive) и пароль не спрошен", err, ps2.calls)
	}
}

// TestConnectNewEmptyKnownHostsBeforeKeys — политика проверяется до сбора
// ключей: пустой KnownHostsPath — ошибка без чтения каталога ключей.
func TestConnectNewEmptyKnownHostsBeforeKeys(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	writeKey(t, dir, "id_ed25519", "")
	_, att, err := ConnectNew("127.0.0.1", "1", "root", AuthSource{KeyDir: dir}, HostKeyPolicy{})
	if err == nil || len(att.Offered) != 0 || att.Outcome != KeysUndetermined {
		t.Fatalf("err=%v att=%#v, want ошибка до сбора ключей", err, att)
	}
}

// kbdRounds — сервер keyboard-interactive в несколько раундов; записывает
// ответы каждого раунда. Принимает, если все раунды пройдены с паролем в
// первом (второй раунд пароль принимать не должен — проверяем, что он туда не
// уходит).
func kbdRounds(rounds [][]string, echos [][]bool, got *[][]string) func(*ssh.ServerConfig) {
	return func(c *ssh.ServerConfig) {
		c.PasswordCallback = nil
		c.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			for i, qs := range rounds {
				ans, err := ch("", "", qs, echos[i])
				if err != nil {
					return nil, err
				}
				*got = append(*got, ans)
			}
			return nil, nil
		}
	}
}

// TestConnectNewKbdSecondFactor — в той же попытке после пароля другой
// скрытый вопрос: пароль во второй раунд не уходит, ErrExtraPrompt с текстом
// вопроса (без утверждения «второй фактор»).
func TestConnectNewKbdSecondFactor(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	var got [][]string
	srv := startFakeAuthServerConf(t, nil, "", kbdRounds(
		[][]string{{"Password: "}, {"Verification code: "}}, [][]bool{{false}, {false}}, &got))
	ps := &pwSource{pw: sshPw}
	_, _, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: t.TempDir(), Password: ps.fn}, trustPolicy(t))
	var xp *ExtraPromptError
	if !errors.As(err, &xp) || xp.Prompt != "Verification code: " || errors.Is(err, ErrSecondFactor) {
		t.Fatalf("err = %v, want ExtraPromptError «Verification code: » (не ErrSecondFactor)", err)
	}
	if len(got) != 1 || len(got[0]) != 1 || got[0][0] != sshPw {
		t.Fatalf("ответы сервера = %d раундов, want ровно один с паролем", len(got))
	}
	var ae *AuthError
	if !errors.As(err, &ae) || leaksPassword(err.Error()) {
		t.Fatalf("ожидался *AuthError без пароля в тексте: %v", err)
	}
}

// TestConnectNewKbdVisibleInput — один вопрос с видимым вводом: это не
// пароль, пароль не спрашивается и не уходит.
func TestConnectNewKbdVisibleInput(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	var got [][]string
	srv := startFakeAuthServerConf(t, nil, "", kbdRounds([][]string{{"Login code: "}}, [][]bool{{true}}, &got))
	ps := &pwSource{pw: sshPw}
	_, _, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: t.TempDir(), Password: ps.fn}, trustPolicy(t))
	if !errors.Is(err, ErrKbdInteractive) || ps.calls != 0 || len(got) != 0 {
		t.Fatalf("err=%v calls=%d rounds=%d, want ErrKbdInteractive, пароль не спрошен и не отправлен", err, ps.calls, len(got))
	}
}

// TestConnectNewNoClientAuthUndetermined — сервер впускает без проверки
// (NoClientAuth), ключ в каталоге есть: это не «ключ принят», а
// KeysUndetermined с примечанием (тест различения и доезда).
func TestConnectNewNoClientAuthUndetermined(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	k := writeKey(t, dir, "id_ed25519", "")
	srv := startFakeAuthServerConf(t, []ssh.PublicKey{k}, "", func(c *ssh.ServerConfig) { c.NoClientAuth = true })
	ps := &pwSource{pw: sshPw}
	sess, att, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: dir, Password: ps.fn}, trustPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Client.Close()
	if att.Outcome != KeysUndetermined || ps.calls != 0 || !strings.Contains(strings.Join(att.Notes, ";"), "без проверки ключа") {
		t.Fatalf("att=%#v calls=%d, want KeysUndetermined с примечанием", att, ps.calls)
	}
}

// twoMethodServer — сервер с password и keyboard-interactive. partialOK:
// верный пароль даёт частичный успех, дальше keyboard-interactive просит код
// (второй фактор). Иначе обычный отказ пароля, kbd тоже перечислен.
func twoMethodServer(partialOK bool, kbdAnswers *[][]string) func(*ssh.ServerConfig) {
	code := func(_ ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		ans, err := ch("", "", []string{"Verification code: "}, []bool{false})
		if err != nil {
			return nil, err
		}
		*kbdAnswers = append(*kbdAnswers, ans)
		return nil, errors.New("код неверен")
	}
	return func(c *ssh.ServerConfig) {
		c.PublicKeyCallback = nil
		c.PasswordCallback = func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if partialOK && string(p) == sshPw {
				return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{KeyboardInteractiveCallback: code}}
			}
			return nil, errors.New("пароль не принят")
		}
		c.KeyboardInteractiveCallback = code
	}
}

// TestConnectNewWrongPasswordNotSecondFactor — различение: неверный пароль на
// сервере с password+keyboard-interactive — «пароль не подошёл», а не
// «второй фактор»; доезд: верный пароль + частичный успех → ErrSecondFactor.
func TestConnectNewWrongPasswordNotSecondFactor(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	for _, partialOK := range []bool{false, true} {
		t.Run(fmt.Sprint("частичный=", partialOK), func(t *testing.T) {
			var kbd [][]string
			srv := startFakeAuthServerConf(t, nil, "", twoMethodServer(partialOK, &kbd))
			ps := &pwSource{pw: sshPw}
			_, _, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: t.TempDir(), Password: ps.fn}, trustPolicy(t))
			var ae *AuthError
			if !errors.As(err, &ae) || !ae.PasswordTried {
				t.Fatalf("ожидался *AuthError с паролем, got %v", err)
			}
			if got := errors.Is(err, ErrSecondFactor); got != partialOK {
				t.Fatalf("ErrSecondFactor=%v, want %v (err %v)", got, partialOK, err)
			}
			if !partialOK && !errors.Is(err, ErrPasswordRejected) {
				t.Fatalf("неверный пароль: want ErrPasswordRejected, got %v", err)
			}
			if len(kbd) != 0 || leaksPassword(err.Error()) {
				t.Fatalf("пароль ушёл во второй вопрос или в текст: kbd=%d", len(kbd))
			}
		})
	}
}

// TestConnectNewKbdThenPassword — keyboard-interactive дал частичный успех,
// затем сервер просит password: пароль второй раз не уходит (ErrSecondFactor
// из PasswordCallback).
func TestConnectNewKbdThenPassword(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	pwCalls := 0
	srv := startFakeAuthServerConf(t, nil, "", func(c *ssh.ServerConfig) {
		c.PublicKeyCallback = nil
		c.PasswordCallback = nil
		c.KeyboardInteractiveCallback = func(_ ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			ans, err := ch("", "", []string{"Password: "}, []bool{false})
			if err != nil || len(ans) != 1 || ans[0] != sshPw {
				return nil, errors.New("нет")
			}
			return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{
				PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
					pwCalls++
					return nil, errors.New("нет")
				},
			}}
		}
	})
	ps := &pwSource{pw: sshPw}
	_, _, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: t.TempDir(), Password: ps.fn}, trustPolicy(t))
	if !errors.Is(err, ErrSecondFactor) || pwCalls != 0 {
		t.Fatalf("err=%v pwCalls=%d, want ErrSecondFactor и пароль второй раз не отправлен", err, pwCalls)
	}
}

// TestConnectNewDropDuringKeyCheck — соединение рвётся, когда сервер
// проверяет ключ: вывод «сервер отверг ключи», сделанный по ходу (в колбэке
// пароля он помечен как предварительный), в итоге снимается →
// KeysUndetermined с примечанием.
func TestConnectNewDropDuringKeyCheck(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	writeKey(t, dir, "id_ed25519", "")
	srv := startFakeAuthServer(t, nil, sshPw)
	srv.dropOnPubkey.Store(true)
	ps := &pwSource{pw: sshPw}
	_, att, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: dir, Password: ps.fn}, trustPolicy(t))
	if err == nil {
		t.Fatal("ожидалась ошибка")
	}
	var ae *AuthError
	if errors.As(err, &ae) {
		t.Fatalf("обрыв не должен выглядеть отказом аутентификации: %v", err)
	}
	if att.Outcome != KeysUndetermined || !strings.Contains(strings.Join(att.Notes, ";"), "вывод о ключах недостоверен") {
		t.Fatalf("att=%#v, want KeysUndetermined с примечанием", att)
	}
	if ps.calls > 0 && !ps.got.Provisional {
		t.Fatal("в колбэке пароля вывод не помечен предварительным")
	}
}

// TestConnectNewKbdSamePromptAgain — в той же попытке сервер снова спросил
// «Password: » (переспрос после неверного): «пароль не подошёл», а не
// «ещё вопрос»/«второй фактор»; пароль второй раз не уходит.
func TestConnectNewKbdSamePromptAgain(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	var got [][]string
	srv := startFakeAuthServerConf(t, nil, "", kbdRounds(
		[][]string{{"Password: "}, {"Password: "}}, [][]bool{{false}, {false}}, &got))
	ps := &pwSource{pw: sshPw}
	_, _, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: t.TempDir(), Password: ps.fn}, trustPolicy(t))
	if !errors.Is(err, ErrPasswordRejected) || errors.Is(err, ErrExtraPrompt) || errors.Is(err, ErrSecondFactor) {
		t.Fatalf("err = %v, want ErrPasswordRejected", err)
	}
	if len(got) != 1 {
		t.Fatalf("пароль ушёл %d раз, want 1", len(got))
	}
}

// TestConnectNewPasswordCallbackCancelled — колбэк пароля вернул ошибку
// («Отмена»), сервер только с password: *AuthError, исход KeysRejected
// сохраняется, примечания про обрыв связи нет.
func TestConnectNewPasswordCallbackCancelled(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	writeKey(t, dir, "id_ed25519", "")
	srv := startFakeAuthServer(t, nil, sshPw) // по умолчанию: publickey (отказ) + password
	cancel := func(KeyAttempt) ([]byte, error) { return nil, errors.New("отменено leak-marker-L2") }
	_, att, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: dir, Password: cancel}, trustPolicy(t))
	var ae *AuthError
	if !errors.As(err, &ae) || !errors.Is(err, ErrPasswordCancelled) || ae.PasswordTried {
		t.Fatalf("err = %T %v, want *AuthError(ErrPasswordCancelled)", err, err)
	}
	if att.Outcome != KeysRejected || strings.Contains(strings.Join(att.Notes, ";"), "оборвалась") {
		t.Fatalf("att = %#v, want KeysRejected без примечания об обрыве", att)
	}
	if strings.Contains(err.Error(), "leak-marker-L2") {
		t.Fatalf("текст ошибки колбэка пароля в Error(): %q", err.Error())
	}
}

// TestConnectNewKeyPartialThenWrongPassword — ключ дал частичный успех,
// затем пароль не подошёл и сервер предложил keyboard-interactive: «пароль не
// подошёл» (частичный успех был у ключа, не у пароля); ключ — принят.
func TestConnectNewKeyPartialThenWrongPassword(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	k := writeKey(t, dir, "id_ed25519", "")
	var kbd [][]string
	srv := startFakeAuthServerConf(t, nil, "", func(c *ssh.ServerConfig) {
		c.PasswordCallback = nil
		c.PublicKeyCallback = func(_ ssh.ConnMetadata, pk ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(pk.Marshal(), k.Marshal()) {
				return nil, errors.New("нет")
			}
			return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{
				PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
					return nil, errors.New("пароль не принят")
				},
				KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
					ans, err := ch("", "", []string{"Password: "}, []bool{false})
					if err == nil {
						kbd = append(kbd, ans)
					}
					return nil, errors.New("нет")
				},
			}}
		}
	})
	ps := &pwSource{pw: sshPw}
	_, att, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: dir, Password: ps.fn}, trustPolicy(t))
	if !errors.Is(err, ErrPasswordRejected) || errors.Is(err, ErrSecondFactor) {
		t.Fatalf("err = %v, want ErrPasswordRejected", err)
	}
	if att.Outcome != KeysAccepted || len(kbd) != 0 {
		t.Fatalf("Outcome=%v kbd=%d, want KeysAccepted и пароль в kbd не ушёл", att.Outcome, len(kbd))
	}
}

// Аудит AU PR #64, L-3/L-2: ни вопрос сервера, ни текст ошибки колбэка
// пароля не попадают в Error() — оба могут нести пароль.
func TestConnectNewServerTextNotInError(t *testing.T) {
	const secret = "s3cr3t-from-server"
	xp := &ExtraPromptError{Prompt: "your password is " + secret}
	if strings.Contains(xp.Error(), secret) {
		t.Fatalf("вопрос сервера в Error(): %q", xp.Error())
	}
	ae := &AuthError{Err: ErrPasswordCancelled}
	if !errors.Is(ae, ErrPasswordCancelled) {
		t.Fatalf("отмена не распознаётся: %v", ae)
	}
}
