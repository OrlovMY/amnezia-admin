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
}

func startFakeAuthServer(t *testing.T, allowKeys []ssh.PublicKey, allowPassword string) *fakeAuthServer {
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
				sc, chans, reqs, err := ssh.NewServerConn(c, conf)
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
	srv := startFakeAuthServer(t, allow, sc.serverPw)
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
	if len(seen) != 3 {
		t.Fatalf("различимых исходов %d, want 3: %v", len(seen), seen)
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
