// Файл sshauth.go — вход на НОВЫЙ сервер без ключа vpn:// (план БК
// «перенос на чистый сервер», раздел 5, PR 2).
//
// Источники входа по порядку: ssh-agent (только Unix, SSH_AUTH_SOCK) →
// файлы id_ed25519, id_ecdsa, id_rsa из каталога ключей (без парольной
// фразы; с фразой — пропуск с причиной) → пароль от вызывающего.
//
// ТРИ СОСТОЯНИЯ ПО КЛЮЧАМ, А НЕ ДВА (CLAUDE.md): вошли / сервер отверг все
// ключи / ключей нет или агент недоступен. Четвёртое значение —
// KeysUndetermined (нулевое): до проверки ключей дело не дошло (сеть, ключ
// хоста). Нулевое значение НЕ является ответом «нет».
//
// Пароль: []byte от колбэка, обнуляется после Dial, в Session не
// сохраняется (Creds.Password пуст), в текст ошибок не попадает. Ограничение
// x/crypto/ssh: PasswordCallback возвращает string — на время Dial в памяти
// живёт неизменяемая копия, обнулить которую нельзя.
package core

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KeyOutcome — исход попытки входа по ключам.
type KeyOutcome int

const (
	// KeysUndetermined — неизвестно: до проверки ключей сервер не дошёл
	// (сеть, ключ хоста) либо попытки не было.
	KeysUndetermined KeyOutcome = iota
	// KeysAccepted — сервер принял ключ, вход выполнен по ключу.
	KeysAccepted
	// KeysRejected — ключи были предъявлены, сервер не принял ни одного.
	KeysRejected
	// KeysUnavailable — предъявить нечего: ни агента с ключами, ни файлов
	// ключей без парольной фразы. Причины — в KeyAttempt.Notes.
	KeysUnavailable
)

func (o KeyOutcome) String() string {
	switch o {
	case KeysAccepted:
		return "сервер принял ключ"
	case KeysRejected:
		return "сервер отверг все предъявленные ключи"
	case KeysUnavailable:
		return "ключей для входа нет"
	default:
		return "проверка ключей не состоялась"
	}
}

// KeyAttempt — что было с ключами: исход, какие ключи предъявлялись, почему
// какие-то источники пропущены (агент недоступен, ключ под фразой…).
type KeyAttempt struct {
	Outcome KeyOutcome
	Offered []string // "агент: SHA256:…", "файл id_ed25519: SHA256:…"
	Notes   []string // причины пропуска источников
}

// Reason — объяснение для человека.
func (a KeyAttempt) Reason() string {
	s := a.Outcome.String()
	if len(a.Notes) > 0 {
		s += " (" + strings.Join(a.Notes, "; ") + ")"
	}
	return s
}

// AuthSource — откуда брать вход на новый сервер.
type AuthSource struct {
	// KeyDir — каталог с id_ed25519/id_ecdsa/id_rsa. "" → ~/.ssh. Шов для
	// тестов: настоящий ~/.ssh в тестах не читается.
	KeyDir string
	// AgentSocket — путь к сокету ssh-agent. "" → SSH_AUTH_SOCK. На Windows
	// агент не поддерживается (нужна go-winio для named pipe).
	AgentSocket string
	// NoAgent — не обращаться к агенту вовсе.
	NoAgent bool
	// Password — вызывается не более одного раза, только если ключи не
	// дали войти (или их нет); keys — почему пришлось спросить пароль.
	// Возвращённый срез обнуляется после попытки. nil → пароля нет.
	// Пустой срез → отказ от ввода.
	Password func(keys KeyAttempt) ([]byte, error)
}

// keyFileNames — порядок файлов ключей.
var keyFileNames = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

// ErrAgentUnsupported — агент на этой ОС не поддерживается.
var ErrAgentUnsupported = errors.New("ssh-agent на этой ОС не поддерживается")

// ErrNoPassword — пароль не был дан (колбэк вернул пустой срез).
var ErrNoPassword = errors.New("пароль не введён")

// AuthError — вход не удался по аутентификации. Пароля в тексте нет.
type AuthError struct {
	Keys          KeyAttempt
	PasswordTried bool
	Err           error
}

func (e *AuthError) Unwrap() error { return e.Err }

func (e *AuthError) Error() string {
	s := "Сервер не принял вход. Ключи: " + e.Keys.Reason()
	if e.PasswordTried {
		s += "; пароль не подошёл"
	} else {
		s += "; пароль не предъявлялся"
	}
	if e.Err != nil {
		s += ". Ответ: " + e.Err.Error()
	}
	return s
}

// collectSigners собирает ключи из агента и файлов. closeFn закрывает
// соединение с агентом — после Dial.
func collectSigners(src AuthSource) (signers []ssh.Signer, att KeyAttempt, closeFn func()) {
	closeFn = func() {}
	if !src.NoAgent {
		sock := src.AgentSocket
		if sock == "" {
			sock = os.Getenv("SSH_AUTH_SOCK")
		}
		ag, closer, err := dialAgent(sock)
		switch {
		case err != nil:
			att.Notes = append(att.Notes, "агент: "+err.Error())
		default:
			closeFn = func() { _ = closer.Close() }
			ss, err := ag.Signers()
			if err != nil {
				att.Notes = append(att.Notes, "агент: не удалось получить ключи: "+err.Error())
			} else if len(ss) == 0 {
				att.Notes = append(att.Notes, "агент: ключей нет")
			}
			for _, s := range ss {
				signers = append(signers, s)
				att.Offered = append(att.Offered, "агент: "+ssh.FingerprintSHA256(s.PublicKey()))
			}
		}
	} else {
		att.Notes = append(att.Notes, "агент: отключён")
	}

	dir := src.KeyDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			att.Notes = append(att.Notes, "каталог ключей: домашний каталог неизвестен: "+err.Error())
		} else {
			dir = filepath.Join(home, ".ssh")
		}
	}
	if dir != "" {
		found := false
		for _, name := range keyFileNames {
			p := filepath.Join(dir, name)
			data, err := os.ReadFile(p)
			if err != nil {
				if !os.IsNotExist(err) {
					att.Notes = append(att.Notes, name+": не прочитан: "+err.Error())
				}
				continue
			}
			found = true
			s, err := ssh.ParsePrivateKey(data)
			clear(data)
			if err != nil {
				var pm *ssh.PassphraseMissingError
				if errors.As(err, &pm) {
					att.Notes = append(att.Notes, name+": защищён парольной фразой — пропущен")
				} else {
					att.Notes = append(att.Notes, name+": не разобран")
				}
				continue
			}
			signers = append(signers, s)
			att.Offered = append(att.Offered, "файл "+name+": "+ssh.FingerprintSHA256(s.PublicKey()))
		}
		if !found {
			att.Notes = append(att.Notes, "в "+dir+" нет id_ed25519/id_ecdsa/id_rsa")
		}
	}
	if len(signers) == 0 {
		att.Outcome = KeysUnavailable
	}
	return signers, att, closeFn
}

// ConnectNew — вход на новый сервер (без vpn://): ключи агента и файлов,
// затем пароль. Ключ хоста — по pol (как ConnectWithHostKey).
//
// Возвращает исход по ключам ВСЕГДА (и при ошибке): вызывающий показывает,
// почему понадобился пароль. Отказ аутентификации — *AuthError; прочее
// (сеть, ключ хоста) — *ConnectError.
func ConnectNew(host, port, user string, src AuthSource, pol HostKeyPolicy) (*Session, KeyAttempt, error) {
	signers, att, closeAgent := collectSigners(src)
	defer closeAgent()

	var pw []byte
	pwAsked := false
	defer func() { clear(pw) }()
	getPw := func() (string, error) {
		if !pwAsked {
			pwAsked = true
			if len(signers) > 0 {
				// До пароля доходит, только если ключи не прошли.
				att.Outcome = KeysRejected
			}
			p, err := src.Password(att)
			if err != nil {
				clear(p)
				return "", err
			}
			if len(p) == 0 {
				return "", ErrNoPassword
			}
			pw = p
		}
		if pw == nil {
			return "", ErrNoPassword
		}
		return string(pw), nil
	}

	var auths []ssh.AuthMethod
	if len(signers) > 0 {
		auths = append(auths, ssh.PublicKeys(signers...))
	}
	if src.Password != nil {
		auths = append(auths,
			ssh.PasswordCallback(getPw),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				ans := make([]string, len(questions))
				for i := range questions {
					p, err := getPw()
					if err != nil {
						return nil, err
					}
					ans[i] = p
				}
				return ans, nil
			}),
		)
	}
	if len(auths) == 0 {
		return nil, att, &AuthError{Keys: att, Err: errors.New("нет ни ключей, ни пароля")}
	}

	client, fp, err := dialWithHostKey(host, port, user, auths, pol)
	if err != nil {
		ce := ClassifyConnectError(err)
		authFail := ce.Kind == ConnectAuthRejected || errors.Is(err, ErrNoPassword)
		if authFail && len(signers) > 0 && att.Outcome == KeysUndetermined {
			// Пароля не было, ключи предъявлены и не приняты.
			att.Outcome = KeysRejected
		}
		if authFail {
			return nil, att, &AuthError{Keys: att, PasswordTried: pw != nil, Err: err}
		}
		return nil, att, ce
	}
	if len(signers) > 0 && !pwAsked {
		att.Outcome = KeysAccepted
	}
	creds := &ServerCreds{Host: host, Port: port, User: user} // пароль не хранится
	return &Session{Client: client, Creds: creds, r: sshRunner{client}, HostKeyFingerprint: fp}, att, nil
}
