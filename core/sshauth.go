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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
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
	// KeysNotAllowed — ключи были, но сервер не предложил метод publickey
	// (например PubkeyAuthentication no): ключи серверу не показывались, и
	// говорить «отвергнуты» нельзя.
	KeysNotAllowed
	// KeysSignFailed — сервер был готов принять ключ, но подпись не
	// получилась (агент отказал, заблокирован, требует подтверждения).
	KeysSignFailed
)

func (o KeyOutcome) String() string {
	switch o {
	case KeysAccepted:
		return "сервер принял ключ"
	case KeysRejected:
		return "сервер отверг все предъявленные ключи"
	case KeysUnavailable:
		return "ключей для входа нет или агент недоступен"
	case KeysNotAllowed:
		return "сервер не принимает вход по ключу — ключи ему не предъявлялись"
	case KeysSignFailed:
		return "сервер готов был принять ключ, но подписать им не удалось (агент отказал?)"
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
	// Provisional — вывод предварительный: так KeyAttempt выглядит в
	// колбэке пароля, когда вход ещё не завершён (транспортный сбой может
	// его отменить). В итоговом KeyAttempt от ConnectNew — false.
	Provisional bool
}

// Reason — объяснение для человека.
func (a KeyAttempt) Reason() string {
	s := a.Outcome.String()
	if a.Provisional {
		s = "по-видимому, " + s
	}
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
	if e.PasswordTried && (errors.Is(e.Err, ErrSecondFactor) || errors.Is(e.Err, ErrExtraPrompt)) {
		s += "; пароль отправлен, но сервер спросил ещё"
	} else if e.PasswordTried {
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

// keyRec — что на самом деле произошло с ключами во время рукопожатия:
// вызывался ли метод publickey (значит, сервер его предложил), была ли
// попытка подписи и чем закончилась.
type keyRec struct {
	offeredToServer bool
	signOK          int
	signErr         error
}

// recSigner — обёртка ключа, записывающая исход подписи. Подпись
// запрашивается x/crypto только ПОСЛЕ того, как сервер сказал «этот ключ
// годится» (validateKey), поэтому ошибка подписи ≠ «сервер отверг».
type recSigner struct {
	ssh.Signer
	rec *keyRec
}

func (r recSigner) note(sig *ssh.Signature, err error) (*ssh.Signature, error) {
	if err != nil {
		if r.rec.signErr == nil {
			r.rec.signErr = err
		}
	} else {
		r.rec.signOK++
	}
	return sig, err
}

func (r recSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return r.note(r.Signer.Sign(rand, data))
}

// recAlgSigner — то же для AlgorithmSigner (ключи из файлов и агента в
// x/crypto реализуют его; без него терялся бы выбор rsa-sha2-*).
type recAlgSigner struct {
	recSigner
	as ssh.AlgorithmSigner
}

func (r recAlgSigner) SignWithAlgorithm(rand io.Reader, data []byte, algo string) (*ssh.Signature, error) {
	return r.note(r.as.SignWithAlgorithm(rand, data, algo))
}

// Ограничение: обёртка не сохраняет ssh.MultiAlgorithmSigner (сужение
// списка алгоритмов подписи). Ключи из файлов и агента в x/crypto таким
// сужением не пользуются; если появится — подпись может предложить
// алгоритм шире, чем разрешал исходный ключ.
func wrapSigner(s ssh.Signer, rec *keyRec) ssh.Signer {
	base := recSigner{Signer: s, rec: rec}
	if as, ok := s.(ssh.AlgorithmSigner); ok {
		return recAlgSigner{recSigner: base, as: as}
	}
	return base
}

// ErrSecondFactor — пароль принят ЧАСТИЧНО (сервер сообщил частичный успех
// password/keyboard-interactive) и требует ещё метод: второй фактор, пароль
// повторно не уходит.
var ErrSecondFactor = errors.New("пароль принят, но сервер требует второй фактор — не поддерживается, пароль повторно не отправлен")

// ErrExtraPrompt — в той же попытке keyboard-interactive после пароля сервер
// задал ДРУГОЙ вопрос (код, «Current password:» истёкшего пароля…). Что это —
// не утверждаем; текст вопроса — в *ExtraPromptError.
var ErrExtraPrompt = errors.New("сервер задал после пароля ещё вопрос — не поддерживается, пароль повторно не отправлен")

// ExtraPromptError — ErrExtraPrompt с текстом вопроса сервера (пароля в нём
// нет: это приглашение, присланное сервером).
type ExtraPromptError struct{ Prompt string }

func (e *ExtraPromptError) Error() string {
	return fmt.Sprintf("сервер задал после пароля ещё вопрос: %q — не поддерживается, пароль повторно не отправлен", truncRunes(e.Prompt, 80))
}
func (e *ExtraPromptError) Unwrap() error { return ErrExtraPrompt }

// ErrPasswordCancelled — колбэк пароля вернул ошибку (человек нажал
// «Отмена» и т.п.): это отказ от входа, а не обрыв связи.
var ErrPasswordCancelled = errors.New("ввод пароля отменён")

// ErrKbdInteractive — сервер задал в keyboard-interactive не один вопрос о
// пароле или видимый ввод: пароль туда не отправляется.
// ErrPasswordRejected — пароль уже отправлен и не принят, а сервер
// предлагает ещё метод с вопросом: повторно пароль не отправляется.
var ErrPasswordRejected = errors.New("пароль не подошёл")

var ErrKbdInteractive = errors.New("сервер спрашивает не только пароль (keyboard-interactive: несколько вопросов или видимый ввод, возможно второй фактор) — пароль не отправлен")

// keysVerdict — исход по ключам из ФАКТОВ рукопожатия, когда вход по
// ключу не состоялся. Порядок: ошибка подписи (сервер ключ одобрял) →
// метод не предлагался → предложен и отвергнут.
func keysVerdict(rec *keyRec) KeyOutcome {
	switch {
	case rec.signErr != nil:
		return KeysSignFailed
	case !rec.offeredToServer:
		return KeysNotAllowed
	default:
		return KeysRejected
	}
}

// ConnectNew — вход на новый сервер (без vpn://): ключи агента и файлов,
// затем пароль. Ключ хоста — по pol (как ConnectWithHostKey).
//
// Возвращает исход по ключам ВСЕГДА (и при ошибке): вызывающий показывает,
// почему понадобился пароль. Отказ аутентификации — *AuthError; прочее
// (сеть, ключ хоста) — *ConnectError.
func ConnectNew(host, port, user string, src AuthSource, pol HostKeyPolicy) (*Session, KeyAttempt, error) {
	if strings.TrimSpace(pol.KnownHostsPath) == "" {
		return nil, KeyAttempt{}, fmt.Errorf("HostKeyPolicy.KnownHostsPath обязателен")
	}
	signers, att, closeAgent := collectSigners(src)
	defer closeAgent()

	rec := &keyRec{}
	var pw []byte
	pwAsked := false
	pwSent := false      // пароль уже ушёл серверу в этом соединении
	partial := false     // частичный успех пароля (password/keyboard-interactive)
	keysPartial := false // частичный успех ключа: ключ принят, нужен ещё метод
	pwPrompt := ""       // приглашение, на которое ушёл пароль (keyboard-interactive)
	// methodSeq — номер попытки метода: AuthCallback зовётся между
	// попытками. pwSeq — в какой попытке ушёл пароль.
	methodSeq, pwSeq := 0, -1
	authCb := func(ctx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
		methodSeq++
		partial = slices.Contains(ctx.PartialSuccessMethods, "password") || slices.Contains(ctx.PartialSuccessMethods, "keyboard-interactive")
		keysPartial = slices.Contains(ctx.PartialSuccessMethods, "publickey")
		return nil, nil // выбор метода — обычный
	}
	// afterPw — пароль уже ушёл, а сервер спрашивает снова (prompt — текст
	// вопроса keyboard-interactive, "" для метода password).
	//   - та же попытка, тот же вопрос → переспрос: пароль не подошёл;
	//   - та же попытка, другой вопрос → ErrExtraPrompt с текстом вопроса
	//     (код, смена пароля — не угадываем);
	//   - новая попытка после частичного успеха пароля → второй фактор;
	//   - иначе пароль не подошёл, сервер предлагает другой метод.
	afterPw := func(key, shown string) error {
		switch {
		case methodSeq == pwSeq && key == pwPrompt:
			return ErrPasswordRejected
		case methodSeq == pwSeq:
			return &ExtraPromptError{Prompt: shown}
		case partial:
			return ErrSecondFactor
		default:
			return ErrPasswordRejected
		}
	}
	defer func() { clear(pw) }()
	settleKeys := func() {
		if len(signers) > 0 && att.Outcome == KeysUndetermined {
			if keysPartial {
				att.Outcome = KeysAccepted
				att.Notes = append(att.Notes, "ключ принят, но сервер требует ещё метод входа")
				return
			}
			att.Outcome = keysVerdict(rec)
			if rec.signErr != nil {
				att.Notes = append(att.Notes, "подпись: "+rec.signErr.Error())
			}
		}
	}
	getPw := func() (string, error) {
		if !pwAsked {
			pwAsked = true
			// До пароля доходит, только если ключи не дали войти.
			settleKeys()
			q := att
			q.Provisional = true
			p, err := src.Password(q)
			if err != nil {
				clear(p)
				return "", fmt.Errorf("%w: %w", ErrPasswordCancelled, err)
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
		wrapped := make([]ssh.Signer, len(signers))
		for i, s := range signers {
			wrapped[i] = wrapSigner(s, rec)
		}
		auths = append(auths, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			rec.offeredToServer = true
			return wrapped, nil
		}))
	}
	if src.Password != nil {
		auths = append(auths,
			ssh.PasswordCallback(func() (string, error) {
				if pwSent {
					return "", afterPw("", "")
				}
				p, err := getPw()
				if err == nil {
					pwSent, pwSeq = true, methodSeq
				}
				return p, err
			}),
			ssh.KeyboardInteractive(func(_, instruction string, questions []string, echos []bool) ([]string, error) {
				if len(questions) == 0 {
					return nil, nil
				}
				if len(questions) != 1 || echos[0] {
					return nil, ErrKbdInteractive
				}
				prompt := instruction + "\n" + questions[0]
				if pwSent {
					return nil, afterPw(prompt, questions[0])
				}
				p, err := getPw()
				if err != nil {
					return nil, err
				}
				pwSent, pwSeq, pwPrompt = true, methodSeq, prompt
				return []string{p}, nil
			}),
		)
	}
	if len(auths) == 0 {
		return nil, att, &AuthError{Keys: att, Err: errors.New("нет ни ключей, ни пароля")}
	}

	client, fp, err := dialWithHostKey(host, port, user, auths, authCb, pol)
	if err != nil {
		ce := ClassifyConnectError(err)
		authFail := ce.Kind == ConnectAuthRejected || errors.Is(err, ErrNoPassword) || errors.Is(err, ErrKbdInteractive) || errors.Is(err, ErrSecondFactor) || errors.Is(err, ErrPasswordRejected) ||
			errors.Is(err, ErrExtraPrompt) || errors.Is(err, ErrPasswordCancelled)
		if authFail {
			settleKeys()
			return nil, att, &AuthError{Keys: att, PasswordTried: pw != nil, Err: err}
		}
		if len(signers) > 0 && att.Outcome != KeysUndetermined {
			// Вывод о ключах сделан по ходу входа, но вход прервался не по
			// аутентификации: обрыв связи, нарушение протокола, неизвестный
			// сбой (отмена человеком сюда не доходит — это authFail выше).
			// Вывод недостоверен — снимаем его (ревью-5 PR #64, M-G).
			att.Outcome = KeysUndetermined
			att.Notes = append(att.Notes, "вход прервался не по аутентификации — вывод о ключах недостоверен")
		}
		return nil, att, ce
	}
	switch {
	case len(signers) == 0:
	case !pwAsked && rec.signOK > 0:
		att.Outcome = KeysAccepted
	case !pwAsked:
		// Вошли без ключа и без пароля (сервер пустил по «none» или
		// keyboard-interactive без вопросов): про ключи сказать нечего.
		att.Notes = append(att.Notes, "сервер впустил без проверки ключа")
	}
	creds := &ServerCreds{Host: host, Port: port, User: user} // пароль не хранится
	return &Session{Client: client, Creds: creds, r: sshRunner{client}, HostKeyFingerprint: fp}, att, nil
}

// truncRunes — строка от сервера в тексте ошибки не длиннее n рун.
func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
