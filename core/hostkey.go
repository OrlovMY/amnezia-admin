// Файл hostkey.go — политика проверки ключа хоста SSH (PR-4, аудит
// 2026-09-14, Critical: функция полного отключения проверки ключа хоста
// (была в core.Connect) убрана из пакета полностью, без замены на флаг
// "доверять всему").
//
// TOFU (trust-on-first-use) с явным подтверждением человека: неизвестный
// сервер — вопрос через Prompt (или отказ без TTY/без обработчика); известный
// сервер, ключ совпал — тихое подключение; известный сервер, ключ сменился —
// ВСЕГДА жёсткий отказ (ErrHostKeyChanged), без кнопки «всё равно
// подключиться» — этот путь архитектурно невыразим: OnChanged ничего не
// возвращает. Обходного флага «не проверять» нет и не будет (В2 п.3).
package core

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyPolicy — как поступить с ключом хоста сервера при подключении.
//
// Prompt — вопрос человеку о НЕИЗВЕСТНОМ сервере: показать отпечаток,
// спросить «доверять?»; true → ключ записывается в known_hosts. nil →
// неизвестный сервер отвергается без вопроса (CLI без TTY).
//
// OnChanged — ключ ИЗВЕСТНОГО сервера сменился: только показать записанный и
// предъявленный отпечатки, ничего не возвращает; подключение отвергается
// ВСЕГДА. nil → просто ошибка. Тип делает запрещённый путь («принять
// сменившийся ключ») невыразимым — кнопке «всё равно подключиться» некуда
// подключиться.
type HostKeyPolicy struct {
	// KnownHostsPath — обязателен; в приложении —
	// filepath.Join(DefaultVaultDir(), "known_hosts"). Файл может не
	// существовать — это равносильно пустому known_hosts (сервер неизвестен),
	// а не ошибке.
	KnownHostsPath string

	Prompt    func(host, fingerprint string) bool
	OnChanged func(host, knownFp, presentedFp string)

	// ExpectedFingerprint — "" либо "SHA256:…": из -hostkey (CLI) или из
	// .avlt (GUI). Непустой и совпадающий с предъявленным — pinning: запись
	// в known_hosts без вопроса (это не слепое доверие — конкретный
	// отпечаток уже был явно подтверждён раньше человеком, при первом
	// сохранении в CLI-скрипте или в .avlt). Непустой и НЕ совпадающий —
	// всегда отказ (ErrHostKeyMismatch), даже если known_hosts содержит
	// какой-то другой принятый ключ для этого адреса — vault и known_hosts
	// разошлись, и это тоже отказ (не тихое доверие тому, что скажет
	// known_hosts).
	ExpectedFingerprint string
}

var (
	// ErrHostKeyUnknown — сервер не встречался раньше, и подтверждения не
	// было (Prompt == nil, Prompt вернул false, либо ExpectedFingerprint
	// задан, но не совпал — тогда ErrHostKeyMismatch, см. ниже).
	ErrHostKeyUnknown = errors.New("ключ сервера неизвестен и не подтверждён")
	// ErrHostKeyChanged — сервер известен (запись в known_hosts есть), но
	// предъявленный ключ другой. ВСЕГДА отказ — обходного пути «принять
	// новый ключ прямо сейчас» нет; см. ForgetHostKey.
	ErrHostKeyChanged = errors.New("ключ сервера ИЗМЕНИЛСЯ — подключение отклонено")
	// ErrHostKeyMismatch — предъявленный ключ не совпал с ExpectedFingerprint
	// (pinning из -hostkey/.avlt), независимо от того, что говорит
	// known_hosts.
	ErrHostKeyMismatch = errors.New("ключ сервера не совпадает с ожидаемым отпечатком")
)

// HostKeyError — типизированная ошибка проверки ключа хоста (ревью PR-4-Б,
// круг 1, SEC-01 Medium): вызывающий код (GUI) раньше добывал "полученный"
// отпечаток регэкспом из текста ошибки для случая ErrHostKeyMismatch — тот
// же класс хрупкой связи через текст, что уже правили у ErrCASMismatch
// (PR-3). Теперь отпечатки и адрес — поля структуры, достаются через
// errors.As, регэксп в GUI больше не нужен.
//
// Kind — один из ErrHostKeyUnknown/ErrHostKeyChanged/ErrHostKeyMismatch;
// Unwrap возвращает его, поэтому errors.Is(err, ErrHostKeyChanged) и т.п.
// продолжают работать как раньше, ничего в вызывающем коде (кроме GUI,
// который теперь достаёт поля через errors.As) менять не нужно. Error()
// возвращает ТОТ ЖЕ текст, что раньше собирал fmt.Errorf(..., %w, ...) в
// checkHostKey — построчный текст в CLI/логах не меняется.
//
// KnownFp — отпечаток, который считался верным ДО этого подключения:
// записанный в known_hosts (случай ErrHostKeyChanged) либо ожидавшийся по
// хранилищу/-hostkey (случай ErrHostKeyMismatch); "" — для ErrHostKeyUnknown
// (сервер вообще не встречался). PresentedFp — то, что сервер предъявил
// ИМЕННО СЕЙЧАС, в этом подключении.
type HostKeyError struct {
	Kind        error
	Addr        string
	KnownFp     string
	PresentedFp string
	text        string
}

func (e *HostKeyError) Error() string { return e.text }
func (e *HostKeyError) Unwrap() error { return e.Kind }

var (
	// ErrForgetVault — ForgetHostKey не смог перезапечатать .avlt (чтение,
	// разбор пином, шифрование или запись файла) — НИЧЕГО не забыто:
	// known_hosts не трогался вовсе (ревью PR-4-Б, круг 1, SEC-01 Medium:
	// до этого различение шло по strings.Contains(err.Error(), "хранилищ"),
	// что для голой ошибки ОС без этого слова приписывало сбой known_hosts и
	// давало человеку ложную инструкцию — замкнутый круг с ErrForgetKnownHosts).
	ErrForgetVault = errors.New("не удалось перезапечатать хранилище — ключ сервера не забыт")
	// ErrForgetKnownHosts — .avlt уже успешно перезапечатан (отпечаток
	// стёрт, MachineBind сохранён), но правка known_hosts не удалась.
	// Только эта ошибка означает "вручную удалите строку из known_hosts" —
	// ErrForgetVault до этого шага не доходит вовсе.
	ErrForgetKnownHosts = errors.New("не удалось изменить known_hosts")
)

// newHostKeyError строит текст ошибки в точности как раньше делал
// fmt.Errorf("%w: "+format, kind, args...) (kind.Error() на месте %w — то же
// самое, что %s/%v для error), и заполняет структурные поля для errors.As.
func newHostKeyError(kind error, addr, knownFp, presentedFp, format string, args ...any) *HostKeyError {
	head := kind.Error() + ": "
	return &HostKeyError{
		Kind:        kind,
		Addr:        addr,
		KnownFp:     knownFp,
		PresentedFp: presentedFp,
		text:        head + fmt.Sprintf(format, args...),
	}
}

// ConnectWithHostKey — как Connect, но с политикой проверки ключа хоста pol
// вместо полного отключения проверки. Единственный путь установления SSH-
// соединения в пакете core, начиная с PR-4.
func ConnectWithHostKey(creds *ServerCreds, pol HostKeyPolicy) (*Session, error) {
	if strings.TrimSpace(pol.KnownHostsPath) == "" {
		return nil, fmt.Errorf("HostKeyPolicy.KnownHostsPath обязателен")
	}

	var auths []ssh.AuthMethod
	if strings.Contains(creds.Password, "PRIVATE KEY") {
		signer, err := ssh.ParsePrivateKey([]byte(creds.Password))
		if err != nil {
			return nil, fmt.Errorf("не удалось разобрать SSH-ключ из конфига: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	} else {
		auths = append(auths,
			ssh.Password(creds.Password),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				ans := make([]string, len(questions))
				for i := range questions {
					ans[i] = creds.Password
				}
				return ans, nil
			}),
		)
	}

	var acceptedFp string
	conf := &ssh.ClientConfig{
		User: creds.User,
		Auth: auths,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			fp := ssh.FingerprintSHA256(key)
			addr := knownhosts.Normalize(hostname)
			// hostname (НЕ addr) идёт в lookupKnownHost/cb: x/crypto/ssh/
			// knownhosts требует host:port (net.SplitHostPort внутри), а
			// Normalize для порта 22 (SSH по умолчанию) порт как раз убирает
			// — knownhosts.Normalize("host:22") == "host". Раньше сюда шёл
			// addr, и на порту 22 knownhosts-колбэк падал с "missing port in
			// address" вместо (не)нахождения строки known_hosts: после
			// первого удачного TOFU (файла ещё не было — NotExist трактуется
			// как «неизвестен», путь не доходил до cb) второе и все
			// последующие подключения к тому же серверу на 22 порту получали
			// эту ошибку. addr (нормализованный, без порта для 22) остаётся
			// для записи строки known_hosts, текстов ошибок и сравнения в
			// ForgetHostKey — там формат не меняется.
			accepted, err := checkHostKey(pol, addr, hostname, remote, fp, key)
			if err != nil {
				return err
			}
			if accepted {
				acceptedFp = fp
			}
			return nil
		},
		Timeout: 15 * time.Second,
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(creds.Host, creds.Port), conf)
	if err != nil {
		return nil, err
	}
	return &Session{Client: client, Creds: creds, r: sshRunner{client}, HostKeyFingerprint: acceptedFp}, nil
}

// checkHostKey реализует порядок из Г1 задания PR-4. addr — уже нормализован
// (knownhosts.Normalize) адрес: под ним ищется/пишется запись known_hosts
// (appendKnownHost) и он же идёт в тексты ошибок/ExpectedFingerprint;
// lookupAddr — ИСХОДНЫЙ hostname из HostKeyCallback (обязательно с портом,
// как его требует cb из knownhosts.New — см. lookupKnownHost) для самой
// сверки; remote — фактический адрес соединения (нужен только knownhosts-у
// для внутренней проверки, приоритет всегда у lookupAddr).
func checkHostKey(pol HostKeyPolicy, addr, lookupAddr string, remote net.Addr, fp string, key ssh.PublicKey) (accepted bool, err error) {
	keyErr, err := lookupKnownHost(pol.KnownHostsPath, lookupAddr, remote, key)
	if err != nil {
		return false, err
	}

	if keyErr == nil {
		// Шаг 3: ключ принят по known_hosts (записан и совпал).
		if pol.ExpectedFingerprint != "" && pol.ExpectedFingerprint != fp {
			return false, newHostKeyError(ErrHostKeyMismatch, addr, pol.ExpectedFingerprint, fp,
				"адрес %s, ожидался %s (из хранилища), известный и предъявленный ключ сервера — %s",
				addr, pol.ExpectedFingerprint, fp)
		}
		return true, nil
	}

	if len(keyErr.Want) > 0 {
		// Шаг 1: запись есть, но НЕ совпала — жёсткий отказ всегда,
		// ExpectedFingerprint тут не помогает и не проверяется (правка 4.5
		// PQ-01: смена ключа — как OpenSSH ask, без вопроса, без обхода).
		knownFp := ssh.FingerprintSHA256(keyErr.Want[0].Key)
		if pol.OnChanged != nil {
			pol.OnChanged(addr, knownFp, fp)
		}
		return false, newHostKeyError(ErrHostKeyChanged, addr, knownFp, fp,
			"адрес %s, было %s, стало %s (known_hosts: %s); если сервер переустанавливали, удалите строку %q из %s и подключитесь заново",
			addr, knownFp, fp, pol.KnownHostsPath, addr, pol.KnownHostsPath)
	}

	// Шаг 2: записи нет — неизвестный сервер.
	if pol.ExpectedFingerprint != "" {
		if pol.ExpectedFingerprint != fp {
			return false, newHostKeyError(ErrHostKeyMismatch, addr, pol.ExpectedFingerprint, fp,
				"адрес %s, ожидался %s, предъявлен %s", addr, pol.ExpectedFingerprint, fp)
		}
		if err := appendKnownHost(pol.KnownHostsPath, addr, key); err != nil {
			return false, err
		}
		return true, nil
	}
	if pol.Prompt == nil {
		return false, newHostKeyError(ErrHostKeyUnknown, addr, "", fp, "адрес %s, отпечаток %s", addr, fp)
	}
	if !pol.Prompt(addr, fp) {
		return false, newHostKeyError(ErrHostKeyUnknown, addr, "", fp, "адрес %s, отпечаток %s", addr, fp)
	}
	if err := appendKnownHost(pol.KnownHostsPath, addr, key); err != nil {
		return false, err
	}
	return true, nil
}

// lookupKnownHost проверяет ключ key против known_hosts по пути path для
// адреса addr. addr ОБЯЗАН быть в форме host:port (или [ipv6]:port) — именно
// так его требует callback из knownhosts.New (внутри — net.SplitHostPort);
// для этого сюда передаётся исходный hostname из HostKeyCallback, а НЕ
// knownhosts.Normalize(hostname) — Normalize снимает порт 22, и голый хост
// без порта cb отклоняет с "missing port in address" вместо поиска строки
// (см. ConnectWithHostKey). Возвращает:
//   - (nil, nil)      — ключ найден и совпал (принят);
//   - (keyErr, nil)    — либо записи нет (keyErr.Want пуст), либо запись есть,
//     но ключ другой (keyErr.Want непуст) — знквает вызывающий;
//   - (nil, err)       — настоящая ошибка (не про членство: битый файл,
//     ошибка чтения и т.п.).
//
// Отсутствие файла known_hosts — не ошибка, а пустая база (сервер
// неизвестен): рядом с ещё не созданным файлом "Настройки" его, очевидно,
// нет при самом первом подключении когда-либо.
func lookupKnownHost(path, addr string, remote net.Addr, key ssh.PublicKey) (*knownhosts.KeyError, error) {
	if _, statErr := os.Stat(path); statErr != nil {
		if os.IsNotExist(statErr) {
			return &knownhosts.KeyError{}, nil
		}
		return nil, statErr
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать %s: %w", path, err)
	}
	cbErr := cb(addr, remote, key)
	if cbErr == nil {
		return nil, nil
	}
	var keyErr *knownhosts.KeyError
	if errors.As(cbErr, &keyErr) {
		return keyErr, nil
	}
	return nil, cbErr
}

// appendKnownHost дописывает строку addr → key в файл known_hosts по пути
// path атомарно (как SaveVault: tmp + rename), создавая каталог и сам файл
// при необходимости; права 0600.
func appendKnownHost(path, addr string, key ssh.PublicKey) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var buf bytes.Buffer
	buf.Write(existing)
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		buf.WriteByte('\n')
	}
	buf.WriteString(knownhosts.Line([]string{addr}, key))
	buf.WriteByte('\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// ForgetHostKey — «забыть ключ сервера» для записи хранилища vaultPath:
// снимает ОБА следа, как того требует SEC-01 (handoff-2026-09-14/
// С3-позиция-ядра.md, п.1) и правка координатора 2026-09-14 23:58 у Г1
// (заменяет прежнюю сигнатуру ForgetHostKey(pin, path) — та снимала след
// ТОЛЬКО в .avlt и после переустановки сервера на той же машине зацикливала
// R2: ErrHostKeyChanged → Forget → снова ErrHostKeyChanged, потому что
// известный-но-другой ключ в known_hosts никуда не девался):
//  1. перезапечатывает .avlt с пустым HostKeyFingerprint (MachineBind и
//     параметры Argon2 сохраняются);
//  2. АТОМАРНО удаляет из known_hosts по пути knownHostsPath строки, чей
//     адрес после knownhosts.Normalize совпадает с host — прочие строки
//     (другие сервера) остаются нетронутыми.
//
// Соединения НЕ создаёт и НИЧЕГО не обходит — после этого следующее
// ConnectWithHostKey идёт обычным путём НЕИЗВЕСТНОГО сервера (Prompt с
// показом нового отпечатка), а не тихим принятием и не повторным отказом.
// Решение владельца 2026-09-14 (R2): вызов из UI — часть Б.
func ForgetHostKey(pin, vaultPath, knownHostsPath, host string) error {
	data, err := LoadVault(vaultPath)
	if err != nil {
		return fmt.Errorf("%w: не удалось прочитать хранилище: %w", ErrForgetVault, err)
	}
	payload, info, err := OpenVaultInfo(pin, data)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrForgetVault, err)
	}
	payload.HostKeyFingerprint = ""
	sealed, err := SealVault(pin, payload, info.Params, info.MachineBind)
	if err != nil {
		return fmt.Errorf("%w: не удалось перезапечатать хранилище: %w", ErrForgetVault, err)
	}
	if err := WriteVaultFile(vaultPath, sealed); err != nil {
		return fmt.Errorf("%w: %w", ErrForgetVault, err)
	}
	// Хранилище уже перезапечатано (отпечаток стёрт) — отсюда и дальше
	// любой сбой относится ТОЛЬКО к known_hosts, ни в коем случае не к
	// хранилищу: перепутать эти два источника — значит дать человеку ЛОЖНУЮ
	// инструкцию ("удалите строку known_hosts", когда на самом деле не
	// записался .avlt, или наоборот) и загнать его в замкнутый круг
	// (ревью PR-4-Б, круг 1, SEC-01 Medium).
	if err := removeKnownHostLines(knownHostsPath, host); err != nil {
		return fmt.Errorf("%w: %w", ErrForgetKnownHosts, err)
	}
	return nil
}

// removeKnownHostLines удаляет из known_hosts по пути path строки, чей
// адрес (первое, до пробела, поле строки; несколько адресов через запятую —
// как пишет knownhosts.Line) после knownhosts.Normalize совпадает с
// knownhosts.Normalize(host). Прочие строки (в т.ч. записи других серверов,
// комментарии) сохраняются как есть, в исходном порядке. Отсутствие файла —
// не ошибка (нечего забывать). Запись атомарна (tmp + rename, 0600), как
// appendKnownHost/SaveVault.
func removeKnownHostLines(path, host string) error {
	target := knownhosts.Normalize(host)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	lines := strings.Split(string(data), "\n")
	var kept []string
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		match := false
		if len(fields) > 0 && !strings.HasPrefix(fields[0], "#") {
			for _, a := range strings.Split(fields[0], ",") {
				if knownhosts.Normalize(a) == target {
					match = true
					break
				}
			}
		}
		if match {
			continue // это и есть "забыть" — строка выброшена
		}
		kept = append(kept, line)
	}

	var buf bytes.Buffer
	for _, l := range kept {
		buf.WriteString(l)
		buf.WriteByte('\n')
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
