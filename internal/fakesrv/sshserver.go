// Файл sshserver.go — встроенный SSH-сервер (настоящий TCP + SSH-транспорт,
// golang.org/x/crypto/ssh) для тестов PR-4 (проверка ключа хоста) и для
// cmd/fakeserver (ручная проверка QA-02). В отличие от Server (fakesrv.go),
// который подменяет транспорт через интерфейс core.Runner, SSHServer нужен
// ИМЕННО там, где важен сам SSH-рукопожатие и ключ хоста — Runner-подмена их
// не видит вовсе. SSHServer оборачивает Server: команды exec исполняет тот
// же самый Server.Run, то есть один и тот же набор серверных команд и один и
// тот же журнал Commands() что и в остальных тестах пакета.
//
// Поддерживается ровно то, что нужно core.ConnectWithHostKey и
// core/runner.go (sshRunner): аутентификация паролем и ОДИН канал типа
// "session" с ОДНИМ запросом "exec" на канал (без pty/shell/agent-forwarding
// и т.п.) — любой другой запрос к каналу отклоняется, любой другой тип
// канала отклоняется. Слушать разрешено только на 127.0.0.1 (В2 п.1) — сам
// SSHServer порт не ограничивает (адрес передаёт вызывающий), но во всех
// тестах и в cmd/fakeserver используется "127.0.0.1:…".
package fakesrv

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// NewHostKey генерирует случайный ключ хоста ed25519 — для тестов и для
// cmd/fakeserver (если не передан свой).
func NewHostKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("fakesrv: NewHostKey: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("fakesrv: NewHostKey: %w", err)
	}
	return signer, nil
}

// SSHServer — работающий SSH-сервер поверх net.Listener; каждая сессия exec
// исполняется через переданный exec (*Server).
type SSHServer struct {
	ln   net.Listener
	fp   string
	wg   sync.WaitGroup
	once sync.Once

	// mu/conns/closed — реестр открытых TCP-соединений и признак остановки
	// (SEC-01/BE-01, ревью PR-4А круг 1 Medium + круг 2 Low): без реестра
	// Close() мог зависнуть навечно — wg.Wait() ждёт handleConn, а
	// handleConn ждёт данные от клиента, который сам никогда не закроется
	// (например, тест намеренно бросил *Session по ошибочному/
	// регрессионному пути, не вызвав Close()). Регресс тогда не падает, а
	// виснет до таймаута пакета — неотличимо от "тест ещё не дописан".
	// Close() сам обрывает все известные соединения ПЕРЕД wg.Wait().
	//
	// closed И регистрация conns/wg.Add ОБЯЗАНЫ читаться/писаться под ОДНИМ
	// mu (круг 2, Low): иначе есть окно между Accept() (уже вернул conn) и
	// регистрацией в acceptLoop, в которое Close() успевает пройти мимо —
	// такое соединение не попадёт в conns и не будет принудительно закрыто,
	// а wg.Add(1) для него может выполниться уже ПОСЛЕ начала wg.Wait() в
	// Close() (нарушение контракта sync.WaitGroup, потенциальное
	// зависание/паника). Проверка s.closed под тем же mu, которым Close()
	// защищает и установку этого флага, и закрытие всех conns, устраняет
	// окно: либо acceptLoop успевает зарегистрировать соединение и сделать
	// wg.Add ДО того, как Close возьмёт mu (тогда Close увидит его в conns
	// и закроет), либо Close успевает первым — тогда acceptLoop увидит
	// closed==true и закроет свежепринятое соединение сам, не трогая ни
	// conns, ни wg.
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

// ListenSSH поднимает SSH-сервер на addr (в тестах "127.0.0.1:0"), принимает
// пароль password для user, сессии с запросом "exec" исполняет через
// exec.Run (тот же фейк, что для Runner), отвечает stdout + exit-status.
// addr обязан резолвиться в loopback-адрес (127.0.0.0/8 или ::1) — В2 п.1:
// встроенный сервер не должен слушать ни на каком внешнем интерфейсе, и это
// ограничение — забота самого ListenSSH, а не только вызывающего кода
// (cmd/fakeserver и тесты и так передают только "127.0.0.1:…", но ограничение
// внутри функции не даёт этому стать негласным допущением).
func ListenSSH(addr, user, password string, hostKey ssh.Signer, exec *Server) (*SSHServer, error) {
	if hostKey == nil {
		return nil, fmt.Errorf("fakesrv: ListenSSH: hostKey обязателен")
	}
	if exec == nil {
		return nil, fmt.Errorf("fakesrv: ListenSSH: exec (*Server) обязателен")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("fakesrv: ListenSSH: адрес %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("fakesrv: ListenSSH: адрес %q — разрешён только loopback (127.0.0.1 или ::1); встроенный сервер не должен слушать на внешних интерфейсах", addr)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if meta.User() != user || string(pass) != password {
				return nil, fmt.Errorf("fakesrv: неверные логин/пароль")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(hostKey)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("fakesrv: ListenSSH: %w", err)
	}

	s := &SSHServer{
		ln:    ln,
		fp:    ssh.FingerprintSHA256(hostKey.PublicKey()),
		conns: make(map[net.Conn]struct{}),
	}
	s.wg.Add(1)
	go s.acceptLoop(cfg, exec)
	return s, nil
}

// Addr возвращает host:port, на котором реально слушает сервер (важно, когда
// addr при ListenSSH был "127.0.0.1:0" — порт выдаёт ОС).
func (s *SSHServer) Addr() string { return s.ln.Addr().String() }

// Fingerprint — отпечаток (SHA256:…) ключа хоста этого сервера.
func (s *SSHServer) Fingerprint() string { return s.fp }

// Close останавливает сервер: закрывает слушающий сокет, помечает сервер
// закрытым и ПРИНУДИТЕЛЬНО закрывает все уже зарегистрированные соединения
// (см. комментарий у полей mu/conns/closed) — всё это под одним mu, единым
// с acceptLoop, — и только потом ждёт завершения обслуживающих их горутин.
// Идемпотентен.
func (s *SSHServer) Close() error {
	var err error
	s.once.Do(func() {
		err = s.ln.Close()

		s.mu.Lock()
		s.closed = true
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
	})
	s.wg.Wait()
	return err
}

func (s *SSHServer) acceptLoop(cfg *ssh.ServerConfig, exec *Server) {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // закрыт извне (Close) — не ошибка теста
		}

		s.mu.Lock()
		if s.closed {
			// Close() успел пройти мимо этого соединения (окно между
			// Accept() и этой блокировкой) — закрываем сами и НЕ трогаем
			// wg: раз мы не регистрируем conn и не делаем wg.Add, Close()
			// ничего для него ждать не будет, и порядок Add/Wait не
			// нарушается (круг 2, Low).
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()

		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			s.handleConn(conn, cfg, exec)
		}()
	}
}

func (s *SSHServer) handleConn(conn net.Conn, cfg *ssh.ServerConfig, exec *Server) {
	defer conn.Close()
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		// неверный пароль, отказ рукопожатия и т.п. — не ошибка теста,
		// вызывающая сторона (ssh.Dial) увидит это как обычный отказ auth
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	var wg sync.WaitGroup
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			handleSession(ch, chReqs, exec)
		}()
	}
	wg.Wait()
}

// execRequestMsg/exitStatusMsg — формы SSH channel-request payload'ов из
// RFC 4254 §6.5/§6.10 (имена и теги совпадают с (неэкспортированными)
// структурами в golang.org/x/crypto/ssh/session.go — пакет их не
// экспортирует, поэтому здесь своя копия минимально необходимой формы).
type execRequestMsg struct {
	Command string
}
type exitStatusMsg struct {
	Status uint32
}

// handleSession обслуживает один канал "session": принимает единственный
// запрос "exec", исполняет команду через exec.Run, пишет stdout в канал,
// stderr — в Channel.Stderr(), затем отправляет exit-status и закрывает
// канал. Любой другой тип запроса ("pty-req", "shell", "subsystem",
// "env", "window-change", …) отклоняется явным отказом (WantReply=false
// запросы — как OpenSSH, дают false без падения).
func handleSession(ch ssh.Channel, reqs <-chan *ssh.Request, exec *Server) {
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" {
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}

		var m execRequestMsg
		if err := ssh.Unmarshal(req.Payload, &m); err != nil {
			if req.WantReply {
				req.Reply(false, nil)
			}
			return
		}
		if req.WantReply {
			req.Reply(true, nil)
		}

		stdin, _ := io.ReadAll(ch)
		out, runErr := exec.Run(m.Command, stdin)

		if _, werr := io.WriteString(ch, out); werr != nil {
			return
		}
		code := uint32(0)
		if runErr != nil {
			fmt.Fprint(ch.Stderr(), runErr.Error())
			code = 1
		}
		sendExitStatus(ch, code)
		return // одна exec-сессия на канал — после неё канал закрывается (defer)
	}
}

func sendExitStatus(ch ssh.Channel, code uint32) {
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMsg{Status: code}))
}
