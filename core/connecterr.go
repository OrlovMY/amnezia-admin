package core

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
)

// Файл connecterr.go — понятный человеку отказ входа по SSH (отзыв владельца
// по rc.4: «старый ключ к новому серверу перестал действовать, вроде логично,
// но не однозначно понятно»). Прежде CLI и GUI печатали голый текст
// golang.org/x/crypto/ssh: «ssh: handshake failed: ssh: unable to
// authenticate, attempted methods [none password], no supported methods
// remain» — правда, но не ответ на вопрос «что мне делать».
//
// ТРИ СОСТОЯНИЯ, А НЕ ДВА (CLAUDE.md). Вид определяется только по ПРИЗНАКУ;
// нет признака — ConnectUnknown с исходной причиной, без догадок. Порядок
// проверок — от частного к общему так, чтобы частный НЕ перехватывал чужое:
// ключ хоста (типизированная ошибка ядра) → отказ аутентификации (точная
// фраза x/crypto/ssh) → сеть (типы net/syscall) → неизвестно.
//
// Секретов в тексте нет: исходные ошибки x/crypto/ssh и net не содержат ни
// пароля, ни ключа (в них — имена методов и адрес), а собственный текст
// пароль/ключ не упоминает. Сторож — TestConnectErrorNoSecret.

// ConnectErrKind — вид отказа подключения.
type ConnectErrKind int

const (
	// ConnectUnknown — признака нет: печатается исходная причина как есть.
	ConnectUnknown ConnectErrKind = iota
	// ConnectAuthRejected — сервер ответил, но не принял ни пароль, ни
	// SSH-ключ из vpn://.
	ConnectAuthRejected
	// ConnectHostKey — ключ хоста не прошёл проверку (изменился, не совпал
	// с хранилищем или не подтверждён).
	ConnectHostKey
	// ConnectNetwork — до SSH дело не дошло: отказ соединения, таймаут,
	// имя не разрешилось, сеть недоступна.
	ConnectNetwork
)

// ConnectError — отказ ConnectWithHostKey. Error() — объяснение для человека
// (одинаковое в CLI и GUI), Unwrap — исходная ошибка: errors.Is(err,
// ErrHostKeyUnknown) и errors.As(err, *HostKeyError) работают как прежде.
type ConnectError struct {
	Kind ConnectErrKind
	Err  error
}

func (e *ConnectError) Unwrap() error { return e.Err }

// Тексты — константами, чтобы тесты и вызывающий код сверялись с ними, а не
// с копией.
const (
	ConnectAuthRejectedText = "Сервер не принял ключ входа из vpn:// (SSH-ключ или пароль). " +
		"Обычно так бывает, если сервер переустановили или ключ удалили из authorized_keys — " +
		"получите новый ключ vpn:// для этого сервера"
	ConnectHostKeyChangedText = "Ключ хоста сервера не совпал с сохранённым — программа отказывается подключаться: " +
		"по этому адресу отвечает другой сервер или этот сервер переустановили, а подмену с первого взгляда от переустановки не отличить. " +
		"Если переустановка ожидаема — забудьте старый ключ сервера (в программе: кнопка «Забыть ключ сервера»; " +
		"в командной строке: удалите строку из known_hosts) и подключитесь заново — программа покажет новый отпечаток и спросит, доверять ли ему. " +
		"Если не переустанавливали — не подключайтесь"
	ConnectNetworkText = "Не удалось установить соединение с сервером (сеть, адрес или порт): " +
		"сервер выключен, недоступен по сети или порт SSH закрыт"
	ConnectUnknownText = "Не удалось подключиться"
)

func (e *ConnectError) Error() string {
	cause := ""
	if e.Err != nil {
		cause = e.Err.Error()
	}
	switch e.Kind {
	case ConnectAuthRejected:
		return ConnectAuthRejectedText + ". Ответ сервера: " + cause
	case ConnectHostKey:
		var hke *HostKeyError
		if errors.As(e.Err, &hke) && hke.Kind == ErrHostKeyUnknown {
			// «Не подтверждён» — не «не совпал»: объяснение про переустановку
			// здесь было бы неправдой, достаточно текста ядра.
			return cause
		}
		return ConnectHostKeyChangedText + ". Подробности: " + cause
	case ConnectNetwork:
		return ConnectNetworkText + ". Причина: " + cause
	default:
		return ConnectUnknownText + ": " + cause
	}
}

// ClassifyConnectError определяет вид отказа по признакам; nil → nil.
func ClassifyConnectError(err error) *ConnectError {
	if err == nil {
		return nil
	}
	var ce *ConnectError
	if errors.As(err, &ce) {
		return ce
	}
	return &ConnectError{Kind: classifyConnect(err), Err: err}
}

func classifyConnect(err error) ConnectErrKind {
	if errors.Is(err, ErrHostKeyChanged) || errors.Is(err, ErrHostKeyMismatch) || errors.Is(err, ErrHostKeyUnknown) {
		return ConnectHostKey
	}
	// x/crypto/ssh не экспортирует тип клиентского отказа аутентификации —
	// только текст (client_auth.go). Фраза точная; если библиотека её
	// сменит, вид станет ConnectUnknown (честное «не знаем»), а не чужим.
	if strings.Contains(err.Error(), "ssh: unable to authenticate") {
		return ConnectAuthRejected
	}
	var dnsErr *net.DNSError
	var opErr *net.OpError
	var netErr net.Error
	switch {
	case errors.As(err, &dnsErr),
		errors.As(err, &opErr),
		errors.Is(err, syscall.ECONNREFUSED),
		errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &netErr) && netErr.Timeout():
		return ConnectNetwork
	}
	return ConnectUnknown
}
