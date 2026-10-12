package core

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Файл clienthost.go — адрес сервера в конфигах клиентов (требование
// владельца: «Новые ключи надо генерировать с DNS-именем, а не с IP»).
//
// Прежде Endpoint клиентского конфига и адрес в ссылке XRay брались из
// hostName админского ключа vpn:// — у многих серверов это IP. Конфиг с IP
// при переезде сервера приходится перевыпускать каждому клиенту; конфиг с
// именем — достаточно перевести DNS.
//
// ТРИ СОСТОЯНИЯ проверки имени (CLAUDE.md): совпадает / указывает на другие
// адреса / проверить не удалось. Нулевое значение ClientHostStatus —
// «не удалось», чтобы забытое присваивание не превращалось в «совпадает».

// ClientHostSetting — сохранённый выбор адреса для клиентов (внутри
// зашифрованного хранилища .avlt, VaultPayload). Нулевое значение — выбор
// ещё не сделан.
type ClientHostSetting struct {
	Host   string // DNS-имя для конфигов клиентов; "" — не задано
	KeepIP bool   // человек явно отказался от имени: «оставить IP»
}

// endpointAddr — host:port для Endpoint; IPv6 — в квадратных скобках
// (иначе «2001:db8::1:51820» не разобрать).
func endpointAddr(host, port string) string {
	return net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"), port)
}

// IssuedHost — адрес, с которым конфиги выдаются в этом сеансе, и известен
// ли он. Неизвестен — в ключе IP, а выбор адреса для клиентов не сделан:
// раньше конфиги могли выдаваться и по имени (копия не должна утверждать
// IP, признаки 2 и 4).
func (s *Session) IssuedHost() (string, bool) {
	if s.ClientHost != "" {
		return s.ClientHost, true
	}
	if s.Creds == nil {
		return "", false
	}
	if s.ClientHostDecided || !IsIPHost(s.Creds.Host) {
		return s.Creds.Host, true
	}
	return "", false
}

// IsIPHost — адрес является IP-литералом (v4 или v6, допускаются скобки).
func IsIPHost(h string) bool {
	h = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(h), "["), "]")
	return net.ParseIP(h) != nil
}

// DecideClientHost — какой адрес ставить в конфиги клиентов и нужно ли
// спросить человека. Порядок ветвей: явное имя главнее всего; имя в ключе —
// не спрашивать; IP в ключе — спрашивать, пока человек не сказал «оставить
// IP».
func DecideClientHost(keyHost string, set ClientHostSetting) (host string, ask bool) {
	if set.Host != "" {
		return set.Host, false
	}
	if !IsIPHost(keyHost) {
		return keyHost, false
	}
	if set.KeepIP {
		return keyHost, false
	}
	return keyHost, true
}

// NormalizeClientHost — имя, введённое человеком: без пробелов, в нижнем
// регистре, без завершающей точки. Ошибка — пусто, IP вместо имени или
// недопустимые символы.
func NormalizeClientHost(name string) (string, error) {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if n == "" {
		return "", fmt.Errorf("имя не указано")
	}
	if IsIPHost(n) {
		return "", fmt.Errorf("%q — это IP-адрес, а нужно DNS-имя (например vpn.example.com)", n)
	}
	if len(n) > 253 {
		return "", fmt.Errorf("имя длиннее 253 символов")
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("%q — не DNS-имя (пустая или неверная часть между точками)", n)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", fmt.Errorf("%q — не DNS-имя: допустимы латинские буквы, цифры, дефис и точка (кириллический домен вводите в виде xn--…)", n)
			}
		}
	}
	return n, nil
}

// ClientHostStatus — исход проверки имени. Нулевое значение — «не удалось».
type ClientHostStatus int

const (
	ClientHostUnknown  ClientHostStatus = iota // проверить не удалось
	ClientHostMatch                            // имя указывает на этот сервер
	ClientHostMismatch                         // имя указывает на другие адреса
)

// ClientHostCheck — результат сверки имени с адресом сервера.
type ClientHostCheck struct {
	Status   ClientHostStatus
	Name     string
	ServerIP string   // адрес, к которому подключились по SSH ("" — неизвестен)
	Resolved []string // все адреса имени (A и AAAA), как вернул резолвер
	Reason   string   // почему «не удалось»
}

// SystemResolver — системный резолвер с ограничением по времени.
func SystemResolver(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

// ServerIP — IP, к которому реально установлено SSH-подключение (а не то,
// что написано в ключе). "" — неизвестен (сессия без SSH и не IP в ключе).
func (s *Session) ServerIP() string {
	if s.Client != nil {
		if h, _, err := net.SplitHostPort(s.Client.RemoteAddr().String()); err == nil {
			if ip := net.ParseIP(h); ip != nil {
				return ip.String()
			}
		}
	}
	if s.Creds != nil && IsIPHost(s.Creds.Host) {
		return net.ParseIP(strings.Trim(s.Creds.Host, "[]")).String()
	}
	return ""
}

// EndpointHost — адрес сервера, который ставится в конфиги клиентов:
// выбранное имя (ClientHost) или, если не выбрано, hostName ключа.
func (s *Session) EndpointHost() string {
	if s.ClientHost != "" {
		return s.ClientHost
	}
	if s.Creds == nil {
		return ""
	}
	return s.Creds.Host
}

// CheckClientHost — сверка имени с адресом сервера. Сравниваются записи
// того же семейства, что и адрес подключения (A для IPv4, AAAA для IPv6):
// «совпадает» — только если ВСЕ такие записи указывают на сервер; хотя бы
// одна чужая — «другие адреса» (часть клиентов уйдёт не туда). Записей
// нужного семейства нет, имя не разрешилось, адрес сервера неизвестен —
// «не удалось», без догадок.
func CheckClientHost(name, serverIP string, resolve Resolver) ClientHostCheck {
	c := ClientHostCheck{Name: name, ServerIP: serverIP}
	srv := net.ParseIP(serverIP)
	if srv == nil {
		c.Reason = "неизвестен адрес, к которому подключена программа"
		return c
	}
	if !publicIP(srv) {
		c.Reason = fmt.Sprintf("подключение идёт через частный/туннельный адрес %s — публичный адрес сервера программе неизвестен, сравнивать имя не с чем", serverIP)
		return c
	}
	if resolve == nil {
		c.Reason = "резолвер недоступен"
		return c
	}
	ips, err := resolve(name)
	if err != nil {
		c.Reason = "имя не разрешилось: " + err.Error()
		return c
	}
	if len(ips) == 0 {
		c.Reason = "у имени нет ни одной записи A/AAAA"
		return c
	}
	srv4 := srv.To4() != nil
	same := 0
	match := 0
	for _, ip := range ips {
		c.Resolved = append(c.Resolved, ip.String())
		if (ip.To4() != nil) != srv4 {
			continue
		}
		same++
		if ip.Equal(srv) {
			match++
		}
	}
	switch {
	case same == 0:
		fam := "A (IPv4)"
		if !srv4 {
			fam = "AAAA (IPv6)"
		}
		c.Reason = fmt.Sprintf("у имени нет записей %s — сравнить с адресом сервера %s не с чем", fam, serverIP)
	case match == same:
		c.Status = ClientHostMatch
	default:
		c.Status = ClientHostMismatch
	}
	return c
}

// cgnat — 100.64.0.0/10 (RFC 6598): net.IP.IsPrivate его не включает.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// publicIP — адрес, с которым имеет смысл сравнивать DNS-ответ: не
// loopback, не частный (10/8, 172.16/12, 192.168/16, fc00::/7), не
// link-local, не CGNAT, не unspecified.
func publicIP(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || cgnat.Contains(ip))
}

// dnsHint — оговорка ко всем исходам: проверка — ответ DNS этого компьютера.
const dnsHint = " Это ответ DNS на этом компьютере — подсказка, а не гарантия того, что видят клиенты."

// Text — человеческое описание исхода (одна-две фразы) с оговоркой dnsHint.
func (c ClientHostCheck) Text() string { return c.text() + dnsHint }

func (c ClientHostCheck) text() string {
	got := strings.Join(c.Resolved, ", ")
	switch c.Status {
	case ClientHostMatch:
		t := fmt.Sprintf("Имя %s указывает на этот сервер (%s).", c.Name, c.ServerIP)
		if other := c.otherFamily(); other != "" {
			t += " Записи другого семейства (" + other + ") не проверены: принадлежат ли они этому серверу, неизвестно."
		}
		return t
	case ClientHostMismatch:
		return fmt.Sprintf("ВНИМАНИЕ: имя %s указывает на %s, а программа подключена к %s. Клиенты с таким конфигом пойдут НЕ на этот сервер (или не все на этот).", c.Name, got, c.ServerIP)
	}
	return fmt.Sprintf("Проверить имя %s не удалось: %s. Это не значит ни «совпадает», ни «не совпадает».", c.Name, c.Reason)
}

func (c ClientHostCheck) otherFamily() string {
	srv := net.ParseIP(c.ServerIP)
	if srv == nil {
		return ""
	}
	var out []string
	for _, s := range c.Resolved {
		if ip := net.ParseIP(s); ip != nil && (ip.To4() != nil) != (srv.To4() != nil) {
			out = append(out, s)
		}
	}
	return strings.Join(out, ", ")
}

// ClientHostIPWarning — громкое предупреждение для конфига, выданного с IP.
func ClientHostIPWarning(ip string) string {
	return fmt.Sprintf("ВНИМАНИЕ: в конфиге клиента IP-адрес сервера %s, а не DNS-имя. При переезде сервера такой конфиг придётся перевыпускать каждому клиенту. Укажите имя: -client-host vpn.example.com (имя должно указывать на этот сервер).", ip)
}
