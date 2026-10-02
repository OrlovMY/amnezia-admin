package canary

import (
	"net"
	"strings"
)

// К8, финальный раунд (AU-UX М2, решение ядра): связь «через сервер»
// проверяется объективно. «Сайт открылся» ловит и туннель, который
// приложение тихо выключило: телефон откроет сайт напрямую. Поэтому
// человек вводит адрес, который показал сайт проверки IP, а канарейка сама
// сверяет его с адресом тестового сервера. Ожидаемый ответ не подсказывается.

// ipCheckSite — сайт проверки IP, который называется человеку.
const ipCheckSite = "https://ifconfig.me (или другой сайт, показывающий IP)"

// ipSiteFailed — что ввести, если сайт проверки не открылся.
const ipSiteFailed = "не открылся"

// ipQuestion — хвост вопроса о связи: одна форма для всех шагов К8.
func ipQuestion(lead string) string {
	return lead + " Откройте " + ipCheckSite + " и введите адрес, который он показал. Если сайт не открылся — введите «" + ipSiteFailed + "»; Enter или «пропустить» — не проверять."
}

// serverIPs — адреса тестового сервера: сам Host, если это IP, иначе — его
// разрешение. Пусто — адрес не определён (тогда ответ сверить не с чем).
func serverIPs(host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	return ips
}

// ipStatus — введённое человеком против ожидания. viaServer — ждём связь
// через сервер (адрес совпал); !viaServer — ждём, что связи через сервер
// НЕТ (адрес иной либо сайт не открылся). Три исхода, ни одна ветка не
// превращает «не знаем» в «да» или «нет»:
//   - пусто или «пропустить» — НЕ ПРОВЕРЕНО;
//   - не IP и не «не открылся» — НЕ ПРОВЕРЕНО (сверить нечего);
//   - адрес сервера не определён — НЕ ПРОВЕРЕНО.
func ipStatus(input string, server []net.IP, viaServer bool) (Status, string) {
	in := strings.ToLower(strings.TrimSpace(input))
	switch {
	case in == "" || in == "пропустить":
		return NotChecked, "пропущено"
	case len(server) == 0:
		return NotChecked, "адрес тестового сервера не определён — сверить не с чем"
	case strings.Contains(in, ipSiteFailed):
		if viaServer {
			return Fail, "сайт проверки IP не открылся"
		}
		return Pass, "сайт проверки IP не открылся"
	}
	ip := net.ParseIP(in)
	if ip == nil {
		return NotChecked, "введено не IP-адрес — сверить не с чем"
	}
	match := false
	for _, s := range server {
		if s.Equal(ip) {
			match = true
		}
	}
	switch {
	case match && viaServer:
		return Pass, "адрес совпал с адресом сервера"
	case match:
		return Fail, "адрес совпал с адресом сервера — связь через сервер есть"
	case viaServer:
		return Fail, "адрес " + ip.String() + " — не адрес сервера: связь идёт мимо сервера"
	}
	return Pass, "адрес " + ip.String() + " — не адрес сервера"
}

// askIP — вопрос о связи. AskIP не задан — НЕ ПРОВЕРЕНО.
func (e *Env) askIP(lead string, viaServer bool) (Status, string) {
	if e.AskIP == nil {
		return NotChecked, "ввод адреса недоступен"
	}
	host := ""
	if e.Sess != nil && e.Sess.Creds != nil {
		host = e.Sess.Creds.Host
	}
	return ipStatus(e.AskIP(ipQuestion(lead)), serverIPs(host), viaServer)
}
