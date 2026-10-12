package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strings"
	"unicode/utf8"
)

// Файл vaultlabel.go — подписи сохранённых серверов на экране подключения
// (отзыв владельца по rc.4: «задавал имя подключению, а вижу "Сервер 1" и
// "Сервер 2"»).
//
// Метка внутри .avlt зашифрована и до ввода пина неизвестна, поэтому подпись
// лежит рядом ОТКРЫТО: <файл>.avlt.label (JSON, 0600). В ней только то, что
// человек и так видит на экране: имя и адрес host:port. Ни ключа vpn://, ни
// пароля, ни отпечатка — их место внутри зашифрованного файла.
//
// ТРИ СОСТОЯНИЯ. Подпись известна (файл есть и читается) — показываем её.
// Подписи нет (старый файл, сохранённый до этой правки) — честное «Сервер N»;
// подпись появится после первого успешного входа по этому файлу. Подпись
// есть, но не читается — тоже «Сервер N», без выдумывания имени.

// VaultLabel — открытая подпись сохранённого сервера.
type VaultLabel struct {
	Name string `json:"name"`
	Addr string `json:"addr,omitempty"`
}

// VaultLabelMaxRunes — длина подписи в списке, дальше многоточие; полное
// имя — в заголовке диалога пин-кода.
const VaultLabelMaxRunes = 48

func vaultLabelPath(vaultPath string) string { return vaultPath + ".label" }

// ServerAddr — адрес для подписи: host, порт — только если не 22,
// пользователь — только если не root (root у Amnezia по умолчанию и
// только загромождал бы подпись).
func ServerAddr(host, port, user string) string {
	a := host
	if port != "" && port != "22" {
		a = net.JoinHostPort(host, port)
	}
	if user != "" && user != "root" {
		a = user + "@" + a
	}
	return a
}

// DefaultServerName — имя сервера по умолчанию: описание из ключа vpn://
// (поле description — то самое имя, которое задают в приложении
// AmneziaVPN), иначе адрес. Пустая строка — если не известно ни то, ни другое.
func DefaultServerName(cfg map[string]any) string {
	if d := strings.TrimSpace(Str(cfg, "description")); d != "" {
		return d
	}
	host := Str(cfg, "hostName")
	if host == "" {
		return ""
	}
	port := Str(cfg, "port")
	if port == "0" {
		port = ""
	}
	return ServerAddr(host, port, Str(cfg, "userName"))
}

// ChooseServerName — имя для подписи сохранённого сервера: метка, которую
// человек задал в программе, главнее описания из ключа. Исключение — метка,
// совпадающая с голым адресом: так программа до этой правки подставляла
// значение по умолчанию сама, и человек его не выбирал.
func ChooseServerName(label, host string, cfg map[string]any) string {
	label = strings.TrimSpace(label)
	if label != "" && label != host {
		return label
	}
	if n := DefaultServerName(cfg); n != "" {
		return n
	}
	return label
}

// WriteVaultLabel пишет открытую подпись рядом с vaultPath (атомарно, 0600).
func WriteVaultLabel(vaultPath string, l VaultLabel) error {
	data, err := json.Marshal(l)
	if err != nil {
		return err
	}
	p := vaultLabelPath(vaultPath)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// ReadVaultLabel читает подпись. ok=false, err=nil — подписи нет (старый
// файл); err != nil — подпись есть, но прочитать её не удалось.
func ReadVaultLabel(vaultPath string) (l VaultLabel, ok bool, err error) {
	data, err := os.ReadFile(vaultLabelPath(vaultPath))
	if errors.Is(err, fs.ErrNotExist) {
		return VaultLabel{}, false, nil
	}
	if err != nil {
		return VaultLabel{}, false, err
	}
	if err := json.Unmarshal(data, &l); err != nil {
		return VaultLabel{}, false, fmt.Errorf("подпись %s повреждена: %w", vaultLabelPath(vaultPath), err)
	}
	l.Name = strings.TrimSpace(l.Name)
	if l.Name == "" {
		return VaultLabel{}, false, fmt.Errorf("подпись %s пуста", vaultLabelPath(vaultPath))
	}
	return l, true, nil
}

// VaultNames — подписи для списка сохранённых серверов, в порядке vaults.
// Неизвестная подпись — «Сервер N» (N — позиция в списке). Одинаковые
// имена у разных серверов различаются адресом («AEZA test — 1.2.3.4»), а
// если и адрес совпал или неизвестен — номером. Длинные имена обрезаются
// многоточием до VaultLabelMaxRunes (Short); Full — полная подпись (для
// заголовка диалога пин-кода).
type VaultName struct{ Short, Full string }

// VaultNames — см. VaultName.
func VaultNames(vaults []string) []VaultName {
	labels := make([]VaultLabel, len(vaults))
	known := make([]bool, len(vaults))
	for i, p := range vaults {
		l, ok, err := ReadVaultLabel(p)
		known[i] = ok && err == nil
		labels[i] = l
	}
	return vaultNamesFrom(labels, known)
}

func vaultNamesFrom(labels []VaultLabel, known []bool) []VaultName {
	n := len(labels)
	full := make([]string, n)
	count := map[string]int{}
	for i := range labels {
		if known[i] {
			count[labels[i].Name]++
		}
	}
	for i := range labels {
		switch {
		case !known[i]:
			full[i] = fmt.Sprintf("Сервер %d", i+1)
		case count[labels[i].Name] > 1 && labels[i].Addr != "" && labels[i].Addr != labels[i].Name:
			full[i] = labels[i].Name + " — " + labels[i].Addr
		default:
			full[i] = labels[i].Name
		}
	}
	// Второй круг: совпало и с адресом (или адреса нет) — номер.
	seen := map[string]int{}
	for _, f := range full {
		seen[f]++
	}
	for i := range full {
		if seen[full[i]] > 1 {
			full[i] = fmt.Sprintf("%s (%d)", full[i], i+1)
		}
	}
	out := make([]VaultName, n)
	for i, f := range full {
		out[i] = VaultName{Short: TruncateRunes(f, VaultLabelMaxRunes), Full: f}
	}
	return out
}

// TruncateRunes обрезает s до max знаков с многоточием в конце.
func TruncateRunes(s string, max int) string {
	if utf8.RuneCountInString(s) <= max || max < 1 {
		return s
	}
	r := []rune(s)
	return string(r[:max-1]) + "…"
}
