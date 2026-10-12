package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
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
	// Sum — SHA-256 содержимого .avlt, для которого записана подпись.
	Sum string `json:"sha256"`
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

// LabelState — состояние подписи сохранённого сервера.
type LabelState int

const (
	// LabelAbsent — подписи нет (файл сохранён до появления подписей).
	LabelAbsent LabelState = iota
	// LabelOK — подпись есть и относится именно к этому .avlt.
	LabelOK
	// LabelBroken — подпись есть, но не читается или пуста.
	LabelBroken
	// LabelMismatch — подпись читается, но записана для другого содержимого
	// .avlt (файл заменили, скопировали, восстановили; подпись осталась от
	// прежнего). Её имя не показывается: оно может быть чужим.
	LabelMismatch
)

// Пометки к «Сервер N» — различимо от «подписи нет».
const (
	LabelBrokenNote   = "подпись повреждена"
	LabelMismatchNote = "подпись не совпадает с файлом ключа"
)

func vaultSum(vaultPath string) (string, error) {
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:]), nil
}

// WriteVaultLabel пишет открытую подпись рядом с vaultPath (атомарно, 0600),
// привязывая её к ТЕКУЩЕМУ содержимому .avlt (SHA-256). Пустое имя
// заменяется адресом; если неизвестно и то и другое — подпись не пишется
// (пустая подпись была бы «повреждённой»).
func WriteVaultLabel(vaultPath string, l VaultLabel) error {
	l.Name = strings.TrimSpace(l.Name)
	if l.Name == "" {
		l.Name = l.Addr
	}
	if l.Name == "" {
		return nil
	}
	sum, err := vaultSum(vaultPath)
	if err != nil {
		return err
	}
	l.Sum = sum
	data, err := json.Marshal(l)
	if err != nil {
		return err
	}
	p := vaultLabelPath(vaultPath)
	f, err := os.CreateTemp(filepath.Dir(p), filepath.Base(p)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(tmp, 0600)
	}
	if werr == nil {
		werr = os.Rename(tmp, p)
	}
	if werr != nil {
		os.Remove(tmp)
		return werr
	}
	return nil
}

// ReadVaultLabel читает подпись и проверяет её привязку к .avlt. err —
// причина для LabelBroken (и сбоя чтения самого .avlt).
func ReadVaultLabel(vaultPath string) (l VaultLabel, st LabelState, err error) {
	data, err := os.ReadFile(vaultLabelPath(vaultPath))
	if errors.Is(err, fs.ErrNotExist) {
		return VaultLabel{}, LabelAbsent, nil
	}
	if err != nil {
		return VaultLabel{}, LabelBroken, err
	}
	if err := json.Unmarshal(data, &l); err != nil {
		return VaultLabel{}, LabelBroken, fmt.Errorf("подпись %s повреждена: %w", vaultLabelPath(vaultPath), err)
	}
	l.Name = strings.TrimSpace(l.Name)
	if l.Name == "" {
		return VaultLabel{}, LabelBroken, fmt.Errorf("подпись %s пуста", vaultLabelPath(vaultPath))
	}
	sum, err := vaultSum(vaultPath)
	if err != nil {
		return l, LabelBroken, err
	}
	if l.Sum != sum {
		return l, LabelMismatch, nil
	}
	return l, LabelOK, nil
}

// keepLabelAfterRewrite — после перезаписи .avlt программой (WriteVaultFile)
// подпись, бывшая верной ДО перезаписи (wasOK), перепривязывается к новому
// содержимому. Неверная подпись не «узаконивается». Сбой записи не скрыт:
// подпись останется несовпадающей и будет так и показана.
func keepLabelAfterRewrite(vaultPath string, l VaultLabel, wasOK bool) {
	if wasOK {
		_ = WriteVaultLabel(vaultPath, l) // сбой виден в списке как «не совпадает»
	}
}

// RemoveOrphanVaultLabels удаляет подписи, у которых нет своего .avlt
// (ключ удалили руками) — адрес сервера не должен лежать на диске без нужды.
// При показе такие подписи и так не участвуют (список строится по .avlt).
func RemoveOrphanVaultLabels(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var firstErr error
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(n), ".avlt.label") {
			continue
		}
		vault := filepath.Join(dir, n[:len(n)-len(".label")])
		if _, err := os.Stat(vault); errors.Is(err, fs.ErrNotExist) {
			if rerr := os.Remove(filepath.Join(dir, n)); rerr != nil && firstErr == nil {
				firstErr = rerr
			}
		}
	}
	return firstErr
}

// VaultName — подпись для списка сохранённых серверов. Неизвестная подпись —
// «Сервер N» (N — позиция в списке), с пометкой, если подпись повреждена
// или не от этого файла. Одинаковые имена различаются адресом
// («AEZA test — 1.2.3.4»), а если и адрес совпал или неизвестен — номером.
// Short обрезается многоточием до VaultLabelMaxRunes, но обрезается только
// имя: различитель сохраняется. Full — полная подпись (заголовок диалога
// пин-кода).
type VaultName struct{ Short, Full string }

// VaultNames — см. VaultName.
func VaultNames(vaults []string) []VaultName {
	labels := make([]VaultLabel, len(vaults))
	states := make([]LabelState, len(vaults))
	for i, p := range vaults {
		labels[i], states[i], _ = ReadVaultLabel(p) // причина сбоя — в состоянии LabelBroken
	}
	return vaultNamesFrom(labels, states)
}

func vaultNamesFrom(labels []VaultLabel, states []LabelState) []VaultName {
	n := len(labels)
	base := make([]string, n)
	suffix := make([]string, n)
	count := map[string]int{}
	for i := range labels {
		if states[i] == LabelOK {
			count[labels[i].Name]++
		}
	}
	for i := range labels {
		switch states[i] {
		case LabelOK:
			base[i] = labels[i].Name
			if count[labels[i].Name] > 1 && labels[i].Addr != "" && labels[i].Addr != labels[i].Name {
				suffix[i] = " — " + labels[i].Addr
			}
		case LabelBroken:
			base[i] = fmt.Sprintf("Сервер %d", i+1)
			suffix[i] = " (" + LabelBrokenNote + ")"
		case LabelMismatch:
			base[i] = fmt.Sprintf("Сервер %d", i+1)
			suffix[i] = " (" + LabelMismatchNote + ")"
		default:
			base[i] = fmt.Sprintf("Сервер %d", i+1)
		}
	}
	// Второй круг: совпало и с адресом (или адреса нет) — номер.
	seen := map[string]int{}
	for i := range base {
		seen[base[i]+suffix[i]]++
	}
	for i := range base {
		if seen[base[i]+suffix[i]] > 1 {
			suffix[i] += fmt.Sprintf(" (%d)", i+1)
		}
	}
	out := make([]VaultName, n)
	for i := range base {
		budget := VaultLabelMaxRunes - utf8.RuneCountInString(suffix[i])
		if budget < 8 {
			budget = 8
		}
		out[i] = VaultName{Short: TruncateRunes(base[i], budget) + suffix[i], Full: base[i] + suffix[i]}
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
