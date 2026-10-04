package canary

// К9 — Р-4 (перенос сервера): запись с ключами под замком A3б на живом
// контейнере (amnezia-xray — ключи XRay; семейство WG — открытый ключ
// сервера и PSK). Канарейка пишет ТЕ ЖЕ байты, что прочитала (server.json не
// переписывается — XRay не перезапускается), и проверяет: команда с
// дополнительными файлами исполняется в настоящем контейнере, сверка
// дополнительного файла останавливает запись, права после записи 0600,
// временных файлов не остаётся. Содержимое ключей не печатается.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"amnezia-admin/core"
)

// XRayFamily — имя контейнера для -skip-family (К9).
const XRayFamily = core.XRayContainer

// K9Target — контейнер К9: каталог, файл конфигурации и ключи из
// закрытого списка дополнительных файлов записи.
type K9Target struct {
	Container, Dir, Conf string
	Keys                 []string
}

// K9XRayTarget — amnezia-xray (Р-4).
var K9XRayTarget = K9Target{core.XRayContainer, "/opt/amnezia/xray", "server.json",
	[]string{"xray_uuid.key", "xray_short_id.key", "xray_public.key", "xray_private.key"}}

// K9WGTarget — контейнер семейства WG: открытый ключ сервера и общий PSK,
// которые приложение Amnezia читает при каждой выдаче клиента.
func K9WGTarget(f core.WGFamily) K9Target {
	return K9Target{f.Container, f.Dir, f.File, []string{"wireguard_server_public_key.key", "wireguard_psk.key"}}
}

type k9File struct {
	data   []byte
	exists bool
}

func k9Sum(f k9File) string {
	if !f.exists {
		return core.CASAbsent
	}
	s := sha256.Sum256(f.data)
	return hex.EncodeToString(s[:])
}

// K9 — строки К9 для контейнера tg. present — контейнер найден; skip —
// пропущен флагом.
func K9(remote func(string) (string, error), remoteIn func(string, []byte) (string, error), tg K9Target, present, skip bool) []Result {
	row := func(id, name string) Result { return Result{ID: id, Name: tg.Container + ": " + name} }
	k9Dir, k9Keys := tg.Dir, tg.Keys
	if skip {
		return nil
	}
	if !present {
		r := row("К9", "запись с ключами под замком")
		r.Detail = "контейнера на сервере нет — живой проверки нет; установите его на тестовом сервере или пропустите осознанно: -skip-family " + tg.Container
		return []Result{r}
	}
	if remoteIn == nil {
		r := row("К9", "запись с ключами под замком")
		r.Detail = "нет команды со stdin — запись не выполнялась"
		return []Result{r}
	}
	docker := "docker"
	dk := func(cmd string) (string, error) {
		out, err := remote(docker + " exec " + tg.Container + " sh -c '" + cmd + "'")
		if err != nil && docker == "docker" && strings.Contains(strings.ToLower(out+err.Error()), "permission denied") {
			docker = "sudo -n docker"
			out, err = remote(docker + " exec " + tg.Container + " sh -c '" + cmd + "'")
		}
		return out, err
	}
	read := func() (map[string]k9File, error) {
		out := map[string]k9File{}
		for _, n := range append([]string{tg.Conf, "clientsTable"}, k9Keys...) {
			o, err := dk("cd " + k9Dir + " && if [ -e " + n + " ]; then echo Y; base64 " + n + " | tr -d \"\\n\"; echo; else echo N; fi")
			if err != nil {
				return nil, fmt.Errorf("%s не прочитан: %v", n, err)
			}
			ls := strings.Split(strings.TrimSpace(strings.ReplaceAll(o, "\r", "")), "\n")
			switch {
			case len(ls) >= 1 && ls[0] == "N":
				out[n] = k9File{}
			case len(ls) == 2 && ls[0] == "Y":
				b, err := base64.StdEncoding.DecodeString(ls[1])
				if err != nil {
					return nil, fmt.Errorf("%s: ответ не разобран", n)
				}
				out[n] = k9File{data: b, exists: true}
			case len(ls) == 1 && ls[0] == "Y":
				out[n] = k9File{data: []byte{}, exists: true}
			default:
				return nil, fmt.Errorf("%s: ответ не разобран", n)
			}
		}
		return out, nil
	}
	same := func(a, b map[string]k9File) string {
		for n, f := range a {
			if k9Sum(f) != k9Sum(b[n]) {
				return n
			}
		}
		return ""
	}
	write := func(fs map[string]k9File, extras []core.CASExtra) (int, string, error) {
		var data [][]byte
		for _, x := range extras {
			f := fs[x.Name]
			if f.exists {
				data = append(data, f.data)
			} else {
				data = append(data, nil)
			}
		}
		stdin := core.CASWriteStdin(nil, fs["clientsTable"].data, data...)
		build := core.CASWriteCommand
		if docker != "docker" {
			build = core.CASWriteCommandSudo
		}
		cmd, err := build(core.CASLabelApply, tg.Container, k9Dir, tg.Conf, k9Sum(fs[tg.Conf]), k9Sum(fs["clientsTable"]), extras...)
		if err != nil {
			return 0, "", err
		}
		out, err := remoteIn(cmd, stdin)
		if err == nil {
			return 0, out, nil
		}
		var es interface{ ExitStatus() int }
		if errors.As(err, &es) {
			return es.ExitStatus(), out, nil
		}
		return -1, out, err
	}

	skipped := func(id, name string) Result {
		r := row(id, name)
		r.Detail = "не выполнялся: К9.0 не пройден — запись не начиналась"
		return r
	}
	r0 := row("К9.0", "файлы прочитаны")
	before, err := read()
	if err != nil {
		r0.Detail = err.Error()
		return []Result{r0, skipped("К9.1", "запись с ключами"), skipped("К9.2", "сверка ключа останавливает запись")}
	}
	if !before[tg.Conf].exists || !before["clientsTable"].exists {
		r0.Detail = "нет " + tg.Conf + " или clientsTable — протокол установлен не полностью"
		return []Result{r0, skipped("К9.1", "запись с ключами"), skipped("К9.2", "сверка ключа останавливает запись")}
	}
	var present9 []string
	var extras []core.CASExtra
	for _, k := range k9Keys {
		extras = append(extras, core.CASExtra{Name: k, Want: k9Sum(before[k])})
		if before[k].exists {
			present9 = append(present9, k)
		}
	}
	r0.Status, r0.Detail = Pass, "ключи на сервере: "+strings.Join(present9, ", ")
	rs := []Result{r0}

	// К9.1 — запись тех же байтов всеми шестью путями.
	r1 := row("К9.1", "запись с ключами (те же байты): файлы заменены (новый inode), права 0600, без временных файлов")
	// AU Medium-2: те же байты не отличают «заменили» от «не трогали» —
	// замену доказывает новый inode каждого записанного файла.
	written := append([]string{"clientsTable"}, present9...)
	inodes := func() ([]string, error) {
		o, err := dk("cd " + k9Dir + " && stat -c %i " + strings.Join(written, " "))
		if err != nil {
			return nil, err
		}
		f := strings.Fields(o)
		if len(f) != len(written) {
			return nil, fmt.Errorf("ответ stat не разобран: %s", oneLine(o))
		}
		return f, nil
	}
	ino0, ierr := inodes()
	if ierr != nil {
		r1.Detail = "inode до записи не прочитаны: " + ierr.Error() + " — запись не выполнялась"
		rs = append(rs, r1)
		r2 := row("К9.2", "устаревшая сумма ключа — «изменился», ничего не записано")
		r2.Detail = "не выполнялся: К9.1 не дошёл до записи"
		return append(rs, r2)
	}
	code, out, err := write(before, extras)
	switch {
	case err != nil:
		r1.Detail = "команда не выполнилась: " + err.Error()
	case code != 0:
		r1.Status, r1.Detail = Fail, fmt.Sprintf("код %d: %s", code, oneLine(out))
	default:
		after, err := read()
		if err != nil {
			r1.Detail = "после записи: " + err.Error()
			break
		}
		if n := same(before, after); n != "" {
			r1.Status, r1.Detail = Fail, n+" после записи тех же байтов изменился"
			break
		}
		ino1, err := inodes()
		if err != nil {
			r1.Detail = "inode после записи не прочитаны: " + err.Error()
			break
		}
		var kept []string
		for i, n := range written {
			if ino0[i] == ino1[i] {
				kept = append(kept, n)
			}
		}
		if len(kept) > 0 {
			r1.Status, r1.Detail = Fail, "код 0, но inode не изменился (файл не заменён): "+strings.Join(kept, ", ")
			break
		}
		perm, err := dk("cd " + k9Dir + " && stat -c %a clientsTable " + strings.Join(present9, " ") + "; ls -a | grep -c \"\\.aa\\.\" || true")
		if err != nil {
			r1.Detail = "права не прочитаны: " + err.Error()
			break
		}
		ls := strings.Fields(perm)
		if len(ls) != len(present9)+2 {
			r1.Detail = "ответ stat не разобран: " + oneLine(perm)
			break
		}
		for _, p := range ls[:len(ls)-1] {
			if p != "600" {
				r1.Status, r1.Detail = Fail, "права после записи "+strings.Join(ls[:len(ls)-1], " ")+", ждали 600"
			}
		}
		if r1.Status == Fail {
			break
		}
		if ls[len(ls)-1] != "0" {
			r1.Status, r1.Detail = Fail, "остались временные файлы *.aa.*: "+ls[len(ls)-1]
			break
		}
		r1.Status, r1.Detail = Pass, fmt.Sprintf("код 0; inode всех записанных файлов новые; суммы прежние; права 600 у clientsTable и %d ключей; временных нет", len(present9))
	}
	rs = append(rs, r1)

	// К9.2 — устаревшая сумма ключа: код 3, имя ключа, ничего не записано.
	r2 := row("К9.2", "устаревшая сумма ключа — «изменился», ничего не записано")
	bad := append([]core.CASExtra(nil), extras...)
	victim := -1
	for i, x := range bad {
		if x.Want != core.CASAbsent {
			victim = i
		}
	}
	if victim < 0 {
		r2.Detail = "на сервере нет ни одного ключа — сверять нечего"
		return append(rs, r2)
	}
	bad[victim].Want = strings.Repeat("0", 64)
	changed := map[string]k9File{}
	for n, f := range before {
		changed[n] = f
	}
	vf := changed[bad[victim].Name]
	vf.data = append(bytes.Clone(vf.data), []byte("canary-k9")...)
	changed[bad[victim].Name] = vf
	code, out, err = write(changed, bad)
	switch {
	case err != nil:
		r2.Detail = "команда не выполнилась: " + err.Error()
	case code != 3 || !strings.Contains(out, "changed: "+bad[victim].Name):
		r2.Status, r2.Detail = Fail, fmt.Sprintf("код %d (ждали 3 и «changed: %s»): %s", code, bad[victim].Name, oneLine(out))
	default:
		after, err := read()
		if err != nil {
			r2.Detail = "после отказа: " + err.Error()
		} else if n := same(before, after); n != "" {
			r2.Status, r2.Detail = Fail, n+" изменился, хотя запись отказала"
		} else {
			r2.Status, r2.Detail = Pass, "код 3, «changed: "+bad[victim].Name+"», файлы прежние"
		}
	}
	return append(rs, r2)
}
