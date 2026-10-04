package core

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"amnezia-admin/internal/fakesrv"
)

var backupNow = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

func backupSession(t *testing.T, srv *fakesrv.Server) *Session {
	t.Helper()
	t.Cleanup(SetXRayWaits(0, 0))
	return NewSessionWithRunner(srv, &ServerCreds{Host: "vpn.example.org", Port: "22", User: "root"})
}

func okResolver(string) ([]net.IP, error)  { return []net.IP{net.ParseIP("203.0.113.7")}, nil }
func badResolver(string) ([]net.IP, error) { return nil, errors.New("no such host") }

func ctrOf(t *testing.T, b *Backup, name string) BackupContainer {
	t.Helper()
	for _, c := range b.Containers {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("контейнера %s нет в копии", name)
	return BackupContainer{}
}

func fileOfB(c BackupContainer, name string) BackupFile {
	for _, f := range c.Files {
		if f.Name == name {
			return f
		}
	}
	return BackupFile{Name: name, Status: "НЕТ В КОПИИ"}
}

// TestBackupRoundTrip — снять с fakesrv → записать → прочитать: те же
// контейнеры, байты файлов совпадают с сервером.
func TestBackupRoundTrip(t *testing.T) {
	srv := fakesrv.New()
	s := backupSession(t, srv)
	b, err := s.CollectBackup("test", backupNow, okResolver)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Complete {
		t.Fatalf("копия неполная: %+v", b.Containers)
	}
	data, err := EncodeBackup(b, PlainLayer{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeBackup(data, PlainLayer{})
	if err != nil {
		t.Fatal(err)
	}
	c := ctrOf(t, got, "amnezia-awg")
	wg, _ := srv.File("/opt/amnezia/awg/wg0.conf")
	if f := fileOfB(c, "wg0.conf"); f.Status != FileSaved || !bytes.Equal(f.Data.Bytes(), wg) {
		t.Errorf("wg0.conf после круга: %s", f.Status)
	}
	if c.Port != "51820" || c.Subnet != "10.8.1.1/24" || c.Version != "старый AWG" || c.VersionState != VersionKnown {
		t.Errorf("порт/подсеть/версия: %q %q %q %q", c.Port, c.Subnet, c.Version, c.VersionState)
	}
	if got.IssuedAddress.Kind != AddressKindName || got.IssuedAddress.ResolveStatus != ResolveOK || got.IssuedAddress.ResolvedIP != "203.0.113.7" {
		t.Errorf("адрес выдачи: %+v", got.IssuedAddress)
	}
}

// TestBackupFileStates — три состояния файла: нет на сервере (копия полная)
// ≠ не удалось прочитать (копия неполная). Тест различения и доезда:
// «не прочитан» возникает боевым путём — fakesrv отказывает в чтении.
func TestBackupFileStates(t *testing.T) {
	t.Run("clientsTable нет — absent, копия полная", func(t *testing.T) {
		srv := fakesrv.New()
		srv.DeleteFile("/opt/amnezia/awg/clientsTable")
		b, _ := backupSession(t, srv).CollectBackup("t", backupNow, okResolver)
		c := ctrOf(t, b, "amnezia-awg")
		if f := fileOfB(c, "clientsTable"); f.Status != FileAbsent {
			t.Errorf("clientsTable: %s, ждали absent", f.Status)
		}
		if c.Status != CtrSaved || !b.Complete {
			t.Errorf("контейнер %s, полная=%v — ждали сохранено и полная", c.Status, b.Complete)
		}
	})
	t.Run("clientsTable не читается — unreadable, копия неполная", func(t *testing.T) {
		srv := fakesrv.New()
		srv.FailRead = map[string]error{"/opt/amnezia/awg/clientsTable": errors.New("cat: Permission denied")}
		b, _ := backupSession(t, srv).CollectBackup("t", backupNow, okResolver)
		c := ctrOf(t, b, "amnezia-awg")
		if f := fileOfB(c, "clientsTable"); f.Status != FileUnreadable {
			t.Errorf("clientsTable: %s, ждали unreadable", f.Status)
		}
		if c.Status != CtrUnreadable || b.Complete {
			t.Errorf("контейнер %s, полная=%v — ждали не прочитан и неполная", c.Status, b.Complete)
		}
	})
	t.Run("фраза «No such file» о другом пути — unreadable", func(t *testing.T) {
		srv := fakesrv.New()
		srv.FailRead = map[string]error{"/opt/amnezia/awg/clientsTable": errors.New("stderr: sh: /etc/x: No such file or directory")}
		b, _ := backupSession(t, srv).CollectBackup("t", backupNow, okResolver)
		if f := fileOfB(ctrOf(t, b, "amnezia-awg"), "clientsTable"); f.Status != FileUnreadable {
			t.Errorf("clientsTable: %s, ждали unreadable", f.Status)
		}
	})
	t.Run("ключевых файлов нет — absent", func(t *testing.T) {
		srv := fakesrv.New()
		b, _ := backupSession(t, srv).CollectBackup("t", backupNow, okResolver)
		c := ctrOf(t, b, "amnezia-awg")
		for _, n := range []string{"wireguard_server_public_key.key", "wireguard_psk.key"} {
			if f := fileOfB(c, n); f.Status != FileAbsent {
				t.Errorf("%s: %s", n, f.Status)
			}
		}
	})
	t.Run("ключевой файл есть — сохранён", func(t *testing.T) {
		srv := fakesrv.New()
		srv.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("PSK-SERVER\n"))
		b, _ := backupSession(t, srv).CollectBackup("t", backupNow, okResolver)
		if f := fileOfB(ctrOf(t, b, "amnezia-awg"), "wireguard_psk.key"); f.Status != FileSaved || string(f.Data.Bytes()) != "PSK-SERVER\n" {
			t.Errorf("wireguard_psk.key: %s", f.Status)
		}
	})
	t.Run("файла конфигурации нет — контейнер не прочитан", func(t *testing.T) {
		srv := fakesrv.New()
		srv.DeleteFile("/opt/amnezia/awg/wg0.conf")
		b, _ := backupSession(t, srv).CollectBackup("t", backupNow, okResolver)
		if c := ctrOf(t, b, "amnezia-awg"); c.Status != CtrUnreadable || b.Complete {
			t.Errorf("контейнер %s, полная=%v", c.Status, b.Complete)
		}
	})
}

// mutatingRunner — между чтениями wg0.conf меняет его (чужая запись).
type mutatingRunner struct {
	*fakesrv.Server
	n     int
	limit int
}

func (m *mutatingRunner) Run(cmd string, stdin []byte) (string, error) {
	out, err := m.Server.Run(cmd, stdin)
	if strings.HasSuffix(cmd, "cat /opt/amnezia/awg/wg0.conf") && (m.limit == 0 || m.n < m.limit) {
		m.n++
		old, _ := m.Server.File("/opt/amnezia/awg/wg0.conf")
		m.Server.SetFile("/opt/amnezia/awg/wg0.conf", append(old, []byte(fmt.Sprintf("# %d\n", m.n))...))
	}
	return out, err
}

// TestBackupInconsistent — файл меняется между чтениями все попытки →
// «несогласованный снимок», копия неполная; успокоился — сохранено.
func TestBackupInconsistent(t *testing.T) {
	m := &mutatingRunner{Server: fakesrv.New()}
	s := NewSessionWithRunner(m, &ServerCreds{Host: "203.0.113.1"})
	b, _ := s.CollectBackup("t", backupNow, nil)
	if c := ctrOf(t, b, "amnezia-awg"); c.Status != CtrInconsistent || b.Complete {
		t.Errorf("ждали несогласованный снимок: %s полная=%v", c.Status, b.Complete)
	}
	m2 := &mutatingRunner{Server: fakesrv.New(), limit: 2}
	b, _ = NewSessionWithRunner(m2, &ServerCreds{Host: "203.0.113.1"}).CollectBackup("t", backupNow, nil)
	if c := ctrOf(t, b, "amnezia-awg"); c.Status != CtrSaved {
		t.Errorf("после двух чужих записей снимок не получен: %s", c.Status)
	}
}

// TestBackupNotIncluded — неподдерживаемый протокол перечислен «не входит»,
// полноты не отменяет.
func TestBackupNotIncluded(t *testing.T) {
	srv := fakesrv.New()
	srv.Names = append(srv.Names, "amnezia-openvpn")
	b, _ := backupSession(t, srv).CollectBackup("t", backupNow, okResolver)
	if c := ctrOf(t, b, "amnezia-openvpn"); c.Status != CtrNotIncluded {
		t.Errorf("openvpn: %s", c.Status)
	}
	if !b.Complete {
		t.Error("«не входит» сделало копию неполной")
	}
}

// TestBackupXRayAndAWG2 — XRay: шесть файлов, версия «XRay», порт; awg2 —
// версия параметров; awg2 без признаков версии — «не определена».
func TestBackupXRayAndAWG2(t *testing.T) {
	x := fakesrv.NewXRay("master")
	b, _ := backupSession(t, x).CollectBackup("t", backupNow, okResolver)
	c := ctrOf(t, b, XRayContainer)
	if c.Status != CtrSaved || c.Version != "XRay" || c.Port != "443" || len(c.Files) != 6 {
		t.Errorf("xray: %s %q %q файлов %d", c.Status, c.Version, c.Port, len(c.Files))
	}
	if f := fileOfB(c, "xray_uuid.key"); f.Status != FileSaved {
		t.Errorf("xray_uuid.key: %s", f.Status)
	}
	a := fakesrv.NewAWG2()
	b, _ = backupSession(t, a).CollectBackup("t", backupNow, okResolver)
	c = ctrOf(t, b, "amnezia-awg2")
	if c.Status != CtrSaved || c.VersionState != VersionKnown || c.Version == "" {
		t.Errorf("awg2: %s %q %q", c.Status, c.Version, c.VersionState)
	}
	conf, _ := a.File("/opt/amnezia/awg/awg0.conf")
	plain := []string{}
	for _, l := range strings.Split(string(conf), "\n") {
		k := strings.TrimSpace(strings.SplitN(l, "=", 2)[0])
		switch k {
		case "S3", "S4", "H1", "H2", "H3", "H4", "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
			"RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies":
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(l), "# I") {
			continue
		}
		plain = append(plain, l)
	}
	a.SetFile("/opt/amnezia/awg/awg0.conf", []byte(strings.Join(plain, "\n")))
	b, _ = backupSession(t, a).CollectBackup("t", backupNow, okResolver)
	if c := ctrOf(t, b, "amnezia-awg2"); c.VersionState != VersionUnknown || c.Version != "" {
		t.Errorf("awg2 без признаков: %q %q — ждали «не определена»", c.Version, c.VersionState)
	}
}

// TestIssuedAddress — IP / имя разрешилось / имя не разрешилось: третье —
// «не удалось», а не пустой IP. Тест доезда — через CollectBackup с
// подставным резолвером.
func TestIssuedAddress(t *testing.T) {
	if a := issuedAddress("198.51.100.4", badResolver); a.Kind != AddressKindIP || a.ResolveStatus != ResolveNotNeeded {
		t.Errorf("IP: %+v", a)
	}
	if a := issuedAddress("vpn.example.org", okResolver); a.ResolveStatus != ResolveOK || a.ResolvedIP == "" {
		t.Errorf("имя: %+v", a)
	}
	b, _ := backupSession(t, fakesrv.New()).CollectBackup("t", backupNow, badResolver)
	if a := b.IssuedAddress; a.Kind != AddressKindName || a.ResolveStatus != ResolveFailed || a.ResolvedIP != "" {
		t.Errorf("имя не разрешилось: %+v — ждали resolve_status=failed", a)
	}
}

// TestBackupSecretsNotPrinted — канарейка: ни один глагол fmt и ни один
// текст ошибки не выдаёт приватный ключ сервера из копии.
func TestBackupSecretsNotPrinted(t *testing.T) {
	srv := fakesrv.New()
	wg, _ := srv.File("/opt/amnezia/awg/wg0.conf")
	priv := parseWgConf(string(wg)).iface["PrivateKey"]
	if len(priv) < 20 {
		t.Fatalf("тест ничего не значит: ключ %q", priv)
	}
	b, _ := backupSession(t, srv).CollectBackup("t", backupNow, okResolver)
	c := ctrOf(t, b, "amnezia-awg")
	f := fileOfB(c, "wg0.conf")
	for _, v := range []string{fmt.Sprint(b), fmt.Sprintf("%v", b), fmt.Sprintf("%+v", b), fmt.Sprintf("%#v", b),
		fmt.Sprintf("%v", c), fmt.Sprintf("%+v", f), fmt.Sprintf("%s", f.Data), fmt.Sprintf("%q", f.Data), fmt.Sprintf("%x", f.Data)} {
		if strings.Contains(v, priv) || strings.Contains(v, "[Interface]") {
			t.Fatalf("секрет в выводе fmt: %.120s", v)
		}
	}
	// повреждённая копия: текст отказа не несёт содержимого
	data, _ := EncodeBackup(b, PlainLayer{})
	data[len(data)-5] ^= 1
	_, err := DecodeBackup(data, PlainLayer{})
	if err == nil || strings.Contains(err.Error(), priv) {
		t.Fatalf("отказ: %v", err)
	}
}

// TestBackupDecodeRefusals — всё или ничего: каждый дефект — отказ
// ErrBackupNotRead, частичного результата нет.
func TestBackupDecodeRefusals(t *testing.T) {
	b, _ := backupSession(t, fakesrv.New()).CollectBackup("t", backupNow, okResolver)
	good, _ := EncodeBackup(b, PlainLayer{})
	if _, err := DecodeBackup(good, PlainLayer{}); err != nil {
		t.Fatalf("исправная копия не прочитана: %v", err)
	}
	mut := func(f func([]byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	headerEnd := bytes.Index(good, []byte("\n\n")) + 2
	cases := []struct {
		name, want string
		data       []byte
		layers     []BackupLayer
	}{
		{"не копия", "не файл копии", []byte("hello\nworld\nx\n\n{}"), nil},
		{"обрезан", "обрезан", good[:10], nil},
		{"новее", "более новой версией", mut(func(d []byte) []byte { return bytes.Replace(d, []byte("AABK 1\n"), []byte("AABK 2\n"), 1) }), nil},
		{"слой не известен", "не известен", mut(func(d []byte) []byte { return bytes.Replace(d, []byte("layer none"), []byte("layer pass"), 1) }), nil},
		{"байт тела", "повреждён", mut(func(d []byte) []byte { d[headerEnd+3] ^= 1; return d }), nil},
		{"сумма в заголовке", "повреждён", mut(func(d []byte) []byte { i := bytes.Index(d, []byte("sha256 ")) + 8; d[i] ^= 1; return d }), nil},
		{"заголовок", "заголовок", mut(func(d []byte) []byte { return bytes.Replace(d, []byte("layer none"), []byte("layerXnone"), 1) }), nil},
	}
	for _, c := range cases {
		layers := c.layers
		if layers == nil {
			layers = []BackupLayer{PlainLayer{}}
		}
		got, err := DecodeBackup(c.data, layers...)
		if !errors.Is(err, ErrBackupNotRead) || got != nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (результат %v)", c.name, err, got != nil)
		}
	}
	// повреждённый файл внутри при верной внешней сумме (пересобранный)
	b.Containers[0].Files[0].SHA256 = strings.Repeat("0", 64)
	bad, _ := EncodeBackup(b, PlainLayer{})
	if _, err := DecodeBackup(bad, PlainLayer{}); !errors.Is(err, ErrBackupNotRead) || !strings.Contains(err.Error(), "внутри копии повреждён") {
		t.Errorf("сумма файла внутри: %v", err)
	}
}

// TestBackupGolden — золотой файл формата 1 читается (будущие версии
// обязаны его читать). Обновление: AMNEZIA_BACKUP_GOLDEN=1.
func TestBackupGolden(t *testing.T) {
	p := filepath.Join("testdata", "v1.aabk")
	if os.Getenv("AMNEZIA_BACKUP_GOLDEN") == "1" {
		srv := fakesrv.New()
		srv.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("golden-test-psk\n"))
		b, err := NewSessionWithRunner(srv, &ServerCreds{Host: "golden.example.test"}).CollectBackup("golden", backupNow, okResolver)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := EncodeBackup(b, PlainLayer{})
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	b, err := ReadBackupFile(p, PlainLayer{})
	if err != nil {
		t.Fatalf("золотой файл формата 1 не прочитан: %v", err)
	}
	if b.FormatVersion != 1 || b.Server.Host != "golden.example.test" || b.IssuedAddress.ResolveStatus != ResolveOK {
		t.Errorf("золотой файл: %+v", b.Server)
	}
	c := ctrOf(t, b, "amnezia-awg")
	if f := fileOfB(c, "wireguard_psk.key"); string(f.Data.Bytes()) != "golden-test-psk\n" {
		t.Errorf("wireguard_psk.key в золотом файле: %s", f.Status)
	}
}

// TestWriteBackupFile — 0600, не перезаписывает существующий.
func TestWriteBackupFile(t *testing.T) {
	b, _ := backupSession(t, fakesrv.New()).CollectBackup("t", backupNow, okResolver)
	p := filepath.Join(t.TempDir(), "x.aabk")
	if err := WriteBackupFile(p, b, PlainLayer{}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Errorf("права: %v %v", fi.Mode(), err)
	}
	if err := WriteBackupFile(p, b, PlainLayer{}); err == nil {
		t.Error("существующая копия перезаписана")
	}
	if got, err := ReadBackupFile(p, PlainLayer{}); err != nil || len(got.Containers) == 0 {
		t.Errorf("записанная копия не прочитана: %v", err)
	}
}
