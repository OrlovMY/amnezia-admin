package canary

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

var reStepLine = regexp.MustCompile(`(?m)^\[[^\]]+\] (\S+) `)

// TestProgramStepsMatchRegistry — сторож AU-LOGIC Р-4 раунд 2, High-1: прогон
// ПРОГРАММЫ канарейки (run целиком: флаги, SSH, все контейнеры, finish)
// против fakesrv с amnezia-awg и amnezia-xray. Множество ID в выводе обязано
// совпасть с реестром для этих контейнеров: каждый обязательный шаг есть,
// ни одной строки «шаг не исполнялся» и «вне реестра», ни одного ID вне
// реестра. Подсадки (проверены вручную, см. ОТЧЁТ-A3Б-Р4.md): убрать вызов
// finish из run; убрать вызов K9; добавить в реестр шаг без исполнения;
// вернуть строку с ID вне реестра — каждая роняет тест.
func TestProgramStepsMatchRegistry(t *testing.T) {
	if testing.Short() {
		t.Skip("прогон программы канарейки целиком")
	}
	tmp := t.TempDir()
	t.Setenv("TMP", tmp)
	t.Setenv("TEMP", tmp)
	t.Setenv("TMPDIR", tmp)

	fs := fakesrv.New()
	// пустой amnezia-awg (П0: клиентов нет ни в файлах, ни в работающем сервере)
	wg, _ := fs.File("/opt/amnezia/awg/wg0.conf")
	fs.SetFile("/opt/amnezia/awg/wg0.conf", []byte(string(wg)[:strings.Index(string(wg), "[Peer]")]))
	fs.DeleteFile("/opt/amnezia/awg/clientsTable")
	if _, err := fs.Run("docker exec amnezia-awg bash -c 'wg syncconf wg0 <(wg-quick strip /opt/amnezia/awg/wg0.conf)'", nil); err != nil {
		t.Fatal(err)
	}
	fs.Names = append(fs.Names, "amnezia-xray")

	const user, pw = "root", "canary-program-pw"
	hk, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := fakesrv.ListenSSH("127.0.0.1:0", user, pw, hk, fs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	host, port, _ := net.SplitHostPort(ln.Addr())
	raw, _ := json.Marshal(map[string]any{"hostName": host, "userName": user, "password": pw, "port": port})
	key := "vpn://" + base64.RawURLEncoding.EncodeToString(raw)

	cli := filepath.Join(tmp, "amnezia-admin")
	if runtime.GOOS == "windows" {
		cli += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", cli, "amnezia-admin/cmd/cli").CombinedOutput(); err != nil {
		t.Fatalf("сборка cmd/cli: %v\n%s", err, out)
	}

	var out, errOut bytes.Buffer
	env := map[string]string{"AMNEZIA_KEY": key}
	code := Main([]string{"-not-production", RequiredConfirmation, "-new", cli, "-hostkey", ln.Fingerprint(), "-rounds", "2"},
		func(k string) string { return env[k] }, strings.NewReader(""), &out, &errOut)
	o := out.String()
	if code == 0 {
		t.Errorf("итог 0 на fakesrv, который шагов записи не моделирует")
	}
	if !strings.Contains(o, "ИТОГ:") {
		t.Fatalf("в выводе нет ИТОГ (finish не исполнялся?):\n%s\nstderr:\n%s", o, errOut.String())
	}
	for _, bad := range []string{"шаг не исполнялся", "вне реестра"} {
		if strings.Contains(o, bad) {
			t.Errorf("в выводе «%s»:\n%s", bad, o)
		}
	}
	got := map[string]bool{}
	for _, m := range reStepLine.FindAllStringSubmatch(o, -1) {
		got[m[1]] = true
	}
	for id := range got {
		if !InRegistry(id) {
			t.Errorf("ID %s вне реестра", id)
		}
	}
	// ожидаемое для amnezia-awg (не awg2) и amnezia-xray: все обязательные
	// шаги WG и прогона, К8 одной строкой, К9.0–К9.2.
	var missing []string
	for _, s := range Steps {
		want := false
		switch s.Scope {
		case ScopeWG, ScopeRun:
			want = true
		case ScopeK8:
			want = s.ID == "К8"
		case ScopeK9:
			want = s.ID != "К9"
		}
		if want && !got[s.ID] {
			missing = append(missing, s.ID)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("в выводе нет шагов %v:\n%s", missing, o)
	}
	k9xray := regexp.MustCompile(`(?m)^\[[^\]]+\] К9\.0 \(amnezia-xray\)`)
	if !k9xray.MatchString(o) {
		t.Errorf("К9 на amnezia-xray не исполнялся:\n%s", o)
	}
	if t.Failed() || os.Getenv("CANARY_SHOW") != "" {
		fmt.Fprintln(os.Stderr, o)
	}
}
