package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Поддельный сервер сноса: контейнеры (с портами), тома, образы; журнал.

type tdFake struct {
	mu                   sync.Mutex
	ctrs, vols, imgs     map[string]string // имя → порты (у томов/образов "")
	failInventory        bool              // docker ps -a с портами не отвечает
	failMeasure          bool              // после сноса списки не отвечают
	keep                 string            // это имя docker rm не удаляет
	stopped              map[string]bool   // остановленные контейнеры
	rmCalls              []string
	all                  []string
	rmStarted, collected bool
}

func newTDFake() *tdFake {
	return &tdFake{
		ctrs: map[string]string{"amnezia-awg2": "0.0.0.0:51820->51820/udp", "amnezia-xray": "0.0.0.0:443->443/tcp"},
		vols: map[string]string{"amnezia-xray-data": "", "other-vol": ""},
		imgs: map[string]string{"amnezia-awg2": "", "amnezia-xray": "", "nginx": ""},
	}
}

var reTDRm = regexp.MustCompile(`docker (rm -f|volume rm|rmi) (\S+?);`)

func (f *tdFake) names(m map[string]string) string {
	var out []string
	for n := range m {
		out = append(out, n)
	}
	sort.Strings(out)
	return strings.Join(out, "\n") + "\n"
}

func (f *tdFake) Run(cmd string, _ []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.all = append(f.all, cmd)
	if m := reTDRm.FindStringSubmatch(cmd); m != nil {
		f.rmStarted = true
		f.rmCalls = append(f.rmCalls, m[1]+" "+m[2])
		if m[2] != f.keep {
			delete(map[string]map[string]string{"rm -f": f.ctrs, "volume rm": f.vols, "rmi": f.imgs}[m[1]], m[2])
		}
		return instOK(""), nil
	}
	measureDown := f.failMeasure && f.rmStarted
	switch {
	case strings.Contains(cmd, "{{.Names}}|{{.State}}|{{.Ports}}"):
		if f.failInventory {
			return "", errors.New("связь оборвалась")
		}
		var lines []string
		for n, p := range f.ctrs {
			st := "running"
			if f.stopped[n] {
				st = "exited"
			}
			lines = append(lines, n+"|"+st+"|"+p)
		}
		lines = append(lines, "web|running|0.0.0.0:80->80/tcp")
		sort.Strings(lines)
		return instOK(strings.Join(lines, "\n") + "\n"), nil
	case strings.Contains(cmd, "docker ps -a"):
		if measureDown {
			return "", errors.New("связь оборвалась")
		}
		return instOK(f.names(f.ctrs)), nil
	case strings.Contains(cmd, "docker volume ls"):
		if measureDown {
			return "", errors.New("связь оборвалась")
		}
		return instOK(f.names(f.vols)), nil
	case strings.Contains(cmd, "docker images"):
		if measureDown {
			return "", errors.New("связь оборвалась")
		}
		return instOK(f.names(f.imgs)), nil
	}
	// всё прочее (в т.ч. docker ps настоящего CollectBackupCtx) — отказ
	return "", errors.New("нет ответа")
}

func tdSess(f *tdFake) *Session {
	return NewSessionWithRunner(f, &ServerCreds{Host: "203.0.113.9"})
}

// tdCopy — копия цели: awg2 сохранён с двумя клиентами, xray — как задано.
func tdCopy(xrayStatus string) *Backup {
	tbl := `[{"clientId":"k1","userData":{"clientName":"Иван"}},{"clientId":"k2","userData":{"clientName":"Мария"}}]`
	b := &Backup{FormatVersion: BackupFormat, Complete: true, CreatedAt: "2026-11-09T00:00:00Z", Containers: []BackupContainer{
		{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg", Status: CtrSaved, Version: "2", VersionState: VersionKnown, Files: []BackupFile{
			{Name: "awg0.conf", Status: FileSaved, Data: NewSecret([]byte(awg2Conf))},
			{Name: "clientsTable", Status: FileSaved, Data: NewSecret([]byte(tbl))},
			{Name: "wireguard_server_public_key.key", Status: FileSaved, Data: NewSecret([]byte("PUB"))},
			{Name: "wireguard_psk.key", Status: FileSaved, Data: NewSecret([]byte("PSK"))}}},
	}}
	xc := BackupContainer{Name: "amnezia-xray", Dir: "/opt/amnezia/xray", Status: xrayStatus}
	if xrayStatus == CtrSaved {
		xc.Version, xc.VersionState = "XRay", VersionKnown
		xc.Files = []BackupFile{{Name: xrayConfFile, Status: FileSaved, Data: NewSecret([]byte(xraySrcJSON("443")))},
			{Name: "clientsTable", Status: FileAbsent},
			{Name: "xray_uuid.key", Status: FileSaved, Data: NewSecret([]byte(fkUUID))},
			{Name: "xray_short_id.key", Status: FileSaved, Data: NewSecret([]byte(fkShort))},
			{Name: "xray_public.key", Status: FileSaved, Data: NewSecret([]byte("pub"))},
			{Name: "xray_private.key", Status: FileSaved, Data: NewSecret([]byte(fkPriv))}}
	} else {
		xc.Reason = "нет доступа"
		for _, n := range []string{xrayConfFile, "clientsTable", "xray_uuid.key", "xray_short_id.key", "xray_public.key", "xray_private.key"} {
			xc.Files = append(xc.Files, BackupFile{Name: n, Status: FileUnreadable, Reason: "нет доступа"})
		}
		b.Complete = false
	}
	b.Containers = append(b.Containers, xc)
	for i := range b.Containers {
		for j := range b.Containers[i].Files {
			f := &b.Containers[i].Files[j]
			if f.Status == FileSaved {
				sum := sha256.Sum256(f.Data.Bytes())
				f.SHA256, f.Size = hex.EncodeToString(sum[:]), f.Data.Len()
			}
		}
	}
	return b
}

func withTDCollect(t *testing.T, b *Backup, err error) {
	t.Helper()
	old := teardownCollect
	teardownCollect = func(context.Context, *Session, string, time.Time, Resolver, ProgressFunc) (*Backup, error) {
		return b, err
	}
	t.Cleanup(func() { teardownCollect = old })
}

func withTDMarker(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "marker.json")
	old := OpMarkerPath
	OpMarkerPath = func() (string, error) { return p, nil }
	t.Cleanup(func() { OpMarkerPath = old })
	return p
}

func TestTeardownAllowedClosedList(t *testing.T) {
	for _, c := range []struct {
		kind, name string
		want       bool
	}{
		{"container", "amnezia-awg", true}, {"container", "amnezia-awg2", true}, {"container", "amnezia-wireguard", true},
		{"container", "amnezia-xray", true}, {"image", "amnezia-xray", true}, {"volume", "amnezia-xray-data", true},
		{"container", "amnezia-foo", false}, {"container", "web", false}, {"volume", "amnezia-awg2", false},
		{"volume", "other-vol", false}, {"image", "nginx", false}, {"container", "amnezia-xray-data", false},
	} {
		if got := TeardownAllowed(c.kind, c.name); got != c.want {
			t.Errorf("TeardownAllowed(%s, %s) = %v, want %v", c.kind, c.name, got, c.want)
		}
	}
}

// Различение: клиенты «нет» (прочитано) ≠ «не удалось прочитать».
func TestTeardownClientsThreeStates(t *testing.T) {
	for _, c := range []struct {
		name      string
		b         *Backup
		copyWhy   string
		ctr       string
		known     bool
		lineHas   string
		lineHasnt string
	}{
		{"прочитаны двое", tdCopy(CtrSaved), "", "amnezia-awg2", true, "клиенты (2): Иван, Мария", "не удалось"},
		{"clientsTable нет — измеренное «нет»", tdCopy(CtrSaved), "", "amnezia-xray", true, "клиенты: нет (файла clientsTable на сервере нет)", "не удалось"},
		{"контейнер не прочитан", tdCopy(CtrUnreadable), "", "amnezia-xray", false, "клиенты: не удалось прочитать", "клиенты: нет"},
		{"копии нет вовсе", nil, "копия не снята: docker ps", "amnezia-awg2", false, "клиенты: не удалось прочитать (копия не снята", "клиенты: нет"},
	} {
		t.Run(c.name, func(t *testing.T) {
			tc := targetClientsOf(c.b, c.ctr, c.copyWhy)
			if tc.Known != c.known {
				t.Fatalf("Known = %v, want %v (%+v)", tc.Known, c.known, tc)
			}
			p := &TeardownPlan{Inv: &TargetInventory{Containers: []string{c.ctr}, PortsKnown: true, Ports: map[string]string{}, Clients: []TargetClients{tc}}, Copy: c.b, CopyWhy: c.copyWhy}
			text := strings.Join(p.InventoryLines(), "\n")
			if !strings.Contains(text, c.lineHas) {
				t.Errorf("нет %q в\n%s", c.lineHas, text)
			}
			if strings.Contains(text, c.lineHasnt) {
				t.Errorf("лишнее %q в\n%s", c.lineHasnt, text)
			}
		})
	}
}

// Доезд: настоящий CollectBackupCtx на цели, где docker ps не отвечает, —
// клиенты «не удалось прочитать», копии нет, снос — только с отдельным «да».
func TestTeardownPlanRealCollectFailureReachesUnknown(t *testing.T) {
	f := newTDFake()
	p, err := tdSess(f).PlanTeardown(context.Background(), "t", time.Now(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Copy != nil || p.CopyState() != CopyNone || !p.NeedsNoCopyConfirm() {
		t.Fatalf("копия: %v, %v", p.Copy, p.CopyState())
	}
	text := strings.Join(p.InventoryLines(), "\n")
	for _, want := range []string{"контейнер amnezia-awg2 — протокол AmneziaWG; порты: 0.0.0.0:51820->51820/udp", "клиенты: не удалось прочитать", "Копии нового сервера НЕ БУДЕТ",
		"тома: amnezia-xray-data", "образы: amnezia-awg2, amnezia-xray"} {
		if !strings.Contains(text, want) {
			t.Errorf("нет %q в\n%s", want, text)
		}
	}
	for _, bad := range []string{"клиенты: нет", "web", "nginx", "other-vol"} {
		if strings.Contains(text, bad) {
			t.Errorf("лишнее %q в\n%s", bad, text)
		}
	}
}

func TestTeardownInventoryNotRead(t *testing.T) {
	f := newTDFake()
	f.failInventory = true
	_, err := tdSess(f).PlanTeardown(context.Background(), "t", time.Now(), nil, nil)
	if !errors.Is(err, ErrTargetNotRead) {
		t.Fatalf("err = %v, want ErrTargetNotRead", err)
	}
}

func TestTeardownForeignRefused(t *testing.T) {
	withTDMarker(t)
	f := newTDFake()
	f.ctrs["amnezia-mystery"] = ""
	withTDCollect(t, tdCopy(CtrSaved), nil)
	s := tdSess(f)
	p, err := s.PlanTeardown(context.Background(), "t", time.Now(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Refusal(), "amnezia-mystery") {
		t.Fatalf("Refusal = %q", p.Refusal())
	}
	r := s.ExecuteTeardown(p, TeardownOptions{Confirmed: true, NoCopyConfirmed: true, CopyDir: t.TempDir(), Layer: PlainLayer{}, Now: time.Now()})
	if r.State != TeardownRefused || len(f.rmCalls) != 0 {
		t.Fatalf("state %v, rm %v", r.State, f.rmCalls)
	}
}

func tdRun(t *testing.T, f *tdFake, b *Backup, opt TeardownOptions) (TeardownResult, *TeardownPlan) {
	t.Helper()
	withTDCollect(t, b, nil)
	s := tdSess(f)
	p, err := s.PlanTeardown(context.Background(), "t", time.Now(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if opt.CopyDir == "" {
		opt.CopyDir = t.TempDir()
	}
	if opt.Layer == nil {
		opt.Layer = PlainLayer{}
	}
	opt.Now = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)
	return s.ExecuteTeardown(p, opt), p
}

func TestTeardownExecute(t *testing.T) {
	type tcase struct {
		name    string
		prep    func(f *tdFake, opt *TeardownOptions)
		b       *Backup
		state   TeardownState
		rm      bool // команды сноса были
		copy    bool // файл копии остался на диске
		marker  bool // маркер остался
		whyHas  string
		hookBad bool
	}
	for _, c := range []tcase{
		{name: "полная копия, снос, измерено чисто", b: tdCopy(CtrSaved), state: TeardownDone, rm: true, copy: true},
		{name: "нет «да»", b: tdCopy(CtrSaved), prep: func(_ *tdFake, o *TeardownOptions) { o.Confirmed = false }, state: TeardownRefused, whyHas: "не подтверждён"},
		{name: "частичная копия без отдельного «да»", b: tdCopy(CtrUnreadable), state: TeardownRefused, whyHas: "отдельного подтверждения"},
		{name: "частичная копия с отдельным «да»", b: tdCopy(CtrUnreadable), prep: func(_ *tdFake, o *TeardownOptions) { o.NoCopyConfirmed = true }, state: TeardownDone, rm: true, copy: true},
		{name: "копия не записана", b: tdCopy(CtrSaved), prep: func(_ *tdFake, o *TeardownOptions) {
			p := filepath.Join(o.CopyDir, "file")
			os.WriteFile(p, []byte("x"), 0o600)
			o.CopyDir = p
		}, state: TeardownRefused, whyHas: "снос не выполнялся"},
		{name: "копия не сверилась", b: tdCopy(CtrSaved), hookBad: true, state: TeardownRefused, copy: true, whyHas: "проверка не прошла"},
		{name: "осталось после сноса", b: tdCopy(CtrSaved), prep: func(f *tdFake, _ *TeardownOptions) { f.keep = "amnezia-xray" }, state: TeardownFailed, rm: true, copy: true, whyHas: "контейнер amnezia-xray"},
		{name: "измерить не удалось", b: tdCopy(CtrSaved), prep: func(f *tdFake, _ *TeardownOptions) { f.failMeasure = true }, state: TeardownUnknown, rm: true, copy: true, marker: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			mp := withTDMarker(t)
			f := newTDFake()
			opt := TeardownOptions{Confirmed: true, CopyDir: t.TempDir()}
			if c.prep != nil {
				c.prep(f, &opt)
			}
			if c.hookBad {
				teardownVerifyHook = func(b *Backup) { b.Containers[0].Files[1].Data = NewSecret([]byte("[]")) }
				t.Cleanup(func() { teardownVerifyHook = nil })
			}
			r, _ := tdRun(t, f, c.b, opt)
			if r.State != c.state {
				t.Fatalf("State = %v (%s), want %v", r.State, r.Why, c.state)
			}
			if (len(f.rmCalls) > 0) != c.rm {
				t.Errorf("команды сноса: %v, ждали %v", f.rmCalls, c.rm)
			}
			if c.whyHas != "" && !strings.Contains(r.Why, c.whyHas) {
				t.Errorf("Why = %q, нет %q", r.Why, c.whyHas)
			}
			if c.copy {
				st, err := os.Stat(r.CopyPath)
				if err != nil {
					t.Fatalf("копии нет: %v", err)
				}
				if !isWindows() && st.Mode().Perm() != 0o600 {
					t.Errorf("права копии %v", st.Mode().Perm())
				}
				if !strings.HasSuffix(r.CopyPath, "-перед-сносом.aabk") {
					t.Errorf("имя копии %s", r.CopyPath)
				}
			}
			if strings.Contains(r.Why, "Иван") || strings.Contains(r.Why, "PrivateKey") {
				t.Errorf("секрет/данные в Why: %s", r.Why)
			}
			_, err := os.Stat(mp)
			if (err == nil) != c.marker {
				t.Errorf("маркер есть = %v, ждали %v", err == nil, c.marker)
			}
			// закрытый список: ничего постороннего
			for _, rc := range f.rmCalls {
				if strings.Contains(rc, "web") || strings.Contains(rc, "nginx") || strings.Contains(rc, "other-vol") {
					t.Errorf("снесено постороннее: %s", rc)
				}
			}
		})
	}
}

// Снос без копии вовсе (настоящий сбой сбора): только с NoCopyConfirmed, и
// файла копии нет.
func TestTeardownNoCopyNeedsSeparateYes(t *testing.T) {
	withTDMarker(t)
	f := newTDFake()
	s := tdSess(f)
	p, err := s.PlanTeardown(context.Background(), "t", time.Now(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := s.ExecuteTeardown(p, TeardownOptions{Confirmed: true}); r.State != TeardownRefused || len(f.rmCalls) != 0 {
		t.Fatalf("без отдельного «да»: %v %v", r.State, f.rmCalls)
	}
	r := s.ExecuteTeardown(p, TeardownOptions{Confirmed: true, NoCopyConfirmed: true})
	if r.State != TeardownDone || r.CopyPath != "" {
		t.Fatalf("с отдельным «да»: %v %q %s", r.State, r.CopyPath, r.Why)
	}
}

// Прерванный снос оставляет маркер: следующий BeginOpMarker отказывает.
func TestTeardownUnknownLeavesMarkerForNextRun(t *testing.T) {
	withTDMarker(t)
	f := newTDFake()
	f.failMeasure = true
	r, _ := tdRun(t, f, tdCopy(CtrSaved), TeardownOptions{Confirmed: true})
	if r.State != TeardownUnknown {
		t.Fatalf("State %v", r.State)
	}
	m, err := ReadOpMarker()
	if err != nil || m == nil || !strings.Contains(m.Text(), "снос Amnezia") {
		t.Fatalf("маркер: %v %v", m, err)
	}
	if err := BeginOpMarker(OpMarker{Target: "x"}); !errors.Is(err, ErrOpMarkerPending) {
		t.Fatalf("BeginOpMarker = %v", err)
	}
}

// Снос предлагается, только если «нельзя» вызвано одной Amnezia.
func TestTeardownWouldClear(t *testing.T) {
	ok := ProvItem{"ОС", ProvOK, "ок"}
	ctr := ProvItem{provCtrWhat, ProvBad, "уже есть: amnezia-awg2"}
	amzPort := ProvItem{"порт amnezia-awg2 51820/udp (порт из копии)", ProvBad, "порт опубликован контейнером amnezia-awg2 — освободите его"}
	otherPort := ProvItem{"порт amnezia-xray 443/tcp (порт из копии)", ProvBad, "порт занят другой программой"}
	unknown := ProvItem{"свободное место", ProvUnknown, "df не ответил"}
	for _, c := range []struct {
		name  string
		items []ProvItem
		want  bool
	}{
		{"только контейнеры", []ProvItem{ok, ctr}, true},
		{"контейнеры и их порт", []ProvItem{ok, ctr, amzPort}, true},
		{"чужой порт", []ProvItem{ctr, otherPort}, false},
		{"пункт не измерен", []ProvItem{ctr, unknown}, false},
		{"чисто", []ProvItem{ok}, false},
		{"порт Amnezia без контейнеров", []ProvItem{amzPort}, false},
	} {
		if got := TeardownWouldClear(ProvisionReport{Items: c.items}); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// Остановленный контейнер: в копию не попадает, и это сказано прямо —
// с клиентами поимённо, если прочитаны, иначе «не удалось прочитать».
func TestTeardownStoppedContainerNamed(t *testing.T) {
	f := newTDFake()
	f.ctrs["amnezia-wireguard"] = ""
	f.stopped = map[string]bool{"amnezia-wireguard": true}
	withTDCollect(t, tdCopy(CtrSaved), nil) // копия — только запущенные
	p, err := tdSess(f).PlanTeardown(context.Background(), "t", time.Now(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(p.InventoryLines(), "\n")
	want := "В КОПИЮ НЕ ПОПАДЁТ (контейнер остановлен (exited), программа читает только запущенные); после сноса пропадут безвозвратно — клиенты: не удалось прочитать"
	if !strings.Contains(text, want) || p.CopyState() != CopyPartial {
		t.Fatalf("нет %q (копия %v):\n%s", want, p.CopyState(), text)
	}
	if strings.Count(text, "В КОПИЮ НЕ ПОПАДЁТ") != 1 {
		t.Errorf("пометка не только у остановленного:\n%s", text)
	}
	// клиенты прочитаны, а контейнера в копии нет — поимённо
	p.Inv.Clients[1] = TargetClients{Container: "amnezia-wireguard", Known: true, Names: []string{"Пётр"}}
	if text := strings.Join(p.InventoryLines(), "\n"); !strings.Contains(text, "пропадут безвозвратно — клиенты: Пётр") {
		t.Errorf("клиенты не названы поимённо:\n%s", text)
	}
}

// Отмена до сноса: ни копии, ни команд сноса.
func TestTeardownCanceled(t *testing.T) {
	withTDMarker(t)
	f := newTDFake()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, _ := tdRun(t, f, tdCopy(CtrSaved), TeardownOptions{Confirmed: true, Ctx: ctx})
	if r.State != TeardownRefused || len(f.rmCalls) != 0 || r.CopyPath != "" || !strings.Contains(r.Why, "отменено до копии") {
		t.Fatalf("отмена: %v %v %q", r.State, f.rmCalls, r.CopyPath)
	}
}
