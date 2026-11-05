package core

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"amnezia-admin/core/provision"
)

// Поддельный сервер установки: состояние Docker (контейнеры, тома, файлы в
// контейнерах) и журнал команд. Шаг узнаётся по команде и stdin; отказ
// шага — метка кода 1, обрыв — ошибка Runner и «мёртвая» связь дальше.

const (
	fkUUID  = "11111111-2222-4333-8444-555555555555"
	fkShort = "0123abcd"
)

var fkPriv = base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

const awg2Conf = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.8.1.0/24\nListenPort = 51820\n" +
	"Jc = 4\nJmin = 10\nJmax = 50\nS1 = 20\nS2 = 30\nS3 = 15\nS4 = 25\nH1 = 100-200\nH2 = 300-400\nH3 = 500-600\nH4 = 700-800\n"

func xraySrcJSON(port string) string {
	return `{"inbounds":[{"port":` + port + `,"protocol":"vless","settings":{"clients":[{"id":"` + fkUUID +
		`","flow":"xtls-rprx-vision"}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"reality",` +
		`"realitySettings":{"dest":"www.example.com:443","serverNames":["www.example.com"],"privateKey":"` + fkPriv +
		`","shortIds":["` + fkShort + `"]}}}]}`
}

func instBackup() *Backup {
	return &Backup{Containers: []BackupContainer{
		{Name: "amnezia-awg2", Status: CtrSaved, Version: "2", VersionState: VersionKnown, Port: "51820", Subnet: "10.8.1.0/24",
			Files: []BackupFile{{Name: "awg0.conf", Status: FileSaved, Data: NewSecret([]byte(awg2Conf))}}},
		{Name: XRayContainer, Status: CtrSaved, Version: "XRay", VersionState: VersionKnown, Port: "443",
			Files: []BackupFile{{Name: xrayConfFile, Status: FileSaved, Data: NewSecret([]byte(xraySrcJSON("443")))}}},
		{Name: "amnezia-openvpn", Status: CtrNotIncluded, Reason: "OpenVPN копией не поддерживается"},
	}}
}

type instCall struct{ key, cmd, stdin string }

type instFake struct {
	ctrs, vols map[string]bool
	files      map[string]string // "<контейнер>:<путь>" → содержимое
	fail, drop string            // ключ шага
	dead       bool
	calls      []instCall
	// measureConf — подмена awg0.conf при измерении (пусто — как в копии).
	measureConf string
}

func newInstFake() *instFake {
	return &instFake{ctrs: map[string]bool{}, vols: map[string]bool{}, files: map[string]string{}}
}

var reCtrName = regexp.MustCompile(`amnezia-(awg2|awg|wireguard|xray)\b`)

func instCtrOf(s string) string { return reCtrName.FindString(s) }

// stepKey — имя шага по команде и stdin.
func stepKey(cmd, in string) string {
	c := instCtrOf(cmd)
	switch {
	case strings.Contains(cmd, "docker ps -a"):
		return "list"
	case strings.Contains(cmd, "docker volume ls"):
		return "volumes"
	case strings.Contains(cmd, "docker volume rm"):
		return "volrm:" + c
	case strings.Contains(cmd, "docker version"):
		return "dockerver"
	case cmd == hostScriptCmd:
		switch {
		case strings.Contains(in, "Dist: $dist"):
			return "install_docker"
		case strings.Contains(in, "docker network create"):
			return "prepare:" + instCtrOf(in)
		case strings.Contains(in, "docker build"):
			return "build:" + instCtrOf(in)
		case strings.Contains(in, "docker run -d"):
			return "run:" + instCtrOf(in)
		case strings.Contains(in, "docker rm -fv"):
			return "remove:" + instCtrOf(in)
		}
		return "host?"
	case strings.Contains(cmd, "/Dockerfile"):
		return "dockerfile:" + c
	case strings.Contains(cmd, "bash -s"):
		return "configure:" + c
	case strings.Contains(cmd, "start.sh"):
		return "start:" + c
	case strings.Contains(cmd, " sh -s"):
		return "server.json:" + c
	case strings.Contains(cmd, "clientsTable"):
		return "clientsTable:" + c
	case strings.Contains(cmd, "docker restart"):
		return "restart:" + c
	case strings.Contains(cmd, "docker inspect"):
		return "inspect:" + c
	}
	return "?"
}

func instOK(body string) string { return body + instRC + "0\n" }

func (f *instFake) Run(cmd string, stdin []byte) (string, error) {
	in := string(stdin)
	key := stepKey(cmd, in)
	f.calls = append(f.calls, instCall{key, cmd, in})
	if f.dead {
		return "", errors.New("связь оборвалась")
	}
	if key == f.drop {
		f.dead = true
		return "", errors.New("связь оборвалась")
	}
	if key == f.fail {
		return "boom\n" + instRC + "1\n", nil
	}
	name, _, _ := strings.Cut(key, ":")
	c := instCtrOf(key)
	switch name {
	case "list":
		return instOK(strings.Join(keys(f.ctrs), "\n") + "\n"), nil
	case "volumes":
		return instOK(strings.Join(keys(f.vols), "\n") + "\n"), nil
	case "volrm":
		for v := range f.vols {
			if strings.Contains(cmd, v) {
				delete(f.vols, v)
			}
		}
		return instOK(""), nil
	case "dockerver":
		return instOK("27.5.1\n"), nil
	case "run":
		f.ctrs[c] = true
		if c == XRayContainer {
			f.vols[c+"-data"] = true
		}
		return instOK(""), nil
	case "remove":
		delete(f.ctrs, c)
		return instOK(""), nil
	case "configure":
		if c == "amnezia-awg2" {
			conf := awg2Conf
			if f.measureConf != "" {
				conf = f.measureConf
			}
			f.files[c+":/opt/amnezia/awg/awg0.conf"] = conf
		}
		return instOK(""), nil
	case "server.json":
		body := in[strings.Index(in, "<<EOF\n")+6 : strings.LastIndex(in, "EOF\n")]
		body = strings.NewReplacer("$U", fkUUID, "$K", fkPriv, "$S", fkShort).Replace(body)
		f.files[c+":"+xrayDir+"/"+xrayConfFile] = body
		return instOK(""), nil
	case "inspect":
		return instOK("true\n"), nil
	case "install_docker", "prepare", "dockerfile", "build", "start", "clientsTable", "restart":
		return instOK(""), nil
	}
	// Измерение (CheckTarget) — его собственные команды.
	if strings.HasPrefix(cmd, "docker ps --format") {
		return strings.Join(keys(f.ctrs), "\n") + "\n", nil
	}
	if m := regexp.MustCompile(`^docker exec (\S+) cat (\S+)$`).FindStringSubmatch(cmd); m != nil {
		if v, has := f.files[m[1]+":"+m[2]]; has {
			return v, nil
		}
		return "", fmt.Errorf("stderr: cat: %s: No such file or directory", m[2])
	}
	return "", fmt.Errorf("неизвестная команда: %s", cmd)
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func (f *instFake) keys() []string {
	var out []string
	for _, c := range f.calls {
		out = append(out, c.key)
	}
	return out
}

func instRun(t *testing.T, f *instFake) (InstallResult, InstallPlan) {
	t.Helper()
	b := instBackup()
	plan := PlanInstall(b, nil)
	if !plan.Ready() {
		t.Fatalf("план копии-образца не готов: %+v", plan)
	}
	sess := NewSessionWithRunner(f, &ServerCreds{Host: "203.0.113.7"})
	return Install(sess, plan, InstallOptions{Backup: b, PreviewAccepted: true}), plan
}

func installWrites(keys []string) []string {
	var w []string
	for _, k := range keys {
		switch k {
		case "list", "volumes", "dockerver", "?":
		default:
			if !strings.HasPrefix(k, "inspect:") {
				w = append(w, k)
			}
		}
	}
	return w
}

var happyOrder = []string{
	"list", "volumes", "install_docker", "dockerver",
	"prepare:amnezia-awg2", "dockerfile:amnezia-awg2", "build:amnezia-awg2", "run:amnezia-awg2",
	"configure:amnezia-awg2", "start:amnezia-awg2", "clientsTable:amnezia-awg2", "restart:amnezia-awg2", "inspect:amnezia-awg2",
	"prepare:amnezia-xray", "dockerfile:amnezia-xray", "build:amnezia-xray", "run:amnezia-xray",
	"configure:amnezia-xray", "start:amnezia-xray", "server.json:amnezia-xray", "clientsTable:amnezia-xray",
	"restart:amnezia-xray", "inspect:amnezia-xray",
}

// TestInstallOrder — порядок шагов (эталон 05.11) и измерение настоящим
// CheckTarget: оба контейнера «поставлен и измерен».
func TestInstallOrder(t *testing.T) {
	f := newInstFake()
	res, _ := instRun(t, f)
	got := f.keys()
	if len(got) < len(happyOrder) || strings.Join(got[:len(happyOrder)], ",") != strings.Join(happyOrder, ",") {
		t.Fatalf("порядок шагов:\n%v\nждали:\n%v", got, happyOrder)
	}
	for _, k := range got[len(happyOrder):] {
		if k != "?" {
			t.Errorf("после установки — только измерение (команды чтения), а пришло %q", k)
		}
	}
	if !res.ReadyForRestore() || res.Stop {
		t.Fatalf("не готово к переносу: %v", res.Lines())
	}
	for _, c := range res.Containers {
		if c.Outcome != InstallInstalled || c.Measured != CompatMatch {
			t.Errorf("%s: %s — %s", c.Container, c.Verdict(), c.Reason)
		}
	}
	for _, c := range f.calls {
		if strings.Contains(c.key, "remove") {
			t.Errorf("откат при успехе: %s", c.key)
		}
	}
}

// TestInstallNoFirewallScript — setup_host_firewall.sh не уходит на сервер.
func TestInstallNoFirewallScript(t *testing.T) {
	f := newInstFake()
	instRun(t, f)
	for _, rev := range provision.RevisionIDs() {
		fw, err := provision.Script(rev, "setup_host_firewall.sh")
		if err != nil {
			t.Fatal(err)
		}
		first := strings.SplitN(strings.TrimSpace(string(fw)), "\n", 2)[0]
		for _, c := range f.calls {
			if strings.Contains(c.stdin, first) || strings.Contains(c.cmd, first) {
				t.Errorf("на сервер ушёл setup_host_firewall.sh (%s)", c.key)
			}
		}
	}
}

// TestInstallScriptsOnlyViaRender — каждый официальный скрипт на сервере —
// байт в байт результат provision.Render с переменными из копии.
func TestInstallScriptsOnlyViaRender(t *testing.T) {
	f := newInstFake()
	instRun(t, f)
	rev := provision.Rev5106
	R := func(file string, v map[string]string) string {
		s, err := provision.Render(rev, file, v)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		return s
	}
	awgVars := map[string]string{"AWG_SERVER_PORT": "51820", "AWG_SUBNET_IP": "10.8.1.0", "WIREGUARD_SUBNET_CIDR": "24",
		"JUNK_PACKET_COUNT": "4", "JUNK_PACKET_MIN_SIZE": "10", "JUNK_PACKET_MAX_SIZE": "50", "INIT_PACKET_JUNK_SIZE": "20",
		"RESPONSE_PACKET_JUNK_SIZE": "30", "COOKIE_REPLY_PACKET_JUNK_SIZE": "15", "TRANSPORT_PACKET_JUNK_SIZE": "25",
		"INIT_PACKET_MAGIC_HEADER": "100-200", "RESPONSE_PACKET_MAGIC_HEADER": "300-400",
		"UNDERLOAD_PACKET_MAGIC_HEADER": "500-600", "TRANSPORT_PACKET_MAGIC_HEADER": "700-800"}
	for _, n := range []string{"HEADER_PROTECTION_KEY", "CONTENT_PADDING_ADDITION", "REKEY_AFTER_TIME", "REKEY_TIMEOUT",
		"REJECT_AFTER_TIME", "KEEPALIVE_TIMEOUT", "MAX_HANDSHAKE_ATTEMPTS", "RANDOM_TRAILERS", "DISABLE_COOKIES",
		"SPECIAL_JUNK_1", "SPECIAL_JUNK_2", "SPECIAL_JUNK_3", "SPECIAL_JUNK_4", "SPECIAL_JUNK_5"} {
		awgVars[n] = ""
	}
	want := map[string]string{
		"install_docker":            R("install_docker.sh", map[string]string{}),
		"prepare:amnezia-awg2":      R("prepare_host.sh", map[string]string{"DOCKERFILE_FOLDER": "/opt/amnezia/amnezia-awg2"}),
		"dockerfile:amnezia-awg2":   R("awg/Dockerfile", map[string]string{}),
		"build:amnezia-awg2":        R("build_container.sh", map[string]string{"CONTAINER_NAME": "amnezia-awg2", "DOCKERFILE_FOLDER": "/opt/amnezia/amnezia-awg2"}),
		"run:amnezia-awg2":          R("awg/run_container.sh", map[string]string{"CONTAINER_NAME": "amnezia-awg2", "SERVER_IP_ADDRESS": "203.0.113.7", "AWG_SERVER_PORT": "51820"}),
		"configure:amnezia-awg2":    R("awg/configure_container.sh", awgVars),
		"start:amnezia-awg2":        R("awg/start.sh", map[string]string{"AWG_SUBNET_IP": "10.8.1.0", "SERVER_IP_ADDRESS": "203.0.113.7", "WIREGUARD_SUBNET_CIDR": "24"}),
		"dockerfile:amnezia-xray":   R("xray/Dockerfile", map[string]string{}),
		"run:amnezia-xray":          R("xray/run_container.sh", map[string]string{"CONTAINER_NAME": "amnezia-xray", "SERVER_IP_ADDRESS": "203.0.113.7", "XRAY_SERVER_PORT": "443"}),
		"configure:amnezia-xray":    R("xray/configure_container.sh", map[string]string{}),
		"start:amnezia-xray":        R("xray/start.sh", map[string]string{"SERVER_IP_ADDRESS": "203.0.113.7", "XRAY_SERVER_PORT": "443"}),
		"clientsTable:amnezia-xray": "[]",
	}
	seen := map[string]bool{}
	for _, c := range f.calls {
		if w, has := want[c.key]; has {
			seen[c.key] = true
			if c.stdin != w {
				t.Errorf("%s: на сервер ушло не то, что дал provision.Render", c.key)
			}
		}
	}
	for k := range want {
		if !seen[k] {
			t.Errorf("шага %s не было", k)
		}
	}
}

// TestInstallXRayKeysNeverInGo — server.json собирается командой на
// сервере: ни команды, ни stdin не содержат значений ключей, ключевые
// файлы программа не читает; при этом итог разбирается parseXRayServer с
// портом/SNI/flow копии.
func TestInstallXRayKeysNeverInGo(t *testing.T) {
	f := newInstFake()
	instRun(t, f)
	for _, c := range f.calls {
		for _, secret := range []string{fkPriv, fkShort} {
			if strings.Contains(c.cmd, secret) || strings.Contains(c.stdin, secret) {
				t.Errorf("%s: значение ключа XRay прошло через программу", c.key)
			}
		}
		if strings.Contains(c.cmd, "xray_private.key") {
			t.Errorf("%s: программа читает ключ XRay командой", c.key)
		}
	}
	got := f.files[XRayContainer+":"+xrayDir+"/"+xrayConfFile]
	srv, err := parseXRayServer([]byte(got))
	if err != nil {
		t.Fatalf("server.json не той формы: %v\n%s", err, got)
	}
	if srv.port != "443" || srv.serverName != "www.example.com" || srv.clientFlow != xrayFlowVision || srv.ids[0] != fkUUID || srv.shortID != fkShort {
		t.Errorf("server.json: %+v", srv)
	}
}

func TestXRayServerScriptRejects(t *testing.T) {
	for _, c := range [][3]string{{"0", "a.b", ""}, {"443", "a.b'; rm -rf /", ""}, {"443", "a.b", "xtls-other"}, {"0443", "a.b", ""}, {"443", "$(id)", ""}} {
		if _, err := xrayServerScript(c[0], c[1], c[2]); err == nil {
			t.Errorf("принято %q", c)
		}
	}
}

// TestInstallFailEachStep — отказ (известный код) и обрыв на каждом шаге:
// исход, откат только созданных в этом запуске и только их.
func TestInstallFailEachStep(t *testing.T) {
	var steps []string
	for _, k := range happyOrder {
		if k != "list" && k != "volumes" {
			steps = append(steps, k)
		}
	}
	idx := func(k string) int {
		for i, s := range happyOrder {
			if s == k {
				return i
			}
		}
		return -1
	}
	createdBefore := func(step, ctr string) bool { // контейнер «создавался» к моменту шага
		b := idx("build:" + ctr)
		return b >= 0 && idx(step) >= b
	}
	for _, mode := range []string{"fail", "drop"} {
		for _, st := range steps {
			f := newInstFake()
			if mode == "fail" {
				f.fail = st
			} else {
				f.drop = st
			}
			res, _ := instRun(t, f)
			name := mode + "@" + st
			if !res.Stop || res.ReadyForRestore() {
				t.Errorf("%s: не остановлено", name)
				continue
			}
			if res.Refused != "" {
				t.Errorf("%s: отказ до записи, а запись была: %s", name, res.Refused)
			}
			// Откат — только для созданных.
			for _, c := range f.calls {
				if strings.HasPrefix(c.key, "remove:") {
					ctr := strings.TrimPrefix(c.key, "remove:")
					if !createdBefore(st, ctr) {
						t.Errorf("%s: откат %s, который этот запуск не создавал", name, ctr)
					}
				}
			}
			for _, r := range res.Containers {
				created := createdBefore(st, r.Container)
				switch {
				case mode == "drop" && created:
					if r.Outcome != InstallOutcomeUnknown || r.Rollback != RollbackUnknown {
						t.Errorf("%s/%s: обрыв после создания — ждали «неизвестно», а %s (rollback %d)", name, r.Container, r.Verdict(), r.Rollback)
					}
				case mode == "fail" && created:
					if r.Outcome != InstallNotInstalled || r.Rollback != RollbackDone {
						t.Errorf("%s/%s: отказ с откатом — ждали «не поставлен, снят», а %s (rollback %d)", name, r.Container, r.Verdict(), r.Rollback)
					}
					if f.ctrs[r.Container] {
						t.Errorf("%s/%s: контейнер остался после отката", name, r.Container)
					}
				case !created:
					if r.Outcome != InstallNotInstalled && !(mode == "drop" && strings.HasSuffix(st, r.Container) && !created) {
						t.Errorf("%s/%s: не создавался — ждали «не поставлен», а %s", name, r.Container, r.Verdict())
					}
				}
			}
			if mode == "fail" && len(f.vols) != 0 {
				t.Errorf("%s: остался том %v", name, keys(f.vols))
			}
		}
	}
}

// TestInstallDropBeforeCreate — обрыв на шаге до build: контейнер не
// создавался, но ответа нет — исход «неизвестно» (каталог мог появиться).
func TestInstallDropBeforeCreate(t *testing.T) {
	f := newInstFake()
	f.drop = "prepare:amnezia-awg2"
	res, _ := instRun(t, f)
	if res.Containers[0].Outcome != InstallOutcomeUnknown {
		t.Errorf("обрыв на prepare: %s", res.Containers[0].Verdict())
	}
	if res.Containers[1].Outcome != InstallNotInstalled {
		t.Errorf("второй контейнер не начинали: %s", res.Containers[1].Verdict())
	}
	f2 := newInstFake()
	f2.fail = "prepare:amnezia-awg2"
	res2, _ := instRun(t, f2)
	if res2.Containers[0].Outcome != InstallNotInstalled || res2.Containers[0].Rollback != RollbackNotNeeded {
		t.Errorf("отказ prepare: %s rollback=%d", res2.Containers[0].Verdict(), res2.Containers[0].Rollback)
	}
}

// TestInstallMeasureMismatch — измерение не совпало: стоп до клиентов,
// откат своих.
func TestInstallMeasureMismatch(t *testing.T) {
	f := newInstFake()
	f.measureConf = strings.Replace(awg2Conf, "ListenPort = 51820", "ListenPort = 51821", 1)
	res, _ := instRun(t, f)
	if !res.Stop || res.ReadyForRestore() || !strings.Contains(res.StopReason, "amnezia-awg2") {
		t.Fatalf("несовпадение не остановило: %v", res.Lines())
	}
	if res.Containers[0].Measured != CompatMismatch || !strings.Contains(res.Containers[0].Reason, "порт") {
		t.Errorf("awg2: %d %s", res.Containers[0].Measured, res.Containers[0].Reason)
	}
	if len(f.ctrs) != 0 {
		t.Errorf("откат не снял своё: %v", keys(f.ctrs))
	}
}

// TestInstallMeasureUnavailable — измерение не выполнено: «не знаем», стоп.
func TestInstallMeasureUnavailable(t *testing.T) {
	old := installMeasure
	defer func() { installMeasure = old }()
	installMeasure = func(*Session, *Backup, Resolver) (*CompatReport, error) { return nil, errors.New("docker ps упал") }
	f := newInstFake()
	res, _ := instRun(t, f)
	if !res.Stop || res.ReadyForRestore() || res.Measure != nil {
		t.Fatalf("без измерения — готово? %v", res.Lines())
	}
	for _, c := range res.Containers {
		if c.Measured != CompatUnknown {
			t.Errorf("%s: измерено %d без измерения", c.Container, c.Measured)
		}
	}
}

// TestInstallRefusals — отказ ДО любой записи.
func TestInstallRefusals(t *testing.T) {
	b := instBackup()
	plan := PlanInstall(b, nil)
	cases := []struct {
		name  string
		setup func(f *instFake) (InstallPlan, InstallOptions)
		want  string
	}{
		{"превью не подтверждено", func(*instFake) (InstallPlan, InstallOptions) {
			return plan, InstallOptions{Backup: b}
		}, "InstallPreview"},
		{"план не готов", func(*instFake) (InstallPlan, InstallOptions) {
			p := PlanInstall(&Backup{Containers: []BackupContainer{wgCtr("amnezia-awg2", "1.5", VersionKnown)}}, nil)
			return p, InstallOptions{Backup: b, PreviewAccepted: true}
		}, "ни одна закреплённая ревизия"},
		{"нет копии", func(*instFake) (InstallPlan, InstallOptions) {
			return plan, InstallOptions{PreviewAccepted: true}
		}, "копии"},
		{"есть контейнер", func(f *instFake) (InstallPlan, InstallOptions) {
			f.ctrs["amnezia-awg2"] = true
			return plan, InstallOptions{Backup: b, PreviewAccepted: true}
		}, "не чистый: уже есть amnezia-awg2"},
		{"есть том XRay", func(f *instFake) (InstallPlan, InstallOptions) {
			f.vols["amnezia-xray-data"] = true
			return plan, InstallOptions{Backup: b, PreviewAccepted: true}
		}, "amnezia-xray-data"},
		{"чистоту узнать не удалось", func(f *instFake) (InstallPlan, InstallOptions) {
			f.drop = "volumes"
			return plan, InstallOptions{Backup: b, PreviewAccepted: true}
		}, "не проверена"},
	}
	for _, tc := range cases {
		f := newInstFake()
		p, o := tc.setup(f)
		res := Install(NewSessionWithRunner(f, &ServerCreds{Host: "203.0.113.7"}), p, o)
		if res.Refused == "" || !strings.Contains(res.Refused, tc.want) || !res.Stop {
			t.Errorf("%s: %q", tc.name, res.Refused)
		}
		if w := installWrites(f.keys()); len(w) != 0 {
			t.Errorf("%s: запись при отказе: %v", tc.name, w)
		}
		if len(res.Skipped) != len(p.Skipped) {
			t.Errorf("%s: Skipped потерян", tc.name)
		}
	}
}

// TestInstallPreviewM1 — каждый пункт аудита AMNEZIA-SCRIPTS-1 M1–M3 в
// перечне.
func TestInstallPreviewM1(t *testing.T) {
	plan := PlanInstall(instBackup(), nil)
	lines, err := InstallPreview(plan)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(lines, "\n")
	for _, w := range []string{
		"docker.io", "psmisc", "lsof", "версии не закреплены",
		"amnezia-dns-net 172.29.172.0/24",
		"--privileged", "SYS_MODULE", "/lib/modules",
		"amneziavpn/amneziawg-go:latest", ":latest без дайджеста",
		"alpine:3.15", "EOL",
		"без сверки контрольной суммы",
		"51820/udp", "443/tcp", "443/udp",
		"/opt/amnezia/amnezia-awg2", "/opt/amnezia/amnezia-xray", "amnezia-xray-data",
		"setup_host_firewall.sh НЕ запускается",
		"Не ставится: amnezia-openvpn — OpenVPN копией не поддерживается",
		"Откат",
	} {
		if !strings.Contains(all, w) {
			t.Errorf("в перечне нет %q", w)
		}
	}
	if _, err := InstallPreview(InstallPlan{}); err == nil {
		t.Error("пустой план — перечень без ошибки")
	}
}

// TestInstallLines — печать: Verdict + Reason, Skipped целиком; нулевой
// исход — «неизвестно», не «не поставлен».
func TestInstallLines(t *testing.T) {
	var zero InstallContainerResult
	if zero.Outcome != InstallOutcomeUnknown || zero.Verdict() != "неизвестно" || zero.Rollback != RollbackUnknown {
		t.Fatal("нулевой исход обязан значить «неизвестно»")
	}
	f := newInstFake()
	f.drop = "configure:amnezia-xray"
	res, _ := instRun(t, f)
	all := strings.Join(res.Lines(), "\n")
	for _, w := range []string{"amnezia-xray: неизвестно", "связь оборвалась", "откат не подтверждён",
		"Не ставится: amnezia-openvpn — OpenVPN копией не поддерживается", "Перенос клиентов остановлен"} {
		if !strings.Contains(all, w) {
			t.Errorf("в итоге нет %q:\n%s", w, all)
		}
	}
}
