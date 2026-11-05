package provision

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
)

// copyEmbedded — копия вендоренного дерева в изменяемую MapFS.
func copyEmbedded(t *testing.T) fstest.MapFS {
	t.Helper()
	m := fstest.MapFS{}
	err := fs.WalkDir(embedded, "scripts", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(embedded, p)
		if err != nil {
			return err
		}
		m[p] = &fstest.MapFile{Data: b}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Сторож: суммы пересчитываются заново, а не берутся из readVerified.
func TestEmbeddedSumsGuard(t *testing.T) {
	if err := VerifyAll(); err != nil {
		t.Fatalf("VerifyAll: %v", err)
	}
	seen := 0
	err := fs.WalkDir(embedded, "scripts", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rest := strings.TrimPrefix(p, "scripts/")
		rev, file, _ := strings.Cut(rest, "/")
		b, _ := fs.ReadFile(embedded, p)
		sum := sha256.Sum256(b)
		if want := revisions[rev].Files[file]; hex.EncodeToString(sum[:]) != want {
			t.Errorf("%s: сумма %x, закреплена %q", p, sum, want)
		}
		if strings.Contains(string(b), "\r") {
			t.Errorf("%s: CR в тексте — перевод строк испорчен (.gitattributes)", p)
		}
		seen++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	for _, id := range RevisionIDs() {
		if len(revisions[id].Files) == 0 {
			t.Errorf("ревизия %s без файлов", id)
		}
		want += len(revisions[id].Files)
	}
	if seen != want || seen == 0 {
		t.Fatalf("проверено файлов %d, в закрытых списках %d", seen, want)
	}
}

// Канарейки сторожа: подмена байта, лишний и пропавший файл роняют сверку,
// а нетронутая копия — проходит (иначе канарейка падала бы всегда).
func TestTamperCanary(t *testing.T) {
	if err := verifyTree(copyEmbedded(t)); err != nil {
		t.Fatalf("нетронутая копия не прошла: %v", err)
	}
	target := "scripts/" + Rev5106 + "/awg/configure_container.sh"
	cases := map[string]func(m fstest.MapFS){
		"подмена байта": func(m fstest.MapFS) {
			b := append([]byte(nil), m[target].Data...)
			b[10] ^= 1
			m[target] = &fstest.MapFile{Data: b}
		},
		"лишний файл": func(m fstest.MapFS) {
			m["scripts/"+Rev5106+"/awg/evil.sh"] = &fstest.MapFile{Data: []byte("x")}
		},
		"пропавший файл": func(m fstest.MapFS) { delete(m, target) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			m := copyEmbedded(t)
			mut(m)
			if err := verifyTree(m); err == nil {
				t.Fatal("сверка не заметила")
			}
		})
	}
	if _, err := readVerified(embedded, "nope", "build_container.sh"); err == nil {
		t.Error("незакреплённая ревизия прочитана")
	}
	if _, err := Script(Rev5106, "awg/template.conf"); err == nil {
		t.Error("файл вне закрытого списка прочитан")
	}
}

var reUpper = regexp.MustCompile(`\$\{?([A-Z_][A-Z0-9_]*)`)

// Закрытые списки сняты с текста: сверяем заново. Новая переменная в
// скрипте (обновили вендоринг, не обновив список) — красное.
func TestSpecMatchesScripts(t *testing.T) {
	for _, rev := range RevisionIDs() {
		for file := range revisions[rev].Files {
			spec, ok := specFor(rev, file)
			if !ok {
				t.Errorf("%s/%s: нет списка", rev, file)
				continue
			}
			b, err := Script(rev, file)
			if err != nil {
				t.Fatal(err)
			}
			found := map[string]bool{}
			for _, m := range reUpper.FindAllStringSubmatch(string(b), -1) {
				found[m[1]] = true
			}
			want := map[string]bool{}
			for n := range spec.vars {
				want[n] = true
			}
			for _, n := range spec.shell {
				if _, dup := spec.vars[n]; dup {
					t.Errorf("%s/%s: %s одновременно и переменная приложения, и скрипта", rev, file, n)
				}
				want[n] = true
			}
			for n := range found {
				if !want[n] {
					t.Errorf("%s/%s: в тексте $%s, которой нет в закрытых списках", rev, file, n)
				}
			}
			for n := range want {
				if !found[n] {
					t.Errorf("%s/%s: в списке %s, которой нет в тексте", rev, file, n)
				}
			}
		}
	}
}

const testHPK = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" // 32 байта

// goodPool — правильные значения всех переменных приложения (AWG2/3.1).
func goodPool(folder string) map[string]string {
	c := folderContainer[folder]
	if c == "" {
		c = "amnezia-awg2"
	}
	return map[string]string{
		"CONTAINER_NAME": c, "DOCKERFILE_FOLDER": "/opt/amnezia/" + c,
		"SERVER_IP_ADDRESS": "203.0.113.7",
		"AWG_SERVER_PORT":   "51820", "WIREGUARD_SERVER_PORT": "51821", "XRAY_SERVER_PORT": "443",
		"AWG_SUBNET_IP": "10.8.1.0", "WIREGUARD_SUBNET_IP": "10.8.1.0", "WIREGUARD_SUBNET_CIDR": "24",
		"JUNK_PACKET_COUNT": "4", "JUNK_PACKET_MIN_SIZE": "10", "JUNK_PACKET_MAX_SIZE": "50",
		"INIT_PACKET_JUNK_SIZE": "12", "RESPONSE_PACKET_JUNK_SIZE": "12",
		"COOKIE_REPLY_PACKET_JUNK_SIZE": "12", "TRANSPORT_PACKET_JUNK_SIZE": "12",
		"INIT_PACKET_MAGIC_HEADER": "1", "RESPONSE_PACKET_MAGIC_HEADER": "2",
		"UNDERLOAD_PACKET_MAGIC_HEADER": "100-200", "TRANSPORT_PACKET_MAGIC_HEADER": "4",
		"HEADER_PROTECTION_KEY": testHPK, "CONTENT_PADDING_ADDITION": "10-100",
		"REKEY_AFTER_TIME": "100-120", "REKEY_TIMEOUT": "3-7", "REJECT_AFTER_TIME": "150-180",
		"KEEPALIVE_TIMEOUT": "5-15", "MAX_HANDSHAKE_ATTEMPTS": "15-20",
		"RANDOM_TRAILERS": "on", "DISABLE_COOKIES": "on",
		"SPECIAL_JUNK_1": "<r 2><b 0x8580000100010000>", "SPECIAL_JUNK_2": "",
		"SPECIAL_JUNK_3": "<t><c><rc 4><rd 3>", "SPECIAL_JUNK_4": "", "SPECIAL_JUNK_5": "",
	}
}

func varsFor(t *testing.T, rev, file string) map[string]string {
	t.Helper()
	folder, _, _ := strings.Cut(file, "/")
	pool := goodPool(folder)
	names, ok := RequiredVars(rev, file)
	if !ok {
		t.Fatalf("%s/%s: нет списка", rev, file)
	}
	v := map[string]string{}
	for _, n := range names {
		v[n] = pool[n]
	}
	return v
}

// upstreamReplace — дословно SshSession::replaceVars: QString::replace по
// очереди, без границ слова.
func upstreamReplace(text string, vars map[string]string) string {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		text = strings.ReplaceAll(text, "$"+k, vars[k])
	}
	return text
}

// Рендер каждого файла каждой ревизии проходит и даёт то же, что дала бы
// подстановка самого приложения.
func TestRenderAllFilesMatchesUpstream(t *testing.T) {
	n := 0
	for _, rev := range RevisionIDs() {
		for file := range revisions[rev].Files {
			v := varsFor(t, rev, file)
			got, err := Render(rev, file, v)
			if err != nil {
				t.Errorf("%s/%s: %v", rev, file, err)
				continue
			}
			raw, _ := Script(rev, file)
			// Приложение шлёт ВСЕ свои переменные (genBaseVars + протокол),
			// а не закрытый список файла: подстрочная замена задела бы
			// переменную скрипта с общим префиксом (ревью-1 L3).
			full := appVars(file)
			for k, x := range v {
				full[k] = x
			}
			if want := upstreamReplace(string(raw), full); got != want {
				t.Errorf("%s/%s: результат расходится с replaceVars приложения", rev, file)
			}
			n++
		}
	}
	if n == 0 {
		t.Fatal("не отрендерено ни одного файла")
	}
	// Значения действительно доехали в текст.
	out, err := Render(Rev5106, "awg/configure_container.sh", varsFor(t, Rev5106, "awg/configure_container.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ListenPort = 51820", "Address = 10.8.1.0/24", "H3 = 100-200", "HeaderProtectionKey = " + testHPK, "# I1 = <r 2>"} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q", want)
		}
	}
}

func TestRenderRejects(t *testing.T) {
	const rev, cfg = Rev5106, "awg/configure_container.sh"
	cases := []struct {
		name, file, key, val string
		drop, extra          bool
	}{
		{name: "инъекция ;", file: cfg, key: "AWG_SERVER_PORT", val: "51820;reboot"},
		{name: "инъекция $()", file: cfg, key: "SPECIAL_JUNK_1", val: "<r 2>$(id)"},
		{name: "инъекция `", file: cfg, key: "HEADER_PROTECTION_KEY", val: "`id`"},
		{name: "перевод строки — выход из heredoc", file: cfg, key: "SPECIAL_JUNK_2", val: "<t>\nEOF\nreboot"},
		{name: "перевод строки в хосте", file: "awg/run_container.sh", key: "SERVER_IP_ADDRESS", val: "a.b\nreboot"},
		{name: "пробел в хосте", file: "awg/run_container.sh", key: "SERVER_IP_ADDRESS", val: "a b"},
		{name: "$ в значении", file: "awg/start.sh", key: "AWG_SUBNET_IP", val: "$HOME"},
		{name: "порт 0", file: cfg, key: "AWG_SERVER_PORT", val: "0"},
		{name: "порт 65536", file: cfg, key: "AWG_SERVER_PORT", val: "65536"},
		{name: "порт с нулём", file: cfg, key: "AWG_SERVER_PORT", val: "0443"},
		{name: "порт пустой", file: cfg, key: "AWG_SERVER_PORT", val: ""},
		{name: "подсеть IPv6", file: cfg, key: "AWG_SUBNET_IP", val: "fd00::1"},
		{name: "подсеть с CIDR", file: cfg, key: "AWG_SUBNET_IP", val: "10.8.1.0/24"},
		{name: "префикс 33", file: cfg, key: "WIREGUARD_SUBNET_CIDR", val: "33"},
		{name: "H обратный диапазон", file: cfg, key: "INIT_PACKET_MAGIC_HEADER", val: "9-1"},
		{name: "H больше uint32", file: cfg, key: "INIT_PACKET_MAGIC_HEADER", val: "4294967296"},
		{name: "Jc отрицательный", file: cfg, key: "JUNK_PACKET_COUNT", val: "-1"},
		{name: "toggle off", file: cfg, key: "RANDOM_TRAILERS", val: "off"},
		{name: "I-тег незнакомый", file: cfg, key: "SPECIAL_JUNK_1", val: "<x 1>"},
		{name: "ключ 31 байт", file: cfg, key: "HEADER_PROTECTION_KEY", val: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg=="},
		{name: "чужой контейнер", file: "awg/run_container.sh", key: "CONTAINER_NAME", val: "amnezia-xray"},
		{name: "контейнер вне списка", file: "remove_container.sh", key: "CONTAINER_NAME", val: "nginx"},
		{name: "каталог не /opt/amnezia", file: "prepare_host.sh", key: "DOCKERFILE_FOLDER", val: "/etc"},
		{name: "каталог ≠ контейнер", file: "build_container.sh", key: "DOCKERFILE_FOLDER", val: "/opt/amnezia/amnezia-xray"},
		{name: "старый AWG: Jc пустой", file: "awg_legacy/configure_container.sh", key: "JUNK_PACKET_COUNT", val: ""},
		{name: "недостающая", file: cfg, key: "AWG_SERVER_PORT", drop: true},
		{name: "лишняя", file: "xray/start.sh", key: "AWG_SERVER_PORT", val: "1", extra: true},
		{name: "неизвестная", file: cfg, key: "EVIL", val: "1", extra: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := varsFor(t, rev, c.file)
			switch {
			case c.drop:
				delete(v, c.key)
			default:
				v[c.key] = c.val
			}
			_, err := Render(rev, c.file, v)
			if err == nil {
				t.Fatal("принято")
			}
			if len(c.val) > 3 && strings.Contains(err.Error(), c.val) {
				t.Errorf("значение попало в текст ошибки: %v", err)
			}
		})
	}
}

// Пустые параметры обфускации AWG2 — «не задано», а не ошибка: скрипт сам
// удаляет такие строки (configure_container.sh:45).
func TestRenderAWGOptionalEmpty(t *testing.T) {
	v := varsFor(t, Rev5106, "awg/configure_container.sh")
	for _, n := range awgObf {
		v[n] = ""
	}
	if _, err := Render(Rev5106, "awg/configure_container.sh", v); err != nil {
		t.Fatal(err)
	}
}

// Оставшаяся ссылка вне закрытого списка скрипта — ошибка (в т.ч. ${ИМЯ}).
// appVars — полный набор, который приложение передаёт в replaceVars для
// файла (scriptsRegistry.cpp genBaseVars + genAwgVars/genWireGuardVars/
// genXrayVars), с правдоподобными значениями.
func appVars(file string) map[string]string {
	folder, _, _ := strings.Cut(file, "/")
	m := goodPool(folder)
	for k, v := range map[string]string{
		"REMOTE_HOST": "203.0.113.7", "PRIMARY_SERVER_DNS": "8.8.8.8", "SECONDARY_SERVER_DNS": "8.8.4.4",
		"IPSEC_VPN_L2TP_NET": "192.168.42.0/24", "IPSEC_VPN_L2TP_POOL": "192.168.42.10-192.168.42.250",
		"IPSEC_VPN_L2TP_LOCAL": "192.168.42.1", "IPSEC_VPN_XAUTH_NET": "192.168.43.0/24",
		"IPSEC_VPN_XAUTH_POOL": "192.168.43.10-192.168.43.250", "IPSEC_VPN_SHA2_TRUNCBUG": "yes",
		"IPSEC_VPN_VPN_ANDROID_MTU_FIX": "yes", "IPSEC_VPN_DISABLE_IKEV2": "no",
		"IPSEC_VPN_DISABLE_L2TP": "no", "IPSEC_VPN_DISABLE_XAUTH": "no", "IPSEC_VPN_C2C_TRAFFIC": "no",
		"XRAY_SITE_NAME": "www.googletagmanager.com", "PERSISTENT_KEEPALIVE": "25-35",
	} {
		m[k] = v
	}
	return m
}

// Граница имени: $NAME2 — не $NAME (ревью-1 I2). Подстрочная замена дала
// бы «amnezia-awg22» и молча прошла бы.
func TestRenderNameBoundary(t *testing.T) {
	cases := []struct{ txt, want string }{
		{"a $CONTAINER_NAME b", "a amnezia-awg2 b"},
		{"a $CONTAINER_NAME/x", "a amnezia-awg2/x"},
		{"a $CONTAINER_NAME2", ""},
		{"a $CONTAINER_NAME_X", ""},
	}
	for _, c := range cases {
		got, err := render(Rev5106, "remove_container.sh", c.txt, map[string]string{"CONTAINER_NAME": "amnezia-awg2"})
		if c.want == "" {
			if err == nil {
				t.Errorf("%q: принято как %q", c.txt, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q: %q, %v", c.txt, got, err)
		}
	}
}

// «Ставит» без закреплённого бинаря не выдаётся ни из таблицы, ни в
// подписи (ревью-1 M1). Доезд: строка таблицы, а не присваивание State.
func TestSupportYesNeedsPinnedBinary(t *testing.T) {
	saved := installSupports["x"]
	defer func() { installSupports["x"] = saved; delete(installSupports, "x") }()
	installSupports["x"] = map[string]Support{
		"a": {State: SupportYes, BinaryPinned: false},
		"b": {State: SupportYes, BinaryPinned: true},
	}
	if s := InstallSupport("x", "a"); s.State != SupportScriptOnly {
		t.Errorf("незакреплённый бинарь выдан как %v", s.State)
	}
	if s := InstallSupport("x", "b"); s.State != SupportYes {
		t.Errorf("закреплённый: %v", s.State)
	}
	labels := map[string]SupportState{}
	for _, st := range []SupportState{SupportUnknown, SupportYes, SupportScriptOnly, SupportPartial, SupportNo} {
		if prev, dup := labels[st.String()]; dup {
			t.Errorf("подписи %v и %v совпадают", prev, st)
		}
		labels[st.String()] = st
	}
	if a, b := InstallSupport(Rev5106, "1.5"), InstallSupport(Rev5106, "3.1"); a.State == b.State {
		t.Errorf("1.5 и 3.1 неразличимы: %v", a.State)
	}
	if !strings.Contains(InstallSupport(Rev5106, "XRay").Note, "v26.7.28") {
		t.Error("в Note XRay 5.1.0.6 нет расхождения версий")
	}
}

func TestRenderLeftover(t *testing.T) {
	for _, txt := range []string{"echo $AWG_SERVER_PORT $NEW_VAR", "echo ${AWG_SERVER_PORT}"} {
		if _, err := render(Rev5106, "remove_container.sh", txt, map[string]string{"CONTAINER_NAME": "amnezia-awg2"}); err == nil {
			t.Errorf("%q: принято", txt)
		}
	}
	if _, err := render(Rev5106, "remove_container.sh", "x $CONTAINER_NAME $lower", map[string]string{"CONTAINER_NAME": "amnezia-awg2"}); err != nil {
		t.Errorf("переменные в нижнем регистре — оболочки: %v", err)
	}
	if _, err := Render("nope", "remove_container.sh", nil); err == nil {
		t.Error("незакреплённая ревизия")
	}
}

func TestInstallSupports(t *testing.T) {
	families := []string{"3.1", "2", "1.5", "старый AWG", "WireGuard", "XRay"}
	for _, rev := range RevisionIDs() {
		for _, f := range families {
			s := InstallSupport(rev, f)
			want := map[string]SupportState{"1.5": SupportPartial}[f]
			if want == SupportUnknown {
				want = SupportScriptOnly
			}
			if s.State != want || s.Source == "" || s.Container == "" || s.BinaryPinned {
				t.Errorf("%s/%s: %+v, ожидалось %v", rev, f, s, want)
			}
			if _, ok := revisions[rev].Files[strings.SplitN(s.Source, ":", 2)[0]]; !ok {
				t.Errorf("%s/%s: источник %q не вендоренный файл", rev, f, s.Source)
			}
		}
	}
	// Различение: «нет данных» ≠ «не ставит».
	cases := []struct{ rev, fam string }{
		{Rev5106, ""}, // protoVersion при неизвестной версии отдаёт ""
		{Rev5106, "OpenVPN"},
		{"nope", "XRay"},
	}
	for _, c := range cases {
		s := InstallSupport(c.rev, c.fam)
		if s.State != SupportUnknown || s.State == SupportNo {
			t.Errorf("%q/%q: %v, ожидалось «нет данных»", c.rev, c.fam, s.State)
		}
		if s.State.String() == SupportNo.String() {
			t.Error("подпись «нет данных» совпала с «не ставит»")
		}
	}
	if (Support{}).State != SupportUnknown {
		t.Error("нулевое значение — не «нет данных»")
	}
}
