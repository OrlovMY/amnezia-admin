package core

// Тесты BuildAdminKey/VerifyAdminKey/ProtocolParamsFromServer (PR 6).
// Сервер — поддельный SSH на 127.0.0.1:0 (sshauth_test.go); реальных
// серверов нет. Конфигурации сервера — фейки той же формы, что у
// установки (awg2Conf, xraySrcJSON из provision_install_test.go).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

const adminKeyPw = "Канарейка-админ-пароль-Q9z"

func mustParams(t *testing.T, container string, conf string) map[string]any {
	t.Helper()
	p, err := ProtocolParamsFromServer(container, []byte(conf))
	if err != nil {
		t.Fatalf("%s: %v", container, err)
	}
	return p
}

func adminInputT(t *testing.T, pw string, port int) AdminKeyInput {
	t.Helper()
	awg := mustParams(t, "amnezia-awg2", awg2Conf)
	awg["last_config"] = "КЛИЕНТСКИЙ"
	return AdminKeyInput{
		Host: "127.0.0.1", Port: port, User: "root",
		Password: NewSecret([]byte(pw)), PasswordConsent: true,
		Containers: []AdminKeyContainer{
			{Name: "amnezia-awg2", Protocol: awg},
			{Name: "amnezia-xray", Protocol: mustParams(t, "amnezia-xray", xraySrcJSON("443"))},
		},
		DefaultContainer: "amnezia-awg2",
		Description:      "Сервер",
	}
}

func pemKey(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	return string(pem.EncodeToMemory(blk)), sp
}

// Параметры с реальной формы конфигураций; приватный ключ сервера и
// клиенты в них не попадают.
func TestProtocolParamsFromServer(t *testing.T) {
	awg := mustParams(t, "amnezia-awg2", awg2Conf)
	want := map[string]string{"port": "51820", "transport_proto": "udp", "subnet_address": "10.8.1.0", "subnet_cidr": "24",
		"Jc": "4", "Jmin": "10", "Jmax": "50", "S1": "20", "S2": "30", "S3": "15", "S4": "25",
		"H1": "100-200", "H2": "300-400", "H3": "500-600", "H4": "700-800"}
	if len(awg) != len(want) {
		t.Fatalf("awg2: %d полей, ожидалось %d", len(awg), len(want))
	}
	for k, v := range want {
		if awg[k] != v {
			t.Errorf("awg2 %s = %v, ожидалось %s", k, awg[k], v)
		}
	}
	x := mustParams(t, "amnezia-xray", xraySrcJSON("8443"))
	if x["port"] != "8443" || x["transport_proto"] != "tcp" || x["site"] != "www.example.com" || len(x) != 3 {
		t.Fatalf("xray: %v", x)
	}
	wg := mustParams(t, "amnezia-wireguard", "[Interface]\nPrivateKey = K\nAddress = 10.8.2.0/24\nListenPort = 51821\n")
	if wg["port"] != "51821" || wg["subnet_address"] != "10.8.2.0" {
		t.Fatalf("wireguard: %v", wg)
	}
	// AWG1-конфиг без S3/S4 как awg2 — отказ с перечнем, а не неполный набор.
	awg1 := strings.Replace(strings.Replace(awg2Conf, "S3 = 15\n", "", 1), "S4 = 25\n", "", 1)
	_, err := ProtocolParamsFromServer("amnezia-awg2", []byte(awg1))
	if !errors.Is(err, ErrAdminKeyNoProtocolParams) || !strings.Contains(err.Error(), "S3, S4") {
		t.Fatalf("awg2 без S3/S4: %v", err)
	}
	if _, err := ProtocolParamsFromServer("amnezia-awg2", []byte("[Interface]\nPrivateKey = K\n")); !errors.Is(err, ErrAdminKeyNoProtocolParams) {
		t.Fatalf("пустой awg: %v", err)
	}
	if _, err := ProtocolParamsFromServer("amnezia-xray", []byte(`{"x":1}`)); !errors.Is(err, ErrAdminKeyNoProtocolParams) {
		t.Fatalf("чужой server.json: %v", err)
	}
	if _, err := ProtocolParamsFromServer("amnezia-openvpn", nil); err == nil {
		t.Fatal("незнакомый контейнер принят")
	}
}

// Различение: без параметров — отказ; с параметрами — ключ, и после
// DecodeVpnKey параметры на месте.
func TestAdminKeyProtocolParamsRequired(t *testing.T) {
	for _, c := range []string{"amnezia-awg", "amnezia-awg2", "amnezia-wireguard", "amnezia-xray"} {
		for name, p := range map[string]map[string]any{
			"nil":        nil,
			"{}":         {},
			"порт-число": {"port": 51820},
		} {
			in := adminInputT(t, adminKeyPw, 22)
			in.Containers = []AdminKeyContainer{{Name: c, Protocol: p}}
			in.DefaultContainer = c
			k, err := BuildAdminKey(in)
			if !errors.Is(err, ErrAdminKeyNoProtocolParams) || k.Len() != 0 || !strings.Contains(err.Error(), "port") {
				t.Errorf("%s/%s: %v", c, name, err)
			}
		}
	}
	// Полный набор, но порт числом: приложение прочтёт его toString() как "".
	in := adminInputT(t, adminKeyPw, 22)
	in.Containers[0].Protocol["port"] = 51820
	if _, err := BuildAdminKey(in); !errors.Is(err, ErrAdminKeyNoProtocolParams) || !strings.Contains(err.Error(), "нет port") {
		t.Errorf("порт числом при полном наборе: %v", err)
	}
	in = adminInputT(t, adminKeyPw, 22)
	k, err := BuildAdminKey(in)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := DecodeVpnKey(k.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	cs := cfg["containers"].([]any)
	got := cs[0].(map[string]any)["awg"].(map[string]any)
	for _, f := range protocolRequired["amnezia-awg2"] {
		if got[f] != in.Containers[0].Protocol[f] {
			t.Errorf("awg2 %s после разбора: %v", f, got[f])
		}
	}
	if cs[1].(map[string]any)["xray"].(map[string]any)["site"] != "www.example.com" {
		t.Error("xray site после разбора")
	}
}

// Обратная совместимость: тот же разборщик, что читает ключи владельца,
// возвращает те же значения — и для пароля, и для PEM-ключа.
func TestAdminKeyRoundTrip(t *testing.T) {
	pk, _ := pemKey(t)
	for name, pw := range map[string]string{"пароль": adminKeyPw, "PEM": pk} {
		t.Run(name, func(t *testing.T) {
			in := adminInputT(t, pw, 2222)
			key, err := BuildAdminKey(in)
			if err != nil {
				t.Fatal(err)
			}
			s := key.Reveal()
			if !strings.HasPrefix(s, "vpn://") || strings.Contains(s, "=") {
				t.Fatalf("не vpn://base64url без «=»")
			}
			raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, "vpn://"))
			if err != nil || len(raw) < 6 || raw[4] != 0x78 {
				t.Fatalf("не qCompress")
			}
			js, _ := zlibDecompress(raw[4:])
			if int(binary.BigEndian.Uint32(raw[:4])) != len(js) {
				t.Fatalf("длина qCompress не совпала")
			}
			cfg, err := DecodeVpnKey(s)
			if err != nil {
				t.Fatal(err)
			}
			c, err := CredsFromConfig(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if c.Host != "127.0.0.1" || c.Port != "2222" || c.User != "root" || c.Password != pw {
				t.Fatalf("разбор дал другие значения")
			}
			if _, ok := cfg["port"].(float64); !ok {
				t.Fatalf("port не число — приложение читает toInt()")
			}
			if cfg["formatVersion"] != float64(1) || cfg["defaultContainer"] != "amnezia-awg2" || cfg["description"] != "Сервер" {
				t.Fatalf("formatVersion/defaultContainer/description")
			}
			awg := cfg["containers"].([]any)[0].(map[string]any)
			if awg["container"] != "amnezia-awg2" || awg["awg"].(map[string]any)["port"] != "51820" {
				t.Fatalf("контейнер awg2")
			}
			if _, ok := awg["awg"].(map[string]any)["last_config"]; ok {
				t.Fatal("last_config попал в ключ полного доступа")
			}
		})
	}
}

// Различение: нет согласия ≠ нет пароля ≠ выдан; ни один отказ не даёт ключа.
func TestAdminKeyConsentAndPassword(t *testing.T) {
	in := adminInputT(t, adminKeyPw, 22)
	in.PasswordConsent = false
	k, err := BuildAdminKey(in)
	if !errors.Is(err, ErrAdminKeyNoConsent) || k.Len() != 0 {
		t.Fatalf("без согласия: %v, %d байт", err, k.Len())
	}
	in = adminInputT(t, "", 22)
	k, err = BuildAdminKey(in)
	if !errors.Is(err, ErrAdminKeyNoPassword) || errors.Is(err, ErrAdminKeyNoConsent) || k.Len() != 0 {
		t.Fatalf("без пароля: %v", err)
	}
	in.PasswordConsent = false
	if _, err = BuildAdminKey(in); !errors.Is(err, ErrAdminKeyNoConsent) {
		t.Fatalf("%v", err)
	}
}

// adminLeak — детектор утечки: пароль, PEM-тело или начало ключа.
func adminLeak(s string, secrets ...string) bool {
	for _, x := range secrets {
		if x != "" && strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// leakMarks — что искать: пароль целиком, кусок тела PEM, начало ключа.
func leakMarks(pw string, key AdminKey) []string {
	m := []string{pw}
	if strings.Contains(pw, "PRIVATE KEY") {
		lines := strings.Split(pw, "\n")
		m = append(m, lines[1][:20])
	}
	if key.Len() > 0 {
		m = append(m, strings.TrimPrefix(key.Reveal(), "vpn://")[:24])
	}
	return m
}

// Все отказы BuildAdminKey — без пароля/PEM в тексте (таблично).
func TestAdminKeyBuildErrorsNoLeak(t *testing.T) {
	pk, _ := pemKey(t)
	for pwName, pw := range map[string]string{"пароль": adminKeyPw, "PEM": pk} {
		cases := map[string]func(*AdminKeyInput){
			"нет согласия": func(i *AdminKeyInput) { i.PasswordConsent = false },
			"незнакомый контейнер": func(i *AdminKeyInput) {
				i.Containers = append(i.Containers, AdminKeyContainer{Name: "amnezia-openvpn"})
			},
			"дубль":                func(i *AdminKeyInput) { i.Containers = append(i.Containers, i.Containers[1]) },
			"умолчание вне списка": func(i *AdminKeyInput) { i.DefaultContainer = "amnezia-wireguard" },
			"порт 0":               func(i *AdminKeyInput) { i.Port = 0 },
			"нет адреса":           func(i *AdminKeyInput) { i.Host = "" },
			"нет пользователя":     func(i *AdminKeyInput) { i.User = "" },
			"нет параметров":       func(i *AdminKeyInput) { i.Containers[0].Protocol = nil },
		}
		marks := leakMarks(pw, AdminKey{})
		if !adminLeak(pw, marks...) {
			t.Fatal("детектор не срабатывает на сам пароль")
		}
		for n, f := range cases {
			in := adminInputT(t, pw, 22)
			f(&in)
			k, err := BuildAdminKey(in)
			if err == nil || k.Len() != 0 {
				t.Errorf("%s/%s: ключ выдан", pwName, n)
				continue
			}
			if adminLeak(err.Error(), marks...) || adminLeak(fmt.Sprintf("%+v %#v", err, err), marks...) {
				t.Errorf("%s/%s: секрет в тексте ошибки", pwName, n)
			}
		}
	}
}

// Канарейка печати и сериализации: ключ не виден ни через fmt, ни через
// json.Marshal (сам по себе и в составе структуры).
func TestAdminKeyNotPrinted(t *testing.T) {
	key, err := BuildAdminKey(adminInputT(t, adminKeyPw, 22))
	if err != nil {
		t.Fatal(err)
	}
	marks := leakMarks(adminKeyPw, key)
	if !adminLeak(key.Reveal(), marks...) {
		t.Fatal("детектор утечки не срабатывает на сам ключ")
	}
	holder := struct {
		K  AdminKey
		KP *AdminKey
	}{key, &key}
	jk, err1 := json.Marshal(key)
	jh, err2 := json.Marshal(holder)
	jm, err3 := json.Marshal(map[string]any{"k": key})
	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatal(err1, err2, err3)
	}
	for _, s := range []string{
		fmt.Sprint(key), fmt.Sprintf("%v %s %+v %#v %q %x %X", key, key, key, key, key, key, key),
		fmt.Sprintf("%v %+v %#v", holder, holder, holder), key.String(), key.GoString(),
		string(jk), string(jh), string(jm),
	} {
		if adminLeak(s, marks...) {
			t.Fatalf("ключ виден при печати/сериализации")
		}
	}
}

// Каждая ветка несовпадения VerifyAdminKey — ErrAdminKeyMismatch и текст
// без пароля/PEM/ключа (таблично, для пароля и PEM).
func TestVerifyAdminKeyMismatchNoLeak(t *testing.T) {
	pk, _ := pemKey(t)
	for pwName, pw := range map[string]string{"пароль": adminKeyPw, "PEM": pk} {
		key, err := BuildAdminKey(adminInputT(t, pw, 22))
		if err != nil {
			t.Fatal(err)
		}
		marks := leakMarks(pw, key)
		for n, f := range map[string]func(*AdminKeyInput){
			"host":      func(i *AdminKeyInput) { i.Host = "127.0.0.2" },
			"port":      func(i *AdminKeyInput) { i.Port = 23 },
			"user":      func(i *AdminKeyInput) { i.User = "admin" },
			"password":  func(i *AdminKeyInput) { i.Password = NewSecret([]byte("другой")) },
			"контейнер": func(i *AdminKeyInput) { i.Containers = i.Containers[:1] },
			"имя":       func(i *AdminKeyInput) { i.Containers[1].Name = "amnezia-wireguard" },
			"параметр":  func(i *AdminKeyInput) { i.Containers[0].Protocol["Jc"] = "5" },
			"умолчание": func(i *AdminKeyInput) { i.DefaultContainer = "amnezia-xray" },
		} {
			w := adminInputT(t, pw, 22)
			f(&w)
			err := VerifyAdminKey(key, w, "SHA256:x", filepath.Join(t.TempDir(), "kh"))
			if !errors.Is(err, ErrAdminKeyMismatch) {
				t.Errorf("%s/%s: %v", pwName, n, err)
				continue
			}
			if adminLeak(err.Error(), marks...) || adminLeak(fmt.Sprintf("%+v %#v", err, err), marks...) {
				t.Errorf("%s/%s: секрет в тексте ошибки", pwName, n)
			}
		}
		// Ключ не разбирается / нет SSH-доступа.
		bad := AdminKey{s: NewSecret([]byte(key.Reveal()[:len(key.Reveal())-3] + "!!!"))}
		if err := VerifyAdminKey(bad, adminInputT(t, pw, 22), "SHA256:x", "kh"); !errors.Is(err, ErrAdminKeyMismatch) || adminLeak(err.Error(), marks...) {
			t.Errorf("%s/битый: %v", pwName, err != nil)
		}
	}
}

// Доезд: проверка проходит боевым путём ConnectWithHostKey с закреплённым
// отпечатком на поддельном сервере; три исхода различимы.
func TestVerifyAdminKey(t *testing.T) {
	pk, pub := pemKey(t)
	for name, tc := range map[string]struct {
		pw   string
		keys []ssh.PublicKey
	}{
		"пароль": {pw: adminKeyPw},
		"PEM":    {pw: pk, keys: []ssh.PublicKey{pub}},
	} {
		t.Run(name, func(t *testing.T) {
			allowPw := ""
			if tc.keys == nil {
				allowPw = tc.pw
			}
			srv := startFakeAuthServer(t, tc.keys, allowPw)
			port, _ := strconv.Atoi(srv.port)
			in := adminInputT(t, tc.pw, port)
			key, err := BuildAdminKey(in)
			if err != nil {
				t.Fatal(err)
			}
			fp := ssh.FingerprintSHA256(srv.hostKey.PublicKey())
			kh := filepath.Join(t.TempDir(), "known_hosts")
			if err := VerifyAdminKey(key, in, fp, kh); err != nil {
				t.Fatalf("проверка не прошла: %v", err)
			}
			err = VerifyAdminKey(key, in, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", filepath.Join(t.TempDir(), "kh"))
			if err == nil || errors.Is(err, ErrAdminKeyMismatch) || !errors.Is(err, ErrHostKeyMismatch) {
				t.Fatalf("чужой отпечаток: %v", err)
			}
			if err = VerifyAdminKey(key, in, "", kh); err == nil || errors.Is(err, ErrAdminKeyMismatch) {
				t.Fatalf("пустой отпечаток: %v", err)
			}
		})
	}

	// Вход отвергнут — третье состояние, не «ключ не тот» и не nil.
	srv := startFakeAuthServer(t, nil, adminKeyPw)
	port, _ := strconv.Atoi(srv.port)
	in := adminInputT(t, "неверный-пароль", port)
	k2, _ := BuildAdminKey(in)
	err := VerifyAdminKey(k2, in, ssh.FingerprintSHA256(srv.hostKey.PublicKey()), filepath.Join(t.TempDir(), "kh"))
	if err == nil || errors.Is(err, ErrAdminKeyMismatch) || adminLeak(err.Error(), "неверный-пароль") {
		t.Fatalf("отказ входа: %v", err)
	}
}

// Аудит AU PR #69, L1: входная структура с паролем в JSON не попадает.
func TestAdminKeyInputNotMarshaled(t *testing.T) {
	in := AdminKeyInput{Host: "h", User: "root", Password: NewSecret([]byte("hunter2-L1-marker"))}
	for name, f := range map[string]func() ([]byte, error){
		"json":        func() ([]byte, error) { return json.Marshal(in) },
		"json-ptr":    func() ([]byte, error) { return json.Marshal(&in) },
		"json-nested": func() ([]byte, error) { return json.Marshal(struct{ X AdminKeyInput }{in}) },
	} {
		b, err := f()
		if err == nil || strings.Contains(string(b), "aHVudGVy") || strings.Contains(string(b), "hunter2") {
			t.Errorf("%s: err=%v out=%q", name, err, b)
		}
	}
}
