package core

// Тесты BuildAdminKey/VerifyAdminKey (PR 6). Сервер — поддельный SSH на
// 127.0.0.1:0 (sshauth_test.go); реальных серверов нет.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
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

func adminInput(pw string, port int) AdminKeyInput {
	return AdminKeyInput{
		Host: "127.0.0.1", Port: port, User: "root",
		Password: NewSecret([]byte(pw)), PasswordConsent: true,
		Containers: []AdminKeyContainer{
			{Name: "amnezia-awg2", Protocol: map[string]any{"port": "51820", "last_config": "КЛИЕНТСКИЙ"}},
			{Name: "amnezia-xray"},
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

// Обратная совместимость: тот же разборщик, что читает ключи владельца,
// возвращает те же значения — и для пароля, и для PEM-ключа.
func TestAdminKeyRoundTrip(t *testing.T) {
	pk, _ := pemKey(t)
	for name, pw := range map[string]string{"пароль": adminKeyPw, "PEM": pk} {
		t.Run(name, func(t *testing.T) {
			in := adminInput(pw, 2222)
			key, err := BuildAdminKey(in)
			if err != nil {
				t.Fatal(err)
			}
			s := string(key.Bytes())
			if !strings.HasPrefix(s, "vpn://") || strings.Contains(s, "=") {
				t.Fatalf("не vpn://base64url без «=»")
			}
			// Форма Qt: 4 байта BE длины несжатого + zlib.
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
				t.Fatalf("formatVersion/defaultContainer/description: %v %v %v", cfg["formatVersion"], cfg["defaultContainer"], cfg["description"])
			}
			cs := cfg["containers"].([]any)
			awg := cs[0].(map[string]any)
			if awg["container"] != "amnezia-awg2" || awg["awg"].(map[string]any)["port"] != "51820" {
				t.Fatalf("контейнер awg2: %v", awg["container"])
			}
			if _, ok := awg["awg"].(map[string]any)["last_config"]; ok {
				t.Fatal("last_config попал в ключ полного доступа")
			}
			if x := cs[1].(map[string]any); x["container"] != "amnezia-xray" || x["xray"] == nil {
				t.Fatal("контейнер xray")
			}
		})
	}
}

// Различение: нет согласия ≠ нет пароля ≠ выдан; ни один отказ не даёт ключа.
func TestAdminKeyConsentAndPassword(t *testing.T) {
	in := adminInput(adminKeyPw, 22)
	in.PasswordConsent = false
	k, err := BuildAdminKey(in)
	if !errors.Is(err, ErrAdminKeyNoConsent) || k.Len() != 0 {
		t.Fatalf("без согласия: %v, %d байт", err, k.Len())
	}
	in = adminInput("", 22)
	k, err = BuildAdminKey(in)
	if !errors.Is(err, ErrAdminKeyNoPassword) || errors.Is(err, ErrAdminKeyNoConsent) || k.Len() != 0 {
		t.Fatalf("без пароля: %v", err)
	}
	// Без согласия и без пароля — главное отсутствие согласия.
	in.PasswordConsent = false
	if _, err = BuildAdminKey(in); !errors.Is(err, ErrAdminKeyNoConsent) {
		t.Fatalf("%v", err)
	}
}

func TestAdminKeyRejectsBadInput(t *testing.T) {
	cases := map[string]func(*AdminKeyInput){
		"незнакомый контейнер": func(i *AdminKeyInput) {
			i.Containers = append(i.Containers, AdminKeyContainer{Name: "amnezia-openvpn"})
		},
		"дубль":                func(i *AdminKeyInput) { i.Containers = append(i.Containers, AdminKeyContainer{Name: "amnezia-xray"}) },
		"умолчание вне списка": func(i *AdminKeyInput) { i.DefaultContainer = "amnezia-wireguard" },
		"порт 0":               func(i *AdminKeyInput) { i.Port = 0 },
		"нет адреса":           func(i *AdminKeyInput) { i.Host = "" },
	}
	for n, f := range cases {
		in := adminInput(adminKeyPw, 22)
		f(&in)
		if k, err := BuildAdminKey(in); err == nil || k.Len() != 0 {
			t.Errorf("%s: ключ выдан", n)
		} else if strings.Contains(err.Error(), adminKeyPw) {
			t.Errorf("%s: пароль в ошибке", n)
		}
	}
}

// Канарейка печати: ни ключ целиком, ни его хвост, ни пароль не видны
// через fmt и тексты ошибок (в т.ч. VerifyAdminKey).
func TestAdminKeyNotPrinted(t *testing.T) {
	key, err := BuildAdminKey(adminInput(adminKeyPw, 22))
	if err != nil {
		t.Fatal(err)
	}
	full := string(key.Bytes())
	body := strings.TrimPrefix(full, "vpn://")
	leak := func(s string) bool {
		return strings.Contains(s, body[:24]) || strings.Contains(s, adminKeyPw)
	}
	// Канарейка самого детектора: сырые байты обязаны им ловиться.
	if !leak(full) {
		t.Fatal("детектор утечки не срабатывает на сам ключ")
	}
	holder := struct{ K Secret }{key}
	for _, s := range []string{
		fmt.Sprint(key), fmt.Sprintf("%v %s %+v %#v %q %x", key, key, key, key, key, key),
		fmt.Sprintf("%v %+v", holder, holder), key.String(),
	} {
		if leak(s) {
			t.Fatalf("ключ виден при печати")
		}
	}
	want := adminInput(adminKeyPw, 22)
	want.Host = "10.0.0.1"
	err = VerifyAdminKey(key, want, "SHA256:x", filepath.Join(t.TempDir(), "kh"))
	if err == nil || leak(err.Error()) || leak(fmt.Sprintf("%+v", err)) {
		t.Fatalf("ошибка проверки раскрывает ключ: %v", err == nil)
	}
	bad := NewSecret([]byte(full[:len(full)-3] + "!!!"))
	if err = VerifyAdminKey(bad, want, "SHA256:x", filepath.Join(t.TempDir(), "kh")); err == nil || leak(err.Error()) {
		t.Fatal("ошибка разбора раскрывает ключ")
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
			in := adminInput(tc.pw, port)
			key, err := BuildAdminKey(in)
			if err != nil {
				t.Fatal(err)
			}
			fp := ssh.FingerprintSHA256(srv.hostKey.PublicKey())
			kh := filepath.Join(t.TempDir(), "known_hosts")
			if err := VerifyAdminKey(key, in, fp, kh); err != nil {
				t.Fatalf("проверка не прошла: %v", err)
			}
			// Чужой отпечаток — «не удалось проверить», не «ключ не тот».
			err = VerifyAdminKey(key, in, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", filepath.Join(t.TempDir(), "kh"))
			if err == nil || errors.Is(err, ErrAdminKeyMismatch) || !errors.Is(err, ErrHostKeyMismatch) {
				t.Fatalf("чужой отпечаток: %v", err)
			}
			// Без отпечатка — отказ, а не вход с вопросом/доверием.
			if err = VerifyAdminKey(key, in, "", kh); err == nil || errors.Is(err, ErrAdminKeyMismatch) {
				t.Fatalf("пустой отпечаток: %v", err)
			}
		})
	}

	// Ключ не тот: каждое поле по отдельности.
	key, _ := BuildAdminKey(adminInput(adminKeyPw, 22))
	for n, f := range map[string]func(*AdminKeyInput){
		"host":      func(i *AdminKeyInput) { i.Host = "127.0.0.2" },
		"port":      func(i *AdminKeyInput) { i.Port = 23 },
		"user":      func(i *AdminKeyInput) { i.User = "admin" },
		"password":  func(i *AdminKeyInput) { i.Password = NewSecret([]byte("другой")) },
		"контейнер": func(i *AdminKeyInput) { i.Containers = i.Containers[:1] },
		"умолчание": func(i *AdminKeyInput) { i.DefaultContainer = "amnezia-xray" },
	} {
		w := adminInput(adminKeyPw, 22)
		f(&w)
		if err := VerifyAdminKey(key, w, "SHA256:x", filepath.Join(t.TempDir(), "kh")); !errors.Is(err, ErrAdminKeyMismatch) {
			t.Errorf("%s: %v", n, err)
		}
	}

	// Сервер недоступен — третье состояние, не «ключ не тот» и не nil.
	srv := startFakeAuthServer(t, nil, adminKeyPw)
	port, _ := strconv.Atoi(srv.port)
	in := adminInput("неверный-пароль", port)
	k2, _ := BuildAdminKey(in)
	err := VerifyAdminKey(k2, in, ssh.FingerprintSHA256(srv.hostKey.PublicKey()), filepath.Join(t.TempDir(), "kh"))
	if err == nil || errors.Is(err, ErrAdminKeyMismatch) {
		t.Fatalf("отказ входа: %v", err)
	}
}
