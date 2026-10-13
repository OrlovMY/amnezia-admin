package core_test

// Серия QR формата AmneziaVPN: тест-зеркало их декодера
// (importController.cpp:321-382 parseQrCodeChunk + extractConfigFromQr п.3)
// от PNG до .conf. Подмены, обязанные ронять тест: магия little-endian,
// last_config объектом, кусок 851 вместо 850, без 4-байтной длины qCompress,
// StdEncoding вместо URL, коррекция не LOW, ключ протокола "awg2".
// Живым сканом приложения НЕ проверено.

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"strings"
	"testing"

	"amnezia-admin/core"

	"github.com/makiuchi-d/gozxing"
	gzqr "github.com/makiuchi-d/gozxing/qrcode"
)

// mirrorAssemble — их parseQrCodeChunk: куски в любом порядке, повтор
// безвреден; возвращает склеенные байты qCompress.
func mirrorAssemble(t *testing.T, texts []string) []byte {
	t.Helper()
	parts := map[int][]byte{}
	total := -1
	for _, s := range texts {
		blk, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("кусок не base64url без «=»: %v", err)
		}
		if len(blk) < 8 {
			t.Fatalf("кусок короче заголовка: %d", len(blk))
		}
		if m := int16(binary.BigEndian.Uint16(blk[0:2])); m != 1984 {
			t.Fatalf("магия %d, ждали 1984 (qint16 BE)", m)
		}
		n, i := int(blk[2]), int(blk[3])
		if total != -1 && n != total {
			t.Fatalf("число кусков менялось: %d → %d", total, n)
		}
		total = n
		l := binary.BigEndian.Uint32(blk[4:8])
		if int(l) != len(blk)-8 {
			t.Fatalf("длина куска %d, а данных %d (QByteArray: uint32 BE)", l, len(blk)-8)
		}
		parts[i] = blk[8:]
	}
	if len(parts) != total {
		t.Fatalf("собрано %d из %d", len(parts), total)
	}
	var q []byte
	for i := 0; i < total; i++ {
		p, ok := parts[i]
		if !ok {
			t.Fatalf("нет куска %d", i)
		}
		// Свойство их кодера (qrCodeUtils.cpp:16): все, кроме последнего, — 850.
		if (i < total-1 && len(p) != 850) || len(p) > 850 {
			t.Fatalf("кусок %d: %d байт, ждали 850 (последний ≤ 850)", i, len(p))
		}
		q = append(q, p...)
	}
	return q
}

// mirrorUncompress — qUncompress: 4 байта BE длины + zlib.
func mirrorUncompress(t *testing.T, q []byte) []byte {
	t.Helper()
	if len(q) < 4 {
		t.Fatal("нет 4-байтной длины qCompress")
	}
	r, err := zlib.NewReader(bytes.NewReader(q[4:]))
	if err != nil {
		t.Fatalf("после 4 байт длины не zlib: %v", err)
	}
	js, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if n := binary.BigEndian.Uint32(q[:4]); int(n) != len(js) {
		t.Fatalf("длина qCompress %d, распаковано %d", n, len(js))
	}
	return js
}

// mirrorConf — разбор JSON как в приложении: контейнер, ключ протокола,
// last_config СТРОКОЙ с JSON → config.
func mirrorConf(t *testing.T, js []byte, container, proto string) (string, map[string]any) {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(js, &top); err != nil {
		t.Fatalf("не JSON: %v", err)
	}
	if v, _ := top["format_version"].(float64); v != 1 {
		t.Fatalf("format_version %v, ждали 1", top["format_version"])
	}
	if top["defaultContainer"] != container {
		t.Fatalf("defaultContainer %v", top["defaultContainer"])
	}
	cs, _ := top["containers"].([]any)
	if len(cs) != 1 {
		t.Fatalf("контейнеров %d", len(cs))
	}
	c0, _ := cs[0].(map[string]any)
	if c0["container"] != container {
		t.Fatalf("container %v", c0["container"])
	}
	pc, ok := c0[proto].(map[string]any)
	if !ok {
		t.Fatalf("нет ключа протокола %q: %v", proto, keysOf(c0))
	}
	lc, ok := pc["last_config"].(string)
	if !ok {
		t.Fatalf("last_config не строка (%T): приложение получит пусто", pc["last_config"])
	}
	var cl map[string]any
	if err := json.Unmarshal([]byte(lc), &cl); err != nil {
		t.Fatalf("last_config не JSON: %v", err)
	}
	conf, _ := cl["config"].(string)
	return conf, pc
}

func keysOf(m map[string]any) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return k
}

// decodePNG — тест доезда от картинки: PNG → текст и уровень коррекции.
func decodePNG(t *testing.T, b []byte) (string, string) {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		t.Fatal(err)
	}
	res, err := gzqr.NewQRCodeReader().Decode(bmp, map[gozxing.DecodeHintType]any{gozxing.DecodeHintType_PURE_BARCODE: true})
	if err != nil {
		t.Fatalf("PNG не распознан как QR: %v", err)
	}
	return res.GetText(), fmt.Sprint(res.GetResultMetadata()[gozxing.ResultMetadataType_ERROR_CORRECTION_LEVEL])
}

// wgClientConf — клиентский .conf WireGuard с настоящими по форме ключами.
func wgClientConf(extra string) string {
	k := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	return "[Interface]\nPrivateKey = " + k(7) + "\nAddress = 10.8.1.5/32\nDNS = 1.1.1.1, 1.0.0.1\n" + extra +
		"\n[Peer]\nPublicKey = " + k(9) + "\nPresharedKey = " + k(11) + "\nAllowedIPs = 0.0.0.0/0, ::/0\n" +
		"Endpoint = 203.0.113.10:51820\nPersistentKeepalive = 25\n"
}

func TestAmneziaQRRoundTrip(t *testing.T) {
	for _, c := range []struct {
		name, container, proto, conf string
		minChunks                    int
	}{
		{"WireGuard, один кусок", "amnezia-wireguard", "wireguard", wgClientConf(""), 1},
		{"AmneziaWG", "amnezia-awg", "awg", wgClientConf("Jc = 4\nJmin = 10\nJmax = 50\nS1 = 20\nS2 = 30\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n"), 1},
		{"AWG2, огромный I1 (не влезает в один QR)", "amnezia-awg2", "awg", awg2Config(t, 6000), 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			texts, key, err := core.AmneziaQRTexts(c.conf, c.container)
			if err != nil {
				t.Fatalf("серия не построена: %v", err)
			}
			if len(texts) < c.minChunks {
				t.Fatalf("проверка ничего не значит: кусков %d < %d", len(texts), c.minChunks)
			}
			// Порядок сканирования любой, повтор безвреден: обратный порядок + повтор.
			rev := []string{texts[0]}
			for i := len(texts) - 1; i >= 0; i-- {
				rev = append(rev, texts[i])
			}
			got, pc := mirrorConf(t, mirrorUncompress(t, mirrorAssemble(t, rev)), c.container, c.proto)
			if got != c.conf {
				t.Fatalf("config из last_config не совпал с исходным .conf (%d и %d байт)", len(got), len(c.conf))
			}
			if c.container == "amnezia-awg2" && pc["protocol_version"] != "2" {
				t.Errorf("AWG2 без protocol_version \"2\": %v", pc["protocol_version"])
			}
			// Обратный путь — наш DecodeVpnKey (тот же qCompress).
			m, err := core.DecodeVpnKey(key)
			if err != nil || m["defaultContainer"] != c.container {
				t.Fatalf("DecodeVpnKey: %v %v", err, m["defaultContainer"])
			}
			// Доезд от картинки: PNG → тот же текст, коррекция L.
			pngs, err := core.AmneziaQRSeries(c.conf, c.container)
			if err != nil || len(pngs) != len(texts) {
				t.Fatalf("PNG серии: %v, %d из %d", err, len(pngs), len(texts))
			}
			for i, p := range pngs {
				txt, lvl := decodePNG(t, p)
				if txt != texts[i] {
					t.Fatalf("QR %d: распознан другой текст", i+1)
				}
				if lvl != "L" {
					t.Fatalf("QR %d: коррекция %q, у приложения LOW", i+1, lvl)
				}
			}
		})
	}
}

// Доезд: AddUser боевым путём кладёт имя контейнера — по нему GUI решает,
// строить ли серию. Пустое имя — серии не будет вовсе.
func TestAddUserCarriesContainer(t *testing.T) {
	sess := core.NewSessionWithRunner(awg2With(t, awg3Extra), raceCreds())
	cs, err := sess.FindContainers()
	if err != nil || len(cs) != 1 {
		t.Fatalf("%v %+v", err, cs)
	}
	u, err := sess.AddUser(&cs[0], "Dave")
	if err != nil {
		t.Fatal(err)
	}
	if u.Container != "amnezia-awg2" {
		t.Fatalf("NewUser.Container = %q, ждали amnezia-awg2", u.Container)
	}
}

// Заголовок сервера в приложении (description) и hostName — адрес, с которым
// выдан конфиг: DNS-имя, если выбрано, иначе адрес ключа. Боевым путём:
// AddUser на fakesrv → .conf → ключ AmneziaVPN → их декодер. Подмена
// «description = подпись списка / Сервер N» роняет тест.
func TestAmneziaQRDescriptionIsEndpoint(t *testing.T) {
	for _, c := range []struct{ name, clientHost, want string }{
		{"DNS-имя выбрано", "vpn.example.com", "vpn.example.com"},
		{"IP оставлен", "", raceCreds().Host},
	} {
		t.Run(c.name, func(t *testing.T) {
			sess := core.NewSessionWithRunner(awg2With(t, awg3Extra), raceCreds())
			sess.ClientHost = c.clientHost
			cs, err := sess.FindContainers()
			if err != nil || len(cs) != 1 {
				t.Fatalf("%v %+v", err, cs)
			}
			u, err := sess.AddUser(&cs[0], "Eve")
			if err != nil {
				t.Fatal(err)
			}
			texts, _, err := core.AmneziaQRTexts(u.Config, u.Container)
			if err != nil {
				t.Fatal(err)
			}
			var top map[string]any
			if err := json.Unmarshal(mirrorUncompress(t, mirrorAssemble(t, texts)), &top); err != nil {
				t.Fatal(err)
			}
			if top["description"] != c.want || top["hostName"] != c.want {
				t.Fatalf("description %q, hostName %q, ждали %q", top["description"], top["hostName"], c.want)
			}
		})
	}
}

// Третье состояние: серия не построена — ошибка с причиной, а не пустая серия.
func TestAmneziaQRRefuses(t *testing.T) {
	if _, _, err := core.AmneziaQRTexts(wgClientConf(""), "amnezia-xray"); !errors.Is(err, core.ErrAmneziaQRContainer) {
		t.Errorf("XRay: ждали ErrAmneziaQRContainer, получили %v", err)
	}
	noEP := strings.Replace(wgClientConf(""), "Endpoint = 203.0.113.10:51820\n", "", 1)
	texts, _, err := core.AmneziaQRTexts(noEP, "amnezia-awg")
	if err == nil || texts != nil || !strings.Contains(err.Error(), "Endpoint") {
		t.Errorf("без Endpoint: ждали ошибку с полем, получили %v, %d кусков", err, len(texts))
	}
	if strings.Contains(fmt.Sprint(err), "PrivateKey =") {
		t.Errorf("ошибка несёт содержимое конфига: %v", err)
	}
}
