package core

// Серия QR формата приложения AmneziaVPN (amnezia-client f1af8ef,
// core/utils/qrCodeUtils.cpp:9-28, exportController.cpp:96-110,
// importController.cpp:261-382). Текст .conf AmneziaWG 2 с длинными I1–I5
// не влезает в один QR; приложение AmneziaVPN собирает конфиг из серии
// кусков:
//
//	js   — JSON сервера с одним контейнером; last_config — СТРОКА с JSON клиента
//	q    — uint32BE(len(js)) || zlib(js)                (qCompress)
//	кусок i из n (по 850 байт q):
//	       0x07C0 || byte(n) || byte(i) || uint32BE(len) || q[i*850:…]
//	QR_i — base64url без «=», коррекция LOW
//
// Сканер приложения складывает куски в QMap по номеру: порядок сканирования
// любой, повтор безвреден, таймера нет. Живым сканом приложения НЕ проверено.

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/curve25519"
)

// AmneziaQRMagic — магия куска (qrCodeUtils.h:12, qint16 1984).
const AmneziaQRMagic = 1984

// AmneziaQRChunk — размер полезной части куска (qrCodeUtils.cpp:16).
const AmneziaQRChunk = 850

// ErrAmneziaQRContainer — для этого контейнера серия не строится (XRay —
// ссылка vless:// и так влезает в один QR; прочие программа не выдаёт).
var ErrAmneziaQRContainer = errors.New("серия QR AmneziaVPN строится только для WireGuard и AmneziaWG")

// amneziaProtoKey — ключ протокола внутри контейнера: AWG и AWG2 — "awg"
// (containerConfig.cpp:25-37).
func amneziaProtoKey(container string) (string, bool) {
	switch container {
	case "amnezia-awg", "amnezia-awg2":
		return "awg", true
	case "amnezia-wireguard":
		return "wireguard", true
	}
	return "", false
}

// parseConfSections — «ключ = значение» по секциям [Interface] и [Peer].
// Комментарии и пустые строки пропускаются.
func parseConfSections(conf string) (iface, peer map[string]string) {
	iface, peer = map[string]string{}, map[string]string{}
	var cur map[string]string
	for _, ln := range strings.Split(conf, "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case ln == "" || strings.HasPrefix(ln, "#"):
			continue
		case strings.EqualFold(ln, "[Interface]"):
			cur = iface
		case strings.EqualFold(ln, "[Peer]"):
			cur = peer
		default:
			k, v, ok := strings.Cut(ln, "=")
			if ok && cur != nil {
				cur[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	return iface, peer
}

var awgObfKeys = []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"}
var awgSigKeys = []string{"I1", "I2", "I3", "I4", "I5"}

// AmneziaQRJSON — JSON сервера в формате экспорта AmneziaVPN для одного
// клиентского .conf. Ошибка — если в конфиге нет обязательного (ключи,
// адрес сервера): текст ошибки называет поле, но не содержимое конфига.
func AmneziaQRJSON(conf, container string) ([]byte, error) {
	proto, ok := amneziaProtoKey(container)
	if !ok {
		return nil, ErrAmneziaQRContainer
	}
	iface, peer := parseConfSections(conf)
	need := func(m map[string]string, k, sect string) (string, error) {
		if m[k] == "" {
			return "", fmt.Errorf("в конфиге нет %s в [%s]", k, sect)
		}
		return m[k], nil
	}
	priv, err := need(iface, "PrivateKey", "Interface")
	if err != nil {
		return nil, err
	}
	srvPub, err := need(peer, "PublicKey", "Peer")
	if err != nil {
		return nil, err
	}
	endpoint, err := need(peer, "Endpoint", "Peer")
	if err != nil {
		return nil, err
	}
	addr, err := need(iface, "Address", "Interface")
	if err != nil {
		return nil, err
	}
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, errors.New("в конфиге Endpoint не вида адрес:порт")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, errors.New("в конфиге порт Endpoint не число")
	}
	rawPriv, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(rawPriv) != 32 {
		return nil, errors.New("в конфиге PrivateKey не ключ WireGuard")
	}
	rawPub, err := curve25519.X25519(rawPriv, curve25519.Basepoint)
	if err != nil {
		return nil, errors.New("в конфиге PrivateKey не ключ WireGuard")
	}
	clientIP, _, _ := strings.Cut(strings.Split(addr, ",")[0], "/")

	var allowed []string
	for _, a := range strings.Split(peer["AllowedIPs"], ",") {
		if a = strings.TrimSpace(a); a != "" {
			allowed = append(allowed, a)
		}
	}
	client := map[string]any{
		"config":          conf,
		"hostName":        host,
		"port":            port,
		"client_ip":       strings.TrimSpace(clientIP),
		"client_priv_key": priv,
		"client_pub_key":  base64.StdEncoding.EncodeToString(rawPub),
		"server_pub_key":  srvPub,
		"allowed_ips":     allowed,
	}
	if v := peer["PresharedKey"]; v != "" {
		client["psk_key"] = v
	}
	if v := peer["PersistentKeepalive"]; v != "" {
		client["persistent_keep_alive"] = v
	}
	if v := iface["MTU"]; v != "" {
		client["mtu"] = v
	}
	srv := map[string]any{
		"port":            portStr,
		"transport_proto": "udp",
	}
	if proto == "awg" {
		for _, k := range awgObfKeys {
			if v := iface[k]; v != "" {
				client[k], srv[k] = v, v
			}
		}
		for _, k := range awgSigKeys {
			// I1..I5 сервер пишет всегда, даже пустые (awgProtocolConfig.cpp).
			client[k], srv[k] = iface[k], iface[k]
		}
		if container == "amnezia-awg2" {
			client["protocol_version"], srv["protocol_version"] = "2", "2"
		}
	}
	last, err := json.Marshal(client)
	if err != nil {
		return nil, err
	}
	// last_config — СТРОКА с JSON, не объект: объект приложение молча не
	// разберёт и импортирует сервер без клиента (исследование §6.2).
	srv["last_config"] = string(last)

	// description — заголовок сервера в списке приложения (serversModel.cpp
	// NameRole). Это адрес, с которым выдан конфиг (Endpoint = EndpointHost
	// сессии: DNS-имя, если выбрано, иначе адрес ключа), — не «Сервер N» и не
	// подпись нашего списка. Адреса нет — ошибка выше, ничего не выдумываем.
	top := map[string]any{
		"format_version":   1,
		"description":      host,
		"hostName":         host,
		"containers":       []any{map[string]any{"container": container, proto: srv}},
		"defaultContainer": container,
	}
	dns := strings.Split(iface["DNS"], ",")
	if d := strings.TrimSpace(dns[0]); d != "" {
		top["dns1"] = d
	}
	if len(dns) > 1 {
		if d := strings.TrimSpace(dns[1]); d != "" {
			top["dns2"] = d
		}
	}
	return json.MarshalIndent(top, "", "    ")
}

// qCompress — как Qt: uint32 BE длины исходного + zlib-поток.
func qCompress(data []byte) []byte {
	var b bytes.Buffer
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(data)))
	b.Write(n[:])
	w, _ := zlib.NewWriterLevel(&b, 8)
	_, _ = w.Write(data)
	_ = w.Close()
	return b.Bytes()
}

// AmneziaQRChunks режет сжатые байты на тексты QR (base64url без «=»).
func AmneziaQRChunks(q []byte) ([]string, error) {
	n := (len(q) + AmneziaQRChunk - 1) / AmneziaQRChunk
	if n == 0 || n > 255 {
		return nil, fmt.Errorf("серия QR: %d кусков вне 1…255", n)
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		part := q[i*AmneziaQRChunk : min((i+1)*AmneziaQRChunk, len(q))]
		blk := make([]byte, 8, 8+len(part))
		binary.BigEndian.PutUint16(blk[0:2], AmneziaQRMagic)
		blk[2], blk[3] = byte(n), byte(i)
		binary.BigEndian.PutUint32(blk[4:8], uint32(len(part)))
		blk = append(blk, part...)
		out = append(out, base64.RawURLEncoding.EncodeToString(blk))
	}
	return out, nil
}

// AmneziaQRTexts — тексты серии QR и ключ vpn:// (тот же, что отдаёт
// «Поделиться» приложения) для клиентского .conf. Ключ — секрет: не
// печатать, не журналировать.
func AmneziaQRTexts(conf, container string) (texts []string, vpnKey string, err error) {
	js, err := AmneziaQRJSON(conf, container)
	if err != nil {
		return nil, "", err
	}
	q := qCompress(js)
	texts, err = AmneziaQRChunks(q)
	if err != nil {
		return nil, "", err
	}
	return texts, "vpn://" + base64.RawURLEncoding.EncodeToString(q), nil
}

// AmneziaQRModulePx — пикселей на модуль в PNG серии: при 1 пикселе
// (как дало бы size=256 для версии ~24) код мелок для камеры.
const AmneziaQRModulePx = 2

// AmneziaQRSeries — PNG серии QR формата AmneziaVPN, коррекция LOW (как у
// приложения).
func AmneziaQRSeries(conf, container string) ([][]byte, error) {
	texts, _, err := AmneziaQRTexts(conf, container)
	if err != nil {
		return nil, err
	}
	pngs := make([][]byte, 0, len(texts))
	for _, t := range texts {
		png, err := qrcode.Encode(t, qrcode.Low, -AmneziaQRModulePx)
		if err != nil {
			return nil, fmt.Errorf("генерация QR-кода: %w", err)
		}
		pngs = append(pngs, png)
	}
	return pngs, nil
}
