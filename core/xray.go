package core

// XRay (контейнер amnezia-xray, задание AL-01; проект БК-ПРОТОКОЛЫ-AWG2-XRAY,
// разделы 1.2, 2, 3, 4). Источник формы файлов — amnezia-client dev 94b51df
// и master (форма server.json старых серверов):
//
//   - server_scripts/xray/configure_container.sh — ключи xray_uuid.key,
//     xray_short_id.key, xray_public.key, xray_private.key; на master он же
//     пишет server.json, на dev — клиент (writeServerConfigForSetup,
//     core/configurators/xrayConfigurator.cpp:371-472);
//   - start.sh — `killall -KILL xray`, затем `xray -config …/server.json`,
//     затем `tail -f /dev/null`: контейнер живёт и с упавшим xray, поэтому
//     «применено» — это живой ПРОЦЕСС xray, а не состояние контейнера;
//   - изменение клиентов в приложении: правка inbounds[0].settings.clients и
//     `sudo docker restart $CONTAINER_NAME` (xrayConfigurator.cpp:160-182,
//     usersController.cpp:626-727). Горячего применения нет: КАЖДОЕ изменение
//     server.json перезапускает XRay и рвёт подключения всем его клиентам.
//
// Закрытый список формы (раздел 4): всё, что не перечислено, — «формат не
// знаком», только просмотр. Значения полей в причины не попадают: UUID
// клиента — его учётные данные, privateKey — ключ сервера.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

// XRayContainer — имя контейнера XRay (containerTypes, правило «amnezia-» +
// имя типа).
const XRayContainer = "amnezia-xray"

const (
	xrayDir      = "/opt/amnezia/xray"
	xrayConfFile = "server.json"
	xrayUUIDFile = "xray_uuid.key"
	// xrayFlowVision — единственное значение flow, которое пишет amnezia-client
	// (protocolConstants.h: defaultFlow; master configure_container.sh).
	xrayFlowVision = "xtls-rprx-vision"
	// xrayFingerprintDefault — fingerprint клиента, если в server.json его нет
	// (master template.json; protocolConstants.h: defaultFingerprint).
	xrayFingerprintDefault = "chrome"
	// xrayLinkAlias — метка ссылки vless:// (APPLICATION_NAME приложения,
	// exportController.cpp:347).
	xrayLinkAlias = "AmneziaVPN"
)

// IsXRay — контейнер XRay с каталогом из закрытого списка.
func IsXRay(c *Container) bool {
	return c != nil && c.Name == XRayContainer && c.Dir == xrayDir
}

// confFileOf — имя файла конфигурации сервера контейнера: из таблицы
// семейства WG или server.json у XRay. ЕДИНСТВЕННАЯ развилка «какой файл
// пишет запись A3б» — резервная копия, чтение, сверка и запись берут имя
// отсюда.
func confFileOf(c *Container) (string, error) {
	if IsXRay(c) {
		return xrayConfFile, nil
	}
	f, err := WGFamilyOf(c)
	if err != nil {
		return "", err
	}
	return f.File, nil
}

// AmneziaDateLayout — формат creationDate, который пишет приложение Amnezia:
// QDateTime::currentDateTime().toString() — Qt::TextDate, «Thu Oct 1
// 23:18:48 2026» (amnezia-client 94b51df usersController.cpp:437,
// appendClient). Живая проверка 04.10: приложение пишет именно так.
const AmneziaDateLayout = "Mon Jan 2 15:04:05 2006"

// AmneziaDateNow — текущее время в формате приложения Amnezia.
func AmneziaDateNow() string { return time.Now().Format(AmneziaDateLayout) }

// CreatedTime — creationDate как время: формат приложения или прежний
// RFC3339 этой программы; ok == false — не разобрать.
func CreatedTime(s string) (time.Time, bool) {
	for _, l := range []string{AmneziaDateLayout, time.RFC3339} {
		if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// CreatedText — дата создания для показа (CLI list, карточка, GUI таблица):
// разобранная (формат приложения или RFC3339) — «2006-01-02 15:04», с годом;
// не разобранная — исходной строкой целиком (QA-01 р4 Н2: срез до 19 знаков
// терял год у формата приложения).
func CreatedText(s string) string {
	if t, ok := CreatedTime(s); ok {
		return t.Format("2006-01-02 15:04")
	}
	return s
}

// MaskText — граница маскировки текста ошибки перед показом человеку (CLI
// errText, GUI showError): та же maskFreeText, что у ответов сервера, — в
// том числе UUID клиентов XRay (их учётные данные) целиком.
func MaskText(s string) string { return maskFreeText(s) }

// ConfFileName — имя файла конфигурации сервера (для подписей предпросмотра);
// "" — контейнер вне закрытых списков.
func ConfFileName(c *Container) string {
	f, err := confFileOf(c)
	if err != nil {
		return ""
	}
	return f
}

// ---------- отпечаток UUID ----------

var reUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// reUUIDAnywhere — UUID в свободном тексте (граница маскировки maskFreeText).
var reUUIDAnywhere = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)

// UUIDPrint — отпечаток UUID для показа человеку: первые 8 знаков и «…».
// UUID клиента XRay — его учётные данные (проект БК, раздел 5): целиком он
// не печатается нигде, кроме выданного самому клиенту конфига.
func UUIDPrint(id string) string {
	if r := []rune(id); len(r) > 8 {
		return string(r[:8]) + "…"
	}
	return id
}

// KeyText — как показать ClientID клиента контейнера c: у XRay — отпечаток
// UUID, у семейства WG — публичный ключ целиком (он не секрет).
func KeyText(c *Container, clientID string) string {
	if IsXRay(c) {
		return UUIDPrint(clientID)
	}
	return clientID
}

// newUUID — UUID версии 4 (как QUuid::createUuid и `xray uuid`).
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("генерация UUID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// ---------- разбор server.json: закрытый список формы ----------

// xrayServer — разобранный server.json известной формы.
type xrayServer struct {
	root    map[string]any // дерево целиком: незнакомое не теряется
	inbound map[string]any
	ids     []string          // UUID клиентов в порядке файла
	flow    map[string]string // UUID → flow ("" — поля нет)
	// clientFlow — flow, общий для всех клиентов ("" — поля нет у всех): он
	// же у новых и включаемых клиентов.
	clientFlow  string
	port        string
	serverName  string
	shortID     string
	fingerprint string
	publicKey   string // выведен из privateKey
}

// xrayUnknown — причина «формат не знаком» (без значений).
type xrayUnknown struct{ why string }

func (e *xrayUnknown) Error() string { return e.why }

func unknownf(format string, a ...any) error { return &xrayUnknown{fmt.Sprintf(format, a...)} }

// onlyKeys — первый ключ m вне allowed (по алфавиту) или "".
func onlyKeys(m map[string]any, allowed ...string) string {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	var extra []string
	for k := range m {
		if !ok[k] {
			extra = append(extra, k)
		}
	}
	if len(extra) == 0 {
		return ""
	}
	sort.Strings(extra)
	return extra[0]
}

// keyName — имя поля для причины: только похожее на имя, иначе «(имя не показано)».
func keyName(k string) string {
	if len(k) <= 32 && reAWGKeyName.MatchString(k) {
		return k
	}
	return "(имя не показано)"
}

func strField(m map[string]any, k string) (string, bool) {
	v, ok := m[k].(string)
	return v, ok
}

func objField(m map[string]any, k string) (map[string]any, bool) {
	v, ok := m[k].(map[string]any)
	return v, ok
}

// singleString — массив из ровно одной непустой строки.
func singleString(m map[string]any, k string) (string, bool) {
	a, ok := m[k].([]any)
	if !ok || len(a) != 1 {
		return "", false
	}
	s, ok := a[0].(string)
	return s, ok && s != ""
}

var reShortID = regexp.MustCompile(`^[0-9a-fA-F]{1,16}$`)

// parseXRayServer — разбор server.json по закрытому списку формы. Ошибка
// типа *xrayUnknown — формат не знаком; иной ошибки не бывает.
func parseXRayServer(data []byte) (*xrayServer, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, unknownf("server.json не разбирается как JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, unknownf("в server.json после JSON есть посторонний текст")
	}
	root, ok := v.(map[string]any)
	if !ok {
		return nil, unknownf("server.json — не объект JSON")
	}
	if k := onlyKeys(root, "log", "inbounds", "outbounds"); k != "" {
		return nil, unknownf("в server.json есть поле %s", keyName(k))
	}
	inbounds, ok := root["inbounds"].([]any)
	if !ok || len(inbounds) == 0 {
		return nil, unknownf("в server.json нет inbounds")
	}
	if len(inbounds) != 1 {
		return nil, unknownf("в server.json %d inbound (программа знает форму только с одним)", len(inbounds))
	}
	in, ok := inbounds[0].(map[string]any)
	if !ok {
		return nil, unknownf("inbounds[0] в server.json — не объект")
	}
	if k := onlyKeys(in, "port", "protocol", "settings", "streamSettings"); k != "" {
		return nil, unknownf("в inbound есть поле %s", keyName(k))
	}
	if p, _ := strField(in, "protocol"); p != "vless" {
		return nil, unknownf("протокол inbound — не vless")
	}
	portNum, ok := in["port"].(json.Number)
	if !ok {
		return nil, unknownf("порт inbound не число")
	}
	port, err := strconv.Atoi(portNum.String())
	if err != nil || port < 1 || port > 65535 {
		return nil, unknownf("порт inbound вне 1–65535")
	}
	settings, ok := objField(in, "settings")
	if !ok {
		return nil, unknownf("в inbound нет settings")
	}
	if k := onlyKeys(settings, "clients", "decryption"); k != "" {
		return nil, unknownf("в settings есть поле %s", keyName(k))
	}
	if d, _ := strField(settings, "decryption"); d != "none" {
		return nil, unknownf("decryption в settings — не none")
	}
	rawClients, ok := settings["clients"].([]any)
	if !ok {
		return nil, unknownf("в settings нет списка clients")
	}
	srv := &xrayServer{root: root, inbound: in, flow: map[string]string{}, port: strconv.Itoa(port)}
	flows := map[string]bool{}
	for i, rc := range rawClients {
		cl, ok := rc.(map[string]any)
		if !ok {
			return nil, unknownf("клиент №%d в server.json — не объект", i+1)
		}
		if k := onlyKeys(cl, "id", "flow"); k != "" {
			return nil, unknownf("у клиента №%d в server.json есть поле %s", i+1, keyName(k))
		}
		id, _ := strField(cl, "id")
		if !reUUID.MatchString(id) {
			return nil, unknownf("id клиента №%d в server.json — не UUID", i+1)
		}
		if _, dup := srv.flow[id]; dup {
			return nil, unknownf("один UUID записан в server.json дважды (клиент №%d)", i+1)
		}
		f := ""
		if fv, has := cl["flow"]; has {
			fs, isStr := fv.(string)
			if !isStr || fs != xrayFlowVision {
				return nil, unknownf("flow клиента №%d в server.json незнаком", i+1)
			}
			f = fs
		}
		srv.ids = append(srv.ids, id)
		srv.flow[id] = f
		flows[f] = true
	}
	switch len(flows) {
	case 0:
		return nil, unknownf("в server.json нет ни одного клиента — неизвестно, какой flow у новых")
	case 1:
		for f := range flows {
			srv.clientFlow = f
		}
	default:
		return nil, unknownf("у клиентов в server.json разный flow")
	}
	st, ok := objField(in, "streamSettings")
	if !ok {
		return nil, unknownf("в inbound нет streamSettings")
	}
	if k := onlyKeys(st, "network", "security", "realitySettings"); k != "" {
		return nil, unknownf("в streamSettings есть поле %s", keyName(k))
	}
	if n, _ := strField(st, "network"); n != "tcp" {
		return nil, unknownf("транспорт (network) — не tcp")
	}
	if sec, _ := strField(st, "security"); sec != "reality" {
		return nil, unknownf("security — не reality")
	}
	rs, ok := objField(st, "realitySettings")
	if !ok {
		return nil, unknownf("нет realitySettings")
	}
	if k := onlyKeys(rs, "dest", "serverNames", "privateKey", "shortIds", "fingerprint"); k != "" {
		return nil, unknownf("в realitySettings есть поле %s", keyName(k))
	}
	if d, _ := strField(rs, "dest"); d == "" {
		return nil, unknownf("в realitySettings нет dest")
	}
	if srv.serverName, ok = singleString(rs, "serverNames"); !ok {
		return nil, unknownf("serverNames в realitySettings — не один адрес")
	}
	if srv.shortID, ok = singleString(rs, "shortIds"); !ok || !reShortID.MatchString(srv.shortID) {
		return nil, unknownf("shortIds в realitySettings — не один короткий шестнадцатеричный идентификатор")
	}
	srv.fingerprint = xrayFingerprintDefault
	if fv, has := rs["fingerprint"]; has {
		fs, isStr := fv.(string)
		if !isStr || fs == "" {
			return nil, unknownf("fingerprint в realitySettings — не строка")
		}
		srv.fingerprint = fs
	}
	priv, _ := strField(rs, "privateKey")
	pub, err := realityPublicKey(priv)
	if err != nil {
		return nil, unknownf("privateKey в realitySettings — не ключ x25519")
	}
	srv.publicKey = pub
	return srv, nil
}

// realityPublicKey — публичный ключ Reality из приватного (как `xray x25519
// -i`: base64 RawURL, 32 байта).
func realityPublicKey(priv string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(priv)
	if err != nil || len(raw) != 32 {
		return "", errors.New("не ключ")
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(pub), nil
}

// marshalXRay — дерево JSON в байты так, как пишет его amnezia-client
// (QJsonDocument::toJson: ключи по алфавиту, отступ 4 пробела, без
// экранирования <>&). Числа — как прочитаны (json.Number).
func marshalXRay(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "    ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// withClients — байты server.json, где inbounds[0].settings.clients заменён
// на ids (flow — по srv.flow, новые — srv.clientFlow). Всё прочее — то же
// дерево.
func (srv *xrayServer) withClients(ids []string) ([]byte, error) {
	list := make([]any, 0, len(ids))
	for _, id := range ids {
		f, ok := srv.flow[id]
		if !ok {
			f = srv.clientFlow
		}
		cl := map[string]any{"id": id}
		if f != "" {
			cl["flow"] = f
		}
		list = append(list, cl)
	}
	settings := srv.inbound["settings"].(map[string]any)
	old := settings["clients"]
	settings["clients"] = list
	defer func() { settings["clients"] = old }()
	return marshalXRay(srv.root)
}

func (srv *xrayServer) has(id string) bool {
	_, ok := srv.flow[id]
	return ok
}

// ---------- формат контейнера ----------

// XRayFormat — что известно о формате XRay на сервере: три состояния —
// известен (управление) / незнаком (Reason) / не прочитан (Reason, Err).
type XRayFormat struct {
	State  FormatState
	Reason string
	Err    error
}

// xrayState — прочитанное состояние XRay: файлы, служебный UUID, записи.
type xrayState struct {
	raw        []byte
	srv        *xrayServer
	service    string
	tbl        []byte
	tblExisted bool
	clients    []ClientEntry
}

// readXRayServer — server.json и служебный UUID. Ошибка — FormatUnreadable
// или незнакомый формат (*xrayUnknown).
func (s *Session) readXRayServer(c *Container) (raw []byte, srv *xrayServer, service string, err error) {
	raw, srv, err = s.readXRayConf(c)
	if err != nil {
		return nil, nil, "", err
	}
	service, err = s.readXRayInstallID(c)
	if err != nil {
		return nil, nil, "", err
	}
	return raw, srv, service, nil
}

// readXRayConf — server.json по закрытому списку формы.
func (s *Session) readXRayConf(c *Container) ([]byte, *xrayServer, error) {
	out, err := s.catIn(c, c.Dir+"/"+xrayConfFile)
	if err != nil {
		return nil, nil, &xrayUnreadable{what: "server.json", err: err}
	}
	srv, err := parseXRayServer([]byte(out))
	if err != nil {
		return nil, nil, err
	}
	return []byte(out), srv, nil
}

// readXRayInstallID — UUID из xray_uuid.key: клиент, созданный при установке
// XRay (живая проверка 04.10: в приложении Amnezia это ПЕРВЫЙ клиент —
// устройство администратора, — он штатно есть и в server.json, и в
// clientsTable; amnezia-client 94b51df xrayConfigurator.cpp:393-394,
// 430-438, 462-470; exportController.cpp:166-170; usersController.cpp:409).
// Без него не отличить этого клиента — управление недоступно.
func (s *Session) readXRayInstallID(c *Container) (string, error) {
	key, err := s.catIn(c, c.Dir+"/"+xrayUUIDFile)
	if err != nil {
		return "", &xrayUnreadable{what: xrayUUIDFile + " (ключ установки XRay — без него не отличить клиента установки)", err: err}
	}
	id := strings.TrimSpace(key)
	if !reUUID.MatchString(id) {
		return "", unknownf("в %s не UUID", xrayUUIDFile)
	}
	return id, nil
}

// XRayFormatOf — формат XRay контейнера c (для FindContainers).
func (s *Session) XRayFormatOf(c *Container) XRayFormat {
	_, _, _, err := s.readXRayServer(c)
	return xrayFormatOf(err)
}

func xrayFormatOf(err error) XRayFormat {
	var u *xrayUnknown
	var r *xrayUnreadable
	switch {
	case err == nil:
		return XRayFormat{State: FormatKnown}
	case errors.As(err, &u):
		return XRayFormat{State: FormatUnknownKey, Reason: "формат не знаком этой версии программы: " + u.why + "; управляйте этим XRay в приложении Amnezia"}
	case errors.As(err, &r):
		return XRayFormat{State: FormatUnreadable, Reason: "не удалось прочитать " + r.what, Err: r.err}
	}
	return XRayFormat{State: FormatUnreadable, Reason: "не удалось прочитать файлы XRay", Err: err}
}

// xrayUnreadable — файл XRay не прочитан (what — какой, err — причина).
type xrayUnreadable struct {
	what string
	err  error
}

func (e *xrayUnreadable) Error() string {
	return "не удалось прочитать " + e.what + ": " + e.err.Error()
}
func (e *xrayUnreadable) Unwrap() error { return e.err }

// readXRay — полное состояние для плана: server.json, служебный UUID,
// clientsTable. Служебный UUID в clientsTable — формат не знаком.
func (s *Session) readXRay(c *Container) (*xrayState, error) {
	raw, srv, service, err := s.readXRayServer(c)
	if err != nil {
		if f := xrayFormatOf(err); f.Err != nil {
			return nil, fmt.Errorf("XRay — только просмотр: %s: %w", f.Reason, f.Err)
		}
		return nil, fmt.Errorf("XRay — только просмотр: %s", xrayFormatOf(err).Reason)
	}
	tbl, existed, err := s.readClientsTableRaw(c)
	if err != nil {
		return nil, err
	}
	clients, err := parseClientsTable(tbl)
	if err != nil {
		return nil, err
	}
	// Клиент установки (UUID из xray_uuid.key) в clientsTable — НОРМА: это
	// первый клиент приложения Amnezia. Он показывается обычной строкой,
	// действия над ним отказывают (xrayFind).
	return &xrayState{raw: raw, srv: srv, service: service, tbl: tbl, tblExisted: existed, clients: clients}, nil
}

// ---------- вид списка ----------

// XRayAccess — есть ли у записи clientsTable доступ по server.json, с учётом
// поля disabled. ПЯТЬ состояний: расхождение записи и server.json — не
// «активен» и не «отключён», а своё (CLAUDE.md, признак 1).
type XRayAccess int

const (
	// XRayAccessUnknown — нулевое: не определено (незнание, а не «активен»).
	XRayAccessUnknown XRayAccess = iota
	// XRayActive — включён по записи, UUID в server.json есть.
	XRayActive
	// XRayDisabled — отключён по записи, UUID в server.json нет.
	XRayDisabled
	// XRayNoAccess — включён по записи, но UUID в server.json нет: доступа нет.
	XRayNoAccess
	// XRayDisabledButListed — отключён по записи, но UUID в server.json есть:
	// доступ есть.
	XRayDisabledButListed
	// XRayEnabledUnknown — поле disabled испорчено (EnabledUnknown).
	XRayEnabledUnknown
)

// XRayServiceRowID — ClientID синтетической строки клиента установки, когда
// его UUID есть в server.json, а записи в clientsTable нет (настоящий UUID в
// интерфейс не уходит). Ядро отказывает любому действию над ним.
const XRayServiceRowID = "xray-service"

// XRayServiceName — имя клиента установки без записи в clientsTable.
const XRayServiceName = "клиент установки XRay"

// XRayInstallNote — пометка строки клиента установки (решение владельца 2,
// уточнено живой проверкой: строка обычная, без действий).
const XRayInstallNote = "ключ установки XRay (xray_uuid.key) — изменение недоступно"

// XRayView — список XRay для показа.
type XRayView struct {
	Clients []ClientEntry
	Access  map[string]XRayAccess // ClientID → доступ (ReadOnly — всё «неизвестно»)
	// InstallID — UUID клиента установки (xray_uuid.key), "" — не прочитан.
	// Наружу не печатается: только для сравнения со строками списка.
	InstallID string
	// InstallPrint — отпечаток; InstallListed — UUID есть в server.json;
	// InstallInTable — есть запись в clientsTable (норма, первый клиент).
	InstallPrint   string
	InstallListed  bool
	InstallInTable bool
	// Orphans — отпечатки UUID, которые есть в server.json, но нет ни в
	// clientsTable, ни в xray_uuid.key (приложение Amnezia само дописало бы
	// их как «Client N» — мы только показываем).
	Orphans []string
	// ReadOnly — почему только просмотр ("" — управление): формат server.json
	// не знаком или не прочитан, xray_uuid.key не прочитан. Список при этом
	// показывается (только просмотр ≠ ошибка).
	ReadOnly string
}

// IsInstall — строка cl — клиент установки XRay (действия недоступны).
func (v XRayView) IsInstall(cl ClientEntry) bool {
	return cl.ClientID == XRayServiceRowID || (v.InstallID != "" && cl.ClientID == v.InstallID)
}

// LoadXRayView — список клиентов XRay. Ошибка — только если не прочитана
// clientsTable; незнакомый или не прочитанный server.json / xray_uuid.key —
// список с ReadOnly (причина).
func (s *Session) LoadXRayView(c *Container) (XRayView, error) {
	if !IsXRay(c) {
		return XRayView{}, fmt.Errorf("контейнер %s — не XRay", c.Name)
	}
	_, srv, confErr := s.readXRayConf(c)
	install, idErr := s.readXRayInstallID(c)
	tbl, _, err := s.readClientsTableRaw(c)
	if err != nil {
		return XRayView{}, err
	}
	clients, err := parseClientsTable(tbl)
	if err != nil {
		return XRayView{}, err
	}
	v := XRayView{Clients: clients, Access: map[string]XRayAccess{}}
	if idErr == nil {
		v.InstallID, v.InstallPrint = install, UUIDPrint(install)
	}
	switch {
	case confErr != nil:
		v.ReadOnly = xrayFormatOf(confErr).Reason
	case idErr != nil:
		v.ReadOnly = xrayFormatOf(idErr).Reason
	}
	inTable := map[string]bool{}
	for _, cl := range clients {
		inTable[cl.ClientID] = true
		if srv == nil {
			v.Access[cl.ClientID] = XRayAccessUnknown
			continue
		}
		v.Access[cl.ClientID] = xrayAccessOf(cl, srv.has(cl.ClientID))
	}
	v.InstallInTable = v.InstallID != "" && inTable[v.InstallID]
	if srv != nil {
		v.InstallListed = v.InstallID != "" && srv.has(v.InstallID)
		for _, id := range srv.ids {
			if !inTable[id] && id != v.InstallID {
				v.Orphans = append(v.Orphans, UUIDPrint(id))
			}
		}
	}
	return v, nil
}

func xrayAccessOf(cl ClientEntry, listed bool) XRayAccess {
	switch cl.EnabledState() {
	case EnabledUnknown:
		return XRayEnabledUnknown
	case EnabledDisabled:
		if listed {
			return XRayDisabledButListed
		}
		return XRayDisabled
	case EnabledActive:
		if listed {
			return XRayActive
		}
		return XRayNoAccess
	}
	return XRayAccessUnknown
}

// XRayAccessText — состояние записи словами (CLI list, GUI таблица).
func XRayAccessText(a XRayAccess) string {
	switch a {
	case XRayActive:
		return "включён"
	case XRayDisabled:
		return "отключён"
	case XRayNoAccess:
		return "нет в server.json — доступа нет"
	case XRayDisabledButListed:
		return "отключён по записи, но в server.json есть — доступ есть"
	case XRayEnabledUnknown:
		return "включён ли — неизвестно (поле disabled испорчено)"
	}
	return "неизвестно"
}

// XRayStatsNote — почему у XRay нет трафика и активности (вместо 0 и «не
// подключался»: статистики у XRay в программе нет вовсе, раздел 4).
const XRayStatsNote = "XRay не отдаёт статистику: трафик и последнее подключение неизвестны."

// XRayNotes — строки под списком: служебный UUID, сироты.
func XRayNotes(v XRayView) []string {
	var out []string
	if v.ReadOnly != "" {
		out = append(out, "Только просмотр: "+v.ReadOnly+".")
	}
	if v.InstallID != "" && v.ReadOnly == "" && !v.InstallListed {
		out = append(out, fmt.Sprintf("Ключа установки XRay (%s) в server.json нет.", v.InstallPrint))
	}
	if len(v.Orphans) > 0 {
		out = append(out, fmt.Sprintf("В server.json есть UUID без записи в clientsTable (%d): %s. Программа их не меняет; имена им можно дать в приложении Amnezia.",
			len(v.Orphans), strings.Join(v.Orphans, ", ")))
	}
	return out
}

// ---------- клиентский конфиг ----------

// xrayClientConfig — JSON клиента xray (buildClientProtocolConfig,
// xrayConfigurator.cpp:490-560; template.json) и ссылка vless:// (vless.cpp
// Serialize, exportController.cpp:266-350) — то, что выдаёт само приложение.
func xrayClientConfig(srv *xrayServer, host, id string) (config, link string, err error) {
	user := map[string]any{"id": id, "encryption": "none"}
	if srv.clientFlow != "" {
		user["flow"] = srv.clientFlow
	}
	port, _ := strconv.Atoi(srv.port)
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "error"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": 10808, "protocol": "socks",
			"settings": map[string]any{"udp": true},
		}},
		"outbounds": []any{map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": host, "port": port, "users": []any{user},
			}}},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality",
				"realitySettings": map[string]any{
					"fingerprint": srv.fingerprint, "serverName": srv.serverName,
					"publicKey": srv.publicKey, "shortId": srv.shortID, "spiderX": "",
				},
			},
		}},
	}
	b, err := marshalXRay(cfg)
	if err != nil {
		return "", "", err
	}
	return string(b), xrayLink(srv, host, id), nil
}

// xrayLink — vless://UUID@host:port?… в порядке параметров vless.cpp Serialize.
func xrayLink(srv *xrayServer, host, id string) string {
	q := []string{"encryption=none", "security=reality"}
	if srv.clientFlow != "" {
		q = append(q, "flow="+srv.clientFlow)
	}
	q = append(q, "sni="+urlQueryEscape(srv.serverName), "fp="+urlQueryEscape(srv.fingerprint),
		"pbk="+urlQueryEscape(srv.publicKey), "sid="+urlQueryEscape(srv.shortID))
	h := host
	if strings.Contains(h, ":") {
		h = "[" + h + "]" // IPv6
	}
	return "vless://" + id + "@" + h + ":" + srv.port + "?" + strings.Join(q, "&") + "#" + xrayLinkAlias
}

// urlQueryEscape — экранирование значения запроса (QUrl FullyEncoded: всё
// вне незарезервированных знаков).
func urlQueryEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// XRayConfigNote — что человек обязан знать при выдаче конфига XRay.
const XRayConfigNote = "Файл — конфиг XRay в формате JSON (как «XRay native format» приложения Amnezia); QR — ссылка vless://. В конфиге UUID клиента — это его пароль: не пересылайте конфиг посторонним."

// XRayClientConfig — конфиг существующего клиента, собранный с сервера (у
// XRay сервер хранит UUID — перевыпуск не нужен). Только для клиента,
// который включён и есть в server.json.
func (s *Session) XRayClientConfig(c *Container, clientID string) (*NewUser, error) {
	if !IsXRay(c) {
		return nil, fmt.Errorf("контейнер %s — не XRay", c.Name)
	}
	if clientID == XRayServiceRowID {
		return nil, errXRayService
	}
	st, err := s.readXRay(c)
	if err != nil {
		return nil, err
	}
	idx := findClient(st.clients, clientID)
	if idx < 0 {
		return nil, fmt.Errorf("клиент %s не найден в clientsTable", UUIDPrint(clientID))
	}
	cl := st.clients[idx]
	if a := xrayAccessOf(cl, st.srv.has(clientID)); a != XRayActive {
		return nil, fmt.Errorf("конфиг %q не выдан: %s", cl.Name(), XRayAccessText(a))
	}
	cfg, link, err := xrayClientConfig(st.srv, s.Creds.Host, clientID)
	if err != nil {
		return nil, err
	}
	return &NewUser{Name: cl.Name(), Config: cfg, Link: link, Ext: ".json", Note: XRayConfigNote}, nil
}

// ---------- планы ----------

// ErrXRayNeedsConfirm — обёртка «план и сразу запись» (AddUser, DeleteByID,
// SetEnabled…) получила план XRay с перезапуском: такой план пишется только
// через Plan* → подтверждение перезапуска → Apply того же плана (решение
// владельца 1; AU-LOGIC High-2). Ничего не записано.
var ErrXRayNeedsConfirm = errors.New("изменение XRay перезапускает его и рвёт подключения: нужен план и подтверждение перезапуска — ничего не записано")

var errXRayService = errors.New("клиент установки XRay (ключ xray_uuid.key) программа не меняет: его нельзя удалить, отключить, перевыпустить или переименовать — управляйте им в приложении Amnezia")

// xrayPlan — план XRay из прочитанного состояния и нового списка UUID и записей.
func (s *Session) xrayPlan(c *Container, st *xrayState, action, subject string, ids []string, clients []ClientEntry, summary string) (*Plan, error) {
	confAfter := st.raw
	if !sameIDs(ids, st.srv.ids) {
		b, err := st.srv.withClients(ids)
		if err != nil {
			return nil, fmt.Errorf("сборка server.json: %w", err)
		}
		confAfter = b
	}
	tblAfter, err := json.MarshalIndent(clients, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("сборка clientsTable: %w", err)
	}
	p := &Plan{
		Container:  c,
		Action:     action,
		Subject:    subject,
		wgBefore:   st.raw,
		wgAfter:    confAfter,
		tblBefore:  st.tbl,
		tblAfter:   tblAfter,
		tblExisted: st.tblExisted,
	}
	p.xraySummary = summary
	s.fillSHA(p)
	return p, nil
}

func sameIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func without(ids []string, id string) []string {
	out := make([]string, 0, len(ids))
	for _, x := range ids {
		if x != id {
			out = append(out, x)
		}
	}
	return out
}

// xrayFind — запись clientID (не служебная) и её индекс.
func xrayFind(st *xrayState, clientID string) (int, error) {
	if clientID == XRayServiceRowID || clientID == st.service {
		return -1, errXRayService
	}
	if err := requireClientID(clientID); err != nil {
		return -1, err
	}
	idx := findClient(st.clients, clientID)
	if idx < 0 {
		return -1, fmt.Errorf("клиент %s не найден в clientsTable", UUIDPrint(clientID))
	}
	return idx, nil
}

func xrayLine(sign, name, id, what string) string {
	return fmt.Sprintf("%s %s (UUID %s)%s", sign, name, UUIDPrint(id), what)
}

func (s *Session) planXRayAdd(c *Container, name string) (*Plan, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	st, err := s.readXRay(c)
	if err != nil {
		return nil, err
	}
	for _, cl := range st.clients {
		if cl.Name() == name {
			return nil, fmt.Errorf("пользователь с именем %q уже существует", name)
		}
	}
	id, err := newUUID()
	if err != nil {
		return nil, err
	}
	clients := append(append([]ClientEntry{}, st.clients...), ClientEntry{
		ClientID: id,
		UserData: map[string]any{"clientName": name, "creationDate": AmneziaDateNow()},
	})
	p, err := s.xrayPlan(c, st, "add", name, append(append([]string{}, st.srv.ids...), id), clients,
		xrayLine("+", name, id, ": новый клиент"))
	if err != nil {
		return nil, err
	}
	cfg, link, err := xrayClientConfig(st.srv, s.Creds.Host, id)
	if err != nil {
		return nil, err
	}
	p.result = &NewUser{Name: name, Config: cfg, Link: link, Ext: ".json", Note: XRayConfigNote}
	return p, nil
}

func (s *Session) planXRayDelete(c *Container, clientID string) (*Plan, error) {
	st, err := s.readXRay(c)
	if err != nil {
		return nil, err
	}
	idx, err := xrayFind(st, clientID)
	if err != nil {
		return nil, err
	}
	name := st.clients[idx].Name()
	clients, _ := filterClientsByID(st.clients, clientID)
	return s.xrayPlan(c, st, "delete", name, without(st.srv.ids, clientID), clients,
		xrayLine("-", name, clientID, ": удаляется из server.json и clientsTable"))
}

func (s *Session) planXRayRename(c *Container, clientID, newName string) (*Plan, error) {
	st, err := s.readXRay(c)
	if err != nil {
		return nil, err
	}
	idx, err := xrayFind(st, clientID)
	if err != nil {
		return nil, err
	}
	old := st.clients[idx].Name()
	clients, err := renameClientInList(st.clients, clientID, newName)
	if err != nil {
		return nil, err
	}
	newName = strings.TrimSpace(newName)
	return s.xrayPlan(c, st, "rename", newName, st.srv.ids, clients,
		fmt.Sprintf("~ %q → %q (UUID %s): только имя в clientsTable, server.json не меняется, XRay не перезапускается", old, newName, UUIDPrint(clientID)))
}

func (s *Session) planXRaySetEnabled(c *Container, clientID string, enabled bool) (*Plan, error) {
	st, err := s.readXRay(c)
	if err != nil {
		return nil, err
	}
	idx, err := xrayFind(st, clientID)
	if err != nil {
		return nil, err
	}
	cl := st.clients[idx]
	name := cl.Name()
	listed := st.srv.has(clientID)
	clients := append([]ClientEntry{}, st.clients...)
	ud := make(map[string]any, len(cl.UserData)+1)
	for k, v := range cl.UserData {
		ud[k] = v
	}
	if enabled {
		if cl.EnabledState() == EnabledUnknown {
			return nil, EnabledUnknownError(cl)
		}
		if !cl.Disabled() {
			return nil, fmt.Errorf("пользователь %q уже включён", name)
		}
		if listed {
			return nil, fmt.Errorf("пользователь %q отключён по записи, но его UUID в server.json есть — доступ у него уже есть; включение отменено, чтобы не править запись вслепую. Отключите его — это уберёт UUID из server.json", name)
		}
		delete(ud, "disabled")
		delete(ud, "disabledAt")
		clients[idx] = ClientEntry{ClientID: clientID, UserData: ud}
		ids := append(append([]string{}, st.srv.ids...), clientID)
		return s.xrayPlan(c, st, "enable", name, ids, clients, xrayLine("+", name, clientID, ": возвращается в server.json (включение)"))
	}
	if cl.Disabled() && !listed {
		return nil, fmt.Errorf("пользователь %q уже отключён", name)
	}
	ud["disabled"] = true
	ud["disabledAt"] = time.Now().Format(time.RFC3339)
	clients[idx] = ClientEntry{ClientID: clientID, UserData: ud}
	p, err := s.xrayPlan(c, st, "disable", name, without(st.srv.ids, clientID), clients,
		xrayLine("-", name, clientID, ": убирается из server.json (отключение), запись остаётся"))
	if err != nil {
		return nil, err
	}
	if !listed {
		p.note = "Доступ уже отрезан: UUID клиента в server.json нет. Исправлена только запись в clientsTable (disabled = true); XRay не перезапускается."
	}
	return p, nil
}

func (s *Session) planXRayRekey(c *Container, clientID string) (*Plan, error) {
	st, err := s.readXRay(c)
	if err != nil {
		return nil, err
	}
	idx, err := xrayFind(st, clientID)
	if err != nil {
		return nil, err
	}
	cl := st.clients[idx]
	name := cl.Name()
	if cl.EnabledState() == EnabledUnknown {
		return nil, EnabledUnknownError(cl)
	}
	if cl.Disabled() {
		return nil, fmt.Errorf("пользователь %q отключён — сначала включите его, затем перевыпускайте конфиг", name)
	}
	if !st.srv.has(clientID) {
		return nil, fmt.Errorf("UUID пользователя %q не найден в server.json — данные рассинхронизированы, перевыпуск отменён", name)
	}
	id, err := newUUID()
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(st.srv.ids))
	for i, x := range st.srv.ids {
		ids[i] = x
		if x == clientID {
			ids[i] = id
		}
	}
	st.srv.flow[id] = st.srv.flow[clientID]
	clients, err := rekeyClientInList(st.clients, clientID, id)
	if err != nil {
		return nil, err
	}
	p, err := s.xrayPlan(c, st, "rekey", name, ids, clients,
		fmt.Sprintf("~ %s: UUID %s → %s (старый конфиг перестанет работать)", name, UUIDPrint(clientID), UUIDPrint(id)))
	if err != nil {
		return nil, err
	}
	cfg, link, err := xrayClientConfig(st.srv, s.Creds.Host, id)
	if err != nil {
		return nil, err
	}
	p.result = &NewUser{Name: name, Config: cfg, Link: link, Ext: ".json", Replaces: clientID, Note: XRayConfigNote}
	return p, nil
}

// ---------- применение: перезапуск и живость ----------

// RestartsXRay — запишет ли план server.json, то есть перезапустит ли XRay
// (и оборвёт ли подключения всем его клиентам). Переименование — нет.
func (p *Plan) RestartsXRay() bool {
	return IsXRay(p.Container) && !bytes.Equal(p.wgBefore, p.wgAfter)
}

// XRayRestartWarning — текст предупреждения перед действием, перезапускающим
// XRay (решение владельца 1; слова — проект БК, раздел 3). Число
// подключённых XRay узнать нельзя — так и сказано, а не «0».
const XRayRestartWarning = "XRay будет перезапущен: соединения ВСЕХ пользователей XRay оборвутся " +
	"(сколько их сейчас подключено — узнать нельзя: XRay не отдаёт статистику).\n" +
	"На тестовом сервере перезапуск занимал 1–3 секунды; когда переподключится приложение пользователя, зависит от приложения.\n" +
	"Пользователей WireGuard и AmneziaWG это не затрагивает.\n" +
	"Если перезапуск не удастся, программа вернёт прежние настройки — это ещё один перезапуск."

// XRayRestartTitle, XRayRestartConfirm — заголовок и кнопка подтверждения.
const (
	XRayRestartTitle   = "XRay будет перезапущен"
	XRayRestartConfirm = "Перезапустить и применить"
)

// xrayLive — жив ли процесс xray: ТРИ состояния.
type xrayLive int

const (
	xrayLiveUnknown xrayLive = iota // проверить не удалось — не «жив» и не «мёртв»
	xrayAlive
	xrayDead
)

// Ожидания после перезапуска: опрос до появления процесса, затем повторная
// проверка через паузу (xray с плохим конфигом падает сразу после старта).
// Переменные — тестам (0).
var (
	xrayPollEvery  = time.Second
	xrayPollTimes  = 10
	xrayStableWait = 3 * time.Second
)

// xrayLivenessCmd — pidof из busybox образа (alpine, server_scripts/xray/
// Dockerfile). Нет pidof — «notool»: проверить нечем, а не «мёртв».
func xrayLivenessCmd(name string) string {
	return fmt.Sprintf("docker exec %s sh -c 'command -v pidof >/dev/null 2>&1 || { echo notool; exit 0; }; pidof xray >/dev/null && echo alive || echo dead'", name)
}

func (s *Session) xrayLiveness(c *Container) (xrayLive, string) {
	out, err := s.docker(xrayLivenessCmd(c.Name), nil)
	if err != nil {
		return xrayLiveUnknown, fmt.Sprintf("проверка процесса xray не выполнилась: %v", err)
	}
	switch strings.TrimSpace(out) {
	case "alive":
		return xrayAlive, "процесс xray работает"
	case "dead":
		return xrayDead, "процесса xray нет"
	case "notool":
		return xrayLiveUnknown, "в контейнере нет pidof — проверить процесс xray нечем"
	}
	return xrayLiveUnknown, fmt.Sprintf("непонятный ответ проверки процесса xray: %q", shortReply(out))
}

// waitXRay — живость после перезапуска: опрос, пока процесс не появится;
// появился — повторная проверка через xrayStableWait.
func (s *Session) waitXRay(c *Container) (xrayLive, string) {
	var st xrayLive
	var why string
	for i := 0; i < xrayPollTimes; i++ {
		st, why = s.xrayLiveness(c)
		if st == xrayAlive {
			break
		}
		time.Sleep(xrayPollEvery)
	}
	if st != xrayAlive {
		return st, why
	}
	time.Sleep(xrayStableWait)
	return s.xrayLiveness(c)
}

// xrayStartedAt — время запуска контейнера XRay (docker inspect StartedAt):
// измерение «перезапускался ли». Пустой ответ — ошибка, а не «не менялся».
func (s *Session) xrayStartedAt(c *Container) (string, error) {
	out, err := s.docker("docker inspect -f '{{.State.StartedAt}}' "+c.Name, nil)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(out)
	if v == "" {
		return "", errors.New("пустой ответ docker inspect")
	}
	return v, nil
}

// restartXRay — `docker restart`, как в amnezia-client (с sudo при отказе
// прав — s.docker).
func (s *Session) restartXRay(c *Container) error {
	if _, err := s.docker("docker restart "+c.Name, nil); err != nil {
		return fmt.Errorf("перезапуск XRay: %w", err)
	}
	return nil
}

// xrayPrecheck — перед записью server.json: есть ли чем проверить, что
// XRay поднялся. Нечем — запись не начинается (иначе исход был бы «записали
// и не знаем»).
func (s *Session) xrayPrecheck(c *Container) error {
	st, why := s.xrayLiveness(c)
	switch st {
	case xrayLiveUnknown:
		return fmt.Errorf("перед записью: %s — после перезапуска не проверить, работает ли XRay; ничего не записано: %w", why, notStarted{errors.New(why)})
	case xrayDead:
		// QA Н1 (решение ядра): XRay уже не работает — перезапуск с новым
		// файлом не отличить от прежней поломки; не пишем.
		return fmt.Errorf("XRay не работает уже сейчас (процесса xray нет) — ничего не записано; сначала выясните, почему он остановлен: %w", notStarted{errors.New(why)})
	}
	return nil
}

// verifyXRay — после перезапуска: процесс xray жив (файлы сверены до этого).
func (s *Session) verifyXRay(c *Container) error {
	st, why := s.waitXRay(c)
	switch st {
	case xrayAlive:
		return nil
	case xrayDead:
		return fmt.Errorf("XRay не запустился с новым server.json (%s)", why)
	}
	return fmt.Errorf("не удалось проверить, запустился ли XRay (%s)", why)
}

// XRayVerifyScope — граница проверки XRay вслух (проект БК, 2.3).
const XRayVerifyScope = "Проверено: оба файла байт в байт; XRay перезапущен и его процесс работает. Принят ли каждый клиент — проверить нечем (у XRay нет списка подключённых)."

// xrayNotRestarted — пояснение к частичной записи XRay: перезапуска не было.
func xrayNotRestarted(c *Container) string {
	if IsXRay(c) {
		return "; XRay не перезапускался — работает со старым server.json до следующего перезапуска контейнера"
	}
	return ""
}

// SetXRayWaits — шов для тестов (core, cmd/cli, cmd/gui): паузы после
// перезапуска XRay. Возвращает функцию возврата прежних значений.
func SetXRayWaits(poll, stable time.Duration) (restore func()) {
	p, n, st := xrayPollEvery, xrayPollTimes, xrayStableWait
	xrayPollEvery, xrayStableWait = poll, stable
	if poll == 0 {
		xrayPollTimes = 3
	}
	return func() { xrayPollEvery, xrayPollTimes, xrayStableWait = p, n, st }
}
