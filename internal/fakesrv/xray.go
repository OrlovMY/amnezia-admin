package fakesrv

// XRay (AL-01): контейнер amnezia-xray. Файлы — по шаблонам из исходников
// amnezia-client (testdata/xray), секреты — случайные. Перезапуск
// (`docker restart`) «перечитывает» server.json: процесс xray жив, если файл
// разбирается и хук не велел ему упасть. Живость проверяется той же
// командой pidof, что шлёт core.

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

//go:embed testdata/xray/server.master.json
var xrayMasterTemplate string

//go:embed testdata/xray/server.dev.json
var xrayDevTemplate string

// XRayDir — каталог XRay в контейнере.
const XRayDir = "/opt/amnezia/xray"

var (
	reXRayRestart  = regexp.MustCompile(`^docker restart (\S+)$`)
	reXRayLiveness = regexp.MustCompile(`^docker exec (\S+) sh -c 'command -v pidof >/dev/null 2>&1 \|\| \{ echo notool; exit 0; \}; pidof xray >/dev/null && echo alive \|\| echo dead'$`)
)

// XRayHooks — хуки XRay (правятся тестом до работы Session).
type XRayHooks struct {
	// FailRestart — `docker restart` возвращает эту ошибку; процесс не трогается.
	FailRestart error
	// DeadOnRestart — номер перезапуска (с 1) → xray после него не поднялся.
	DeadOnRestart map[int]bool
	// NoPidof — в контейнере нет pidof (проверка отвечает notool).
	NoPidof bool
	// FailLivenessFrom — если > 0, проверка живости падает ошибкой exec,
	// начиная с N-го вызова.
	FailLivenessFrom int
	// Garbage — проверка живости отвечает этим текстом.
	Garbage string
}

type xrayRuntime struct {
	restarts      int
	alive         bool
	ids           []string // UUID, с которыми xray поднялся последний раз
	livenessCalls int
}

// NewXRay — сервер с контейнером amnezia-xray. variant — "master" или
// "dev" (форма server.json). В server.json — служебный UUID (xray_uuid.key)
// и два клиента Alice и Bob, они же в clientsTable.
func NewXRay(variant string) *Server {
	tpl := xrayMasterTemplate
	if variant == "dev" {
		tpl = xrayDevTemplate
	}
	service := RandUUID()
	var pk [32]byte
	if _, err := rand.Read(pk[:]); err != nil {
		panic(err)
	}
	var sid [8]byte
	if _, err := rand.Read(sid[:]); err != nil {
		panic(err)
	}
	conf := strings.NewReplacer(
		"$XRAY_SERVER_PORT", "443",
		"$XRAY_CLIENT_ID", service,
		"$XRAY_SITE_NAME", "www.googletagmanager.com",
		"$XRAY_PRIVATE_KEY", base64.RawURLEncoding.EncodeToString(pk[:]),
		"$XRAY_SHORT_ID", hex.EncodeToString(sid[:]),
	).Replace(tpl)
	alice, bob := RandUUID(), RandUUID()
	conf = XRayWithClients(conf, service, alice, bob)
	now := time.Now().Format(time.RFC3339)
	tbl, err := json.MarshalIndent([]clientEntry{
		{ClientID: alice, UserData: map[string]any{"clientName": "Alice", "creationDate": now}},
		{ClientID: bob, UserData: map[string]any{"clientName": "Bob", "creationDate": now}},
	}, "", "    ")
	if err != nil {
		panic(err)
	}
	s := &Server{
		Names: []string{"amnezia-xray"},
		files: map[string][]byte{
			XRayDir + "/server.json":   []byte(conf),
			XRayDir + "/xray_uuid.key": []byte(service + "\n"),
			XRayDir + "/clientsTable":  tbl,
		},
	}
	s.xray = &xrayRuntime{alive: true, ids: XRayIDs([]byte(conf))}
	return s
}

// RandUUID — UUID v4 (как `xray uuid`).
func RandUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// XRayWithClients — server.json conf, где clients = ids (flow vision у всех);
// сериализация — отступ 4, без экранирования HTML.
func XRayWithClients(conf string, ids ...string) string {
	var root map[string]any
	dec := json.NewDecoder(strings.NewReader(conf))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		panic("fakesrv: шаблон server.json: " + err.Error())
	}
	in := root["inbounds"].([]any)[0].(map[string]any)
	list := []any{}
	for _, id := range ids {
		list = append(list, map[string]any{"id": id, "flow": "xtls-rprx-vision"})
	}
	in["settings"].(map[string]any)["clients"] = list
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "    ")
	if err := enc.Encode(root); err != nil {
		panic(err)
	}
	return b.String()
}

// XRayIDs — UUID клиентов server.json (nil — файл не разбирается).
func XRayIDs(conf []byte) []string {
	var root struct {
		Inbounds []struct {
			Settings struct {
				Clients []struct {
					ID string `json:"id"`
				} `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(conf, &root); err != nil || len(root.Inbounds) == 0 {
		return nil
	}
	var out []string
	for _, c := range root.Inbounds[0].Settings.Clients {
		out = append(out, c.ID)
	}
	return out
}

// XRayRestarts — сколько раз перезапускали XRay.
func (s *Server) XRayRestarts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.xray == nil {
		return 0
	}
	return s.xray.restarts
}

// XRayAlive — жив ли процесс xray сейчас.
func (s *Server) XRayAlive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.xray != nil && s.xray.alive
}

// XRayRuntimeIDs — UUID, с которыми xray поднялся последний раз.
func (s *Server) XRayRuntimeIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.xray == nil {
		return nil
	}
	return append([]string(nil), s.xray.ids...)
}

// dispatchXRay — команды XRay; ok == false — не команда XRay.
func (s *Server) dispatchXRay(cmd string) (out string, err error, ok bool) {
	if m := reXRayRestart.FindStringSubmatch(cmd); m != nil {
		if m[1] != "amnezia-xray" || s.xray == nil {
			return "", fmt.Errorf("fakesrv: неизвестная команда %q", cmd), true
		}
		if s.XRay.FailRestart != nil {
			return "", s.XRay.FailRestart, true
		}
		s.xray.restarts++
		conf := s.files[XRayDir+"/server.json"]
		ids := XRayIDs(conf)
		s.xray.alive = ids != nil && json.Valid(conf) && !s.XRay.DeadOnRestart[s.xray.restarts]
		if s.xray.alive {
			s.xray.ids = ids
		} else {
			s.xray.ids = nil
		}
		return "amnezia-xray\n", nil, true
	}
	if m := reXRayLiveness.FindStringSubmatch(cmd); m != nil {
		if m[1] != "amnezia-xray" || s.xray == nil {
			return "", fmt.Errorf("fakesrv: неизвестная команда %q", cmd), true
		}
		s.xray.livenessCalls++
		switch {
		case s.XRay.FailLivenessFrom > 0 && s.xray.livenessCalls >= s.XRay.FailLivenessFrom:
			return "", fmt.Errorf("команда %q: exit status 1; stderr: Error response from daemon: имитированный отказ", cmd), true
		case s.XRay.Garbage != "":
			return s.XRay.Garbage, nil, true
		case s.XRay.NoPidof:
			return "notool\n", nil, true
		case s.xray.alive:
			return "alive\n", nil, true
		}
		return "dead\n", nil, true
	}
	return "", nil, false
}
