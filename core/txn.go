package core

// Транзакционный слой поверх мутаций сервера (PR-2): каждая мутация делится
// на «план» (Plan* — только чтение, вычисляет новое содержимое wg0.conf и
// clientsTable) и «применение» (Apply — CAS → пишет → проверяет). Разделение
// даёт dry-run (план без записи, core/txn.go:Diff) и транзакцию с CAS/verify/
// restore (I2) бесплатно — один и тот же план используется в обоих случаях.
//
// Мьютекс (I5): экспортированные Plan*/Apply берут s.mu сами; внутри пакета —
// варианты без блокировки (*Locked), которыми пользуются старые обёртки
// (AddUser, DeleteByID, ...) и держат mu один раз на весь plan→apply.
// sync.Mutex не реентерабелен — повторный Lock из-под уже взятого даёт
// deadlock, поэтому обёртки вызывают только *Locked-варианты, никогда
// экспортированные Plan*/Apply.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Plan — вычисленное изменение сервера, ещё не записанное. Поля с строчной
// буквы видны только внутри пакета core: наружу (dry-run в CLI/GUI) отдаётся
// только Diff(), а result (конфиг с приватным ключом) — только после Apply.
type Plan struct {
	Container *Container
	Action    string // "add" | "delete" | "rekey" | "rename" | "disable" | "enable"
	Subject   string // имя пользователя, над которым действие

	wgBefore, wgAfter   []byte
	tblBefore, tblAfter []byte // tblBefore == nil, если clientsTable отсутствовала
	tblExisted          bool
	wgSHA, tblSHA       string // hex sha256 прочитанных байтов (для CAS); tblSHA пуст, если !tblExisted

	result *NewUser // для add/rekey: конфиг клиента (приватный ключ!) — наружу только после Apply
}

// Diff возвращает построчный diff «-/+» по обоим файлам (без unified-формата
// и контекстных строк — только изменившееся; см. В2 п.7 задания). Пустая
// строка означает «файл не меняется» (например, wg0.conf при RenameUser).
// Значения секретов (PresharedKey/PrivateKey в wg0.conf, "psk" в
// clientsTable) замаскированы — см. maskSecrets.
func (p *Plan) Diff() (wgDiff, tblDiff string) {
	return maskSecrets(lineDiff(p.wgBefore, p.wgAfter)), maskSecrets(lineDiff(p.tblBefore, p.tblAfter))
}

// ---------- маскировка секретов в предпросмотре (SEC-01, review-reply PR-2Б
// круг 1, 2026-09-14, High) ----------
//
// Diff() — единственное, что видят CLI (-dry-run) и GUI («Показать
// изменения») ДО применения плана; маскировка стоит здесь одним местом,
// чтобы cmd/ ничего не дублировали. Решение владельца (форма, 14.09.2026):
// PSK в предпросмотре скрывать ВСЕГДА, флага раскрытия (-show-secrets) не
// заводить — ни в CLI, ни в GUI.
//
// Маскировать нужно не только "свои" секреты субъекта операции, но и
// секреты ДРУГИХ пользователей: lineDiff (см. выше) не минимален — общий
// суффикс обрезается посимвольно по строкам, и при rekey (removePeerFromConf
// в середине файла + buildPeerBlock в конец) все peer-блоки ПОСЛЕ удалённого
// сдвигаются на одну позицию и показываются как «изменившиеся», хотя их
// содержимое — включая PresharedKey постороннего пользователя — то же
// самое. Реальный прогон (SEC-01) подтвердил утечку такого рода.
var (
	// reWgSecretLine — "PresharedKey = …" / "PrivateKey = …" строка wg0.conf,
	// с учётом ведущего "-"/"+" из lineDiff и произвольных пробелов вокруг "=".
	reWgSecretLine = regexp.MustCompile(`^([-+]\s*)(PresharedKey|PrivateKey)(\s*=\s*).*$`)
	// reTblSecretLine — строка JSON clientsTable вида `"psk": "<value>",` —
	// сохранённый PresharedKey отключённого пользователя (planDisableLocked).
	reTblSecretLine = regexp.MustCompile(`^([-+]\s*"psk"\s*:\s*)".*"(,?)\s*$`)
)

// maskSecrets заменяет значения секретов на плейсхолдер построчно; формат
// строки (какой файл — wg0.conf или clientsTable) не важен, оба паттерна
// проверяются на каждой строке, так что одна функция обслуживает оба
// вызова Diff() выше.
func maskSecrets(diff string) string {
	if diff == "" {
		return diff
	}
	lines := strings.Split(diff, "\n")
	for i, l := range lines {
		if m := reWgSecretLine.FindStringSubmatch(l); m != nil {
			lines[i] = m[1] + m[2] + m[3] + "<скрыто>"
			continue
		}
		if m := reTblSecretLine.FindStringSubmatch(l); m != nil {
			lines[i] = m[1] + `"<скрыто>"` + m[2]
		}
	}
	return strings.Join(lines, "\n")
}

// lineDiff — простой построчный diff: общий префикс и общий суффикс строк
// отбрасываются, середина «до» печатается с "-", середина «после» — с "+".
// Не минимальный (не LCS), но для конфигов, где меняется хвост или один
// блок/поле, даёт читаемый и правильный по содержанию результат; unified-
// формат намеренно не требуется (В2 п.7).
func lineDiff(before, after []byte) string {
	beforeLines := splitLines(before)
	afterLines := splitLines(after)

	i := 0
	for i < len(beforeLines) && i < len(afterLines) && beforeLines[i] == afterLines[i] {
		i++
	}
	j := 0
	for j < len(beforeLines)-i && j < len(afterLines)-i &&
		beforeLines[len(beforeLines)-1-j] == afterLines[len(afterLines)-1-j] {
		j++
	}

	var b strings.Builder
	for _, l := range beforeLines[i : len(beforeLines)-j] {
		fmt.Fprintf(&b, "-%s\n", l)
	}
	for _, l := range afterLines[i : len(afterLines)-j] {
		fmt.Fprintf(&b, "+%s\n", l)
	}
	return b.String()
}

func splitLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

// ---------- чтение clientsTable сырыми байтами (общее для LoadClients и Plan*) ----------

// probeClientsTable — тот же `test -f`, что и раньше в LoadClients; вынесен
// отдельно, чтобы CAS (Г4) мог проверить "файла по-прежнему нет", не читая
// содержимое.
func (s *Session) probeClientsTable(c *Container) (bool, error) {
	probe, err := s.docker(fmt.Sprintf("docker exec %s sh -c 'test -f %s/clientsTable && echo yes || echo no'", c.Name, c.Dir), nil)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(probe) == "yes", nil
}

// readClientsTableRaw — сырые байты clientsTable и признак существования
// файла. LoadClients и Plan* пользуются этим же чтением, чтобы CAS и verify
// сверяли ровно то, что было реально прочитано.
func (s *Session) readClientsTableRaw(c *Container) (data []byte, existed bool, err error) {
	exists, err := s.probeClientsTable(c)
	if err != nil {
		return nil, false, fmt.Errorf("проверка наличия clientsTable: %w", err)
	}
	if !exists {
		return nil, false, nil
	}
	out, err := s.catIn(c, c.Dir+"/clientsTable")
	if err != nil {
		return nil, false, fmt.Errorf("чтение clientsTable: %w", err)
	}
	return []byte(out), true, nil
}

// parseClientsTable разбирает сырые байты clientsTable в список записей.
// Пустой (после TrimSpace) файл — пустой список, не ошибка (см. LoadClients).
func parseClientsTable(data []byte) ([]ClientEntry, error) {
	if strings.TrimSpace(string(data)) == "" {
		return []ClientEntry{}, nil
	}
	var list []ClientEntry
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("clientsTable повреждена: %w", err)
	}
	return list, nil
}

// findClient возвращает индекс записи с данным ClientID, или -1.
func findClient(clients []ClientEntry, clientID string) int {
	for i, cl := range clients {
		if cl.ClientID == clientID {
			return i
		}
	}
	return -1
}

func peerPubKeysFromBytes(data []byte) map[string]bool {
	conf := parseWgConf(string(data))
	out := make(map[string]bool, len(conf.peers))
	for _, p := range conf.peers {
		if pk := p["PublicKey"]; pk != "" {
			out[pk] = true
		}
	}
	return out
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// fillSHA считает контрольные суммы прочитанных байтов (для CAS, Г4) — Plan*
// вызывает её последней, когда wgBefore/tblBefore уже собраны.
func (s *Session) fillSHA(p *Plan) {
	p.wgSHA = sha256Hex(p.wgBefore)
	if p.tblExisted {
		p.tblSHA = sha256Hex(p.tblBefore)
	}
}

// ---------- Plan* — только чтение ----------

// PlanAddUser планирует создание пользователя (см. AddUser).
func (s *Session) PlanAddUser(c *Container, name string) (*Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.planAddUserLocked(c, name)
}

// PlanDelete планирует удаление клиента по ClientID (см. DeleteByID).
func (s *Session) PlanDelete(c *Container, clientID string) (*Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.planDeleteLocked(c, clientID)
}

// PlanRekey планирует перевыпуск ключей клиента (см. RegenerateUser).
func (s *Session) PlanRekey(c *Container, clientID string) (*Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.planRekeyLocked(c, clientID)
}

// PlanRename планирует переименование клиента (см. RenameUser).
func (s *Session) PlanRename(c *Container, clientID, newName string) (*Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.planRenameLocked(c, clientID, newName)
}

// PlanSetEnabled планирует включение/отключение клиента (см. SetEnabled).
func (s *Session) PlanSetEnabled(c *Container, clientID string, enabled bool) (*Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.planSetEnabledLocked(c, clientID, enabled)
}

func (s *Session) planAddUserLocked(c *Container, name string) (*Plan, error) {
	if !c.Managed {
		return nil, fmt.Errorf("создание пользователей для %s не поддерживается этой утилитой", c.Proto)
	}
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)

	tblBefore, tblExisted, err := s.readClientsTableRaw(c)
	if err != nil {
		return nil, err
	}
	existing, err := parseClientsTable(tblBefore)
	if err != nil {
		return nil, err
	}
	for _, cl := range existing {
		if cl.Name() == name {
			return nil, fmt.Errorf("пользователь с именем %q уже существует", name)
		}
	}

	raw, err := s.catIn(c, c.Dir+"/wg0.conf")
	if err != nil {
		return nil, fmt.Errorf("чтение wg0.conf: %w", err)
	}
	conf := parseWgConf(raw)

	serverPriv := conf.iface["PrivateKey"]
	if serverPriv == "" {
		return nil, fmt.Errorf("в wg0.conf нет PrivateKey сервера")
	}
	serverPub, err := pubFromPriv(serverPriv)
	if err != nil {
		return nil, err
	}
	listenPort := conf.iface["ListenPort"]
	if listenPort == "" {
		listenPort = "51820"
	}

	// allocateIP (Г1, core/ipalloc.go) — резерв отключённых учитывается через
	// existing (уже прочитанные до этой точки записи clientsTable).
	clientIP, err := allocateIP(conf, existing)
	if err != nil {
		return nil, err
	}

	priv, pub, err := genKey()
	if err != nil {
		return nil, err
	}
	psk, err := genPSK()
	if err != nil {
		return nil, err
	}

	peerBlock := buildPeerBlock(pub, psk, clientIP+"/32")
	wgAfter := []byte(raw + peerBlock)

	clients := append(append([]ClientEntry{}, existing...), ClientEntry{
		ClientID: pub,
		UserData: map[string]any{
			"clientName":   name,
			"creationDate": time.Now().Format(time.RFC3339),
		},
	})
	tblAfter, err := json.MarshalIndent(clients, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("сборка clientsTable: %w", err)
	}

	config := buildClientConfigText(conf, serverPub, s.Creds.Host, listenPort, priv, psk, clientIP)

	p := &Plan{
		Container:  c,
		Action:     "add",
		Subject:    name,
		wgBefore:   []byte(raw),
		wgAfter:    wgAfter,
		tblBefore:  tblBefore,
		tblAfter:   tblAfter,
		tblExisted: tblExisted,
		result:     &NewUser{Name: name, IP: clientIP, Config: config},
	}
	s.fillSHA(p)
	return p, nil
}

func (s *Session) planDeleteLocked(c *Container, clientID string) (*Plan, error) {
	if !c.Managed {
		return nil, fmt.Errorf("удаление пользователей для %s не поддерживается этой утилитой", c.Proto)
	}
	if err := requireClientID(clientID); err != nil {
		return nil, err
	}

	tblBefore, tblExisted, err := s.readClientsTableRaw(c)
	if err != nil {
		return nil, err
	}
	clients, err := parseClientsTable(tblBefore)
	if err != nil {
		return nil, err
	}
	idx := findClient(clients, clientID)
	if idx < 0 {
		return nil, fmt.Errorf("клиент с ключом %q не найден", clientID)
	}
	name := clients[idx].Name() // Subject — имя, не ключ (review changes-requested, Low)
	newClients, _ := filterClientsByID(clients, clientID)

	raw, err := s.catIn(c, c.Dir+"/wg0.conf")
	if err != nil {
		return nil, fmt.Errorf("чтение wg0.conf: %w", err)
	}
	newConf, err := removePeerFromConf(raw, clientID)
	if err != nil {
		return nil, err
	}
	tblAfter, err := json.MarshalIndent(newClients, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("сборка clientsTable: %w", err)
	}

	p := &Plan{
		Container:  c,
		Action:     "delete",
		Subject:    name,
		wgBefore:   []byte(raw),
		wgAfter:    []byte(newConf),
		tblBefore:  tblBefore,
		tblAfter:   tblAfter,
		tblExisted: tblExisted,
	}
	s.fillSHA(p)
	return p, nil
}

func (s *Session) planRekeyLocked(c *Container, clientID string) (*Plan, error) {
	if !c.Managed {
		return nil, fmt.Errorf("перевыпуск конфигов для %s не поддерживается этой утилитой", c.Proto)
	}
	if err := requireClientID(clientID); err != nil {
		return nil, err
	}

	tblBefore, tblExisted, err := s.readClientsTableRaw(c)
	if err != nil {
		return nil, err
	}
	clients, err := parseClientsTable(tblBefore)
	if err != nil {
		return nil, err
	}
	idx := findClient(clients, clientID)
	if idx < 0 {
		return nil, fmt.Errorf("клиент с ключом %q не найден", clientID)
	}
	name := clients[idx].Name()

	// Г3, решение владельца 14.09.2026 (инвариант I4): отключённого нельзя
	// перевыпустить молча — rekeyClientInList стирает disabled/allowedIP, и
	// отключённый пользователь включился бы без ведома администратора.
	// Проверка — ДО чтения wg0.conf: отказ не должен зависеть от состояния
	// сервера, раз решение принимается по одной лишь clientsTable.
	if clients[idx].Disabled() {
		return nil, fmt.Errorf("пользователь %q отключён — сначала включите его, затем перевыпускайте конфиг", name)
	}

	raw, err := s.catIn(c, c.Dir+"/wg0.conf")
	if err != nil {
		return nil, fmt.Errorf("чтение wg0.conf: %w", err)
	}
	conf := parseWgConf(raw)

	serverPriv := conf.iface["PrivateKey"]
	if serverPriv == "" {
		return nil, fmt.Errorf("в wg0.conf нет PrivateKey сервера")
	}
	serverPub, err := pubFromPriv(serverPriv)
	if err != nil {
		return nil, err
	}
	listenPort := conf.iface["ListenPort"]
	if listenPort == "" {
		listenPort = "51820"
	}

	// IP всегда берётся из уже существующего блока peer'а (Г3) — ветка
	// "иначе выделяем новый" удалена: активная по таблице запись без peer'а в
	// wg0.conf — рассинхрон таблицы и конфига, а не повод выдать новый адрес
	// (тот самый путь, которым живой пользователь тихо получал чужой IP).
	clientIP := ""
	found := false
	for _, p := range conf.peers {
		if p["PublicKey"] == clientID {
			found = true
			if m := ipRe.FindStringSubmatch(p["AllowedIPs"]); m != nil {
				clientIP = fmt.Sprintf("%s.%s", m[1], m[2])
			}
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("peer %q не найден в wg0.conf — данные рассинхронизированы, перевыпуск отменён", clientID)
	}
	if clientIP == "" {
		return nil, fmt.Errorf("peer %q найден в wg0.conf, но AllowedIPs не удалось разобрать — перевыпуск отменён", clientID)
	}

	priv, pub, err := genKey()
	if err != nil {
		return nil, err
	}
	psk, err := genPSK()
	if err != nil {
		return nil, err
	}

	removedConf, err := removePeerFromConf(raw, clientID)
	if err != nil {
		return nil, err
	}
	wgAfter := []byte(removedConf + buildPeerBlock(pub, psk, clientIP+"/32"))

	newClients, err := rekeyClientInList(clients, clientID, pub)
	if err != nil {
		return nil, err // не должно случиться — clientID уже найден выше
	}
	tblAfter, err := json.MarshalIndent(newClients, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("сборка clientsTable: %w", err)
	}

	config := buildClientConfigText(conf, serverPub, s.Creds.Host, listenPort, priv, psk, clientIP)

	p := &Plan{
		Container:  c,
		Action:     "rekey",
		Subject:    name,
		wgBefore:   []byte(raw),
		wgAfter:    wgAfter,
		tblBefore:  tblBefore,
		tblAfter:   tblAfter,
		tblExisted: tblExisted,
		result:     &NewUser{Name: name, IP: clientIP, Config: config},
	}
	s.fillSHA(p)
	return p, nil
}

func (s *Session) planRenameLocked(c *Container, clientID, newName string) (*Plan, error) {
	if !c.Managed {
		return nil, fmt.Errorf("переименование пользователей для %s не поддерживается этой утилитой", c.Proto)
	}
	if err := requireClientID(clientID); err != nil {
		return nil, err
	}

	tblBefore, tblExisted, err := s.readClientsTableRaw(c)
	if err != nil {
		return nil, err
	}
	clients, err := parseClientsTable(tblBefore)
	if err != nil {
		return nil, err
	}
	newClients, err := renameClientInList(clients, clientID, newName)
	if err != nil {
		return nil, err
	}
	tblAfter, err := json.MarshalIndent(newClients, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("сборка clientsTable: %w", err)
	}

	// RenameUser не трогает wg0.conf: читаем его только для CAS/verify —
	// wgAfter делается байт-в-байт равным wgBefore, и Apply не пишет
	// wg0.conf и не вызывает syncconf, пока план ничего в конфиге не меняет
	// (Г1) — переименование не должно рвать соединения, как и раньше.
	raw, err := s.catIn(c, c.Dir+"/wg0.conf")
	if err != nil {
		return nil, fmt.Errorf("чтение wg0.conf: %w", err)
	}

	p := &Plan{
		Container:  c,
		Action:     "rename",
		Subject:    strings.TrimSpace(newName),
		wgBefore:   []byte(raw),
		wgAfter:    []byte(raw),
		tblBefore:  tblBefore,
		tblAfter:   tblAfter,
		tblExisted: tblExisted,
	}
	s.fillSHA(p)
	return p, nil
}

func (s *Session) planSetEnabledLocked(c *Container, clientID string, enabled bool) (*Plan, error) {
	if !c.Managed {
		return nil, fmt.Errorf("управление пользователями для %s не поддерживается этой утилитой", c.Proto)
	}
	if enabled {
		return s.planEnableLocked(c, clientID)
	}
	return s.planDisableLocked(c, clientID)
}

func (s *Session) planDisableLocked(c *Container, clientID string) (*Plan, error) {
	if err := requireClientID(clientID); err != nil {
		return nil, err
	}
	tblBefore, tblExisted, err := s.readClientsTableRaw(c)
	if err != nil {
		return nil, err
	}
	clients, err := parseClientsTable(tblBefore)
	if err != nil {
		return nil, err
	}
	idx := findClient(clients, clientID)
	if idx < 0 {
		return nil, fmt.Errorf("клиент с ключом %q не найден", clientID)
	}
	if clients[idx].Disabled() {
		return nil, fmt.Errorf("пользователь %q уже отключён", clients[idx].Name())
	}

	raw, err := s.catIn(c, c.Dir+"/wg0.conf")
	if err != nil {
		return nil, fmt.Errorf("чтение wg0.conf: %w", err)
	}
	conf := parseWgConf(raw)
	var peer map[string]string
	for _, pp := range conf.peers {
		if pp["PublicKey"] == clientID {
			peer = pp
			break
		}
	}
	if peer == nil {
		return nil, fmt.Errorf("peer с ключом %q не найден в wg0.conf", clientID)
	}

	newConf, err := removePeerFromConf(raw, clientID)
	if err != nil {
		return nil, err
	}

	newClients := make([]ClientEntry, len(clients))
	copy(newClients, clients)
	ud := make(map[string]any, len(newClients[idx].UserData)+4)
	for k, v := range newClients[idx].UserData {
		ud[k] = v
	}
	ud["disabled"] = true
	ud["disabledAt"] = time.Now().Format(time.RFC3339)
	ud["psk"] = peer["PresharedKey"]
	ud["allowedIP"] = peer["AllowedIPs"]
	newClients[idx].UserData = ud
	tblAfter, err := json.MarshalIndent(newClients, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("сборка clientsTable: %w", err)
	}

	p := &Plan{
		Container:  c,
		Action:     "disable",
		Subject:    clients[idx].Name(),
		wgBefore:   []byte(raw),
		wgAfter:    []byte(newConf),
		tblBefore:  tblBefore,
		tblAfter:   tblAfter,
		tblExisted: tblExisted,
	}
	s.fillSHA(p)
	return p, nil
}

func (s *Session) planEnableLocked(c *Container, clientID string) (*Plan, error) {
	if err := requireClientID(clientID); err != nil {
		return nil, err
	}
	tblBefore, tblExisted, err := s.readClientsTableRaw(c)
	if err != nil {
		return nil, err
	}
	clients, err := parseClientsTable(tblBefore)
	if err != nil {
		return nil, err
	}
	idx := findClient(clients, clientID)
	if idx < 0 {
		return nil, fmt.Errorf("клиент с ключом %q не найден", clientID)
	}
	if !clients[idx].Disabled() {
		return nil, fmt.Errorf("пользователь %q уже активен", clients[idx].Name())
	}
	psk := Str(clients[idx].UserData, "psk")
	allowedIP := Str(clients[idx].UserData, "allowedIP")
	if psk == "" || allowedIP == "" {
		return nil, fmt.Errorf("невозможно включить: параметры peer не сохранены, пересоздайте пользователя")
	}

	raw, err := s.catIn(c, c.Dir+"/wg0.conf")
	if err != nil {
		return nil, fmt.Errorf("чтение wg0.conf: %w", err)
	}
	conf := parseWgConf(raw)

	// Г2, решение владельца 14.09.2026: если резервный IP отключённого занял
	// кто-то другой, пока он был отключён (новый пользователь, чужой
	// rekey-в-конфликт и т.п.) — отказ с именем занявшего, а не тихая
	// перезапись/дубль AllowedIPs. usedIPs уже включает собственный резерв
	// включаемого (под его же ClientID) — это не конфликт, поэтому сравнение
	// именно с ClientID субъекта, а не просто "адрес занят".
	if owner, ok := usedIPs(conf, clients)[hostIP(allowedIP)]; ok && owner != clientID {
		return nil, fmt.Errorf("IP %s занят пользователем %s — включить нельзя. Удалите или отключите его либо перевыпустите ему конфиг",
			hostIP(allowedIP), ownerLabel(clients, owner))
	}

	block := buildPeerBlock(clientID, psk, allowedIP)
	wgAfter := []byte(raw + block)

	newClients := make([]ClientEntry, len(clients))
	copy(newClients, clients)
	ud := make(map[string]any, len(newClients[idx].UserData))
	for k, v := range newClients[idx].UserData {
		if k == "disabled" || k == "disabledAt" || k == "psk" || k == "allowedIP" {
			continue
		}
		ud[k] = v
	}
	newClients[idx].UserData = ud
	tblAfter, err := json.MarshalIndent(newClients, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("сборка clientsTable: %w", err)
	}

	p := &Plan{
		Container:  c,
		Action:     "enable",
		Subject:    clients[idx].Name(),
		wgBefore:   []byte(raw),
		wgAfter:    wgAfter,
		tblBefore:  tblBefore,
		tblAfter:   tblAfter,
		tblExisted: tblExisted,
	}
	s.fillSHA(p)
	return p, nil
}

// ---------- Apply — транзакция (I2) ----------

// Apply применяет ранее построенный план: CAS → backup → запись → verify;
// любая ошибка на запись/verify откатывает файлы к прочитанному состоянию
// (restore). Конфиг с приватным ключом (для add/rekey) возвращается только
// после успешного verify — конфиг, выданный раньше, мог не заработать.
func (s *Session) Apply(p *Plan) (*NewUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyLocked(p)
}

func (s *Session) applyLocked(p *Plan) (*NewUser, error) {
	c := p.Container

	// 1. CAS — до любой записи (fail-safe: сервер с неизвестным busybox лучше
	// оставить как есть, чем записать поверх изменённого файла).
	if err := s.checkCAS(c, p); err != nil {
		return nil, err
	}

	// 2. backup — существующая команда, без изменений.
	if err := s.backup(c); err != nil {
		return nil, err
	}

	wgChanged := !bytes.Equal(p.wgBefore, p.wgAfter)

	// 3-5. запись → sync → verify
	if err := s.applySteps(c, p, wgChanged); err != nil {
		// 6. откат к прочитанному состоянию
		return nil, s.restore(c, p, wgChanged, err)
	}

	// 7. только после успешного verify — конфиг наружу
	return p.result, nil
}

func (s *Session) applySteps(c *Container, p *Plan, wgChanged bool) error {
	if wgChanged {
		if err := s.writeIn(c, c.Dir+"/wg0.conf", p.wgAfter); err != nil {
			return fmt.Errorf("запись wg0.conf: %w", err)
		}
	}
	if err := s.writeIn(c, c.Dir+"/clientsTable", p.tblAfter); err != nil {
		return fmt.Errorf("запись clientsTable: %w", err)
	}
	if wgChanged {
		if err := s.syncWg(c); err != nil {
			return fmt.Errorf("wg syncconf: %w", err)
		}
	}
	return s.verify(c, p, wgChanged)
}

// verify — шаг 5: (a) файлы на сервере байт в байт равны wgAfter/tblAfter;
// (b) множество активных PublicKey в рантайме равно множеству PublicKey всех
// [Peer] в wgAfter (пропускается для rename — checkPeers=wgChanged, а у
// rename wg0.conf не меняется).
func (s *Session) verify(c *Container, p *Plan, checkPeers bool) error {
	wgNow, err := s.catIn(c, c.Dir+"/wg0.conf")
	if err != nil {
		return fmt.Errorf("проверка wg0.conf: %w", err)
	}
	if wgNow != string(p.wgAfter) {
		return fmt.Errorf("проверка не пройдена: wg0.conf на сервере не совпадает с ожидаемым")
	}
	tblNow, err := s.catIn(c, c.Dir+"/clientsTable")
	if err != nil {
		return fmt.Errorf("проверка clientsTable: %w", err)
	}
	if tblNow != string(p.tblAfter) {
		return fmt.Errorf("проверка не пройдена: clientsTable на сервере не совпадает с ожидаемым")
	}
	if !checkPeers {
		return nil
	}
	stats, err := s.GetPeerStats(c)
	if err != nil {
		return fmt.Errorf("проверка активных peer'ов: %w", err)
	}
	want := peerPubKeysFromBytes(p.wgAfter)
	if len(stats) != len(want) {
		return fmt.Errorf("проверка не пройдена: набор активных peer'ов на сервере не совпадает с ожидаемым")
	}
	for pk := range want {
		if _, ok := stats[pk]; !ok {
			return fmt.Errorf("проверка не пройдена: peer %s не применился на сервере", pk)
		}
	}
	return nil
}

// restore — шаг 6: откат файлов к прочитанному состоянию (теми же командами,
// что запись — В2 п.3, не cp из backup/), с последующей проверкой ИТОГА —
// SEC-01 (changes-requested, 2026-09-14): настоящий `wg syncconf` при отказе
// НЕ гарантирует, что рантайм остался прежним — wireguard-tools setconf.c и
// amneziawg-go device/uapi.go (IpcSetOperation) применяют peer'ы по мере
// разбора конфигурации и при ошибке возвращают её БЕЗ отката уже применённых
// строк. Поэтому «файлы вернулись» не означает «рантайм тоже вернулся»:
// повторный syncconf на восстановлении может успеть частично примениться и
// упасть, оставив рантайм в состоянии, отличном и от старого, и от нового.
// Пытаемся записать ОБА файла независимо друг от друга (даже если один не
// удалось — второй всё равно пробуем), чтобы восстановить максимум
// возможного. Ровно три исхода:
//
//	(а) оба файла записались, и (если wg0.conf менялся) активные peer'ы на
//	    сервере после повторного syncconf совпадают с wgBefore — «состояние
//	    восстановлено и проверено», НЕЗАВИСИМО от кода возврата самого
//	    повторного syncconf (мог вернуть ошибку, но фактическое состояние
//	    всё равно совпало);
//	(б) оба файла записались, но проверка (файлов и/или активных peer'ов)
//	    после повторного syncconf разошлась с wgBefore — «файлы
//	    восстановлены, но применить их не удалось», с явным предупреждением,
//	    что активные подключения могут отличаться от wg0.conf;
//	(в) хотя бы один файл не удалось записать — «восстановить не удалось»,
//	    с указанием, какой файл вернулся, а какой нет, и путём к backup/.
func (s *Session) restore(c *Container, p *Plan, wgChanged bool, cause error) error {
	var wgWriteErr error
	if wgChanged {
		wgWriteErr = s.writeIn(c, c.Dir+"/wg0.conf", p.wgBefore)
	}
	tblBefore := p.tblBefore
	if !p.tblExisted {
		tblBefore = []byte{}
	}
	// clientsTable пишем НЕЗАВИСИМО от исхода записи wg0.conf — один файл не
	// должен тянуть за собой отказ восстановления другого (SEC-01, п.3).
	tblWriteErr := s.writeIn(c, c.Dir+"/clientsTable", tblBefore)

	if wgWriteErr != nil || tblWriteErr != nil {
		wgStatus := "не менялся"
		if wgChanged {
			if wgWriteErr != nil {
				wgStatus = fmt.Sprintf("НЕ восстановлен (%v)", wgWriteErr)
			} else {
				wgStatus = "восстановлен"
			}
		}
		tblStatus := "восстановлена"
		if tblWriteErr != nil {
			tblStatus = fmt.Sprintf("НЕ восстановлена (%v)", tblWriteErr)
		}
		return fmt.Errorf("ВНИМАНИЕ: восстановить не удалось — wg0.conf: %s; clientsTable: %s; резервные копии на сервере: %s/backup/wg0.conf.* и %s/backup/clientsTable.* (самые свежие); исходная причина: %v",
			wgStatus, tblStatus, c.Dir, c.Dir, cause)
	}

	// Оба файла точно на месте. Повторный syncconf — попытка вернуть и
	// рантайм; его код возврата сам по себе ничего не решает (см. комментарий
	// выше) — решает то, что реально проверим ниже.
	var syncErr error
	if wgChanged {
		syncErr = s.syncWg(c)
	}

	wgNow, wgReadErr := s.catIn(c, c.Dir+"/wg0.conf")
	tblNow, tblReadErr := s.catIn(c, c.Dir+"/clientsTable")
	filesVerified := wgReadErr == nil && tblReadErr == nil &&
		wgNow == string(p.wgBefore) && tblNow == string(tblBefore)

	runtimeVerified := true
	var runtimeErr error
	if wgChanged {
		stats, err := s.GetPeerStats(c)
		if err != nil {
			runtimeVerified, runtimeErr = false, err
		} else {
			want := peerPubKeysFromBytes(p.wgBefore)
			if len(stats) != len(want) {
				runtimeVerified = false
			} else {
				for pk := range want {
					if _, ok := stats[pk]; !ok {
						runtimeVerified = false
						break
					}
				}
			}
		}
	}

	// Код возврата повторного syncconf (syncErr) сам по себе НЕ решает исход —
	// решает то, что реально проверено ниже (filesVerified/runtimeVerified):
	// syncconf может вернуть ошибку и тем не менее оставить рантайм таким,
	// каким он уже был (совпадающим с wgBefore), и наоборот — вернуть 0 и
	// разойтись. syncErr используется только как дополнительный контекст в
	// тексте (б), когда runtimeVerified уже и так ложно.
	var verifyErr error
	switch {
	case wgReadErr != nil:
		verifyErr = fmt.Errorf("проверка wg0.conf после отката: %w", wgReadErr)
	case tblReadErr != nil:
		verifyErr = fmt.Errorf("проверка clientsTable после отката: %w", tblReadErr)
	case !filesVerified:
		verifyErr = fmt.Errorf("содержимое файлов после отката не совпадает с прочитанным состоянием")
	case runtimeErr != nil:
		verifyErr = runtimeErr
	case !runtimeVerified && syncErr != nil:
		verifyErr = fmt.Errorf("набор активных peer'ов не совпадает с ожидаемым (повторный syncconf: %w)", syncErr)
	case !runtimeVerified:
		verifyErr = fmt.Errorf("набор активных peer'ов на сервере после отката не совпадает с ожидаемым")
	}

	if verifyErr == nil {
		return fmt.Errorf("операция отменена, состояние восстановлено и проверено: %v", cause)
	}
	return fmt.Errorf("ВНИМАНИЕ: файлы восстановлены, но применить их не удалось (%v): активные подключения могут отличаться от wg0.conf до повторного применения или перезапуска контейнера; исходная причина: %v",
		verifyErr, cause)
}

// ---------- CAS по sha256sum (Г4, ядро: fail-safe, отдельный коммит) ----------

// ErrCASMismatch — сентинел отказа CAS (review PR-2, carryover 1): план
// построен по уже неактуальному чтению сервера — либо контрольная сумма
// разошлась, либо её не удалось проверить (нет sha256sum на сервере, сбой
// команды). До этого коммита cmd/gui/main.go распознавал отказ CAS по
// русским подстрокам текста ошибки (isCASRefusal); errors.Is(err,
// ErrCASMismatch) — тот же смысл, но не завязан на формулировку.
var ErrCASMismatch = errors.New("план устарел: сервер изменился с момента чтения")

// checkCAS — шаг 1 Apply. Расхождение контрольной суммы или невозможность её
// проверить (нет sha256sum на сервере, любой ненулевой код) — отказ ДО любой
// записи. Для отсутствовавшей при планировании clientsTable проверяем не
// сумму, а сам факт отсутствия (test -f), как и предписано Г4.
func (s *Session) checkCAS(c *Container, p *Plan) error {
	if err := s.casCheckFile(c, c.Dir+"/wg0.conf", p.wgSHA); err != nil {
		return err
	}
	if !p.tblExisted {
		exists, err := s.probeClientsTable(c)
		if err != nil {
			return fmt.Errorf("не удалось проверить контрольную сумму — запись отменена: %w: %w", ErrCASMismatch, err)
		}
		if exists {
			return fmt.Errorf("файл %s изменился с момента чтения — обновите список и повторите: %w", c.Dir+"/clientsTable", ErrCASMismatch)
		}
		return nil
	}
	return s.casCheckFile(c, c.Dir+"/clientsTable", p.tblSHA)
}

// casCheckFile — единственная новая серверная команда этого PR: sha256sum
// через s.docker (чтобы работал sudo-фолбэк).
func (s *Session) casCheckFile(c *Container, path, wantSHA string) error {
	out, err := s.docker(fmt.Sprintf("docker exec %s sha256sum %s", c.Name, path), nil)
	if err != nil {
		return fmt.Errorf("не удалось проверить контрольную сумму — запись отменена: %w: %w", ErrCASMismatch, err)
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return fmt.Errorf("не удалось проверить контрольную сумму — запись отменена: пустой ответ sha256sum: %w", ErrCASMismatch)
	}
	if fields[0] != wantSHA {
		return fmt.Errorf("файл %s изменился с момента чтения — обновите список и повторите: %w", path, ErrCASMismatch)
	}
	return nil
}

