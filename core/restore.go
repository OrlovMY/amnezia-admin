package core

// Восстановление «заменить целиком» на новом сервере (переезд; решения
// владельца 1–3, 5; ядра Р-4…Р-6). Запись — только механизмом A3б: Plan →
// Apply (CAS под замком /run/lock, закрытый список файлов с ключами —
// Plan.extra, откат по таблице исходов). Перед заменой — автокопия цели;
// не снялась полностью — замена запрещена. XRay — последним и только с
// подтверждением перезапуска. После syncconf ключ и порт работающего
// интерфейса сверяются с копией (Р-5); не совпали — «не применено», откат.
//
// Режим «добавить недостающих» не делается (Р-6, бэклог).

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// RestoreItem — один контейнер восстановления (предпросмотр без секретов).
type RestoreItem struct {
	Container string
	Proto     string
	// Removed — клиенты нового сервера, которых нет в копии: после замены
	// их не будет (перечисляются поимённо).
	Removed []string
	// Clients — число клиентов в копии.
	Clients      int
	RestartsXRay bool
	plan         *Plan
}

// RestorePlan — план переезда: контейнеры в порядке применения (WG, затем
// XRay).
type RestorePlan struct {
	Items  []RestoreItem
	Compat *CompatReport
	source *Backup
}

// ErrRestoreStopped — переезд остановлен до записи.
var ErrRestoreStopped = errors.New("переезд остановлен до записи")

func stopped(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrRestoreStopped, fmt.Sprintf(format, a...))
}

func clientIDs(tbl []byte) ([]ClientEntry, bool) {
	if len(strings.TrimSpace(string(tbl))) == 0 {
		return nil, true
	}
	var list []ClientEntry
	if err := json.Unmarshal(tbl, &list); err != nil {
		return nil, false
	}
	return list, true
}

// PlanRestore — план замены целиком по копии b на этом (новом) сервере.
// Только чтение. compat — результат CheckTarget по той же копии: СТОП или
// неподтверждённый адрес (addressConfirmed=false при NeedAddressConfirm) —
// отказ до плана.
func (s *Session) PlanRestore(b *Backup, compat *CompatReport, addressConfirmed bool) (*RestorePlan, error) {
	switch {
	case compat == nil:
		return nil, stopped("совместимость нового сервера не проверена")
	case compat.Stop:
		return nil, stopped("проверка нового сервера нашла расхождения — сначала исправьте их на новом сервере")
	case compat.NeedAddressConfirm && !addressConfirmed:
		return nil, stopped("адрес выдачи другой или не проверен — нужно отдельное подтверждение")
	}
	cs, err := s.FindContainers()
	if err != nil {
		return nil, stopped("список контейнеров нового сервера не получен: %v", err)
	}
	byName := map[string]*Container{}
	for i := range cs {
		byName[cs[i].Name] = &cs[i]
	}
	rp := &RestorePlan{Compat: compat, source: b}
	var xray []RestoreItem
	for _, bc := range b.Containers {
		if bc.Status == CtrNotIncluded {
			continue
		}
		if bc.Status != CtrSaved {
			return nil, stopped("%s в копии не сохранён", bc.Name)
		}
		c := byName[bc.Name]
		if c == nil {
			return nil, stopped("на новом сервере нет %s", bc.Name)
		}
		it, err := s.planRestoreContainer(c, bc)
		if err != nil {
			return nil, err
		}
		if IsXRay(c) {
			xray = append(xray, it)
		} else {
			rp.Items = append(rp.Items, it)
		}
	}
	rp.Items = append(rp.Items, xray...)
	if len(rp.Items) == 0 {
		return nil, stopped("в копии нет ни одного контейнера, который можно перенести")
	}
	return rp, nil
}

func (s *Session) planRestoreContainer(c *Container, bc BackupContainer) (RestoreItem, error) {
	names, _, ok := backupFilesOf(c)
	if !ok || len(bc.Files) != len(names) {
		return RestoreItem{}, stopped("%s: состав файлов копии не совпадает с этой программой", c.Name)
	}
	src := map[string]BackupFile{}
	for _, f := range bc.Files {
		src[f.Name] = f
	}
	tgt := map[string]BackupFile{}
	for _, n := range names {
		d, st, why := s.readFileState(c, n)
		if st == FileUnreadable {
			return RestoreItem{}, stopped("%s/%s на новом сервере не прочитан (%s)", c.Name, n, why)
		}
		tgt[n] = BackupFile{Name: n, Status: st, Data: NewSecret(d)}
	}
	conf := names[0]
	if tgt[conf].Status != FileSaved {
		return RestoreItem{}, stopped("%s: на новом сервере нет %s", c.Name, conf)
	}
	if err := checkAWG2Writable(c, string(src[conf].Data.Bytes())); err != nil {
		return RestoreItem{}, stopped("%v", err)
	}
	p := &Plan{Container: c, Action: "restore", Subject: c.Name,
		wgBefore: tgt[conf].Data.Bytes(), wgAfter: src[conf].Data.Bytes()}
	if t := tgt["clientsTable"]; t.Status == FileSaved {
		p.tblBefore, p.tblExisted = t.Data.Bytes(), true
	}
	if f := src["clientsTable"]; f.Status == FileSaved {
		p.tblAfter = f.Data.Bytes()
	} else {
		p.tblAfter = []byte("[]")
	}
	for _, n := range names[2:] {
		f := src[n]
		if f.Status != FileSaved {
			continue // в копии ключа нет — файл цели не трогаем
		}
		t := tgt[n]
		p.extra = append(p.extra, planExtra{name: n, before: t.Data.Bytes(), after: f.Data.Bytes(), existed: t.Status == FileSaved})
	}
	if err := p.checkExtras(); err != nil {
		return RestoreItem{}, stopped("%v — установка на новом сервере неполная", err)
	}
	s.fillSHA(p)
	it := RestoreItem{Container: c.Name, Proto: c.Title(), plan: p, RestartsXRay: p.RestartsXRay()}
	after, okA := clientIDs(p.tblAfter)
	before, okB := clientIDs(p.tblBefore)
	if !okA || !okB {
		return RestoreItem{}, stopped("%s: clientsTable не разобрана — список удаляемых неизвестен", c.Name)
	}
	it.Clients = len(after)
	keep := map[string]bool{}
	for _, e := range after {
		keep[e.ClientID] = true
	}
	for _, e := range before {
		if !keep[e.ClientID] {
			n := e.Name()
			if n == "" {
				n = "(без имени)"
			}
			it.Removed = append(it.Removed, n)
		}
	}
	return it, nil
}

// RestoreState — исход контейнера.
type RestoreState int

const (
	RestoreUnknown    RestoreState = iota // записано, итог неизвестен — нулевое значение
	RestoreDone                           // восстановлен и проверен
	RestoreNotWritten                     // не восстановлен, ничего не записано
	RestoreRolledBack                     // не восстановлен, откат выполнен и проверен
	RestoreSkipped                        // не трогался: остановлено на предыдущем
	RestoreDeclined                       // XRay: перезапуск не подтверждён
)

func (r RestoreState) String() string {
	switch r {
	case RestoreDone:
		return "восстановлен"
	case RestoreNotWritten:
		return "не восстановлен, ничего не записано"
	case RestoreRolledBack:
		return "не восстановлен, откат выполнен"
	case RestoreSkipped:
		return "пропущен (остановлено на предыдущем)"
	case RestoreDeclined:
		return "пропущен (перезапуск XRay не подтверждён)"
	}
	return "не восстановлен, состояние неизвестно"
}

// RestoreOutcome — исход контейнера с причиной.
type RestoreOutcome struct {
	Container string
	State     RestoreState
	Err       error
}

// RestoreOptions — параметры переезда.
type RestoreOptions struct {
	AutoCopyDir string // каталог автокопии цели (обязателен)
	ToolVersion string
	Now         time.Time
	Resolve     Resolver
	Layer       BackupLayer
	// ConfirmXRay — подтверждение перезапуска XRay (вызывается, только если
	// его часть что-то меняет). nil — «нет».
	ConfirmXRay func() bool
}

var reSafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// AutoCopyName — имя файла автокопии цели.
func AutoCopyName(host string, now time.Time) string {
	h := reSafeName.ReplaceAllString(host, "_")
	return fmt.Sprintf("%s-%s-перед-восстановлением.aabk", h, now.UTC().Format("20060102-150405"))
}

func classify(err error) RestoreState {
	switch {
	case err == nil:
		return RestoreDone
	case errors.Is(err, ErrRolledBack):
		return RestoreRolledBack
	case errors.Is(err, ErrWriteNotStarted), errors.Is(err, ErrCASMismatch), errors.Is(err, ErrServerBusy),
		errors.Is(err, ErrServerToolMissing), errors.Is(err, ErrSudoDenied):
		return RestoreNotWritten
	}
	return RestoreUnknown
}

// Restore — применение плана: автокопия цели, затем контейнеры по очереди
// до первого сбоя. Ошибка — автокопия не снята или не записана: тогда
// ничего не записано. Иначе исходы по контейнерам.
func (s *Session) Restore(rp *RestorePlan, opt RestoreOptions) (autoCopy string, outs []RestoreOutcome, err error) {
	if rp == nil || len(rp.Items) == 0 {
		return "", nil, stopped("план пуст")
	}
	if opt.AutoCopyDir == "" || opt.Layer == nil {
		return "", nil, stopped("не задан каталог или слой автокопии")
	}
	cur, err := s.CollectBackup(opt.ToolVersion, opt.Now, opt.Resolve)
	if err != nil {
		return "", nil, stopped("автокопия нового сервера не снята (%v) — замена запрещена", err)
	}
	if !cur.Complete {
		return "", nil, stopped("автокопия нового сервера неполная — замена запрещена")
	}
	host := ""
	if s.Creds != nil {
		host = s.Creds.Host
	}
	autoCopy = filepath.Join(opt.AutoCopyDir, AutoCopyName(host, opt.Now))
	if err := WriteBackupFile(autoCopy, cur, opt.Layer); err != nil {
		return "", nil, stopped("автокопия нового сервера не записана (%v) — замена запрещена", err)
	}
	failed := false
	for _, it := range rp.Items {
		o := RestoreOutcome{Container: it.Container}
		switch {
		case failed:
			o.State = RestoreSkipped
		case it.RestartsXRay && (opt.ConfirmXRay == nil || !opt.ConfirmXRay()):
			o.State = RestoreDeclined
		default:
			_, aerr := s.Apply(it.plan)
			o.State, o.Err = classify(aerr), aerr
			failed = aerr != nil
		}
		outs = append(outs, o)
	}
	return autoCopy, outs, nil
}

// RestoreRuntimeNote — граница проверки после замены (Р-5): что сверено.
const RestoreRuntimeNote = "Проверено: файлы байт в байт; набор клиентов, открытый ключ и порт работающего сервера совпали с копией. " +
	"Параметры маскировки AWG (Jc…H4, S3/S4, I1–I5, поля AWG3) в работающем сервере не сверялись — вывод awg show их не показывает в разобранном программой виде. " +
	"Открыт ли порт снаружи (файрвол хостера), программа изнутри проверить не может."

// ifaceRuntimeOf — открытый ключ и порт работающего интерфейса (первая
// строка wg/awg show dump). Приватный ключ (первое поле) не читается.
func (s *Session) ifaceRuntimeOf(c *Container) (pub, port string, err error) {
	fam, err := WGFamilyOf(c)
	if err != nil {
		return "", "", err
	}
	out, err := s.docker(fmt.Sprintf("docker exec %s %s show %s dump", c.Name, fam.Tool, fam.Iface), nil)
	if err != nil {
		return "", "", fmt.Errorf("%s show: %w", fam.Tool, err)
	}
	line := strings.SplitN(strings.TrimRight(out, "\r\n"), "\n", 2)[0]
	f := strings.Split(strings.TrimRight(line, "\r"), "\t")
	if len(f) < 3 {
		return "", "", fmt.Errorf("%s show: строка интерфейса не разобрана", fam.Tool)
	}
	return f[1], f[2], nil
}

// verifyRestoredIface — Р-5: ключ и порт работающего интерфейса равны
// ожидаемым из записанного файла. Три исхода: nil — совпали; ошибка
// «не применено» — прочитаны и не совпали; ошибка «не проверено» — не
// прочитаны. Обе ошибки ведут к откату.
func (s *Session) verifyRestoredIface(c *Container, conf []byte) error {
	iface := parseWgConf(string(conf)).iface
	wantPub, err := pubFromPriv(iface["PrivateKey"])
	if err != nil {
		return fmt.Errorf("проверка не пройдена: ключ сервера в копии не разобран")
	}
	pub, port, err := s.ifaceRuntimeOf(c)
	if err != nil {
		return fmt.Errorf("проверка не выполнена: работающий интерфейс не прочитан (%v) — применилось ли, неизвестно", err)
	}
	if pub != wantPub || port != iface["ListenPort"] {
		return fmt.Errorf("не применено: работающий сервер не принял ключ сервера или порт из копии — нужен перезапуск контейнера %s (оборвёт все подключения этого протокола)", c.Name)
	}
	return nil
}
