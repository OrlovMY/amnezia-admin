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
	"context"
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
	Clients int
	// Target — пользователи нового сервера до записи; Conflicts — их
	// пересечения с клиентами копии (restoretarget.go).
	Target       TargetUsers
	Conflicts    []RestoreConflict
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

// installIDOf — UUID клиента установки XRay из файла xray_uuid.key; false —
// файла нет или в нём не UUID.
func installIDOf(f BackupFile) (string, bool) {
	if f.Status != FileSaved {
		return "", false
	}
	id := strings.TrimSpace(string(f.Data.Bytes()))
	return id, reUUID.MatchString(id)
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
	wg := !IsXRay(c)
	tgtCl, errT := clientsOf(before, p.wgBefore, wg)
	srcCl, errS := clientsOf(after, p.wgAfter, wg)
	if errT != nil || errS != nil {
		return RestoreItem{}, stopped("%s: конфигурация клиентов не разобрана — кто есть на сервере и в копии, неизвестно", c.Name)
	}
	svc, tgtSvc, srcSvc := ServiceNone, "", ""
	if !wg {
		svc = ServiceUnknown
		if id, ok := installIDOf(tgt[xrayUUIDFile]); ok {
			svc, tgtSvc = ServiceFound, id
		}
		srcSvc, _ = installIDOf(src[xrayUUIDFile])
	}
	it.Removed = removedOf(tgtCl, srcCl, tgtSvc, srcSvc)
	it.Target, it.Conflicts = compareTarget(tgtCl, srcCl, svc, tgtSvc, srcSvc)
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
	// Checked — граница проверки (только у RestoreDone).
	Checked string
}

// RestoreOptions — параметры переезда.
type RestoreOptions struct {
	AutoCopyDir string // каталог автокопии цели (обязателен)
	ToolVersion string
	Now         time.Time
	Resolve     Resolver
	Layer       BackupLayer
	// Ctx — отмена: действует ДО первой записи на сервер (после автокопии);
	// с началом записи не проверяется — прерывать A3б посередине опаснее.
	// nil — без отмены.
	Ctx context.Context
	// Progress — этапы: автокопия (чтение, запись), контейнер N из M.
	Progress ProgressFunc
	// ConfirmXRay — подтверждение перезапуска XRay (вызывается, только если
	// его часть что-то меняет). nil — «нет».
	ConfirmXRay func() bool
	// TargetConfirmed — отдельное подтверждение: на новом сервере есть
	// пользователи или конфликты с копией (RestorePlan.NeedsTargetConfirm).
	// Без него такой план не записывается.
	TargetConfirmed bool
}

var reSafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// AutoCopyName — имя файла автокопии цели.
func AutoCopyName(host string, now time.Time) string {
	h := reSafeName.ReplaceAllString(host, "_")
	return fmt.Sprintf("%s-%s-перед-восстановлением.aabk", h, now.UTC().Format("20060102-150405"))
}

// classify — исход контейнера по ошибке Apply. Порядок существенен
// (AU-LOGIC р2 High-1): ошибка отката (restoreError) несёт в Unwrap и
// причину, и исход отката — сентинелы «ничего не записано» (занято, нет
// утилиты, sudo) у неё относятся к ОТКАТУ, а запись уже была. Поэтому
// сначала — откат (по его kind), затем «записано частично/неизвестно», и
// только у ошибки без отката — «ничего не записано». Всё неопознанное —
// «неизвестно», не «восстановлен» и не «ничего не записано».
func classify(err error) RestoreState {
	if err == nil {
		return RestoreDone
	}
	var re *restoreError
	if errors.As(err, &re) {
		if re.kind == ErrRolledBack {
			return RestoreRolledBack
		}
		return RestoreUnknown
	}
	var rf *rollbackForeignError
	switch {
	case errors.As(err, &rf):
		return RestoreUnknown
	case errors.Is(err, ErrWritePartial), errors.Is(err, ErrWriteUnknown):
		return RestoreUnknown
	case errors.Is(err, ErrWriteNotStarted), errors.Is(err, ErrCASMismatch), errors.Is(err, ErrServerBusy),
		errors.Is(err, ErrServerToolMissing), errors.Is(err, ErrSudoDenied):
		return RestoreNotWritten
	}
	return RestoreUnknown
}

// Граница проверки у восстановленного контейнера (AU-LOGIC р2 High-2):
// своя у WG и у XRay; печатается только у «восстановлен».
const (
	RestoreCheckedWG   = "проверено: файлы байт в байт, набор клиентов, открытый ключ и порт работающего сервера; параметры маскировки AWG в работающем сервере не сверялись"
	RestoreCheckedXRay = "проверено: файлы байт в байт и что процесс XRay после перезапуска жив; принял ли он каждого клиента — проверить нечем"
	RestoreOutsideNote = "Открыт ли порт снаружи (файрвол хостера), программа изнутри проверить не может."
)

// Restore — применение плана: автокопия цели, затем контейнеры по очереди
// до первого сбоя. Ошибка — автокопия не снята или не записана: тогда
// ничего не записано. Иначе исходы по контейнерам.
func (s *Session) Restore(rp *RestorePlan, opt RestoreOptions) (autoCopy string, outs []RestoreOutcome, err error) {
	if rp == nil || len(rp.Items) == 0 {
		return "", nil, stopped("план пуст")
	}
	if rp.NeedsTargetConfirm() && !opt.TargetConfirmed {
		return "", nil, stopped("на новом сервере есть пользователи (%d) или конфликты с копией — запись без отдельного подтверждения запрещена", rp.TargetUserCount())
	}
	if opt.AutoCopyDir == "" || opt.Layer == nil {
		return "", nil, stopped("не задан каталог или слой автокопии")
	}
	ctx := opt.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	sub := func(p Progress) {
		p.Text = "автокопия нового сервера: " + p.Text
		if p.Stage == StageRead {
			p.Stage = StageAutoCopy
		}
		report(opt.Progress, p)
	}
	cur, err := s.CollectBackupCtx(ctx, opt.ToolVersion, opt.Now, opt.Resolve, sub)
	if errors.Is(err, ErrCanceled) {
		return "", nil, fmt.Errorf("%w — ничего не записано", err)
	}
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
	autoCopy, err = WriteBackupFileUniqueCtx(ctx, filepath.Join(opt.AutoCopyDir, AutoCopyName(host, opt.Now)), cur, opt.Layer, sub)
	if errors.Is(err, ErrCanceled) {
		return "", nil, fmt.Errorf("%w — ничего не записано", err)
	}
	if err != nil {
		return "", nil, stopped("автокопия нового сервера не записана (%v) — замена запрещена", err)
	}
	report(opt.Progress, Progress{Stage: StageAutoCopy, Text: "автокопия нового сервера сохранена: " + autoCopy})
	// последняя точка отмены — до первой записи на сервер
	if err := canceled(ctx); err != nil {
		return autoCopy, nil, fmt.Errorf("%w — на сервер ничего не записано (автокопия сохранена: %s)", err, autoCopy)
	}
	failed := false
	m := len(rp.Items)
	for i, it := range rp.Items {
		report(opt.Progress, Progress{Stage: StageContainer, Done: i, Total: m, Writing: true,
			Text: fmt.Sprintf("контейнер %d из %d: запись и проверка — %s", i+1, m, it.Container)})
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
			if o.State == RestoreDone {
				o.Checked = RestoreCheckedWG
				if IsXRay(it.plan.Container) {
					o.Checked = RestoreCheckedXRay
				}
			}
		}
		outs = append(outs, o)
	}
	report(opt.Progress, Progress{Stage: StageContainer, Done: m, Total: m, Writing: true, Text: "запись завершена — итог"})
	return autoCopy, outs, nil
}

// ifaceRuntimeOf — открытый ключ и порт работающего интерфейса: отдельными
// командами «<tool> show <iface> public-key» и «… listen-port» (SEC-01 Н-3:
// dump не читается — его первая строка начинается с ПРИВАТНОГО ключа
// интерфейса).
func (s *Session) ifaceRuntimeOf(c *Container) (pub, port string, err error) {
	fam, err := WGFamilyOf(c)
	if err != nil {
		return "", "", err
	}
	get := func(what string) (string, error) {
		out, err := s.docker(fmt.Sprintf("docker exec %s %s show %s %s", c.Name, fam.Tool, fam.Iface, what), nil)
		if err != nil {
			return "", fmt.Errorf("%s show %s: %w", fam.Tool, what, err)
		}
		v := strings.TrimSpace(out)
		if v == "" || strings.ContainsAny(v, " \t\n") {
			return "", fmt.Errorf("%s show %s: ответ не разобран", fam.Tool, what)
		}
		return v, nil
	}
	if pub, err = get("public-key"); err != nil {
		return "", "", err
	}
	if port, err = get("listen-port"); err != nil {
		return "", "", err
	}
	return pub, port, nil
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
