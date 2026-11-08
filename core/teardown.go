package core

// Снос Amnezia на НЕчистой цели перед установкой «с нуля» (решение
// владельца 05.11: «снос с подтверждением и бэкапом»).
//
// Порядок, который нельзя переставлять:
//  1. PlanTeardown — только чтение: состав цели (контейнеры, тома, образы
//     Amnezia по ЗАКРЫТОМУ списку имён, порты), клиенты по контейнерам,
//     копия цели в памяти. Имя amnezia-* вне закрытого списка — отказ
//     целиком: что это, программа не знает, сносить не вправе, а без сноса
//     установка всё равно откажет («сервер не чистый»).
//  2. ExecuteTeardown — копия цели на диск (0600) → перечитать и сверить с
//     тем, что снято → маркер незавершённой операции → docker rm -f / volume
//     rm / rmi ТОЛЬКО по закрытому списку → измерение: осталось ли что-то.
//     Копия не записана или не сверилась — сноса нет.
//
// Три состояния везде (CLAUDE.md): клиентов «нет» говорится только по
// прочитанной clientsTable; не прочитали — «не удалось прочитать». Копия:
// полная / частичная или пустая (снимать нечего или не прочиталось — снос
// только с отдельным явным подтверждением) / не записана (снос запрещён).
// Итог сноса: снесено (измерено) / не снесено (измерено, осталось …) /
// неизвестно (измерить не удалось) — нулевое значение «неизвестно».
//
// ОС, Docker, сеть amnezia-dns-net, каталоги /opt/amnezia, authorized_keys
// не трогаются: команды сноса — только три docker-команды с именем из
// закрытого списка.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// teardownVolumes — тома Amnezia, которые сносятся (закрытый список).
// Источник: prepareScripts (removeVolume = <контейнер>-data у XRay) и
// remove_container.sh приложения.
var teardownVolumes = map[string]bool{"amnezia-xray-data": true}

// TeardownAllowed — имя из закрытого списка сноса: контейнер/образ — имя
// типа Amnezia из containerTypes (с синонимами), том — teardownVolumes.
func TeardownAllowed(kind, name string) bool {
	if kind == "volume" {
		return teardownVolumes[name]
	}
	_, _, ok := lookupContainer(name)
	return ok
}

// reDockerName — имя, которое безопасно подставить в команду (без кавычек
// и пробелов). Закрытый список и так его гарантирует; это вторая стена.
var reDockerName = regexp.MustCompile(`^amnezia-[a-z0-9-]+$`)

// TargetClients — клиенты одного контейнера цели. Known=false — список
// прочитать не удалось (Why — почему); это не «клиентов нет».
type TargetClients struct {
	Container string
	Known     bool
	Names     []string
	Why       string
}

// TargetInventory — состав нечистой цели.
type TargetInventory struct {
	Containers []string          // контейнеры Amnezia (закрытый список)
	Volumes    []string          // тома Amnezia (закрытый список)
	Images     []string          // образы Amnezia (закрытый список)
	Ports      map[string]string // контейнер → опубликованные порты (как в docker ps)
	PortsKnown bool              // false — порты прочитать не удалось
	Foreign    []string          // amnezia-* вне закрытого списка — сносить нельзя
	Clients    []TargetClients   // по контейнерам Containers
}

// Empty — Amnezia на цели нет (по закрытому списку и вне его).
func (inv *TargetInventory) Empty() bool {
	return inv != nil && len(inv.Containers)+len(inv.Volumes)+len(inv.Images)+len(inv.Foreign) == 0
}

// CopyState — что есть в копии цели.
type CopyState int

const (
	// CopyNone — копировать нечего или снять не удалось (нулевое значение:
	// незнание не превращается в «копия есть»).
	CopyNone CopyState = iota
	// CopyPartial — сохранены не все контейнеры цели.
	CopyPartial
	// CopyFull — сохранены все контейнеры цели.
	CopyFull
)

// TeardownPlan — итог чтения цели (ничего не изменено).
type TeardownPlan struct {
	Inv     *TargetInventory
	Copy    *Backup // nil — копия не снята (CopyWhy)
	CopyWhy string
	host    string
}

// CopyState — полнота копии по контейнерам цели.
func (p *TeardownPlan) CopyState() CopyState {
	if p == nil || p.Copy == nil || p.Inv == nil {
		return CopyNone
	}
	saved := map[string]bool{}
	for _, c := range p.Copy.Containers {
		if c.Status == CtrSaved {
			saved[c.Name] = true
		}
	}
	n := 0
	for _, c := range p.Inv.Containers {
		if saved[c] {
			n++
		}
	}
	switch {
	case n == 0:
		return CopyNone
	case n == len(p.Inv.Containers):
		return CopyFull
	}
	return CopyPartial
}

// NotCopied — контейнеры цели, конфигурации которых в копию не попадут.
func (p *TeardownPlan) NotCopied() []string {
	saved := map[string]bool{}
	if p != nil && p.Copy != nil {
		for _, c := range p.Copy.Containers {
			if c.Status == CtrSaved {
				saved[c.Name] = true
			}
		}
	}
	var out []string
	if p != nil && p.Inv != nil {
		for _, c := range p.Inv.Containers {
			if !saved[c] {
				out = append(out, c)
			}
		}
	}
	return out
}

// NeedsNoCopyConfirm — снос без полной копии: нужно отдельное подтверждение.
func (p *TeardownPlan) NeedsNoCopyConfirm() bool { return p.CopyState() != CopyFull }

// Refusal — почему сносить нельзя ("" — можно с подтверждением).
func (p *TeardownPlan) Refusal() string {
	switch {
	case p == nil || p.Inv == nil:
		return "состав нового сервера не прочитан"
	case len(p.Inv.Foreign) > 0:
		return "на новом сервере есть контейнеры, тома или образы с именем amnezia-*, которых нет в списке программы: " + strings.Join(p.Inv.Foreign, ", ") +
			" — что это, программа не знает и сносить не будет. Удалите их вручную, если они не нужны, и повторите"
	case len(p.Inv.Containers)+len(p.Inv.Volumes)+len(p.Inv.Images) == 0:
		return "сносить нечего: Amnezia на новом сервере не найдена"
	}
	return ""
}

// TeardownCopyName — имя файла копии цели перед сносом.
func TeardownCopyName(host string, now time.Time) string {
	return fmt.Sprintf("%s-%s-перед-сносом.aabk", reSafeName.ReplaceAllString(host, "_"), now.UTC().Format("20060102-150405"))
}

// teardownCollect — снятие копии цели (шов теста).
var teardownCollect = func(ctx context.Context, s *Session, toolVersion string, now time.Time, r Resolver, p ProgressFunc) (*Backup, error) {
	return s.CollectBackupCtx(ctx, toolVersion, now, r, p)
}

// ErrTargetNotRead — состав цели прочитать не удалось.
var ErrTargetNotRead = errors.New("состав нового сервера прочитать не удалось")

// InspectTarget — состав цели (только чтение). Ошибка — список контейнеров,
// томов или образов не получен: состав неизвестен, а не «пусто».
func (s *Session) InspectTarget() (*TargetInventory, error) {
	inv := &TargetInventory{Ports: map[string]string{}}
	st, body, _ := s.instStep(rcTail(`if ! command -v docker >/dev/null 2>&1; then exit 0; fi; sudo -n docker ps -a --format "{{.Names}}|{{.Ports}}"`), nil)
	if st != stepOK {
		return nil, fmt.Errorf("%w: список контейнеров не получен", ErrTargetNotRead)
	}
	inv.PortsKnown = true
	for _, l := range strings.Split(body, "\n") {
		n, ports, _ := strings.Cut(strings.TrimSpace(l), "|")
		if !strings.HasPrefix(n, "amnezia-") {
			continue
		}
		if TeardownAllowed("container", n) {
			inv.Containers = append(inv.Containers, n)
			inv.Ports[n] = strings.TrimSpace(ports)
		} else {
			inv.Foreign = append(inv.Foreign, "контейнер "+n)
		}
	}
	for _, kind := range []string{"volume", "image"} {
		names, ok := s.listNames(kind)
		if !ok {
			return nil, fmt.Errorf("%w: список %s не получен", ErrTargetNotRead, map[string]string{"volume": "томов", "image": "образов"}[kind])
		}
		for _, n := range names {
			if !strings.HasPrefix(n, "amnezia-") {
				continue
			}
			switch {
			case !TeardownAllowed(kind, n):
				inv.Foreign = append(inv.Foreign, map[string]string{"volume": "том ", "image": "образ "}[kind]+n)
			case kind == "volume":
				inv.Volumes = append(inv.Volumes, n)
			default:
				inv.Images = append(inv.Images, n)
			}
		}
	}
	sort.Strings(inv.Containers)
	sort.Strings(inv.Volumes)
	sort.Strings(inv.Images)
	sort.Strings(inv.Foreign)
	return inv, nil
}

// PlanTeardown — состав цели, клиенты и копия цели в памяти (только
// чтение). Ошибка — состав цели не прочитан (ErrTargetNotRead). Копия, не
// снятая целиком, — не ошибка: CopyWhy, клиенты «не удалось прочитать».
func (s *Session) PlanTeardown(ctx context.Context, toolVersion string, now time.Time, r Resolver, p ProgressFunc) (*TeardownPlan, error) {
	inv, err := s.InspectTarget()
	if err != nil {
		return nil, err
	}
	tp := &TeardownPlan{Inv: inv}
	if s.Creds != nil {
		tp.host = s.Creds.Host
	}
	if len(inv.Containers) > 0 {
		b, cerr := teardownCollect(ctx, s, toolVersion, now, r, p)
		if errors.Is(cerr, ErrCanceled) {
			return nil, cerr
		}
		if cerr != nil {
			tp.CopyWhy = "копия не снята: " + MaskText(cerr.Error())
		} else {
			tp.Copy = b
		}
	}
	for _, c := range inv.Containers {
		inv.Clients = append(inv.Clients, targetClientsOf(tp.Copy, c, tp.CopyWhy))
	}
	return tp, nil
}

// targetClientsOf — клиенты контейнера из копии цели; Known только по
// прочитанной clientsTable (или по измеренному «файла нет»).
func targetClientsOf(b *Backup, ctr, copyWhy string) TargetClients {
	tc := TargetClients{Container: ctr}
	if b == nil {
		tc.Why = "не удалось прочитать (" + dash(copyWhy) + ")"
		return tc
	}
	for _, bc := range b.Containers {
		if bc.Name != ctr {
			continue
		}
		if bc.Status != CtrSaved {
			tc.Why = "не удалось прочитать (" + dash(ctrStateText[bc.Status]) + ")"
			return tc
		}
		for _, f := range bc.Files {
			if f.Name != "clientsTable" {
				continue
			}
			switch f.Status {
			case FileAbsent:
				tc.Known, tc.Why = true, "файла clientsTable на сервере нет"
				return tc
			case FileSaved:
				list, err := parseClientsTable(f.Data.Bytes())
				if err != nil {
					tc.Why = "не удалось прочитать (clientsTable не разобрана)"
					return tc
				}
				tc.Known = true
				for _, e := range list {
					tc.Names = append(tc.Names, displayName(e.Name()))
				}
				return tc
			}
		}
		tc.Why = "не удалось прочитать (clientsTable не прочитана)"
		return tc
	}
	tc.Why = "не удалось прочитать (контейнер не запущен или не входит в копию)"
	return tc
}

// InventoryLines — состав цели для человека (CLI и GUI — один текст).
func (p *TeardownPlan) InventoryLines() []string {
	if p == nil || p.Inv == nil {
		return []string{"Состав нового сервера: не удалось прочитать."}
	}
	inv := p.Inv
	out := []string{"Состав нового сервера (Amnezia):"}
	for i, c := range inv.Containers {
		l := "  контейнер " + c
		if ct, _, ok := lookupContainer(c); ok && ct.Proto != "" {
			l += " — протокол " + ct.Proto
		}
		switch {
		case !inv.PortsKnown:
			l += "; порты: не удалось прочитать"
		case inv.Ports[c] == "":
			l += "; опубликованных портов нет"
		default:
			l += "; порты: " + inv.Ports[c]
		}
		out = append(out, l)
		if i < len(inv.Clients) {
			tc := inv.Clients[i]
			switch {
			case !tc.Known:
				out = append(out, "      клиенты: "+tc.Why)
			case len(tc.Names) == 0:
				out = append(out, "      клиенты: нет ("+dash(tc.Why)+")")
			default:
				out = append(out, fmt.Sprintf("      клиенты (%d): %s", len(tc.Names), strings.Join(tc.Names, ", ")))
			}
		}
	}
	if len(inv.Volumes) > 0 {
		out = append(out, "  тома: "+strings.Join(inv.Volumes, ", "))
	}
	if len(inv.Images) > 0 {
		out = append(out, "  образы: "+strings.Join(inv.Images, ", "))
	}
	if len(inv.Foreign) > 0 {
		out = append(out, "  НЕ ИЗ СПИСКА ПРОГРАММЫ (сноситься не будут): "+strings.Join(inv.Foreign, ", "))
	}
	switch p.CopyState() {
	case CopyFull:
		out = append(out, "Копия нового сервера перед сносом: будет записана и проверена (все контейнеры).")
	case CopyPartial:
		out = append(out, "Копия нового сервера перед сносом: ЧАСТИЧНАЯ — не попадут: "+strings.Join(p.NotCopied(), ", ")+". Их настройки и клиенты пропадут безвозвратно.")
	default:
		why := p.CopyWhy
		if why == "" {
			why = "ни один контейнер не сохранён"
		}
		out = append(out, "Копии нового сервера НЕ БУДЕТ: копировать нечего или прочитать не удалось ("+why+"). Снос сотрёт настройки и клиентов этих контейнеров безвозвратно.")
	}
	out = append(out, "Сносятся только перечисленные контейнеры, тома и образы Amnezia. ОС, Docker, сеть amnezia-dns-net, каталоги /opt/amnezia и ключи входа (authorized_keys) не трогаются.")
	return out
}

// TeardownState — итог сноса. Нулевое значение — «неизвестно».
type TeardownState int

const (
	TeardownUnknown TeardownState = iota // измерить не удалось / оборвалось
	TeardownRefused                      // не начинался — на сервере ничего не изменено
	TeardownFailed                       // измерено: осталось (Left)
	TeardownDone                         // измерено: Amnezia на цели нет
)

func (s TeardownState) String() string {
	switch s {
	case TeardownRefused:
		return "снос не выполнялся — на новом сервере ничего не изменено"
	case TeardownFailed:
		return "снесено НЕ всё"
	case TeardownDone:
		return "снесено (проверено: контейнеров, томов и образов Amnezia на сервере нет)"
	}
	return "итог сноса НЕИЗВЕСТЕН"
}

// TeardownOptions — согласия и параметры копии.
type TeardownOptions struct {
	Confirmed       bool // явное «да» на снос
	NoCopyConfirmed bool // отдельное «да» на снос без полной копии
	CopyDir         string
	Layer           BackupLayer
	Now             time.Time
	Tool            string
	Ctx             context.Context
	Progress        ProgressFunc
}

// TeardownResult — итог.
type TeardownResult struct {
	State    TeardownState
	Why      string
	CopyPath string   // "" — копия не записывалась
	Left     []string // что осталось (TeardownFailed)
	Marker   bool     // маркер незавершённой операции записан этим сносом
}

// teardownVerifyHook — шов теста: подмена перечитанной копии.
var teardownVerifyHook func(*Backup)

// ExecuteTeardown — копия → проверка копии → маркер → снос → измерение.
// Маркер снимается только при измеренном итоге (Done/Failed); при
// неизвестном итоге остаётся — следующий запуск о нём скажет.
func (s *Session) ExecuteTeardown(p *TeardownPlan, opt TeardownOptions) TeardownResult {
	refuse := func(why string) TeardownResult { return TeardownResult{State: TeardownRefused, Why: why} }
	if why := p.Refusal(); why != "" {
		return refuse(why)
	}
	if !opt.Confirmed {
		return refuse("снос не подтверждён")
	}
	if p.NeedsNoCopyConfirm() && !opt.NoCopyConfirmed {
		return refuse("полной копии нового сервера не будет — снос без неё требует отдельного подтверждения")
	}
	ctx := opt.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	res := TeardownResult{}
	if p.CopyState() != CopyNone {
		if opt.CopyDir == "" || opt.Layer == nil {
			return refuse("не задан каталог или слой копии нового сервера")
		}
		if err := os.MkdirAll(opt.CopyDir, 0o700); err != nil {
			return refuse("каталог копии не создан: " + MaskText(err.Error()) + " — снос не выполнялся")
		}
		path, err := WriteBackupFileUniqueCtx(ctx, filepath.Join(opt.CopyDir, TeardownCopyName(p.host, opt.Now)), p.Copy, opt.Layer, opt.Progress)
		if err != nil {
			return refuse("копия нового сервера не записана: " + MaskText(err.Error()) + " — снос не выполнялся")
		}
		res.CopyPath = path
		if err := verifyCopyFile(path, p.Copy, opt.Layer); err != nil {
			r := refuse("копия нового сервера записана (" + path + "), но проверка не прошла: " + MaskText(err.Error()) + " — снос не выполнялся")
			r.CopyPath = path
			return r
		}
	}
	if err := canceled(ctx); err != nil {
		r := refuse("отменено до сноса")
		r.CopyPath = res.CopyPath
		return r
	}
	names := append(append(append([]string{}, p.Inv.Containers...), p.Inv.Volumes...), p.Inv.Images...)
	mk := OpMarker{Target: p.host, Started: opt.Now, Step: "снос Amnezia на новом сервере", Installed: names, Tool: opt.Tool}
	if err := BeginOpMarker(mk); err != nil {
		r := refuse(MaskText(err.Error()) + " — снос не выполнялся")
		r.CopyPath = res.CopyPath
		return r
	}
	res.Marker = true
	report(opt.Progress, Progress{Stage: StageContainer, Writing: true, Text: "снос Amnezia на новом сервере…"})
	for _, n := range p.Inv.Containers {
		s.teardownCmd("container", n)
	}
	for _, n := range p.Inv.Volumes {
		s.teardownCmd("volume", n)
	}
	for _, n := range p.Inv.Images {
		s.teardownCmd("image", n)
	}
	// измерение — исход только по нему, не по кодам команд
	unknown := false
	for _, kind := range []string{"container", "volume", "image"} {
		got, ok := s.listNames(kind)
		if !ok {
			unknown = true
			continue
		}
		for _, n := range got {
			if TeardownAllowed(kind, n) {
				res.Left = append(res.Left, map[string]string{"container": "контейнер ", "volume": "том ", "image": "образ "}[kind]+n)
			}
		}
	}
	switch {
	case len(res.Left) > 0:
		res.State, res.Why = TeardownFailed, "на сервере осталось: "+strings.Join(res.Left, ", ")
	case unknown:
		res.State, res.Why = TeardownUnknown, "после сноса не удалось узнать, что осталось на сервере (связь или права)"
	default:
		res.State = TeardownDone
	}
	if res.State != TeardownUnknown {
		if err := ClearOpMarker(); err != nil {
			res.Why = strings.TrimPrefix(res.Why+"; маркер незавершённой операции не удалён: "+MaskText(err.Error()), "; ")
		}
	}
	return res
}

// teardownCmd — одна команда сноса; имя повторно сверяется со списком.
func (s *Session) teardownCmd(kind, name string) {
	if !TeardownAllowed(kind, name) || !reDockerName.MatchString(name) {
		return
	}
	q := map[string]string{"container": "sudo -n docker rm -f ", "volume": "sudo -n docker volume rm ", "image": "sudo -n docker rmi "}[kind]
	s.instStep(rcTail(q+name), nil) // исход — по измерению
}

// verifyCopyFile — перечитать файл копии и сверить с тем, что снято: те же
// контейнеры, статусы и байты файлов. На Linux/macOS — ещё права 0600.
func verifyCopyFile(path string, want *Backup, layer BackupLayer) error {
	if !isWindows() {
		st, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("файл копии не найден: %v", err)
		}
		if st.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("файл копии доступен не только владельцу (%v)", st.Mode().Perm())
		}
	}
	got, err := ReadBackupFile(path, layer)
	if err != nil {
		return fmt.Errorf("файл копии не прочитан: %v", err)
	}
	if teardownVerifyHook != nil {
		teardownVerifyHook(got)
	}
	if len(got.Containers) != len(want.Containers) {
		return errors.New("в перечитанной копии другое число контейнеров")
	}
	for i, wc := range want.Containers {
		gc := got.Containers[i]
		if gc.Name != wc.Name || gc.Status != wc.Status || len(gc.Files) != len(wc.Files) {
			return fmt.Errorf("в перечитанной копии контейнер %s не совпал", wc.Name)
		}
		for j, wf := range wc.Files {
			gf := gc.Files[j]
			if gf.Name != wf.Name || gf.Status != wf.Status || !bytes.Equal(gf.Data.Bytes(), wf.Data.Bytes()) {
				return fmt.Errorf("в перечитанной копии файл %s/%s не совпал", wc.Name, wf.Name)
			}
		}
	}
	return nil
}

// TeardownWouldClear — «нельзя ставить» в предпроверке вызвано ТОЛЬКО
// Amnezia на цели: пункт о контейнерах amnezia-* и порты, опубликованные
// контейнерами amnezia-*. Любой другой запрет или неизмеренный пункт — нет:
// снос не сделал бы цель годной, а сносить, чтобы потом остановиться,
// нельзя.
func TeardownWouldClear(r ProvisionReport) bool {
	dirty := false
	for _, it := range r.Items {
		switch {
		case it.State == ProvOK:
		case it.State != ProvBad:
			return false
		case it.What == provCtrWhat:
			dirty = true
		case strings.Contains(it.Reason, "порт опубликован контейнером amnezia-"):
		default:
			return false
		}
	}
	return dirty
}
