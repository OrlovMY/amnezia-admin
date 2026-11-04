package core

// Прямой переезд «на лету» (решения владельца 05.11, Б1): источник читается
// в память и сразу, без записи копии на диск, проверяется против цели и
// переносится на неё тем же конвейером, что и восстановление из файла:
// CollectBackupCtx(источник) → CheckTarget(цель) → PlanRestore → Restore.
//
// Источник — только чтение. Копия источника НЕ кодируется и НЕ пишется ни
// в файл, ни во временный каталог: секреты источника (приватный ключ
// сервера, PSK клиентов, UUID XRay) живут только в памяти процесса. На диск
// пишется единственное — автокопия ЦЕЛИ перед заменой (Restore).
//
// Три состояния у вопроса «один ли это сервер»: да / нет / узнать не
// удалось; «не удалось» — тоже отказ (переезд сервера на самого себя —
// затирание боевых данных, а не переезд).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SameServerVerdict — три исхода сверки источника и цели.
type SameServerVerdict int

const (
	SameUnknown SameServerVerdict = iota // узнать не удалось — нулевое значение
	SameYes                              // это один сервер
	SameNo                               // разные серверы
)

func (v SameServerVerdict) String() string {
	switch v {
	case SameYes:
		return "один и тот же сервер"
	case SameNo:
		return "разные серверы"
	}
	return "узнать не удалось"
}

// ErrSameServer — источник и цель совпадают или это не удалось исключить.
var ErrSameServer = errors.New("источник и цель — один и тот же сервер, либо это не удалось исключить")

// SameServer — один ли сервер за двумя сессиями. Порядок: отпечаток ключа
// хоста (сильнейший признак: равен — один сервер, различен — разные), затем
// адреса (разрешённые). Тот же IP, но разные SSH-порты, и нет отпечатков —
// не знаем (это может быть и один сервер с двумя портами), а не «разные».
func SameServer(a, b *Session, resolve Resolver) (SameServerVerdict, string) {
	if a == nil || b == nil {
		return SameUnknown, "сессия не передана"
	}
	if a.HostKeyFingerprint != "" && b.HostKeyFingerprint != "" {
		if a.HostKeyFingerprint != b.HostKeyFingerprint {
			return SameNo, "ключи хоста различаются"
		}
		// Ключ хоста равен: один сервер — только если и адреса те же. Новый
		// VPS, поднятый из снимка или клона старого, несёт тот же ключ хоста
		// при другом адресе — это «не знаем», а не «один сервер».
		if a.Creds != nil && b.Creds != nil {
			aips, aok := hostIPs(a.Creds.Host, resolve)
			bips, bok := hostIPs(b.Creds.Host, resolve)
			if aok && bok && intersects(aips, bips) {
				return SameYes, "у обоих один и тот же ключ хоста " + a.HostKeyFingerprint + " и один адрес"
			}
		}
		return SameUnknown, "ключ хоста у обоих одинаковый (" + a.HostKeyFingerprint + "), но адреса разные или не сверены: это либо один сервер под двумя адресами, " +
			"либо новый сервер, поднятый из снимка или клона старого, с тем же ключом хоста. Не записываем, пока не уверены. Если это клон — на новом сервере " +
			"перегенерируйте ключи хоста (rm /etc/ssh/ssh_host_* && dpkg-reconfigure openssh-server или эквивалент для вашей ОС), удалите старый отпечаток из known_hosts и повторите"
	}
	if a.Creds == nil || b.Creds == nil {
		return SameUnknown, "адрес одного из серверов неизвестен"
	}
	aips, aok := hostIPs(a.Creds.Host, resolve)
	bips, bok := hostIPs(b.Creds.Host, resolve)
	if !aok || !bok {
		bad := a.Creds.Host
		if aok {
			bad = b.Creds.Host
		}
		return SameUnknown, "адрес " + bad + " не разрешился, ключи хоста не сравнить"
	}
	if !intersects(aips, bips) {
		return SameNo, "адреса различаются"
	}
	if portOf(a.Creds) == portOf(b.Creds) {
		return SameYes, "тот же адрес и порт SSH"
	}
	return SameUnknown, "тот же адрес при разных портах SSH, ключи хоста не сравнить"
}

func portOf(c *ServerCreds) string {
	if c.Port == "" || c.Port == "0" {
		return "22"
	}
	return c.Port
}

// MigrationOptions — параметры сбора и проверки.
type MigrationOptions struct {
	ToolVersion string
	Now         time.Time
	Resolve     Resolver
	Progress    ProgressFunc
}

// Migration — собранный в памяти источник, проверка цели и план. Ни одного
// байта источника на диске.
type Migration struct {
	src    *Backup
	dst    *Session
	Compat *CompatReport
	// Plan — nil при Compat.Stop: плана нет, пока цель не исправлена.
	Plan *RestorePlan
}

// Source — снимок источника в памяти (для сводки; секреты скрыты типом
// Secret).
func (m *Migration) Source() *Backup { return m.src }

// PrepareMigration — только чтение обоих серверов. Ошибка: источник и цель
// совпадают / не удалось исключить (ErrSameServer), источник не прочитан,
// список контейнеров цели не получен (ErrRestoreStopped), план не построен
// (ErrRestoreStopped). СТОП проверки — не ошибка: Compat.Stop, Plan == nil.
func PrepareMigration(ctx context.Context, src, dst *Session, opt MigrationOptions) (*Migration, error) {
	if v, why := SameServer(src, dst, opt.Resolve); v != SameNo {
		return nil, fmt.Errorf("%w (%s)", ErrSameServer, why)
	}
	b, err := src.CollectBackupCtx(ctx, opt.ToolVersion, opt.Now, opt.Resolve, opt.Progress)
	if err != nil {
		if errors.Is(err, ErrCanceled) {
			return nil, err
		}
		return nil, fmt.Errorf("источник не прочитан — переезд невозможен: %w", err)
	}
	compat, err := dst.CheckTarget(b, opt.Resolve)
	if err != nil {
		return nil, stopped("%v", err)
	}
	m := &Migration{src: b, dst: dst, Compat: compat}
	if compat.Stop {
		return m, nil
	}
	if m.Plan, err = dst.PlanRestore(b, compat, true); err != nil {
		return nil, err
	}
	return m, nil
}

// MigrateOptions — параметры записи на цель.
type MigrateOptions struct {
	RestoreOptions
	// AddressConfirmed — отдельное подтверждение при Compat.NeedAddressConfirm
	// («адрес другой» / «проверить не удалось»). Без него — отказ в ядре, а
	// не только в CLI.
	AddressConfirmed bool
}

// Apply — запись на цель: автокопия ЦЕЛИ, затем контейнеры по очереди
// (Session.Restore). Источник не участвует: ни чтения, ни записи.
func (m *Migration) Apply(opt MigrateOptions) (autoCopy string, outs []RestoreOutcome, err error) {
	switch {
	case m == nil || m.Compat == nil:
		return "", nil, stopped("совместимость нового сервера не проверена")
	case m.Compat.Stop || m.Plan == nil:
		return "", nil, stopped("проверка нового сервера нашла расхождения — сначала исправьте их на новом сервере")
	case m.Compat.NeedAddressConfirm && !opt.AddressConfirmed:
		return "", nil, stopped("адрес выдачи другой или не проверен — нужно отдельное подтверждение")
	}
	return m.dst.Restore(m.Plan, opt.RestoreOptions)
}

// MigrationOutcomeLines — итог прямого переезда. От RestoreOutcomeLines
// отличается тем, что говорит про автокопию ЦЕЛИ (источник на диск не
// записывался), не отсылает к файлу копии и отдельным разделом называет
// третье состояние: у части контейнеров цели итог неизвестен.
func MigrationOutcomeLines(autoCopy string, autoEncrypted bool, outs []RestoreOutcome) []string {
	out := []string{"Автокопия НОВОГО сервера (состояние до замены) записана на диск: " + autoCopy,
		"  Источник на диск не записывался: его данные были только в памяти программы, сервер-источник не изменён."}
	if autoEncrypted {
		out = append(out, "  (автокопия нового сервера зашифрована паролем)")
	} else {
		out = append(out, "  "+AutoCopyUnencryptedNote)
	}
	var done, notDone, unknown []string
	for _, o := range outs {
		line := fmt.Sprintf("  %s: %s", o.Container, o.State)
		if o.Err != nil {
			line += " — " + MaskText(o.Err.Error())
		}
		out = append(out, line)
		switch o.State {
		case RestoreDone:
			out = append(out, "      "+o.Checked)
			done = append(done, o.Container)
		case RestoreUnknown:
			unknown = append(unknown, o.Container)
			notDone = append(notDone, o.Container)
		default:
			notDone = append(notDone, o.Container)
		}
	}
	if len(done) > 0 {
		out = append(out, RestoreOutsideNote)
	}
	if len(unknown) > 0 {
		out = append(out, "НЕИЗВЕСТНО, ЧТО ЗАПИСАНО на новом сервере: "+strings.Join(unknown, ", ")+
			" — связь или запись оборвались на середине, и программа не смогла установить, замена выполнена, не выполнена или выполнена частично. Это НЕ «успех» и НЕ «ничего не записано». "+
			"Не запускайте на новом сервере ничего, что зависит от этих контейнеров, пока не проверите их вручную; прежнее состояние нового сервера — в автокопии выше.")
	}
	if len(done) > 0 && len(notDone) > 0 {
		out = append(out, "ПЕРЕНЕСЕНО ЧАСТИЧНО. Уже заменены и НЕ откатываются: "+strings.Join(done, ", ")+
			". Не перенесены или итог неизвестен: "+strings.Join(notDone, ", ")+
			". Устраните причину (см. выше) и запустите переезд ещё раз: источник читается заново, перенесённые контейнеры уже совпадают, проверка их пропустит без расхождений.")
	}
	out = append(out, ForeignConfigsNote)
	return append(out, AmneziaAppSteps...)
}
