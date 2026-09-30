package writeoutcome

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"amnezia-admin/core"
)

// wrapped — ошибка ядра, как её отдаёт Apply: обёрнутая, с сентинелами внутри.
func wrapped(sentinels ...error) error {
	return &multiIs{targets: sentinels}
}

type multiIs struct{ targets []error }

func (m *multiIs) Error() string { return "подробности ядра" }
func (m *multiIs) Is(t error) bool {
	for _, x := range m.targets {
		if x == t {
			return true
		}
	}
	return false
}

// TestClassifyDistinguishes — ТЕСТ РАЗЛИЧЕНИЯ: исходы записи различимы, и
// частный случай не перехватывается общим (признак 3). Ошибки подаются в той
// форме, в которой их отдаёт ядро: исход отката оборачивает и исход команды
// отката («занято», «неизвестно»), «частично» — и «неизвестно», замок — и
// «нет утилиты».
func TestClassifyDistinguishes(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Kind
	}{
		{"изменён другим", wrapped(core.ErrCASMismatch), Changed},
		{"занято", wrapped(core.ErrServerBusy), Busy},
		{"нет утилиты", wrapped(core.ErrServerToolMissing), ToolMissing},
		{"замок не открыт", wrapped(core.ErrLockUnavailable, core.ErrServerToolMissing), LockUnavailable},
		{"запись не начиналась", wrapped(core.ErrWriteNotStarted), NotStarted},
		{"неизвестно", wrapped(core.ErrWriteUnknown), Unknown},
		{"частично", wrapped(core.ErrWritePartial, core.ErrWriteUnknown), Partial},
		{"откат не тронул чужое", fmt.Errorf("x: %w", core.ErrRollbackForeign), RollbackForeign},
		{"откат не выполнен (занято)", wrapped(core.ErrRollbackNotDone, core.ErrServerBusy), RollbackNotDone},
		{"откат не выполнен (замок)", wrapped(core.ErrRollbackNotDone, core.ErrLockUnavailable, core.ErrServerToolMissing), RollbackNotDone},
		{"итог отката неизвестен", wrapped(core.ErrRollbackUnknown, core.ErrWriteUnknown), RollbackUnknown},
		{"итог отката неизвестен (частично)", wrapped(core.ErrRollbackUnknown, core.ErrWritePartial, core.ErrWriteUnknown), RollbackUnknown},
		{"отменено", wrapped(core.ErrRolledBack), RolledBack},
		{"отменено в файлах", wrapped(core.ErrRolledBackNotApplied), RolledBackNotApplied},
		{"не исход записи", errors.New("сеть"), Other},
		{"nil", nil, Other},
	}
	for _, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Errorf("%s: Classify = %d, ожидалось %d", c.name, got, c.want)
		}
	}
}

// TestTextsGolden — дословные тексты; «было → стало» отчёта сверено с ними.
func TestTextsGolden(t *testing.T) {
	const hand = "Передайте подробности ниже тому, кто настраивал сервер."
	const lost = "Изменения записаны в файлы на сервере, но включить их или убедиться, что они работают, не удалось."
	want := map[Kind][3]string{
		Changed:               {"Не записано: сервер изменили в другом месте", "Пока вы работали, пользователей на сервере изменили из другой программы или другого окна. Ничего не записано.", "Обновите список и повторите действие."},
		Busy:                  {"Не записано: сервер занят", "Сервер сейчас выполняет другую запись — возможно, из другой копии этой программы. Ничего не записано.", "Повторите через минуту."},
		ToolMissing:           {"Не записано: на сервере не хватает программы", "На сервере не установлена программа, без которой запись невозможна (её название — в подробностях). Ничего не записано.", "Передайте подробности ниже тому, кто настраивал сервер; после её установки повторите."},
		LockUnavailable:       {"Не записано: сервер не дал начать запись", "Перед записью программа ставит на сервере отметку «идёт запись», чтобы две программы не писали одновременно. Поставить её не удалось. Ничего не записано.", "Передайте подробности ниже тому, кто настраивал сервер (для него: каталог /run/lock должен существовать). После исправления повторите."},
		NotStarted:            {"Не записано: не удалось подготовить запись", "Программа не смогла подготовить запись (например, сделать резервную копию на сервере). Ничего не записано.", "Повторите; если снова не получится — передайте подробности ниже тому, кто настраивал сервер."},
		Unknown:               {"Неизвестно, записаны ли изменения", "Сервер не подтвердил ни запись, ни отказ: изменения могли записаться, а могли и нет.", "Не повторяйте сразу: обновите список и проверьте, что на сервере. Если не совпадает с тем, что вы делали, — передайте подробности ниже тому, кто настраивал сервер."},
		Partial:               {"Записано частично", "Настройки WireGuard (wg0.conf) записаны, а список пользователей (clientsTable) — нет.", "Не повторяйте. " + hand},
		RollbackForeign:       {"Записано, но работа изменений не подтверждена — откат не выполнен", lost + " Отменять их программа не стала: после вашей записи файлы на сервере изменил кто-то другой, и отмена стёрла бы его изменения.", "Не повторяйте. " + hand},
		RollbackNotDone:       {"Записано, но работа изменений не подтверждена — откат не выполнен", lost + " Отменить их программа не смогла: сервер не дал начать отмену. На сервере остались ваши изменения.", "Не повторяйте. " + hand},
		RollbackUnknown:       {"Неизвестно, остались ли изменения на сервере", "Изменения были записаны, но включить их или убедиться, что они работают, не удалось. Программа попыталась их отменить, но получилось ли — неизвестно: на сервере сейчас может быть и новое, и прежнее состояние.", "Не повторяйте. " + hand},
		RolledBack:            {"Не применено: изменения отменены", "Изменения были записаны, но включить их или убедиться, что они работают, не удалось, поэтому программа вернула сервер в прежнее состояние и проверила это.", "Сервер в прежнем состоянии. Передайте подробности ниже тому, кто настраивал сервер: он должен выяснить, почему изменения не включились."},
		RolledBackNotApplied:  {"Отменено не до конца: сервер нужно перезапустить", "Изменения были записаны, но убедиться, что они работают, не удалось. Файлы на сервере возвращены к прежнему, однако работающий сервер к прежнему состоянию не вернулся: подключения могут не соответствовать списку, пока сервер не перезапустят.", "Не повторяйте. " + hand},
		RollbackUnverified:    {"Неизвестно, отменены ли изменения", "Изменения были записаны, но убедиться, что они работают, не удалось. Программа записала отмену, но проверить её итог не смогла: на сервере сейчас может быть и новое, и прежнее состояние.", "Не повторяйте. " + hand},
		RolledBackFilesDiffer: {"Неизвестно, что сейчас на сервере", "Изменения были записаны, но убедиться, что они работают, не удалось. Программа записала отмену, но при проверке файлы на сервере не совпали с прежними — возможно, их изменили в другом месте.", "Не повторяйте. " + hand},
	}
	if len(texts) != len(want) {
		t.Errorf("исходов с текстом %d, ожидалось %d", len(texts), len(want))
	}
	for k, w := range want {
		got := texts[k]
		if got.Title != w[0] || got.What != w[1] || got.Next != w[2] {
			t.Errorf("исход %d: текст не совпадает с эталоном:\n%+v", k, got)
		}
	}
}

// TestUnknownNeverClaimed — правило CLAUDE.md: «Ничего не записано» и
// заголовок «Не записано» — РОВНО там, где запись точно не шла.
func TestUnknownNeverClaimed(t *testing.T) {
	nothingWritten := map[Kind]bool{Changed: true, Busy: true, ToolMissing: true, LockUnavailable: true, NotStarted: true}
	for k, tx := range texts {
		says := strings.Contains(tx.What, "Ничего не записано") || strings.HasPrefix(tx.Title, "Не записано")
		if says != nothingWritten[k] {
			t.Errorf("исход %d: «не записано» сказано=%v, а ничего не записано=%v: %+v", k, says, nothingWritten[k], tx)
		}
	}
	if !strings.Contains(texts[Unknown].What, "могли записаться, а могли и нет") {
		t.Errorf("«неизвестно» не называет обе возможности: %q", texts[Unknown].What)
	}
}

// TestRetryOnlyWhenNothingWritten — закрытый список: повтор ТОГО ЖЕ плана —
// только где запись доказанно не начиналась и план не устарел. Ожидание —
// своё, не из retryAllowed.
func TestRetryOnlyWhenNothingWritten(t *testing.T) {
	yes := map[Kind]bool{Busy: true, ToolMissing: true, LockUnavailable: true, NotStarted: true}
	for k, tx := range texts {
		if tx.Retry != yes[k] {
			t.Errorf("исход %d: Retry = %v, ожидалось %v", k, tx.Retry, yes[k])
		}
	}
	if tx, ok := Describe(errors.New("неклассифицированная")); ok || tx.Retry {
		t.Error("неклассифицированная ошибка получила текст или повтор")
	}
}

// TestNoRetryEndsWithStep — сторож механизации AU-UX: у каждого исхода без
// повтора «что делать» оканчивается выполнимым шагом из закрытого списка.
func TestNoRetryEndsWithStep(t *testing.T) {
	for k, tx := range texts {
		if tx.Retry {
			continue
		}
		// Закрытый список шагов: «обновите и повторите» в конце или «передайте
		// подробности … тому, кто настраивал сервер» (у «Не применено» — с
		// пояснением, зачем).
		if !strings.HasSuffix(tx.Next, stepRefreshRetry) && !strings.Contains(strings.ToLower(tx.Next), "передайте подробности ниже тому, кто настраивал сервер") {
			t.Errorf("исход %d без повтора: «что делать» не оканчивается шагом из закрытого списка: %q", k, tx.Next)
		}
	}
}

// TestNoBackupFolderInNext — AU-UX Н3: «папка backup на сервере» — сведение
// для того, кто настраивал сервер (оно в подробностях), не шаг для владельца.
func TestNoBackupFolderInNext(t *testing.T) {
	for k, tx := range texts {
		for _, bad := range []string{"backup", "сверьте его с приложением Amnezia", "процесс"} {
			if strings.Contains(tx.Next+tx.What, bad) {
				t.Errorf("исход %d: в тексте %q", k, bad)
			}
		}
	}
}

// TestEveryTextSaysWhatNext — у каждого текста три непустые части.
func TestEveryTextSaysWhatNext(t *testing.T) {
	for k, tx := range texts {
		if strings.TrimSpace(tx.Next) == "" || strings.TrimSpace(tx.Title) == "" || strings.TrimSpace(tx.What) == "" {
			t.Errorf("исход %d: пустая часть текста: %+v", k, tx)
		}
	}
}
