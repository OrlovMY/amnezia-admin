package writeoutcome

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"amnezia-admin/core"
)

// wrapped — ошибка ядра, как её отдаёт Apply: обёрнутая, с сентинелом внутри.
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

// TestClassifyDistinguishes — ТЕСТ РАЗЛИЧЕНИЯ: семь исходов записи различимы,
// и частный случай не перехватывается общим (признак 3). Ядро отдаёт
// «частично» как ErrWritePartial И ErrWriteUnknown, «замок» — как
// ErrLockUnavailable И ErrServerToolMissing; тест подаёт ровно такие.
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
		{"неизвестно", wrapped(core.ErrWriteUnknown), Unknown},
		{"частично", wrapped(core.ErrWritePartial, core.ErrWriteUnknown), Partial},
		{"откат не тронул чужое", fmt.Errorf("x: %w", core.ErrRollbackForeign), RollbackForeign},
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
	want := map[Kind][3]string{
		Changed:         {"Не записано: сервер изменили в другом месте", "Пока вы работали, пользователей на сервере изменили из другой программы или другого окна. Ничего не записано.", "Обновите список и повторите действие."},
		Busy:            {"Не записано: сервер занят", "Запись на сервере сейчас занята другим процессом — возможно, другой копией этой программы. Ничего не записано.", "Повторите через минуту."},
		ToolMissing:     {"Не записано: на сервере не хватает программы", "На сервере не установлена программа, без которой запись невозможна (её название — в подробностях). Ничего не записано.", "Передайте подробности ниже тому, кто настраивал сервер; после её установки повторите."},
		LockUnavailable: {"Не записано: сервер не дал начать запись", "Перед записью программа ставит на сервере отметку «идёт запись», чтобы две программы не писали одновременно. Поставить её не удалось. Ничего не записано.", "Передайте подробности ниже тому, кто настраивал сервер (для него: каталог /run/lock должен существовать). После исправления повторите."},
		Unknown:         {"Неизвестно, записаны ли изменения", "Сервер не подтвердил ни запись, ни отказ: изменения могли записаться, а могли и нет.", "Не повторяйте сразу: сначала обновите список и проверьте, что на сервере. Резервные копии — в папке backup на сервере (путь в подробностях)."},
		Partial:         {"Записано частично", "Настройки WireGuard (wg0.conf) записаны, а список пользователей (clientsTable) — нет.", "Не повторяйте: обновите список и сверьте его с приложением Amnezia. Резервные копии — в папке backup на сервере (путь в подробностях)."},
		RollbackForeign: {"Записано, но проверка не прошла — откат не выполнен", "Изменения были записаны, но проверка после записи не прошла. Отменить их не удалось: после вашей записи файлы на сервере изменил кто-то другой, и откат стёр бы его изменения.", "Обновите список и проверьте, что на сервере. Резервные копии — в папке backup на сервере (путь в подробностях)."},
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

// TestUnknownNeverClaimed — правило CLAUDE.md: «неизвестно» и «частично» не
// выдаются ни за «не записано», ни за «записано». «Ничего не записано»
// говорится РОВНО там, где запись точно не шла.
func TestUnknownNeverClaimed(t *testing.T) {
	nothingWritten := map[Kind]bool{Changed: true, Busy: true, ToolMissing: true, LockUnavailable: true}
	for k, tx := range texts {
		says := strings.Contains(tx.What, "Ничего не записано") || strings.HasPrefix(tx.Title, "Не записано")
		if says != nothingWritten[k] {
			t.Errorf("исход %d: «не записано» сказано=%v, а ничего не записано=%v: %+v", k, says, nothingWritten[k], tx)
		}
	}
	for _, k := range []Kind{Unknown, Partial} {
		if strings.HasPrefix(texts[k].Title, "Записано ") && k == Unknown {
			t.Errorf("«неизвестно» выдано за «записано»: %q", texts[k].Title)
		}
	}
	if !strings.Contains(texts[Unknown].What, "могли записаться, а могли и нет") {
		t.Errorf("«неизвестно» не называет обе возможности: %q", texts[Unknown].What)
	}
}

// TestRetryOnlyWhenNothingWritten — пункт 5 задания: повтор ТОГО ЖЕ плана
// («Применить» остаётся активной) безвреден только там, где ничего не
// записано И план не устарел. «Изменён другим» — ничего не записано, но план
// устарел: повтор провалится тем же.
func TestRetryOnlyWhenNothingWritten(t *testing.T) {
	want := map[Kind]bool{Busy: true, ToolMissing: true, LockUnavailable: true,
		Changed: false, Unknown: false, Partial: false, RollbackForeign: false}
	for k, w := range want {
		if texts[k].Retry != w {
			t.Errorf("исход %d: Retry = %v, ожидалось %v", k, texts[k].Retry, w)
		}
	}
}

// TestEveryTextSaysWhatNext — у каждого текста есть «что делать дальше».
func TestEveryTextSaysWhatNext(t *testing.T) {
	for k, tx := range texts {
		if strings.TrimSpace(tx.Next) == "" || strings.TrimSpace(tx.Title) == "" || strings.TrimSpace(tx.What) == "" {
			t.Errorf("исход %d: пустая часть текста: %+v", k, tx)
		}
	}
	if _, ok := Describe(errors.New("сеть")); ok {
		t.Error("не исход записи получил текст исхода")
	}
}
