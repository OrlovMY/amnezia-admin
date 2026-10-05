package core

// Прогресс и отмена долгих операций копии (отзыв владельца на v0.5.0-rc.1:
// «прогресс-бар, xxx из xxx, остальные кнопки недоступны, кроме отмены»).

import (
	"context"
	"errors"
	"fmt"
)

// Этапы.
const (
	StageRead      = "чтение"
	StageEncrypt   = "шифрование"
	StageWrite     = "запись файла"
	StageAutoCopy  = "автокопия"
	StageContainer = "запись на сервер"
)

// Progress — событие прогресса. Total == 0 — этап без счёта (бесконечная
// полоса). Writing — началась запись на сервер: отмена с этого момента
// недоступна.
type Progress struct {
	Stage       string
	Done, Total int
	Text        string
	Writing     bool
}

// ProgressFunc — получатель прогресса (может быть nil).
type ProgressFunc func(Progress)

func report(fn ProgressFunc, p Progress) {
	if fn != nil {
		fn(p)
	}
}

// ErrCanceled — операция отменена человеком; ничего не записано.
var ErrCanceled = errors.New("отменено")

func canceled(ctx context.Context) error {
	if ctx == nil || ctx.Err() == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrCanceled, ctx.Err())
}

// progressCounter — счёт чтений снятия копии.
type progressCounter struct {
	fn          ProgressFunc
	done, total int
}

func (p *progressCounter) emit(text string) {
	if text == "" {
		text = fmt.Sprintf("прочитано файлов %d из %d", p.done, p.total)
	}
	report(p.fn, Progress{Stage: StageRead, Done: p.done, Total: p.total, Text: text})
}

func (p *progressCounter) step(ctr string, pass int) {
	p.done++
	p.emit(fmt.Sprintf("прочитано файлов %d из %d — %s (проход %d из 2)", p.done, p.total, ctr, pass))
}

func (p *progressCounter) retry(n int) {
	p.total += 2 * n
	p.emit(fmt.Sprintf("файлы менялись при чтении — повторное чтение; прочитано %d из %d", p.done, p.total))
}
