package core

import (
	"errors"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// TestCollectCancelMidRead — QA-01 Н1: отмена ПОСРЕДИ чтения (из
// ProgressFunc после k-го чтения): CollectBackupCtx сам возвращает
// ErrCanceled, чтений cat на сервере меньше полного числа. Подмена «нет
// проверки отмены перед каждым чтением» роняет тест.
func TestCollectCancelMidRead(t *testing.T) {
	cats := func(s *fakesrv.Server) int {
		n := 0
		for _, c := range s.Commands() {
			if strings.Contains(c, " cat /opt/amnezia/") {
				n++
			}
		}
		return n
	}
	full := fakesrv.New()
	if _, err := backupSession(t, full).CollectBackup("t", backupNow, okResolver); err != nil {
		t.Fatal(err)
	}
	srv := fakesrv.New()
	const k = 3
	ctx, fn := cancelAt(func(p Progress) bool { return p.Done == k })
	b, err := backupSession(t, srv).CollectBackupCtx(ctx, "t", backupNow, okResolver, fn)
	if !errors.Is(err, ErrCanceled) || b != nil {
		t.Fatalf("ждали отмену из CollectBackupCtx: %v (копия %v)", err, b != nil)
	}
	if got, all := cats(srv), cats(full); got >= all || got != k {
		t.Errorf("чтений после отмены на %d-м: %d (полное число %d)", k, got, all)
	}
}
