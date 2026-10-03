package fakesrv

import (
	"testing"
	"time"
)

const legacyCmd = "docker exec -i amnezia-awg sh -c 'cat > /opt/amnezia/awg/x.tmp && mv /opt/amnezia/awg/x.tmp /opt/amnezia/awg/x'"

// TestLegacyPairWait — барьер прежней записи (CI macOS 03.10): первая
// прежняя запись ждёт вторую и выполняется только вместе с ней — даже если
// вторая пришла заметно позже. Одиночная идёт после ожидания. Подмена
// «барьера нет» роняет первый случай: первая запись завершилась бы до
// прихода второй.
func TestLegacyPairWait(t *testing.T) {
	s := New()
	s.Configure(func(s *Server) { s.AllowLegacyWrite = true; s.LegacyPairWait = 5 * time.Second })
	start := time.Now()
	first := make(chan time.Duration)
	go func() {
		if _, err := s.Run(legacyCmd, []byte("a")); err != nil {
			t.Error(err)
		}
		first <- time.Since(start)
	}()
	const lag = 300 * time.Millisecond
	time.Sleep(lag)
	if _, err := s.Run(legacyCmd, []byte("b")); err != nil {
		t.Fatal(err)
	}
	if d := <-first; d < lag || d > 4*time.Second {
		t.Fatalf("первая прежняя запись завершилась через %v: ждали после прихода второй (%v) и до таймаута", d, lag)
	}

	s.Configure(func(s *Server) { s.LegacyPairWait = 200 * time.Millisecond })
	t0 := time.Now()
	if _, err := s.Run(legacyCmd, []byte("c")); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t0); d < 200*time.Millisecond || d > 3*time.Second {
		t.Fatalf("одиночная прежняя запись: %v, ждали ≈200 мс", d)
	}
	if got, _ := s.File("/opt/amnezia/awg/x"); string(got) != "c" {
		t.Fatalf("одиночная запись не выполнена: %q", got)
	}
}
