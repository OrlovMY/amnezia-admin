package canary

// Маскировка секретов — ОДНА, на границе печати канарейки (QA-01 Н1,
// CLAUDE.md «Секреты»: маскировка ставится в одном месте на границе, а не
// по месту вызова). cmd/canary-a3b оборачивает этим писателем и stdout, и
// stderr и отдаёт его же в Env.Out; всё, что канарейка печатает, — отчёт
// шагов, вопросы, ошибки, — проходит через Writer. В тексте шагов (Detail,
// oneLine) маскировки нет.

import (
	"io"
	"regexp"
	"strings"
	"sync"
)

var (
	// reVpnKey — ключ vpn:// целиком.
	reVpnKey = regexp.MustCompile(`vpn://\S+`)
	// rePEM — блок приватного ключа (в том числе оборванный: BEGIN без END
	// — до конца текста).
	rePEM = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`)
	// rePrivKeyLine — PrivateKey = … из конфигов WireGuard.
	rePrivKeyLine = regexp.MustCompile(`(PrivateKey\s*=\s*)\S+`)
)

// Masker — что маскировать: шаблоны (vpn://, PEM, PrivateKey =) и
// дословные секреты из ключа (пароль, ключ SSH в поле password).
type Masker struct {
	mu      sync.Mutex
	secrets []string
}

// NewMasker — маскировщик с дословными секретами (пустые и короче 4 знаков
// пропускаются: такой «секрет» замаскировал бы половину текста).
func NewMasker(secrets ...string) *Masker {
	m := &Masker{}
	m.Add(secrets...)
	return m
}

// Add — ещё дословные секреты (ключ разобран позже, чем заведён вывод).
func (m *Masker) Add(secrets ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range secrets {
		if len(s) >= 4 {
			m.secrets = append(m.secrets, s)
			// PEM в одну строку (oneLine склеивает переводы строк) — тоже.
			if f := strings.Join(strings.Fields(s), " "); f != s && len(f) >= 4 {
				m.secrets = append(m.secrets, f)
			}
		}
	}
}

// Mask — текст без секретов.
func (m *Masker) Mask(s string) string {
	m.mu.Lock()
	secrets := append([]string(nil), m.secrets...)
	m.mu.Unlock()
	for _, x := range secrets {
		s = strings.ReplaceAll(s, x, "***")
	}
	s = rePEM.ReplaceAllString(s, "***")
	s = reVpnKey.ReplaceAllString(s, "vpn://***")
	return rePrivKeyLine.ReplaceAllString(s, "${1}***")
}

// Writer — w, через который всё проходит маскированным.
func (m *Masker) Writer(w io.Writer) io.Writer { return &maskWriter{m: m, w: w} }

type maskWriter struct {
	m *Masker
	w io.Writer
}

func (mw *maskWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(mw.w, mw.m.Mask(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}
