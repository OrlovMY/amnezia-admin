package canary

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"amnezia-admin/core"
)

// П0-К6 (живой прогон 03.10): приложение Amnezia в окне К6 переписывает
// clientsTable целиком и дописывает записи администратора allowed_ips.

// appRewrite — как приложение Amnezia: добавляет своего пользователя и
// дописывает записи id поле allowed_ips.
func appRewrite(t *testing.T, f *fakeServer, id string) {
	t.Helper()
	addAppUser(t, f)
	allowedIPs(t, f, id)
}

// adminAllowedIPs — AllowedIPs блока [Peer] администратора (ключ id) в
// файле конфигурации.
func adminAllowedIPs(t *testing.T, f *fakeServer, id string) string {
	t.Helper()
	raw, _ := f.exec.File(f.env.Ctr.Dir + "/" + f.env.fam.File)
	for _, l := range strings.Split(peerBlocks(string(raw))[id], "\n") {
		if kv := strings.SplitN(l, "=", 2); len(kv) == 2 && strings.TrimSpace(kv[0]) == "AllowedIPs" {
			return strings.TrimSpace(kv[1])
		}
	}
	t.Fatal("AllowedIPs администратора нет")
	return ""
}

// allowedIPs — дописать записи id поле allowed_ips, равное AllowedIPs её
// [Peer] (как приложение Amnezia на живом стенде 03.10).
func allowedIPs(t *testing.T, f *fakeServer, id string) {
	v := adminAllowedIPs(t, f, id)
	editAdmin(t, f, id, func(ud map[string]any) { ud["allowed_ips"] = v })
}

// foreignAllowedIPs — allowed_ips с чужим значением (не AllowedIPs peer'а).
func foreignAllowedIPs(t *testing.T, f *fakeServer, id string) {
	editAdmin(t, f, id, func(ud map[string]any) { ud["allowed_ips"] = "10.99.0.1/32" })
}

// spoilAdmin — случай аудитора р8: clientName «ИСПОРЧЕНО» и disabled.
func spoilAdmin(t *testing.T, f *fakeServer, id string) {
	editAdmin(t, f, id, func(ud map[string]any) { ud["clientName"] = "ИСПОРЧЕНО"; ud["disabled"] = true })
}

// dropRecord — убрать из clientsTable запись id; [Peer] остаётся (чтобы
// НЕ ПРОЙДЕН шёл именно от пропажи записи).
func dropRecord(t *testing.T, f *fakeServer, id string) {
	t.Helper()
	p := f.env.Ctr.Dir + "/clientsTable"
	raw, _ := f.exec.File(p)
	var tbl, out []map[string]any
	if err := json.Unmarshal(raw, &tbl); err != nil {
		t.Fatal(err)
	}
	for _, r := range tbl {
		if r["clientId"] != id {
			out = append(out, r)
		}
	}
	if len(out) != len(tbl)-1 {
		t.Fatal("записи администратора нет")
	}
	b, _ := json.Marshal(out)
	f.exec.SetFile(p, b)
}

// editAdmin — правка userData записи id прямо в clientsTable стенда.
func editAdmin(t *testing.T, f *fakeServer, id string, edit func(map[string]any)) {
	t.Helper()
	p := f.env.Ctr.Dir + "/clientsTable"
	raw, ok := f.exec.File(p)
	if !ok {
		t.Fatal("clientsTable нет")
	}
	var tbl []map[string]any
	if err := json.Unmarshal(raw, &tbl); err != nil {
		t.Fatal(err)
	}
	hit := false
	for _, r := range tbl {
		if r["clientId"] == id {
			edit(r["userData"].(map[string]any))
			hit = true
		}
	}
	if !hit {
		t.Fatal("записи администратора нет")
	}
	b, _ := json.Marshal(tbl)
	f.exec.SetFile(p, b)
}

func addAppUser(t *testing.T, f *fakeServer) {
	t.Helper()
	if _, err := f.env.Sess.AddUser(f.env.Ctr, "app-user"); err != nil {
		t.Fatal(err)
	}
}

// peerTouch — правка первого блока [Peer] (администратора) в файле
// конфигурации.
func peerTouch(t *testing.T, f *fakeServer) {
	t.Helper()
	p := f.env.Ctr.Dir + "/" + f.env.fam.File
	raw, _ := f.exec.File(p)
	s := strings.Replace(string(raw), "[Peer]\n", "[Peer]\n# тронуто\n", 1)
	if s == string(raw) {
		t.Fatal("[Peer] не найден")
	}
	f.exec.SetFile(p, []byte(s))
}

// TestP0K6Window — правка записи администратора приложением в окне К6 —
// сведение, итог ПРОЙДЕН; та же правка вне окна — НЕ ПРОЙДЕН; [Peer] в
// окне — НЕ ПРОЙДЕН; снимок после К6 не снят — НЕ ПРОВЕРЕНО. Правки и
// обрыв — боевым путём через fakesrv, не присваиванием полей Env.
func TestP0K6Window(t *testing.T) {
	for _, c := range []struct {
		name         string
		inK6, atLock func(t *testing.T, f *fakeServer, id string)
		// afterK6 — правка сразу после чтения файла конфигурации снимком
		// «после К6» (таблица им уже снята): отрезок «после К6 → конец».
		afterK6   func(t *testing.T, f *fakeServer, id string)
		failAfter bool
		status    Status
		want      []string
	}{
		{name: "в окне К6 — сведение", inK6: appRewrite, status: Pass,
			want: []string{"сведение", "появилось allowed_ips = ", "появилась запись"}},
		{name: "в окне К6 чужое allowed_ips — НЕ ПРОВЕРЕНО",
			inK6:   func(t *testing.T, f *fakeServer, id string) { addAppUser(t, f); foreignAllowedIPs(t, f, id) },
			status: NotChecked, want: []string{"чья правка, не различить", `allowed_ips: было нет, стало "10.99.0.1/32"`}},
		{name: "в окне К6 clientName и disabled (аудитор р8) — НЕ ПРОВЕРЕНО",
			inK6:   func(t *testing.T, f *fakeServer, id string) { addAppUser(t, f); spoilAdmin(t, f, id) },
			status: NotChecked, want: []string{"чья правка, не различить", `clientName: было "` + adminName + `", стало "ИСПОРЧЕНО"`, "disabled: было нет, стало true"}},
		{name: "в окне К6 пропала запись (QA-01 р9 Н11) — НЕ ПРОЙДЕН",
			inK6: func(t *testing.T, f *fakeServer, id string) {
				// два пользователя приложения минус пропавшая запись: К6
				// видит «+1» и проходит, итог решает П0-итог
				addAppUser(t, f)
				if _, err := f.env.Sess.AddUser(f.env.Ctr, "app-user-2"); err != nil {
					t.Fatal(err)
				}
				dropRecord(t, f, id)
			},
			status: Fail, want: []string{"пропала (в окне К6)"}},
		{name: "в окне К6 allowed_ips и clientName — НЕ ПРОВЕРЕНО",
			inK6:   func(t *testing.T, f *fakeServer, id string) { appRewrite(t, f, id); spoilAdmin(t, f, id) },
			status: NotChecked, want: []string{"чья правка, не различить"}},
		// AU-LOGIC р9 Low-9: allowed_ips верный, число полей «+1», но сменено
		// clientName — прочие поля обязаны сверяться по значению.
		{name: "в окне К6 allowed_ips верный, сменено clientName — НЕ ПРОВЕРЕНО",
			inK6: func(t *testing.T, f *fakeServer, id string) {
				appRewrite(t, f, id)
				editAdmin(t, f, id, func(ud map[string]any) { ud["clientName"] = "ИСПОРЧЕНО" })
			},
			status: NotChecked, want: []string{"чья правка, не различить", `clientName: было "` + adminName + `", стало "ИСПОРЧЕНО"`}},
		{name: "вне окна — НЕ ПРОЙДЕН",
			inK6:   func(t *testing.T, f *fakeServer, _ string) { addAppUser(t, f) },
			atLock: allowedIPs, status: Fail,
			want: []string{"изменилась (поля: allowed_ips: было нет"}},
		{name: "после К6 — НЕ ПРОЙДЕН",
			inK6:    func(t *testing.T, f *fakeServer, _ string) { addAppUser(t, f) },
			afterK6: allowedIPs, status: Fail,
			want: []string{"изменилась (поля: allowed_ips: было нет"}},
		{name: "[Peer] в окне К6 — НЕ ПРОЙДЕН",
			inK6:   func(t *testing.T, f *fakeServer, id string) { appRewrite(t, f, id); peerTouch(t, f) },
			status: Fail, want: []string{"изменился"}},
		{name: "снимок после К6 не снят — НЕ ПРОВЕРЕНО", inK6: appRewrite, failAfter: true,
			status: NotChecked, want: []string{"снимок после К6 не снят"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, id := withAdmin(t, true)
			preflight(t, f)
			real := f.env.Remote
			locked, broke, asked, after := false, false, false, false
			var mu sync.Mutex // Remote зовут конкурентно (К4)
			f.env.Remote = func(cmd string) (string, error) {
				mu.Lock()
				defer mu.Unlock()
				if c.afterK6 != nil && asked && !after {
					after = true
					out, err := real(cmd)
					c.afterK6(t, f, id)
					return out, err
				}
				if c.atLock != nil && !locked && strings.Contains(cmd, "lslocks") {
					locked = true
					c.atLock(t, f, id)
				}
				if broke {
					broke = false
					return "", errors.New("обрыв связи")
				}
				return real(cmd)
			}
			f.env.Ask = func(q string) Answer {
				if strings.HasPrefix(q, "К6:") {
					c.inK6(t, f, id)
					mu.Lock()
					asked, broke = true, c.failAfter
					mu.Unlock()
				}
				return AnswerYes
			}
			rs, err := Run(f.env)
			if err != nil {
				t.Fatal(err)
			}
			m := byID(rs)
			if !asked || m["К6"].Status != Pass {
				t.Fatalf("К6 не прошёл — проверка ничего не значит: %+v", m["К6"])
			}
			if c.afterK6 != nil && !after {
				t.Fatal("правка после К6 не выполнялась")
			}
			if c.atLock != nil && !locked {
				t.Fatal("правка вне окна не выполнялась")
			}
			r := m["П0-итог"]
			if r.Status != c.status {
				t.Fatalf("П0-итог: %v, ждали %v: %s", r.Status, c.status, r.Detail)
			}
			for _, w := range c.want {
				if !strings.Contains(r.Detail, w) {
					t.Errorf("П0-итог без %q: %s", w, r.Detail)
				}
			}
		})
	}
}

// TestP0K6LockBeforeWindow — AU-LOGIC р8 High-5 п. 2: перед окном К6
// замок /run/lock держит отложенная запись (держатель после К5). Ответ
// lslocks с держателем идёт через настоящий разбор (lockHoldersFrom).
// Держатель исчез за время ожидания core.CASOuterTimeout — окно
// открывается; не исчез или lslocks не ответил — вопрос К6 не задан, К6
// НЕ ПРОВЕРЕНО, П0-итог сверяет «начало → конец» (QA-01 р10 Н12).
func TestP0K6LockBeforeWindow(t *testing.T) {
	const held = "rc=0\nCOMMAND PID TYPE PATH\nflock 4242 FLOCK /run/lock/\n"
	for _, c := range []struct {
		name   string
		answer func(call int, f *fakeServer, id string) (string, error) // ответ на lslocks перед К6, call с 1
		calls  int
		slept  bool
		opened bool
		status Status
		want   string
	}{
		{"держатель исчез за ожидание", func(n int, _ *fakeServer, _ string) (string, error) {
			if n == 1 {
				return held, nil
			}
			return "rc=0\nCOMMAND PID TYPE PATH\n", nil
		}, 2, true, true, Pass, "появилось allowed_ips"},
		{"держатель остался", func(int, *fakeServer, string) (string, error) { return held, nil }, 2, true, false, Pass, "замок не свободен перед К6"},
		{"lslocks не ответил", func(int, *fakeServer, string) (string, error) { return "", errors.New("обрыв связи") }, 2, true, false, Pass, "замок не свободен перед К6"},
		{"держатель остался, до К6 пропал клиент", func(n int, f *fakeServer, id string) (string, error) {
			if n == 1 {
				dropRecord(t, f, id)
			}
			return held, nil
		}, 2, true, false, Fail, "пропала"},
		{"свободен сразу", func(int, *fakeServer, string) (string, error) { return "rc=0\nCOMMAND PID TYPE PATH\n", nil }, 1, false, true, Pass, "появилось allowed_ips"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, id := withAdmin(t, true)
			preflight(t, f)
			real := f.env.Remote
			var mu sync.Mutex
			calls := 0
			f.env.Remote = func(cmd string) (string, error) {
				if strings.HasPrefix(cmd, ": k6-lock; ") {
					mu.Lock()
					calls++
					n := calls
					mu.Unlock()
					return c.answer(n, f, id)
				}
				return real(cmd)
			}
			var slept []time.Duration
			f.env.Sleep = func(d time.Duration) { slept = append(slept, d) }
			asked := false
			f.env.Ask = func(q string) Answer {
				if strings.HasPrefix(q, "К6:") {
					asked = true
					appRewrite(t, f, id)
				}
				return AnswerYes
			}
			rs, err := Run(f.env)
			if err != nil {
				t.Fatal(err)
			}
			m := byID(rs)
			if calls != c.calls {
				t.Errorf("проверок замка перед К6 %d, ждали %d", calls, c.calls)
			}
			wantSleep := time.Duration(core.CASOuterTimeout) * time.Second
			if c.slept != (len(slept) == 1 && slept[0] == wantSleep) || (!c.slept && len(slept) > 0) {
				t.Errorf("ожидание: %v, ждали %v (%v)", slept, c.slept, wantSleep)
			}
			if asked != c.opened {
				t.Fatalf("вопрос К6 задан: %v, ждали %v", asked, c.opened)
			}
			k6, p0 := m["К6"], m["П0-итог"]
			if c.opened {
				if k6.Status != Pass {
					t.Fatalf("К6: %+v", k6)
				}
			} else if k6.Status != NotChecked || !strings.Contains(k6.Detail, "замок не свободен перед К6") {
				t.Fatalf("К6: %+v", k6)
			}
			if p0.Status != c.status || !strings.Contains(p0.Detail, c.want) {
				t.Fatalf("П0-итог: %v: %s", p0.Status, p0.Detail)
			}
		})
	}
}

// TestP0K6BeforeUnread — снимок «до К6» не снят (обрыв на чтении файла
// конфигурации непосредственно перед вопросом К6), приложение в окне правит
// запись администратора → П0-итог НЕ ПРОВЕРЕНО. Номер чтения перед
// вопросом берётся из пробного прогона того же стенда; обрыв обязан
// прийтись на последнюю команду перед вопросом — иначе тест падает.
func TestP0K6BeforeUnread(t *testing.T) {
	run := func(breakAt int) (k6, p0 Result, atAsk int, adjacent bool) {
		f, id := withAdmin(t, true)
		preflight(t, f)
		real := f.env.Remote
		suffix := " cat " + f.env.Ctr.Dir + "/" + f.env.fam.File
		n, last, asked, brokeLast := 0, -1, false, false
		var mu sync.Mutex // Remote зовут конкурентно (К4)
		f.env.Remote = func(cmd string) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			brokeLast = false
			if !asked && strings.HasSuffix(cmd, suffix) {
				n++
				last = n
				if n == breakAt {
					brokeLast = true
					return "", errors.New("обрыв связи")
				}
			}
			return real(cmd)
		}
		f.env.Ask = func(q string) Answer {
			if strings.HasPrefix(q, "К6:") {
				mu.Lock()
				asked, atAsk, adjacent = true, last, brokeLast
				mu.Unlock()
				appRewrite(t, f, id)
			}
			return AnswerYes
		}
		rs, err := Run(f.env)
		if err != nil {
			t.Fatal(err)
		}
		m := byID(rs)
		return m["К6"], m["П0-итог"], atAsk, adjacent
	}
	_, _, at, _ := run(0)
	if at <= 0 {
		t.Fatal("пробный прогон: чтения файла конфигурации перед К6 нет")
	}
	k6, r, _, adjacent := run(at)
	if !adjacent {
		t.Fatal("обрыв пришёлся не на последнюю команду перед вопросом К6 — проверка ничего не значит")
	}
	if k6.Status != Pass {
		t.Fatalf("К6: %+v", k6)
	}
	if r.Status != NotChecked || !strings.Contains(r.Detail, "снимок до К6 не снят") {
		t.Fatalf("П0-итог: %v: %s", r.Status, r.Detail)
	}
}

// TestFieldDiff —перечень полей: не-секретные с было/стало, прочие —
// только имя; неразобранная запись — так и сказано.
func TestFieldDiff(t *testing.T) {
	a := `{"clientId":"k","userData":{"clientName":"A","token":"s1"}}`
	b := `{"clientId":"k","userData":{"clientName":"B","token":"s2","allowed_ips":"10.8.1.1/32"}}`
	got := fieldDiff(a, b)
	for _, w := range []string{`allowed_ips: было нет, стало "10.8.1.1/32"`, `clientName: было "A", стало "B"`, "token (значение не печатается)"} {
		if !strings.Contains(got, w) {
			t.Errorf("нет %q: %s", w, got)
		}
	}
	if strings.Contains(got, "s1") || strings.Contains(got, "s2") {
		t.Errorf("значение не-открытого поля напечатано: %s", got)
	}
	if fieldDiff("{", b) != "поля не разобраны" {
		t.Error("неразобранная запись")
	}
}
