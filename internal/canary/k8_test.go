package canary

// PR-W3: К8 на amnezia-awg2 против fakesrv — через собранную программу и SSH.

import (
	"net"
	"os"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

func awg2Ctr() *core.Container {
	return &core.Container{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG (версия 3.1)", Support: core.SupportYes}
}

// awg2Server — fakesrv amnezia-awg2 с [Interface] после ListenPort = extra.
func awg2Server(extra string) *fakesrv.Server {
	fs := fakesrv.NewAWG2()
	b, _ := fs.File("/opt/amnezia/awg/awg0.conf")
	s := string(b)
	i := strings.Index(s, "ListenPort = 51820\n") + len("ListenPort = 51820\n")
	j := strings.Index(s, "[Peer]")
	fs.SetFile("/opt/amnezia/awg/awg0.conf", []byte(s[:i]+extra+"\n"+s[j:]))
	return fs
}

const k8AWG3 = "Jc = 4\nS3 = 15\nH1 = 100-200\nHeaderProtectionKey = hpk\nRandomTrailers = on\n# I1 = <b 0x01>\n"

// TestK8OnFakesrv — шаги по серверу (К8.1, К8.2, К8.6, К8.8) ПРОЙДЕН;
// шаги на устройствах — по введённому адресу (финальный раунд, AU-UX М2):
// совпал с сервером там, где ждём связь, — ПРОЙДЕН; иной — НЕ ПРОЙДЕН;
// пусто — НЕ ПРОВЕРЕНО. Где связи быть не должно (выключен, прежний
// конфиг) — наоборот. Вариант AWG назван.
func TestK8OnFakesrv(t *testing.T) {
	const other = "198.51.100.7" // чужой адрес: телефон вышел мимо сервера
	// noVia — вопросы, где связи через сервер быть НЕ должно.
	noVia := func(q string) bool {
		return strings.Contains(q, "ВЫКЛЮЧИЛА") || strings.Contains(q, "ПРЕЖНИЙ")
	}
	type want struct{ k3, k4, k5, k7 Status }
	for _, c := range []struct {
		name string
		ip   func(q, server string) string
		w    want
	}{
		{"как ожидается: сервер / чужой", func(q, srv string) string {
			if noVia(q) {
				return other
			}
			return srv
		}, want{Pass, Pass, Pass, Pass}},
		{"как ожидается: сервер / сайт не открылся", func(q, srv string) string {
			if noVia(q) {
				return "не открылся"
			}
			return srv
		}, want{Pass, Pass, Pass, Pass}},
		{"наоборот", func(q, srv string) string {
			if noVia(q) {
				return srv
			}
			return other
		}, want{Fail, Fail, Fail, Fail}},
		// AU-UX М2: туннель тихо выключен — сайт открылся, но адрес чужой.
		{"всегда чужой адрес", func(string, string) string { return other }, want{Fail, Fail, Fail, Fail}},
		{"всегда адрес сервера", func(_, srv string) string { return srv }, want{Pass, Fail, Fail, Pass}},
		{"всегда «не открылся»", func(string, string) string { return "не открылся" }, want{Fail, Fail, Fail, Fail}},
		{"пропуск (Enter)", func(string, string) string { return "" }, want{NotChecked, NotChecked, NotChecked, NotChecked}},
		{"«пропустить»", func(string, string) string { return "пропустить" }, want{NotChecked, NotChecked, NotChecked, NotChecked}},
		{"«да» вместо адреса", func(string, string) string { return "да" }, want{NotChecked, NotChecked, NotChecked, NotChecked}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := emptyFakeOn(t, awg2Server(k8AWG3), awg2Ctr(), false)
			f.env.NewBin = newCLI(t)
			srv := f.env.Sess.Creds.Host
			if net.ParseIP(srv) == nil {
				t.Fatalf("адрес стенда %q — не IP, тест ничего не значит", srv)
			}
			var qs []string
			f.env.Ask = func(q string) Answer { t.Errorf("вопрос «да/нет» в К8: %s", q); return AnswerYes }
			f.env.AskIP = func(q string) string { qs = append(qs, q); return c.ip(q, srv) }
			rs := f.env.k8()
			// QA W3 M2: набор ID шагов, а не их число.
			var got []string
			for _, r := range rs {
				got = append(got, r.ID)
			}
			if strings.Join(got, " ") != "К8.1 К8.2 К8.3 К8.4 К8.5 К8.6 К8.7 К8.8" {
				t.Fatalf("шаги К8: %v", got)
			}
			ws := map[string]Status{"К8.1": Pass, "К8.2": Pass, "К8.3": c.w.k3, "К8.4": c.w.k4, "К8.5": c.w.k5, "К8.6": Pass, "К8.7": c.w.k7, "К8.8": Pass}
			for _, r := range rs {
				if r.Status != ws[r.ID] {
					t.Errorf("%s %s: %s (%s), ждали %s", r.ID, r.Name, r.Status, r.Detail, ws[r.ID])
				}
			}
			if len(qs) != 6 {
				t.Errorf("вопросов об адресе %d, ждали 6", len(qs))
			}
			// названные человеку файлы существуют
			for _, q := range qs {
				for _, pre := range []string{"файл ", "ПРЕЖНИЙ конфиг ", "НОВЫЙ конфиг "} {
					if i := strings.Index(q, pre); i >= 0 && strings.HasPrefix(c.name, "как ожидается") {
						p := q[i+len(pre):]
						p = p[:strings.Index(p, " и подключитесь")]
						if _, err := os.Stat(p); err != nil {
							t.Errorf("в вопросе назван несуществующий файл %q: %s", p, q)
						}
					}
				}
			}
			for _, q := range qs {
				if strings.Contains(q, "НЕТ?") || strings.Contains(q, "ЕСТЬ?") || strings.Contains(q, "К6") || strings.Contains(q, "К8.2") {
					t.Errorf("вопрос с отрицанием или ссылкой на номер шага: %s", q)
				}
				// финальный раунд: ожидаемый ответ не подсказывается
				if strings.Contains(q, "ожидается") || strings.Contains(q, srv) {
					t.Errorf("вопрос подсказывает ответ: %s", q)
				}
				if !strings.Contains(q, "https://ifconfig.me") || !strings.Contains(q, "введите адрес") {
					t.Errorf("вопрос без сайта проверки IP: %s", q)
				}
			}
			if !strings.Contains(rs[0].Detail, "AmneziaWG (версия 3.1)") || !strings.Contains(rs[0].Detail, "проверено на AWG3; AWG2 — только на тестовом стенде") {
				t.Errorf("К8.1 не называет вариант: %s", rs[0].Detail)
			}
			if strings.Contains(rs[0].Detail, "hpk") || strings.Contains(rs[0].Detail, "PrivateKey =") {
				t.Errorf("К8.1 напечатал значения параметров: %s", rs[0].Detail)
			}
		})
	}
}

// TestIPStatus — таблица сверки адреса: ждём связь через сервер / ждём,
// что её нет; совпал / иной / «не открылся» / пусто / не IP / адрес
// сервера не определён. Подмена «любой ввод — да» роняет строки «иной» и
// «не IP».
func TestIPStatus(t *testing.T) {
	srv := []net.IP{net.ParseIP("203.0.113.10")}
	for _, c := range []struct {
		in     string
		server []net.IP
		via    bool
		want   Status
	}{
		{"203.0.113.10", srv, true, Pass},
		{" 203.0.113.10\n", srv, true, Pass},
		{"198.51.100.7", srv, true, Fail},
		{"не открылся", srv, true, Fail},
		{"Сайт НЕ ОТКРЫЛСЯ", srv, true, Fail},
		{"", srv, true, NotChecked},
		{"пропустить", srv, true, NotChecked},
		{"да", srv, true, NotChecked},
		{"203.0.113", srv, true, NotChecked},
		{"203.0.113.10", nil, true, NotChecked},
		{"203.0.113.10", srv, false, Fail},
		{"198.51.100.7", srv, false, Pass},
		{"не открылся", srv, false, Pass},
		{"", srv, false, NotChecked},
		{"да", srv, false, NotChecked},
		{"198.51.100.7", nil, false, NotChecked},
		{"::ffff:203.0.113.10", srv, true, Pass},
	} {
		if got, d := ipStatus(c.in, c.server, c.via); got != c.want {
			t.Errorf("ввод %q, сервер %v, ждём связь=%v: %s (%s), ждали %s", c.in, c.server, c.via, got, d, c.want)
		}
	}
}

// TestK8NoAskIP — AskIP не задан: шаги на устройствах НЕ ПРОВЕРЕНО, не ПРОЙДЕН.
func TestK8NoAskIP(t *testing.T) {
	f := emptyFakeOn(t, awg2Server(k8AWG3), awg2Ctr(), false)
	f.env.NewBin = newCLI(t)
	f.env.AskIP = nil
	for _, r := range f.env.k8() {
		if (r.ID == "К8.3" || r.ID == "К8.4" || r.ID == "К8.5" || r.ID == "К8.7") && r.Status != NotChecked {
			t.Errorf("%s без ввода адреса: %s (%s)", r.ID, r.Status, r.Detail)
		}
	}
}

// TestExpectStatus — таблица знака: ответ против ожидания.
func TestExpectStatus(t *testing.T) {
	for _, c := range []struct {
		a     Answer
		opens bool
		want  Status
	}{
		{AnswerYes, true, Pass}, {AnswerNo, true, Fail},
		{AnswerYes, false, Fail}, {AnswerNo, false, Pass},
		{AnswerSkip, true, NotChecked}, {AnswerSkip, false, NotChecked},
	} {
		if got := expectStatus(c.a, c.opens); got != c.want {
			t.Errorf("ответ %s, ждали «открывается»=%v: %s, ждали %s", c.a, c.opens, got, c.want)
		}
	}
}

// TestK8StopsOnUnknownKey — К8.1: незнакомый параметр — НЕ ПРОЙДЕН и СТОП:
// остальные шаги НЕ ПРОВЕРЕНО, ни одной записи на сервер.
func TestK8StopsOnUnknownKey(t *testing.T) {
	f := emptyFakeOn(t, awg2Server("S3 = 15\nPostUp = echo x\n"), awg2Ctr(), false)
	f.env.NewBin = newCLI(t)
	f.env.Ask = func(string) Answer { return AnswerYes }
	rs := f.env.k8()
	if rs[0].Status != Fail || !strings.Contains(rs[0].Detail, "PostUp") {
		t.Fatalf("К8.1: %s — %s", rs[0].Status, rs[0].Detail)
	}
	for _, r := range rs[1:] {
		if r.Status != NotChecked {
			t.Errorf("%s после СТОП: %s", r.ID, r.Status)
		}
	}
	for _, cmd := range f.exec.Commands() {
		if strings.Contains(cmd, "flock -w") {
			t.Fatalf("запись после СТОП К8.1: %.80s", cmd)
		}
	}
}

// TestK8StopsOnMissingFile — awg0.conf нет — К8.1 НЕ ПРОВЕРЕНО (не «нет
// параметров»), остальные НЕ ПРОВЕРЕНО.
func TestK8StopsOnMissingFile(t *testing.T) {
	f := emptyFakeOn(t, awg2Server(""), awg2Ctr(), false)
	f.exec.DeleteFile("/opt/amnezia/awg/awg0.conf")
	f.env.NewBin = newCLI(t)
	rs := f.env.k8()
	for _, r := range rs {
		if r.Status != NotChecked {
			t.Errorf("%s: %s (%s), ждали НЕ ПРОВЕРЕНО", r.ID, r.Status, r.Detail)
		}
	}
}

// TestK8Rows — К8 в Run: не amnezia-awg2 — одна строка НЕ ПРИМЕНИМО;
// предусловия не подтверждены — восемь НЕ ПРОВЕРЕНО.
func TestK8Rows(t *testing.T) {
	awg := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg"}
	fam, _ := core.WGFamilyOf(awg)
	e := &Env{Ctr: awg, fam: fam}
	if rs := e.k8Rows(true); len(rs) != 1 || rs[0].Status != NotApplicable {
		t.Errorf("К8 на amnezia-awg: %+v", rs)
	}
	c2 := awg2Ctr()
	fam2, _ := core.WGFamilyOf(c2)
	e2 := &Env{Ctr: c2, fam: fam2}
	rs := e2.k8Rows(false)
	if len(rs) != 8 {
		t.Fatalf("строк К8 без предусловий %d, ждали ровно 8", len(rs))
	}
	for _, r := range rs {
		if r.Status != NotChecked {
			t.Errorf("%s без предусловий: %s", r.ID, r.Status)
		}
	}
}

// TestAWGVariantLine — итог называет проверенный вживую вариант.
func TestAWGVariantLine(t *testing.T) {
	for v, want := range map[string]string{
		"3.1": "проверено на AWG3; AWG2 — только на тестовом стенде",
		"2":   "проверено на AWG2; AWG3 — только на тестовом стенде",
		"":    "версия не определена",
	} {
		if got := AWGVariantLine(v, true); !strings.Contains(got, want) {
			t.Errorf("%q: %q", v, got)
		}
	}
	if AWGVariantLine("3.1", false) != "" {
		t.Error("формат не определён — вариант не называется")
	}
}
