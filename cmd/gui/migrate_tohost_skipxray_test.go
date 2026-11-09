package main

// Находка ревью РЕВЬЮ-TO-HOST-SKIP-XRAY-1 (GUI): в режиме «Новый чистый
// сервер» выбор «без XRay» влиял только на перенос — план установки,
// предпроверка портов и ключ vpn:// строились по ПОЛНОЙ копии. Теперь выбор
// делается ДО «Далее» (при занятом порте XRay — на шаге «Просмотр»), копия
// без XRay (core.BackupWithout) идёт в предпроверку, план, установку,
// перенос и ключ.

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2/test"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// awgXRayServer — источник с AmneziaWG и XRay: без XRay в копии остаётся
// что ставить (иначе план «без XRay» пуст и сцена ничего не значит).
func awgXRayServer() *fakesrv.Server {
	s := xrayMigServer()
	a := fakesrv.New()
	s.Names = append([]string{"amnezia-awg"}, s.Names...)
	for _, p := range []string{"/opt/amnezia/awg/wg0.conf", "/opt/amnezia/awg/clientsTable"} {
		b, _ := a.File(p)
		s.SetFile(p, b)
	}
	return s
}

// thXRayProv — предпроверка «как на сервере с занятым 443»: пункт о порте
// XRay появляется, только если XRay в проверяемой копии (как у
// ProvisionCheckFor — порты берутся из копии). busy=false — порт свободен.
func thXRayProv(busy bool, seen *[]bool) func(*core.Session, *core.Backup) core.ProvisionReport {
	return func(_ *core.Session, b *core.Backup) core.ProvisionReport {
		has := toHostHasXRay(b)
		*seen = append(*seen, has)
		r := core.ProvisionReport{Items: []core.ProvItem{{What: "ОС", State: core.ProvOK, Reason: "Ubuntu 24.04"}}}
		if has {
			st, why := core.ProvOK, "свободен"
			if busy {
				st, why = core.ProvBad, "порт занят другой программой"
			}
			r.Items = append(r.Items, core.ProvItem{What: "порт amnezia-xray 443/tcp (порт из копии)", State: st, Reason: why})
		}
		return r
	}
}

// thConfirmSkip — окно «Перенести без XRay?» показано; нажать «Перенести без XRay».
func thConfirmSkip(t *testing.T, f *thFixture) {
	t.Helper()
	if f.u.toHostSkipAsk == nil {
		t.Fatal("окна «" + toHostSkipTitle + "» нет")
	}
	txt := f.allText()
	if !strings.Contains(txt, "Клиенты XRay на новом сервере работать не будут") || !strings.Contains(txt, "Клиенты XRay") {
		t.Errorf("в окне выбора нет предупреждения и клиентов XRay:\n%s", txt)
	}
	test.Tap(buttonByText(t, f.u.win.Canvas().Overlays().Top(), toHostSkipText))
	waitGUIGoroutines(t)
}

// TestGUIToHostSkipXRay — ТЕСТ РАЗЛИЧЕНИЯ и ДОЕЗДА: «без XRay» ≠ «полный».
// С выбранным «без XRay» XRay не попадает ни в предпроверку (пересчитана по
// копии без XRay), ни в план установки, ни в копию установки и переноса, ни
// в выданный ключ vpn://; итог — «перенесено частично — без XRay». Без
// выбора при занятом 443 «Далее» погашена. Подмена «план по полной копии»
// (PlanInstall(st.full)) роняет случаи «без XRay».
func TestGUIToHostSkipXRay(t *testing.T) {
	for _, c := range []struct {
		name   string
		busy   bool
		via    string // "" — не выбирать; "review" — кнопка просмотра; "radio" — выбор на шаге 2
		noXRay bool
	}{
		{"полный, порт свободен", false, "", false},
		{"занят 443, без выбора", true, "", false},
		{"занят 443, без XRay", true, "review", true},
		{"порт свободен, без XRay на шаге выборов", false, "radio", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newTHFixtureOn(t, newMigFixtureOn(t, awgXRayServer(), xrayMigServer(), migTestDstHost, realFpSrc, realFpDst))
			f.keysOut = core.KeysAccepted
			var seen []bool
			toHostProvCheck = thXRayProv(c.busy, &seen)
			var planNames []string
			var instB, applyB *core.Backup
			inner, innerApply := toHostInstall, toHostApply
			toHostInstall = func(s *core.Session, p core.InstallPlan, o core.InstallOptions) core.InstallResult {
				for _, it := range p.Items {
					planNames = append(planNames, it.Container)
				}
				instB = o.Backup
				return inner(s, p, o)
			}
			toHostApply = func(ctx context.Context, src, dst *core.Session, b *core.Backup, l core.BackupLayer, xrayOK, addrOK bool, now time.Time, p core.ProgressFunc) (string, []core.RestoreOutcome, error) {
				applyB = b
				return innerApply(ctx, src, dst, b, l, xrayOK, addrOK, now, p)
			}
			f.startHost(t)
			r := f.u.toHostReviewed
			if r == nil {
				t.Fatal("шага «Просмотр» нет")
			}
			if !toHostHasXRay(mustBackup(t, f)) {
				t.Fatal("сцена ничего не значит: XRay нет в копии источника")
			}
			if c.busy {
				if !r.next.Disabled() {
					t.Fatal("занят 443, XRay в копии — «Далее» не погашена")
				}
				if r.skip == nil {
					t.Fatal("занят 443 — нет кнопки «" + toHostSkipText + "»")
				}
			}
			if c.via == "" && c.busy {
				return // без выбора дальше нельзя — это и проверено
			}
			if c.via == "review" {
				test.Tap(r.skip)
				thConfirmSkip(t, f)
				r = f.u.toHostReviewed
				if len(seen) < 2 || seen[len(seen)-1] {
					t.Fatalf("предпроверка не пересчитана по копии без XRay: %v", seen)
				}
				if !strings.Contains(r.text, toHostXRayNotMoved) {
					t.Errorf("на просмотре не сказано «%s»:\n%s", toHostXRayNotMoved, r.text)
				}
			}
			if c.via == "radio" {
				v := f.next(t)
				if v.xrayRadio == nil {
					t.Fatal("на шаге выборов нет выбора XRay")
				}
				for _, o := range v.xrayRadio.Options {
					if o == migrateXRaySkip {
						t.Errorf("вариант «%s» на новом сервере неверен: прежнего XRay там нет", o)
					}
				}
				v.xrayRadio.SetSelected(toHostXRaySkipOpt)
				thConfirmSkip(t, f)
				if seen[len(seen)-1] {
					t.Fatalf("предпроверка не пересчитана по копии без XRay: %v", seen)
				}
			}
			v := f.fill(t, true, thKeyPw)
			if c.noXRay && v.xrayRadio != nil {
				t.Error("XRay исключён, а выбор XRay на шаге 2 остался")
			}
			test.Tap(v.apply)
			waitGUIGoroutines(t)

			// ключ vpn:// — из файла, который выдан
			ents, _ := os.ReadDir(f.keyDir)
			if len(ents) != 1 {
				t.Fatalf("файлов ключа: %d", len(ents))
			}
			raw, err := os.ReadFile(f.keyDir + "/" + ents[0].Name())
			if err != nil {
				t.Fatal(err)
			}
			m, err := core.DecodeVpnKey(strings.TrimSpace(string(raw)))
			if err != nil {
				t.Fatal("ключ не разобран: " + core.MaskText(err.Error()))
			}
			kj, _ := json.Marshal(m)
			keyHasXRay := strings.Contains(string(kj), core.XRayContainer)
			planHasXRay := strings.Contains(strings.Join(planNames, " "), core.XRayContainer)
			dstHasXRay := false
			for _, cmd := range f.dst.Commands() {
				dstHasXRay = dstHasXRay || strings.Contains(cmd, core.XRayContainer)
			}
			txt := f.allText()
			for what, got := range map[string]bool{
				"план установки":      planHasXRay,
				"копия установки":     toHostHasXRay(instB),
				"копия переноса":      toHostHasXRay(applyB),
				"ключ vpn://":         keyHasXRay,
				"предпроверка (посл)": seen[len(seen)-1],
			} {
				if got == c.noXRay {
					t.Errorf("%s: XRay есть=%v, а выбрано «без XRay»=%v", what, got, c.noXRay)
				}
			}
			if c.noXRay && dstHasXRay {
				t.Error("на новый сервер ушла команда с amnezia-xray")
			}
			partial := strings.Contains(txt, toHostPartialHead)
			full := strings.Contains(txt, "ПЕРЕНЕСЕНО — все контейнеры")
			if partial != c.noXRay || full == c.noXRay {
				t.Errorf("итог: частично=%v полный=%v, без XRay=%v:\n%s", partial, full, c.noXRay, txt)
			}
			if c.noXRay && (!strings.Contains(txt, toHostXRayNotMoved) || strings.Contains(txt, "оставлен как есть") || strings.Contains(txt, "ПЕРЕНОС НЕ ЗАВЕРШЁН")) {
				t.Errorf("итог без XRay сказан не так:\n%s", txt)
			}
		})
	}
}
