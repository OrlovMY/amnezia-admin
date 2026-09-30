package main

// Осмотр прибором (verify-in-ui) видимых добавок A3б PR-3: диалог исхода
// записи для каждого из семи исходов и окно изменений после исхода. Ошибка —
// НАСТОЯЩАЯ, из sess.AddUser над fakesrv с хуком (текст ядра с путями и кодом
// выхода — тот, что увидит человек).

import (
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
	"amnezia-admin/internal/guiview"
	"amnezia-admin/internal/writeoutcome"
)

// pr3RealErr — ошибка исхода, полученная боевым путём.
func pr3RealErr(t *testing.T, prep func(*fakesrv.Server)) error {
	t.Helper()
	srv := fakesrv.New()
	prep(srv)
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
	_, err := sess.AddUser(pr3Container(), "Mallory")
	if err == nil {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: запись прошла")
	}
	return err
}

func openWriteOutcome(prep func(*fakesrv.Server)) func(t *testing.T, u *ui, sized func()) osmotrScene {
	return func(t *testing.T, u *ui, sized func()) osmotrScene {
		err := pr3RealErr(t, prep)
		osmotrMain(u)
		sized()
		u.showError(err)
		return scenePopup(t, u)
	}
}

func openApplyOutcome(prep func(*fakesrv.Server)) func(t *testing.T, u *ui, sized func()) osmotrScene {
	return func(t *testing.T, u *ui, sized func()) osmotrScene {
		osmotrMain(u)
		sized()
		srv := fakesrv.New()
		prep(srv)
		u.sess = core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
		u.warnSess = guiview.AfterWarned(u.warnServerID())
		plan, err := u.sess.PlanAddUser(pr3Container(), "Mallory")
		if err != nil {
			t.Fatalf("PlanAddUser: %v", err)
		}
		u.showDiffWindow(`добавление "Mallory"`, plan, func(*core.NewUser) {})
		diff := topPopup(t, u.win.Canvas())
		buttonByText(t, diff, "Применить").OnTapped()
		waitGUIGoroutines(t)
		// диалог исхода закрыт — осматривается окно изменений со строкой статуса
		u.win.Canvas().Overlays().Top().Hide()
		return scenePopup(t, u)
	}
}

func init() {
	for _, c := range pr3Cases {
		tx, _ := writeoutcome.Describe(pr3KindErr(c.kind))
		osmotrForms = append(osmotrForms, osmotrForm{
			name: "(з) исход записи: " + c.name, open: openWriteOutcome(c.prep), width: writeErrorDialogWidth - 8, // рамка уже Resize на 8 т., как у всех диалогов прибора
			inventory: []string{"подпись:" + firstLine(tx.Title), "прокрутка:", "кнопка:Закрыть"},
		})
	}
	// Окно изменений после исхода с самой длинной строкой статуса (без
	// повтора: «Закройте это окно…» добавлена) и с повтором.
	for _, c := range pr3Cases {
		if c.kind != writeoutcome.Unknown && c.kind != writeoutcome.Busy {
			continue
		}
		tx, _ := writeoutcome.Describe(pr3KindErr(c.kind))
		osmotrForms = append(osmotrForms, osmotrForm{
			name: "(д) изменения после исхода: " + c.name, open: openApplyOutcome(c.prep), width: 692,
			inventory: []string{"подпись:" + firstLine(`Изменения перед применением: добавление "Mallory"`),
				"подпись:/opt/amnezia/awg/wg0.conf", "прокрутка:", "подпись:/opt/amnezia/awg/clientsTable", "прокрутка:",
				"кнопка:Применить", "подпись:" + firstLine(guiview.ApplyStatus(tx)), "кнопка:Закрыть"},
		})
	}
}
