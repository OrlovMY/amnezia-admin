package main

// Осмотр прибором (verify-in-ui) видимых добавок A3б PR-3: диалог исхода
// записи для каждого из семи исходов и окно изменений после исхода. Ошибка —
// НАСТОЯЩАЯ, из sess.AddUser над fakesrv с хуком (текст ядра с путями и кодом
// выхода — тот, что увидит человек).

import (
	"strings"
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
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
	plan, err := sess.PlanAddUser(pr3Container(), "Mallory")
	if err != nil {
		t.Fatalf("PlanAddUser: %v", err)
	}
	prep(srv) // хуки — после плана: они про запись
	_, err = sess.Apply(plan)
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
		u.sess = core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
		u.warnSess = guiview.AfterWarned(u.warnServerID())
		plan, err := u.sess.PlanAddUser(pr3Container(), "Mallory")
		if err != nil {
			t.Fatalf("PlanAddUser: %v", err)
		}
		prep(srv)
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

// Исход «не хватает прав» (SudoDenied, слияние H1): ошибка — боевым путём,
// sess.Apply над fakesrv через исполнитель, у которого docker без sudo не
// пускает к сокету, а sudo отказывает (тексты настоящих docker и sudo).
func init() {
	tx, _ := writeoutcome.Describe(core.ErrSudoDenied)
	osmotrForms = append(osmotrForms, osmotrForm{
		name: "(з) исход записи: не хватает прав", open: openSudoDenied, width: writeErrorDialogWidth - 8,
		inventory: []string{"подпись:" + firstLine(tx.Title), "прокрутка:", "кнопка:Закрыть"},
	})
}

func openSudoDenied(t *testing.T, u *ui, sized func()) osmotrScene {
	srv := fakesrv.New()
	sess := core.NewSessionWithRunner(&guiSudoDenyRunner{srv: srv}, &core.ServerCreds{Host: "203.0.113.10", User: "deploy", Password: "x"})
	plan, err := sess.PlanAddUser(pr3Container(), "Mallory")
	if err != nil {
		t.Fatalf("PlanAddUser: %v", err)
	}
	_, err = sess.Apply(plan)
	if writeoutcome.Classify(err) != writeoutcome.SudoDenied {
		t.Fatalf("исход не «не хватает прав»: %v", err)
	}
	osmotrMain(u)
	sized()
	u.showError(err)
	return scenePopup(t, u)
}

type guiSudoDenyRunner struct{ srv *fakesrv.Server }

func (r *guiSudoDenyRunner) Run(cmd string, stdin []byte) (string, error) {
	if !strings.Contains(cmd, "flock") {
		return r.srv.Run(cmd, stdin)
	}
	if strings.Contains(cmd, "sudo") {
		return "", &fakesrv.ExitError{Cmd: cmd, Status: 1, Stderr: "sudo: a password is required"}
	}
	return "", &fakesrv.ExitError{Cmd: cmd, Status: 1, Stderr: "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: connect: permission denied"}
}
