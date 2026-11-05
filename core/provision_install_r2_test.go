package core

import (
	"strings"
	"testing"
)

// Ревью-1 PR 5, раунд 2.

// M1: том XRay не удалился откатом — не «снят», а «остался том с ключами»,
// с подсказкой про повторный запуск.
func TestInstallRollbackVolumeMeasured(t *testing.T) {
	f := newInstFake()
	f.fail = "volrm:amnezia-xray"
	// Несовпадение измерения — откат обоих контейнеров.
	f.measureConf = strings.Replace(awg2Conf, "ListenPort = 51820", "ListenPort = 51821", 1)
	res, _ := instRun(t, f)
	x := res.Containers[1]
	if x.Container != XRayContainer || x.Rollback != RollbackFailed || x.Outcome == InstallNotInstalled {
		t.Fatalf("том остался, а откат: %d, %s", x.Rollback, x.Verdict())
	}
	all := strings.Join(res.Lines(), "\n")
	for _, w := range []string{"том с ключами amnezia-xray-data", "повторная установка откажет"} {
		if !strings.Contains(all, w) {
			t.Errorf("нет %q:\n%s", w, all)
		}
	}
	if res.Containers[0].Rollback != RollbackDone {
		t.Errorf("awg2 снят полностью, а %d", res.Containers[0].Rollback)
	}
}

// M2: текст измеренного совпадения не обещает версию бинаря.
func TestInstallMatchTextHonest(t *testing.T) {
	r := InstallContainerResult{Outcome: InstallInstalled, Measured: CompatMatch}
	v := r.Verdict()
	if !strings.Contains(v, "версия бинаря не закреплена и не измерялась") || !strings.Contains(v, "семейству параметров, порту и подсети") {
		t.Errorf("подпись: %q", v)
	}
	if strings.Contains(v, "измерен: совпадает с копией") {
		t.Errorf("голое «совпадает с копией»: %q", v)
	}
	it := PlanInstall(instBackup(), nil).Items[0]
	for _, s := range []string{it.Verdict(), it.Reason} {
		if strings.Contains(s, "подтвердится") {
			t.Errorf("план обещает подтверждение: %q", s)
		}
	}
}

// L1: образ amnezia-* до запуска — цель не чистая, откат его не снесёт.
func TestInstallRefusesExistingImage(t *testing.T) {
	f := newInstFake()
	f.imgs["amnezia-awg2"] = true
	res, _ := instRun(t, f)
	if !strings.Contains(res.Refused, "amnezia-awg2") {
		t.Fatalf("образ не учтён: %q", res.Refused)
	}
	if w := installWrites(f.keys()); len(w) != 0 {
		t.Errorf("запись: %v", w)
	}
}

// L3: два замера через паузу; вырос RestartCount или второй замер не
// «работает» — шаг отказал.
func TestInstallRunningTwice(t *testing.T) {
	for _, out := range []string{"true/0\ntrue/1\n", "true/0\nfalse/0\n", "true/0\n"} {
		f := newInstFake()
		f.inspectOut = out
		res, _ := instRun(t, f)
		if !res.Stop || res.Containers[0].Step != "контейнер запущен" {
			t.Errorf("%q: не остановлено на проверке работы: %v", out, res.Lines())
		}
	}
	for _, c := range newInstFakeCalls(t) {
		if strings.HasPrefix(c.key, "inspect:") && !strings.Contains(c.cmd, "sleep ") {
			t.Errorf("проверка без паузы: %s", c.cmd)
		}
	}
}

func newInstFakeCalls(t *testing.T) []instCall {
	f := newInstFake()
	instRun(t, f)
	return f.calls
}

// N1: при отказе причина печатается один раз.
func TestInstallRefusedOnce(t *testing.T) {
	f := newInstFake()
	f.imgs["amnezia-xray"] = true
	res, _ := instRun(t, f)
	if n := strings.Count(strings.Join(res.Lines(), "\n"), "сервер не чистый"); n != 1 {
		t.Errorf("причина напечатана %d раз", n)
	}
}
