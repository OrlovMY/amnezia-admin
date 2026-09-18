package core_test

import (
	"errors"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// ---------- Место № 1 задания A1, часть core ----------
//
// ЧТО ЗДЕСЬ ДОКАЗЫВАЕТСЯ. Session.GetHandshakes до этой правки УНИЧТОЖАЛА
// ошибку: сигнатура map[string]string третьего состояния не выражает, и
// отказ сервера приходил к вызывающему пустой картой — неотличимо от "у
// всех клиентов подключений не было". Починка в месте печати невозможна:
// там уже нечего различать. Поэтому тест доезда стоит здесь, у источника.
//
// ПУТЬ ОШИБКИ — БОЕВОЙ: транспорт (core.Runner) возвращает отказ ровно на
// той команде, которую шлёт GetPeerStats, а состояние "не удалось" собирает
// сам продукт. Состояние, сконструированное присваиванием в тесте,
// доказывало бы, что печать умеет печатать, и ничего не говорило бы о коде.

// failWgShow — транспорт поверх fakesrv, отказывающий ровно на `wg show wg0
// dump`. Свой тип, а не хук в fakesrv: граница A1-I проходит по core, cmd и
// internal/guiview, и заводить поле в общем фейке ради одного теста значило
// бы расширить правку за объявленную границу.
type failWgShow struct {
	inner *fakesrv.Server
	err   error
	calls int
}

func (f *failWgShow) Run(cmd string, stdin []byte) (string, error) {
	if strings.Contains(cmd, "wg show wg0 dump") {
		f.calls++
		return "", f.err
	}
	return f.inner.Run(cmd, stdin)
}

func wgContainer() *core.Container {
	return &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
}

// TestGetHandshakesReportsFailure — ТЕСТ ДОЕЗДА места № 1: отказ сервера
// доходит до вызывающего ошибкой, а не пустой картой.
func TestGetHandshakesReportsFailure(t *testing.T) {
	boom := errors.New("ssh: connection reset")
	r := &failWgShow{inner: fakesrv.New(), err: boom}
	sess := core.NewSessionWithRunner(r, &core.ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"})

	hs, err := sess.GetHandshakes(wgContainer())
	if err == nil {
		t.Fatalf("GetHandshakes вернула err == nil при отказе `wg show wg0 dump` — "+
			"незнание выдано за знание: вызывающий получит %v и напечатает \"подключений не было\"", hs)
	}
	if !strings.Contains(err.Error(), boom.Error()) {
		t.Errorf("ошибка не донесла причину: %v, want содержит %q", err, boom.Error())
	}
	if hs != nil {
		t.Errorf("при ошибке карта должна быть nil, получено %v: непустая карта рядом с ошибкой "+
			"провоцирует вызывающего читать её и снова считать пустоту ответом", hs)
	}
	if r.calls == 0 {
		t.Fatal("тест ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: команда `wg show wg0 dump` не отправлялась вовсе — " +
			"значит ошибка пришла не тем путём, что в бою")
	}
}

// TestGetHandshakesSuccessUnchanged — вторая сторона того же: при исправном
// сервере поведение прежнее (карта по ключам, "—" для нулевого handshake),
// ошибки нет. Без этой половины правка "всегда возвращать ошибку" прошла бы
// зелёной.
func TestGetHandshakesSuccessUnchanged(t *testing.T) {
	srv := fakesrv.New()
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"})

	hs, err := sess.GetHandshakes(wgContainer())
	if err != nil {
		t.Fatalf("GetHandshakes на исправном сервере: %v", err)
	}
	if len(hs) == 0 {
		t.Fatal("GetHandshakes вернула пустую карту на исправном сервере — тест перестал что-либо проверять")
	}
	for pub, v := range hs {
		if v != "—" {
			t.Errorf("%s: %q, want \"—\" (fakesrv отдаёт нулевой handshake для всех peer'ов)", pub, v)
		}
	}
}
