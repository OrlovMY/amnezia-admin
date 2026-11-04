package main

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestCLIMigrateAddressSecondLine — вторая линия отказа по адресу: адрес
// выдачи у источника не выбран («не удалось»), -address-changes нет. Проверка
// адреса в CLI обойдена швом (bypassAddressGate) — ядро само обязано
// отказать (код 4) и ничего не записать. Подмена «CLI всегда передаёт
// AddressConfirmed=true» роняет тест (записи пошли бы). Контрольный прогон
// без шва — отказ самой CLI, тоже код 4.
func TestCLIMigrateAddressSecondLine(t *testing.T) {
	e := newMigEnv(t, true)
	flags := migrateFlags{apply: true, yes: true, noPw: true, replaceUsers: true}
	run := func(bypass bool) (int, string, string) {
		bypassAddressGate = bypass
		t.Cleanup(func() { bypassAddressGate = false })
		s1, s2 := cliSession(t, e.keySrc, e.kh), cliSession(t, e.keyDst, e.kh) // у источника адрес для клиентов не выбран
		var o, er bytes.Buffer
		code := runMigrate(context.Background(), strings.NewReader(""), &o, &er, false, s1, s2, flags, time.Now())
		return code, o.String(), er.String()
	}
	code, out, errOut := run(false)
	if code != 4 || !strings.Contains(out, "адрес другой или не проверен") || flocks(e.dst) != 0 {
		t.Fatalf("первая линия (CLI): код %d записей %d\n%s\n%s", code, flocks(e.dst), out, errOut)
	}
	code, out, errOut = run(true)
	if code != 4 || !strings.Contains(errOut, "нужно отдельное подтверждение") || flocks(e.dst) != 0 {
		t.Fatalf("вторая линия (ядро): код %d записей %d\n%s\n%s", code, flocks(e.dst), out, errOut)
	}
}

// TestCLIMigrateSameKeyBeforeConnect — одинаковые -key и -to-key: отказ код
// 4 ДО любого подключения (к одному боевому серверу не открываются две
// SSH-сессии). Считаем принятые TCP-соединения. Подмена — удаление раннего
// сравнения ключей — роняет тест (соединения пошли бы).
func TestCLIMigrateSameKeyBeforeConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var accepts atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			c.Close()
		}
	}()
	key := buildTestVpnKey(t, ln.Addr().String(), "root", "fakepw-run-e2e-test")
	code, out, errOut := cliRun(t, t.TempDir()+"/kh", "", "migrate", "-key", key, "-to-key", key, "-apply", "-yes", "-no-password")
	if code != 4 || !strings.Contains(errOut, "ключ источника и ключ цели одинаковы") {
		t.Fatalf("код %d\n%s\n%s", code, out, errOut)
	}
	time.Sleep(200 * time.Millisecond)
	if n := accepts.Load(); n != 0 {
		t.Errorf("подключений до отказа: %d", n)
	}
}
