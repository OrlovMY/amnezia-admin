package core

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

const (
	awgDir = "/opt/amnezia/awg"
	keyPub = "wireguard_server_public_key.key"
	keyPsk = "wireguard_psk.key"
)

// migrationPair — старый сервер (с файлами ключей) и новый (свежая
// установка: свои ключи, свой клиент Carol), одинаковые порт и подсеть.
func migrationPair(t *testing.T) (src, tgt *fakesrv.Server) {
	t.Helper()
	src, tgt = fakesrv.New(), fakesrv.New()
	src.SetFile(awgDir+"/"+keyPub, []byte("OLD-PUB\n"))
	src.SetFile(awgDir+"/"+keyPsk, []byte("OLD-PSK\n"))
	tgt.SetFile(awgDir+"/"+keyPub, []byte("NEW-PUB\n"))
	tgt.SetFile(awgDir+"/"+keyPsk, []byte("NEW-PSK\n"))
	return src, tgt
}

func restoreOpts(t *testing.T) RestoreOptions {
	return RestoreOptions{AutoCopyDir: t.TempDir(), ToolVersion: "t", Now: backupNow, Resolve: okResolver, Layer: PlainLayer{}, TargetConfirmed: true}
}

func planFor(t *testing.T, b *Backup, tgtSess *Session) *RestorePlan {
	t.Helper()
	compat, err := tgtSess.CheckTarget(b, okResolver)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := tgtSess.PlanRestore(b, compat, true)
	if err != nil {
		t.Fatalf("план: %v (проверка: %+v)", err, compat.Rows)
	}
	return rp
}

func writesOf(srv *fakesrv.Server) int {
	n := 0
	for _, c := range srv.Commands() {
		if strings.Contains(c, "flock -w") {
			n++
		}
	}
	return n
}

// TestRestoreMigrationCircle — главный круг переезда: снять копию со
// старого → заменить целиком на новом. На новом конфигурация, clientsTable
// и ключи байт в байт как на старом; работающий интерфейс — ключ и порт
// старого; автокопия нового сделана до записи и читается.
func TestRestoreMigrationCircle(t *testing.T) {
	src, tgt := migrationPair(t)
	b := sourceBackup(t, src, "203.0.113.1")
	ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
	rp := planFor(t, b, ts)
	if len(rp.Items) != 1 || len(rp.Items[0].Removed) != 2 {
		t.Fatalf("предпросмотр: %+v", rp.Items)
	}
	tgtConfBefore, _ := tgt.File(awgDir + "/wg0.conf")
	opt := restoreOpts(t)
	auto, outs, err := ts.Restore(rp, opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(outs) != 1 || outs[0].State != RestoreDone {
		t.Fatalf("исход: %+v", outs)
	}
	for _, n := range []string{"wg0.conf", "clientsTable", keyPub, keyPsk} {
		a, _ := src.File(awgDir + "/" + n)
		got, _ := tgt.File(awgDir + "/" + n)
		if !bytes.Equal(a, got) {
			t.Errorf("%s на новом сервере не равен старому", n)
		}
	}
	ac, err := ReadBackupFile(auto, PlainLayer{})
	if err != nil {
		t.Fatalf("автокопия не читается: %v", err)
	}
	if f := fileOfB(ctrOf(t, ac, "amnezia-awg"), "wg0.conf"); !bytes.Equal(f.Data.Bytes(), tgtConfBefore) {
		t.Error("автокопия — не прежнее состояние нового сервера")
	}
	if fi, err := os.Stat(auto); err != nil || filepath.Dir(auto) != opt.AutoCopyDir || fi.Size() == 0 {
		t.Errorf("автокопия: %v", err)
	}
}

// TestRestoreStopsBeforeWrite — СТОП проверки, неподтверждённый адрес,
// неполная автокопия, ключа нет на цели — ни одной записи.
func TestRestoreStopsBeforeWrite(t *testing.T) {
	t.Run("порт другой — план отвергнут", func(t *testing.T) {
		src, tgt := migrationPair(t)
		setIface(t, tgt, awgDir+"/wg0.conf", "ListenPort", "40000")
		b := sourceBackup(t, src, "203.0.113.1")
		ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
		compat, _ := ts.CheckTarget(b, okResolver)
		if _, err := ts.PlanRestore(b, compat, true); !errors.Is(err, ErrRestoreStopped) {
			t.Fatalf("ждали СТОП: %v", err)
		}
		if writesOf(tgt) != 0 {
			t.Error("запись при СТОП")
		}
	})
	t.Run("адрес другой без подтверждения", func(t *testing.T) {
		src, tgt := migrationPair(t)
		b := sourceBackup(t, src, "203.0.113.1")
		ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "198.51.100.9"})
		compat, _ := ts.CheckTarget(b, okResolver)
		if _, err := ts.PlanRestore(b, compat, false); !errors.Is(err, ErrRestoreStopped) {
			t.Fatalf("ждали СТОП без подтверждения адреса: %v", err)
		}
	})
	t.Run("автокопия неполная — замена запрещена", func(t *testing.T) {
		src, tgt := migrationPair(t)
		b := sourceBackup(t, src, "203.0.113.1")
		ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
		rp := planFor(t, b, ts)
		tgt.FailRead = map[string]error{awgDir + "/" + keyPsk: errors.New("cat: Input/output error")}
		if _, _, err := ts.Restore(rp, restoreOpts(t)); !errors.Is(err, ErrRestoreStopped) || !strings.Contains(err.Error(), "автокопия") {
			t.Fatalf("ждали отказ автокопии: %v", err)
		}
		if writesOf(tgt) != 0 {
			t.Error("запись без автокопии")
		}
	})
	t.Run("ключа сервера на цели нет — установка неполная", func(t *testing.T) {
		src, tgt := migrationPair(t)
		tgt.DeleteFile(awgDir + "/" + keyPsk)
		b := sourceBackup(t, src, "203.0.113.1")
		ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
		compat, _ := ts.CheckTarget(b, okResolver)
		if _, err := ts.PlanRestore(b, compat, true); !errors.Is(err, ErrRestoreStopped) || !strings.Contains(err.Error(), "неполная") {
			t.Fatalf("ждали СТОП «установка неполная»: %v", err)
		}
	})
}

// TestRestoreNotApplied — Р-5: syncconf не применил ключ и порт → «не
// применено», откат выполнен, файлы нового сервера прежние. Подмена «не
// сверять интерфейс» роняет тест (исход стал бы «восстановлен»).
func TestRestoreNotApplied(t *testing.T) {
	src, tgt := migrationPair(t)
	b := sourceBackup(t, src, "203.0.113.1")
	ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
	rp := planFor(t, b, ts)
	before, _ := tgt.File(awgDir + "/wg0.conf")
	tgt.SyncKeepsIface = true
	_, outs, err := ts.Restore(rp, restoreOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if outs[0].State == RestoreDone || outs[0].Err == nil || !strings.Contains(outs[0].Err.Error(), "не применено") {
		t.Fatalf("исход: %v %v", outs[0].State, outs[0].Err)
	}
	if outs[0].State != RestoreRolledBack {
		t.Errorf("ждали «откат выполнен», получили %v", outs[0].State)
	}
	if now, _ := tgt.File(awgDir + "/wg0.conf"); !bytes.Equal(now, before) {
		t.Error("файл нового сервера не возвращён")
	}
}

// TestRestoreStopsOnFirstFailure — сбой на втором контейнере: первый
// восстановлен, второй «ничего не записано», третий (XRay) пропущен.
func TestRestoreStopsOnFirstFailure(t *testing.T) {
	addWG := func(s *fakesrv.Server) {
		s.Names = append(s.Names, "amnezia-wireguard")
		conf, _ := s.File(awgDir + "/wg0.conf")
		tbl, _ := s.File(awgDir + "/clientsTable")
		s.SetFile("/opt/amnezia/wireguard/wg0.conf", conf)
		s.SetFile("/opt/amnezia/wireguard/clientsTable", tbl)
	}
	src, tgt := migrationPair(t)
	addWG(src)
	addWG(tgt)
	b := sourceBackup(t, src, "203.0.113.1")
	ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
	rp := planFor(t, b, ts)
	if len(rp.Items) != 2 {
		t.Fatalf("контейнеров в плане %d", len(rp.Items))
	}
	tgt.WriteFault = map[int]fakesrv.WriteFault{2: {Code: 3}}
	_, outs, err := ts.Restore(rp, restoreOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if outs[0].State != RestoreDone || outs[1].State != RestoreNotWritten {
		t.Fatalf("исходы: %v / %v (%v)", outs[0].State, outs[1].State, outs[1].Err)
	}
	// сбой на первом — второй не трогается
	src2, tgt2 := migrationPair(t)
	addWG(src2)
	addWG(tgt2)
	b2 := sourceBackup(t, src2, "203.0.113.1")
	ts2 := NewSessionWithRunner(tgt2, &ServerCreds{Host: "203.0.113.1"})
	rp2 := planFor(t, b2, ts2)
	tgt2.WriteFault = map[int]fakesrv.WriteFault{1: {Code: 3}}
	_, outs, _ = ts2.Restore(rp2, restoreOpts(t))
	if outs[0].State != RestoreNotWritten || outs[1].State != RestoreSkipped {
		t.Fatalf("сбой на первом: %v / %v", outs[0].State, outs[1].State)
	}
	if writesOf(tgt2) != 1 {
		t.Errorf("после сбоя были записи: %d команд записи", writesOf(tgt2))
	}
}

// TestRestoreXRay — XRay последним; без подтверждения — пропущен, без
// перезапуска; с подтверждением — файлы и ключи XRay как в копии.
func TestRestoreXRay(t *testing.T) {
	mk := func() *fakesrv.Server {
		s := fakesrv.NewXRay("master")
		for _, k := range []string{"xray_short_id.key", "xray_public.key", "xray_private.key"} {
			s.SetFile("/opt/amnezia/xray/"+k, []byte(k+"-"+fakesrv.RandUUID()))
		}
		return s
	}
	src, tgt := mk(), mk()
	b := sourceBackup(t, src, "203.0.113.1")
	ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
	t.Cleanup(SetXRayWaits(0, 0))
	rp := planFor(t, b, ts)
	if !rp.Items[len(rp.Items)-1].RestartsXRay {
		t.Fatal("XRay не последний или не перезапускается")
	}
	_, outs, err := ts.Restore(rp, restoreOpts(t))
	if err != nil || outs[0].State != RestoreDeclined || tgt.XRayRestarts() != 0 {
		t.Fatalf("без подтверждения: %v %v перезапусков %d", err, outs, tgt.XRayRestarts())
	}
	rp = planFor(t, b, ts)
	opt := restoreOpts(t)
	asked := 0
	opt.ConfirmXRay = func() bool { asked++; return true }
	_, outs, err = ts.Restore(rp, opt)
	if err != nil || outs[0].State != RestoreDone || asked != 1 {
		t.Fatalf("с подтверждением: %v %+v спрошено %d", err, outs, asked)
	}
	for _, n := range []string{"server.json", "clientsTable", "xray_uuid.key", "xray_short_id.key", "xray_public.key", "xray_private.key"} {
		a, _ := src.File("/opt/amnezia/xray/" + n)
		got, _ := tgt.File("/opt/amnezia/xray/" + n)
		if !bytes.Equal(a, got) {
			t.Errorf("%s на новом сервере не равен старому", n)
		}
	}
}
