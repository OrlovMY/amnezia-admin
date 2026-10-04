package core

import (
	"errors"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// TestBackupManifestRefusals — QA-01 Н1: закрытые списки и инварианты
// манифеста; каждый дефект — «копия не прочитана», а не пропуск сверки.
func TestBackupManifestRefusals(t *testing.T) {
	fresh := func() *Backup {
		srv := fakesrv.New()
		srv.Names = append(srv.Names, "amnezia-openvpn")
		b, err := backupSession(t, srv).CollectBackup("t", backupNow, okResolver)
		if err != nil || !b.Complete {
			t.Fatalf("исходная копия: %v %v", err, b)
		}
		return b
	}
	awg := func(b *Backup) *BackupContainer {
		for i := range b.Containers {
			if b.Containers[i].Name == "amnezia-awg" {
				return &b.Containers[i]
			}
		}
		t.Fatal("нет amnezia-awg")
		return nil
	}
	cases := []struct {
		name, want string
		mut        func(b *Backup)
	}{
		{"путь вместо имени файла", "не из закрытого списка", func(b *Backup) { awg(b).Files[1].Name = "../../etc/passwd" }},
		{"чужое имя файла", "не из закрытого списка", func(b *Backup) { awg(b).Files[2].Name = "authorized_keys" }},
		{"повтор имени файла", "не из закрытого списка", func(b *Backup) { c := awg(b); c.Files[1].Name = c.Files[0].Name }},
		{"лишний файл", "состав файлов", func(b *Backup) { c := awg(b); c.Files = append(c.Files, c.Files[0]) }},
		{"файла не хватает", "состав файлов", func(b *Backup) { c := awg(b); c.Files = c.Files[:3] }},
		{"статус файла вне списка", "не из закрытого списка", func(b *Backup) { awg(b).Files[1].Status = "maybe" }},
		{"статус контейнера вне списка", "не из закрытого списка", func(b *Backup) { awg(b).Status = "ok" }},
		{"неизвестный контейнер", "не известен", func(b *Backup) { awg(b).Name = "amnezia-evil" }},
		{"чужой каталог", "не известен", func(b *Backup) { awg(b).Dir = "/etc" }},
		{"сохранён без конфигурации", "«сохранён», а файл", func(b *Backup) {
			f := &awg(b).Files[0]
			f.Status, f.Data, f.SHA256, f.Size = FileAbsent, Secret{}, "", 0
		}},
		{"у «нет» есть данные", "есть данные", func(b *Backup) {
			c := awg(b)
			c.Files[2].Data = NewSecret([]byte("x"))
		}},
		{"полнота не соответствует", "признак полноты", func(b *Backup) { b.Complete = false }},
		{"«не входит» с файлами", "есть файлы", func(b *Backup) {
			for i := range b.Containers {
				if b.Containers[i].Status == CtrNotIncluded {
					b.Containers[i].Files = awg(b).Files
				}
			}
		}},
		{"контейнер дважды", "дважды", func(b *Backup) { b.Containers = append(b.Containers, *awg(b)) }},
		{"состояние версии вне списка", "состояние версии", func(b *Backup) { awg(b).VersionState = "probably" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := fresh()
			c.mut(b)
			data, err := EncodeBackup(b, PlainLayer{})
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecodeBackup(data, PlainLayer{})
			if !errors.Is(err, ErrBackupNotRead) || got != nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("ждали отказ «%s», получили %v (результат %v)", c.want, err, got != nil)
			}
		})
	}
	// неполная копия с честным признаком читается
	b := fresh()
	f := &awg(b).Files[1]
	f.Status, f.Data, f.SHA256, f.Size, f.Reason = FileUnreadable, Secret{}, "", 0, "не прочитан"
	awg(b).Status, b.Complete = CtrUnreadable, false
	data, _ := EncodeBackup(b, PlainLayer{})
	if _, err := DecodeBackup(data, PlainLayer{}); err != nil {
		t.Errorf("честная неполная копия не прочитана: %v", err)
	}
}

// TestVersionReasonInCompat — QA-01 (а): причина «версия не определена»
// хранится в копии и показывается в проверке цели.
func TestVersionReasonInCompat(t *testing.T) {
	a := fakesrv.NewAWG2()
	conf, _ := a.File("/opt/amnezia/awg/awg0.conf")
	var keep []string
	for _, l := range strings.Split(string(conf), "\n") {
		k := strings.TrimSpace(strings.SplitN(l, "=", 2)[0])
		if strings.HasPrefix(strings.TrimSpace(l), "# I") {
			continue
		}
		switch k {
		case "S3", "S4", "H1", "H2", "H3", "H4", "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
			"RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies":
			continue
		}
		keep = append(keep, l)
	}
	a.SetFile("/opt/amnezia/awg/awg0.conf", []byte(strings.Join(keep, "\n")))
	b := sourceBackup(t, a, "203.0.113.1")
	bc := ctrOf(t, b, "amnezia-awg2")
	if bc.VersionReason == "" {
		t.Fatalf("причина не сохранена: %+v", bc)
	}
	data, _ := EncodeBackup(b, PlainLayer{})
	b2, err := DecodeBackup(data, PlainLayer{})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := NewSessionWithRunner(fakesrv.NewAWG2(), &ServerCreds{Host: "203.0.113.1"}).CheckTarget(b2, okResolver)
	if row, _ := rowOf(r, "amnezia-awg2", "протокол и версия"); !strings.Contains(row.Text, bc.VersionReason) {
		t.Errorf("причина не показана: %q (ждали «%s»)", row.Text, bc.VersionReason)
	}
}
