package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

// Подписи сохранённых серверов (отзыв владельца по rc.4: «задавал имя, а
// вижу "Select One" и "Сервер 1", "Сервер 2"»). Файлы-подписи пишутся здесь
// руками (JSON рядом с .avlt), без нового API, — первые два теста
// компилируются на прежней ревизии 2f84e37 и падают там поведением.

// emptySum — SHA-256 пустого содержимого: withVaultFiles создаёт пустые .avlt.
const emptySum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// writeLabel пишет подпись; JSON с полем name получает привязку к пустому .avlt.
func writeLabel(t *testing.T, vault, js string) {
	t.Helper()
	if strings.HasPrefix(js, `{"name"`) {
		js = `{"sha256":"` + emptySum + `",` + js[1:]
	}
	if err := os.WriteFile(vault+".label", []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
}

func vaultBlockSelect(t *testing.T) (*widget.Select, *widget.Button) {
	t.Helper()
	u := focusTestUI(t)
	blk := u.savedVaultsBlock(widget.NewButton("", nil), widget.NewLabel(""))
	if blk == nil {
		t.Fatal("блок сохранённых не построен")
	}
	var sel *widget.Select
	var btn *widget.Button
	walkObjects(blk, func(o fyne.CanvasObject) {
		switch w := o.(type) {
		case *widget.Select:
			sel = w
		case *widget.Button:
			btn = w
		}
	})
	return sel, btn
}

func TestSavedVaultNamesFromLabels(t *testing.T) {
	long := strings.Repeat("Очень длинное описание сервера ", 6)
	dir := withVaultFiles(t, "01.avlt", "02.avlt", "03.avlt", "04.avlt", "05.avlt", "06.avlt")
	writeLabel(t, filepath.Join(dir, "01.avlt"), `{"name":"AEZA test","addr":"89.22.229.78"}`)
	// 02 — подписи нет (старый файл): «Сервер 2», а не выдуманное имя.
	writeLabel(t, filepath.Join(dir, "03.avlt"), `{битый`)
	writeLabel(t, filepath.Join(dir, "04.avlt"), `{"name":"Дом","addr":"10.0.0.1"}`)
	writeLabel(t, filepath.Join(dir, "05.avlt"), `{"name":"Дом","addr":"10.0.0.2:2222"}`)
	writeLabel(t, filepath.Join(dir, "06.avlt"), `{"name":"`+long+`","addr":"1.2.3.4"}`)

	sel, _ := vaultBlockSelect(t)
	if sel == nil {
		t.Fatal("списка нет")
	}
	if sel.PlaceHolder != "Выберите сервер" {
		t.Errorf("заглушка %q, ожидалась «Выберите сервер»", sel.PlaceHolder)
	}
	want := []string{"AEZA test", "Сервер 2", "Сервер 3 (подпись повреждена)", "Дом — 10.0.0.1", "Дом — 10.0.0.2:2222"}
	if len(sel.Options) != 6 {
		t.Fatalf("пунктов %d: %q", len(sel.Options), sel.Options)
	}
	for i, w := range want {
		if sel.Options[i] != w {
			t.Errorf("пункт %d = %q, ожидался %q", i+1, sel.Options[i], w)
		}
	}
	last := sel.Options[5]
	if !strings.HasSuffix(last, "…") || len([]rune(last)) > 48 {
		t.Errorf("длинное имя не обрезано многоточием: %q (%d знаков)", last, len([]rune(last)))
	}
	if w := sel.MinSize().Width; w > connectFormWidth {
		t.Errorf("список шире формы: %.0f > %.0f", w, float32(connectFormWidth))
	}
}

func TestSavedVaultSingleNamedButton(t *testing.T) {
	dir := withVaultFiles(t, "01.avlt")
	writeLabel(t, filepath.Join(dir, "01.avlt"), `{"name":"AEZA test","addr":"89.22.229.78"}`)
	sel, btn := vaultBlockSelect(t)
	if sel != nil {
		t.Error("один сервер — должна быть кнопка без заглушки, а не список")
	}
	if btn == nil || btn.Text != "AEZA test" {
		t.Errorf("кнопка: %+v", btn)
	}
}

// M1: два одинаковых длинных имени — разные пункты; различитель не срезан.
func TestSavedVaultLongDuplicatesDistinct(t *testing.T) {
	long := strings.Repeat("Длинное имя сервера ", 4)
	dir := withVaultFiles(t, "01.avlt", "02.avlt")
	writeLabel(t, filepath.Join(dir, "01.avlt"), `{"name":"`+long+`","addr":"1.1.1.1"}`)
	writeLabel(t, filepath.Join(dir, "02.avlt"), `{"name":"`+long+`","addr":"2.2.2.2"}`)
	sel, _ := vaultBlockSelect(t)
	if sel == nil || len(sel.Options) != 2 {
		t.Fatalf("список: %v", sel)
	}
	if sel.Options[0] == sel.Options[1] {
		t.Fatalf("пункты одинаковы: %q", sel.Options[0])
	}
	if !strings.HasSuffix(sel.Options[0], " — 1.1.1.1") || !strings.HasSuffix(sel.Options[1], " — 2.2.2.2") {
		t.Errorf("различитель срезан: %q", sel.Options)
	}
}

// Привязка: .avlt заменили под существующей подписью (тест доезда — файл
// меняется на диске) — чужое имя не показывается.
func TestSavedVaultLabelMismatchNotShown(t *testing.T) {
	dir := withVaultFiles(t, "01.avlt", "02.avlt")
	writeLabel(t, filepath.Join(dir, "01.avlt"), `{"name":"AEZA test","addr":"89.22.229.78"}`)
	if err := os.WriteFile(filepath.Join(dir, "01.avlt"), []byte("другой файл"), 0o600); err != nil {
		t.Fatal(err)
	}
	sel, _ := vaultBlockSelect(t)
	if sel == nil || sel.Options[0] != "Сервер 1 (подпись не совпадает с файлом ключа)" {
		t.Fatalf("подменённый файл: %v", sel.Options)
	}
}

// Подпись без своего .avlt удаляется при показе списка.
func TestOrphanLabelRemoved(t *testing.T) {
	dir := withVaultFiles(t, "01.avlt")
	orphan := filepath.Join(dir, "99.avlt.label")
	if err := os.WriteFile(orphan, []byte(`{"name":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	vaultBlockSelect(t)
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Errorf("осиротевшая подпись осталась: %v", err)
	}
}

// Старый файл без подписи получает её после первого входа: имя — описание
// из ключа (старая метка по умолчанию была голым адресом). Тихо: подписи
// не было — сообщать не о чем.
func TestRefreshVaultLabelOldVault(t *testing.T) {
	dir := withVaultFiles(t, "01.avlt", "02.avlt")
	vc := &vaultCtx{path: filepath.Join(dir, "01.avlt"), payload: core.VaultPayload{Label: "89.22.229.78"}}
	cfg := map[string]any{"description": "AEZA test", "hostName": "89.22.229.78"}
	creds := &core.ServerCreds{Host: "89.22.229.78", Port: "22", User: "root"}
	notice, err := refreshVaultLabel(vc, labelBefore{st: core.LabelAbsent}, cfg, creds)
	if err != nil || notice != "" {
		t.Fatalf("notice=%q err=%v", notice, err)
	}
	sel, _ := vaultBlockSelect(t)
	if sel == nil || sel.Options[0] != "AEZA test" || sel.Options[1] != "Сервер 2" {
		t.Fatalf("после входа: %v", sel)
	}
}

// Несовпадающая/битая подпись после входа исправляется ГРОМКО: notice
// называет и прежнее, и настоящее имя; «всё было верно» — без notice.
func TestRefreshVaultLabelLoud(t *testing.T) {
	cfg := map[string]any{"description": "AEZA test", "hostName": "89.22.229.78"}
	creds := &core.ServerCreds{Host: "89.22.229.78", Port: "22", User: "root"}
	for _, c := range []struct {
		name   string
		before labelBefore
		want   []string
	}{
		{"не совпадала", labelBefore{l: core.VaultLabel{Name: "Чужой", Addr: "10.0.0.9"}, st: core.LabelMismatch},
			[]string{"не совпадала", "Чужой", "10.0.0.9", "AEZA test", "исправлена"}},
		{"повреждена", labelBefore{st: core.LabelBroken}, []string{"повреждена", "AEZA test", "исправлена"}},
		{"верна", labelBefore{st: core.LabelOK}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := withVaultFiles(t, "01.avlt")
			vc := &vaultCtx{path: filepath.Join(dir, "01.avlt")}
			notice, err := refreshVaultLabel(vc, c.before, cfg, creds)
			if err != nil {
				t.Fatal(err)
			}
			if c.want == nil && notice != "" {
				t.Errorf("лишнее сообщение: %q", notice)
			}
			for _, w := range c.want {
				if !strings.Contains(notice, w) {
					t.Errorf("в сообщении нет %q: %q", w, notice)
				}
			}
		})
	}
}
