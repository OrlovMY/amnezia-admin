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
// руками (JSON рядом с .avlt), без нового API, — тест компилируется на
// прежней ревизии 2f84e37 и падает там поведением.

func writeLabel(t *testing.T, vault, js string) {
	t.Helper()
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
	want := []string{"AEZA test", "Сервер 2", "Сервер 3", "Дом — 10.0.0.1", "Дом — 10.0.0.2:2222"}
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

// Старый файл без подписи получает её после первого входа: имя — описание
// из ключа (старая метка по умолчанию была голым адресом).
func TestRefreshVaultLabelOldVault(t *testing.T) {
	dir := withVaultFiles(t, "01.avlt", "02.avlt")
	vc := &vaultCtx{path: filepath.Join(dir, "01.avlt"), payload: core.VaultPayload{Label: "89.22.229.78"}}
	cfg := map[string]any{"description": "AEZA test", "hostName": "89.22.229.78"}
	creds := &core.ServerCreds{Host: "89.22.229.78", Port: "22", User: "root"}
	if err := refreshVaultLabel(vc, cfg, creds); err != nil {
		t.Fatal(err)
	}
	sel, _ := vaultBlockSelect(t)
	if sel == nil || sel.Options[0] != "AEZA test" || sel.Options[1] != "Сервер 2" {
		t.Fatalf("после входа: %v", sel)
	}
}
