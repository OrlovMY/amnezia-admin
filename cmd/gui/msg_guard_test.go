package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Сторож «сообщения только выделяемые» (заказ владельца 05.11.2026).
//
// ЗАКРЫТЫЙ СПИСОК, а не перечень плохого (решение 29.09): в не-тестовых
// файлах cmd/gui разрешены только перечисленные ниже конструкторы пакетов
// widget, canvas и dialog. Новый конструктор (widget.NewRichText,
// canvas.NewText, dialog.ShowInformation, …) — нарушение, пока его не внесут
// сюда видимой строкой диффа с объяснением, почему он не сообщение.
//
// Подпись (widget.NewLabel / NewLabelWithStyle) строится ТОЛЬКО в msg.go,
// в msgLabel и msgLabelStyle, — там она получает Selectable. Снять
// выделение (`.Selectable = false`) нельзя нигде. Свои типы со встроенной
// widget.Label — закрытый список embedAllowed: у каждого своё копирование.
//
// ГРАНИЦЫ, признанные прямо: разбор синтаксический — псевдоним импорта
// пакета (`w "fyne.io/fyne/v2/widget"`) сторож видит как чужой пакет и
// поэтому запрещает любой вызов через псевдоним (alias — нарушение сам по
// себе); рефлексия и сборка виджета через интерфейс не ловятся.
var msgAllowedCtors = map[string]string{
	"widget.NewButton":               "кнопка",
	"widget.NewButtonWithIcon":       "кнопка",
	"widget.NewEntry":                "поле ввода (текст выделяется само)",
	"widget.NewPasswordEntry":        "поле пароля",
	"widget.NewMultiLineEntry":       "поле ввода",
	"widget.NewCheck":                "флажок",
	"widget.NewRadioGroup":           "переключатель",
	"widget.NewSelect":               "список выбора",
	"widget.NewForm":                 "форма (подписи полей — её заголовки)",
	"widget.NewFormItem":             "строка формы",
	"widget.NewAccordion":            "раскрывающийся блок",
	"widget.NewAccordionItem":        "раскрывающийся блок",
	"widget.NewProgressBar":          "полоса прогресса",
	"widget.NewProgressBarInfinite":  "полоса прогресса",
	"widget.NewSeparator":            "разделитель",
	"widget.NewPopUpMenu":            "меню",
	"widget.ShowPopUpMenuAtPosition": "контекстное меню",
	"widget.NewSimpleRenderer":       "отрисовщик своего виджета",
	"widget.NewTextGridFromString":   "предпросмотр diff (данные, не сообщение)",
	"widget.NewTable":                "таблица статистики (stats.go): ячейки — msgLabel, заголовки — кнопки сортировки",
	"canvas.NewRectangle":            "подложка",
	"canvas.NewImageFromResource":    "картинка",
	"dialog.NewCustom":               "диалог со своим (выделяемым) содержимым",
	"dialog.NewCustomConfirm":        "подтверждение со своим содержимым",
	"dialog.NewCustomWithoutButtons": "окно со своим содержимым",
	"dialog.NewFileOpen":             "выбор файла",
	"dialog.NewFileSave":             "выбор файла",
}

// textAssignHomes — где разрешено присваивать поле .Text: конструктор
// подписи-сообщения (маска там же) и конструкторы своих виджетов, чей
// текст — не сообщение (подпись сервера, кнопка с Esc).
var textAssignHomes = map[string]bool{"msg.go:newMsgText": true, "main.go:newServerLabel": true, "xray.go:newEscButton": true}

// msgLabelHomes — где разрешено строить подпись: файл и функция.
var msgLabelHomes = map[string]bool{"msg.go:msgLabel": true, "msg.go:msgLabelStyle": true}

// embedAllowed — свои типы со встроенной widget.Label (не через msgLabel).
var embedAllowed = map[string]string{
	"msgText":       "сама подпись-сообщение (msg.go): выделение и маска",
	"serverLabel":   "подпись сервера: нажатие копирует адрес",
	"tappableLabel": "заголовок колонки таблицы",
	"tableCell":     "ячейка таблицы: «Копировать значение/строку» в меню",
}

var guardedPkgs = map[string]bool{"widget": true, "canvas": true, "dialog": true}

// msgViolations — нарушения в одном файле (src — содержимое).
func msgViolations(name string, src []byte) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return nil, err
	}
	var out []string
	bad := func(n ast.Node, msg string) {
		out = append(out, fmt.Sprintf("%s: %s", fset.Position(n.Pos()), msg))
	}
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		if imp.Name != nil && (strings.HasSuffix(p, "/widget") || strings.HasSuffix(p, "/canvas") || strings.HasSuffix(p, "/dialog")) {
			bad(imp, "псевдоним импорта "+p+" — сторож его не видит")
		}
	}
	for _, decl := range f.Decls {
		fn := ""
		if fd, ok := decl.(*ast.FuncDecl); ok {
			fn = fd.Name.Name
		}
		if gd, ok := decl.(*ast.GenDecl); ok {
			for _, sp := range gd.Specs {
				ts, ok := sp.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, fld := range st.Fields.List {
					if len(fld.Names) == 0 && exprString(fld.Type) == "widget.Label" && embedAllowed[ts.Name.Name] == "" {
						bad(fld, "тип "+ts.Name.Name+" встраивает widget.Label мимо закрытого списка")
					}
				}
			}
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				// Bind/Unbind — текст подписи из привязки данных мимо
				// msgText.SetText (ревью-2 L5).
				if (sel.Sel.Name == "Bind" || sel.Sel.Name == "Unbind") && filepath.Base(name) != "msg.go" {
					bad(x, "вызов ."+sel.Sel.Name+" — текст мимо маски msgText.SetText")
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || !guardedPkgs[pkg.Name] {
					return true
				}
				full := pkg.Name + "." + sel.Sel.Name
				if full == "widget.NewLabel" || full == "widget.NewLabelWithStyle" {
					if !msgLabelHomes[filepath.Base(name)+":"+fn] {
						bad(x, full+" вне msgLabel/msgLabelStyle — подпись без выделения")
					}
					return true
				}
				if !strings.HasPrefix(sel.Sel.Name, "New") && !strings.HasPrefix(sel.Sel.Name, "Show") {
					return true // не конструктор (dialog.Dialog и т.п. — типы)
				}
				if msgAllowedCtors[full] == "" {
					bad(x, full+" не в закрытом списке конструкторов")
				}
			case *ast.SelectorExpr:
				// ЛЮБОЕ обращение к встроенной .Label вне msg.go — вызов,
				// &l.Label, присваивание, передача — обход маски (ревью-1
				// M1, ревью-2 L5). widget.Label (тип) — не обращение;
				// строковые поля .Label чужих структур — закрытый список.
				if x.Sel.Name == "Label" && filepath.Base(name) != "msg.go" {
					if id, ok := x.X.(*ast.Ident); ok && id.Name == "widget" {
						return true
					}
					if !labelFieldAllowed[selectorString(x)] {
						bad(x, "обращение к ."+selectorString(x)+" — встроенная подпись мимо маски msgText")
					}
				}
			case *ast.CompositeLit:
				if s := exprString(x.Type); s == "widget.Label" || s == "canvas.Text" || s == "widget.RichText" {
					bad(x, "литерал "+s+" — подпись мимо msgLabel")
				}
			case *ast.AssignStmt:
				for _, l := range x.Lhs {
					// Текст подписи — только через msgText.SetText (маска в
					// одной точке, ревью-1 M1). Присваивание .Text — обход.
					if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == "Text" && !textAssignHomes[filepath.Base(name)+":"+fn] {
						bad(x, "присваивание .Text мимо msgText.SetText — текст не проходит маску")
					}
				}
				for i, l := range x.Lhs {
					if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == "Selectable" && i < len(x.Rhs) {
						if id, ok := x.Rhs[i].(*ast.Ident); !ok || id.Name != "true" {
							bad(x, "Selectable присваивается не true")
						}
					}
				}
			}
			return true
		})
	}
	return out, nil
}

// labelFieldAllowed — поля с именем Label, которые не подпись: строка
// метки хранилища (core.VaultPayload.Label).
var labelFieldAllowed = map[string]bool{"vc.payload.Label": true}

// selectorString — цепочка a.b.c целиком ("" — не цепочка имён).
func selectorString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		if s := selectorString(x.X); s != "" {
			return s + "." + x.Sel.Name
		}
	}
	return ""
}

func exprString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			return id.Name + "." + x.Sel.Name
		}
	case *ast.StarExpr:
		return exprString(x.X)
	case *ast.Ident:
		return x.Name
	}
	return ""
}

// TestMessagesOnlySelectable — боевой прогон по всем не-тестовым файлам
// cmd/gui плюс канарейки: каждая запрещённая форма обязана быть пойманной.
func TestMessagesOnlySelectable(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	var all []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		v, err := msgViolations(f, src)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, v...)
		checked++
	}
	// Сторож обязан доказать, что читал: main.go и msg.go есть всегда.
	if checked < 2 {
		t.Fatalf("прочитано %d файлов — сторож не выполнялся по существу", checked)
	}
	sort.Strings(all)
	for _, v := range all {
		t.Error(v)
	}

	// Канарейки: заведомые дефекты, на которых сторож обязан споткнуться.
	canaries := map[string]string{
		"NewLabel вне msg.go":    `func f() { _ = widget.NewLabel("x") }`,
		"NewLabelWithStyle":      `func f() { _ = widget.NewLabelWithStyle("x", 0, fyne.TextStyle{}) }`,
		"dialog.ShowInformation": `func f() { dialog.ShowInformation("a", "b", nil) }`,
		"dialog.ShowError":       `func f() { dialog.ShowError(nil, nil) }`,
		"dialog.NewConfirm":      `func f() { _ = dialog.NewConfirm("a", "b", nil, nil) }`,
		"canvas.NewText":         `func f() { _ = canvas.NewText("x", nil) }`,
		"widget.NewRichText":     `func f() { _ = widget.NewRichTextWithText("x") }`,
		"литерал Label":          `func f() { _ = &widget.Label{Text: "x"} }`,
		"Selectable = false":     `func f(l *L) { l.Selectable = false }`,
		"встроенная Label":       `type myLbl struct { widget.Label }`,
		"псевдоним":              "import w \"fyne.io/fyne/v2/widget\"\nfunc f() { _ = w.NewLabel(\"x\") }",
		".Text = мимо маски":     `func f(l *msgText) { l.Text = "vpn://x" }`,
		"&l.Label":               `func f(l *msgText) { p := &l.Label; p.SetText("vpn://x") }`,
		"Bind":                   `func f(l *msgText) { l.Bind(binding.NewString()) }`,
		".Label.SetText":         `func f(l *msgText) { l.Label.SetText("vpn://x") }`,
	}
	for name, body := range canaries {
		src := "package main\n" + body + "\n"
		v, err := msgViolations("canary.go", []byte(src))
		if err != nil {
			t.Fatalf("канарейка %q не разобрана: %v", name, err)
		}
		if len(v) == 0 {
			t.Errorf("канарейка %q не поймана — сторож ослеп", name)
		}
	}
	// И обратная: разрешённое в своём доме не ловится.
	ok := "package main\nfunc msgLabel(s string) { _ = widget.NewLabel(s) }\n"
	if v, _ := msgViolations("msg.go", []byte(ok)); len(v) != 0 {
		t.Errorf("сторож ловит разрешённое: %v", v)
	}
}
