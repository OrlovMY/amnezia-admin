package main

// ПОДСКАЗКА ПРО РАСКЛАДКУ ПРИ ВВОДЕ ПИНА И КЛЮЧА.
//
// ЗАЧЕМ. Просьба владельца 23.09.2026: переключать раскладку на английскую
// при вводе паролей и пин-кодов. Само переключение — системный вызов
// Windows, и проверить его действие можно только в живой сессии владельца
// (см. internal/kbdlayout). А вот СТРАХОВКА, которая работает на всех ОС и
// не зависит от успеха переключения, проверяется здесь боевым путём: текст
// кладётся в настоящее поле ввода диалога, и спрашивается, что после этого
// видно на экране.
//
// СЕКРЕТЫ. Ни один тест ниже не печатает введённого и требует того же от
// программы: подсказка говорит только о ФАКТЕ, сами символы на экран не
// попадают. Это отдельная проверка, а не оговорка в комментарии.
//
// Дословный текст подсказки НАБРАН ЗДЕСЬ РУКАМИ: возьми его из guiview —
// и переименование константы переименовало бы заодно и ожидание.

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

const (
	wantPinLayoutHint = "Похоже, включена не английская раскладка: пин-код принимает только латинские буквы, цифры и знаки препинания."
	wantKeyLayoutHint = "Похоже, включена не английская раскладка: админский ключ состоит только из латинских букв, цифр и знаков препинания."
)

// typedCyrillicPin — то, что получится, если набирать пин, не заметив
// русской раскладки. Набор намеренно бессмысленный: осмысленное слово
// совпало бы буквами с русскими подписями самого диалога, и проверка на
// утечку ловила бы не утечку. В сообщениях тестов он не печатается: это
// пароль.
const typedCyrillicPin = "йцукенгшщзХЪ1"

// typedLatinPin — верный ввод той же длины.
const typedLatinPin = "Abcdefgh1234!"

// visibleTexts собирает тексты ВИДИМЫХ подписей на экране (или в диалоге).
func visibleTexts(root fyne.CanvasObject) []string {
	var out []string
	walkObjects(root, func(o fyne.CanvasObject) {
		if !o.Visible() {
			return
		}
		if l, ok := o.(*widget.Label); ok {
			out = append(out, l.Text)
		}
	})
	return out
}

func hasText(texts []string, want string) bool {
	for _, s := range texts {
		if s == want {
			return true
		}
	}
	return false
}

// passwordEntry — n-е по порядку обхода поле пароля.
func passwordEntry(t *testing.T, root fyne.CanvasObject, n int) *widget.Entry {
	t.Helper()
	var found []*widget.Entry
	walkObjects(root, func(o fyne.CanvasObject) {
		if e, ok := o.(*widget.Entry); ok && e.Password {
			found = append(found, e)
		}
	})
	if len(found) <= n {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: полей пароля на экране %d, нужно хотя бы %d",
			len(found), n+1)
	}
	return found[n]
}

// noEnteredCharsOnScreen — введённое НЕ ПОКАЗАНО.
//
// Сверяется, что ни один КУСОК введённого длиной в 4 знака не виден на
// экране целиком.
//
// ПОЧЕМУ НЕ ПОСИМВОЛЬНО — И ЭТО ГРАНИЦА ПРОВЕРКИ, А НЕ НЕДОСМОТР. Весь
// интерфейс написан по-русски: подписи «Повтор пина», «Привязать к этой
// учётке Windows» содержат те же буквы, что и пин, набранный в русской
// раскладке. Требование «ни одной общей буквы» краснело бы всегда и было бы
// ослаблено первым же действием. Четыре знака подряд — это уже не совпадение
// букв, а показанный кусок секрета.
func noEnteredCharsOnScreen(t *testing.T, texts []string, entered string) {
	t.Helper()
	runes := []rune(entered)
	for _, s := range texts {
		if s == "" {
			continue
		}
		for i := 0; i+4 <= len(runes); i++ {
			if strings.Contains(s, string(runes[i:i+4])) {
				t.Errorf("на экране видна подпись, содержащая кусок введённого секрета " +
					"длиной 4 знака — секрет утёк в текст")
				return
			}
		}
	}
}

// TestSaveKeyDialogHintsAboutLayout — ПЕРВОЕ задание пина («как при первом
// вводе их»): человек набирает пин в русской раскладке, символы скрыты
// звёздочками, и без подсказки он узнает о беде только отказом «недопустимые
// символы» после нажатия «Сохранить».
func TestSaveKeyDialogHintsAboutLayout(t *testing.T) {
	u := focusTestUI(t)
	u.offerSaveKey("vpn://не-настоящий", "Сервер 1", "")
	over := u.win.Canvas().Overlays().List()
	if len(over) == 0 {
		t.Fatal("диалог сохранения ключа не открылся")
	}
	d := over[len(over)-1]

	pin := passwordEntry(t, d, 0)
	pin.SetText(typedCyrillicPin)

	texts := visibleTexts(d)
	if !hasText(texts, wantPinLayoutHint) {
		t.Errorf("в диалоге «Сохранить ключ?» набран пин не в английской раскладке, "+
			"а подсказки про раскладку на экране нет. Видно: %q", texts)
	}
	noEnteredCharsOnScreen(t, texts, typedCyrillicPin)
}

// TestSaveKeyDialogNoHintForLatinPin — СОСЕДНЯЯ ПРИЧИНА: на верном вводе
// подсказки быть не должно. Подсказка, срабатывающая на правильном пине,
// хуже её отсутствия.
func TestSaveKeyDialogNoHintForLatinPin(t *testing.T) {
	u := focusTestUI(t)
	u.offerSaveKey("vpn://не-настоящий", "Сервер 1", "")
	d := u.win.Canvas().Overlays().List()[0]

	pin := passwordEntry(t, d, 0)
	pin.SetText(typedLatinPin)

	if texts := visibleTexts(d); hasText(texts, wantPinLayoutHint) {
		t.Errorf("подсказка про раскладку показана на пине из одной латиницы с цифрами: %q", texts)
	}
}

// TestSaveKeyDialogHintFollowsRepeatField — второе поле («Повтор пина») тоже
// под присмотром: перепутать раскладку на нём так же легко.
func TestSaveKeyDialogHintFollowsRepeatField(t *testing.T) {
	u := focusTestUI(t)
	u.offerSaveKey("vpn://не-настоящий", "Сервер 1", "")
	d := u.win.Canvas().Overlays().List()[0]

	passwordEntry(t, d, 0).SetText(typedLatinPin)
	passwordEntry(t, d, 1).SetText(typedCyrillicPin)

	if texts := visibleTexts(d); !hasText(texts, wantPinLayoutHint) {
		t.Errorf("в поле «Повтор пина» набрано не в английской раскладке, подсказки нет: %q", texts)
	}
}

// TestPinDialogHintsAboutLayout — СЛУЧАЙ ВЛАДЕЛЬЦА ЦЕЛИКОМ («как при первом
// вводе их, так и потом для авторизации»): открытие сохранённого ключа.
// Здесь отказ особенно дорог — неверный пин тратит одну из десяти попыток до
// блокировки на пять минут.
func TestPinDialogHintsAboutLayout(t *testing.T) {
	// В сеть тест не ходит: пул хостов времени подменён на закрытый порт.
	savedHosts := core.NetworkTimeHosts
	core.NetworkTimeHosts = []string{"https://127.0.0.1:1"}
	t.Cleanup(func() { core.NetworkTimeHosts = savedHosts })

	u := focusTestUI(t)
	t.Cleanup(func() { waitGUIGoroutines(t) })
	u.showVaultPinDialog(t.TempDir()+"/нет.avlt", "Сервер 1", widget.NewButton("", nil), widget.NewLabel(""))
	over := u.win.Canvas().Overlays().List()
	if len(over) == 0 {
		t.Fatal("диалог пин-кода не открылся")
	}
	waitGUIGoroutines(t) // фоновый запрос онлайн-времени завершён
	d := over[len(over)-1]

	passwordEntry(t, d, 0).SetText(typedCyrillicPin)

	texts := visibleTexts(d)
	if !hasText(texts, wantPinLayoutHint) {
		t.Errorf("в диалоге «Введите пин-код» набрано не в английской раскладке, "+
			"подсказки нет. Видно: %q", texts)
	}
	noEnteredCharsOnScreen(t, texts, typedCyrillicPin)
}

// TestConnectScreenHintsAboutLayout — поле админского ключа: там тоже только
// латиница, цифры и знаки препинания.
func TestConnectScreenHintsAboutLayout(t *testing.T) {
	u := focusTestUI(t)
	u.showConnectScreen("")
	content := u.win.Canvas().Content()

	key := firstEntry(content)
	if key == nil {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: на экране подключения нет поля ввода")
	}
	key.SetText("vpn://кириллицаВКлюче")

	texts := visibleTexts(content)
	if !hasText(texts, wantKeyLayoutHint) {
		t.Errorf("в поле админского ключа символы не из английской раскладки, "+
			"подсказки нет. Видно: %q", texts)
	}
}

// TestConnectScreenNoHintForLatinKey — соседняя причина: настоящий ключ
// подсказки не вызывает.
func TestConnectScreenNoHintForLatinKey(t *testing.T) {
	u := focusTestUI(t)
	u.showConnectScreen("")
	content := u.win.Canvas().Content()

	key := firstEntry(content)
	key.SetText("vpn://" + testKey)

	if texts := visibleTexts(content); hasText(texts, wantKeyLayoutHint) {
		t.Errorf("подсказка про раскладку показана на обычном ключе vpn://…: %q", texts)
	}
}
