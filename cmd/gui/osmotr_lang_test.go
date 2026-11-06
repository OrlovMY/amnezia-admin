package main

// ПРИБОР НЕ ЗАВИСИТ ОТ ЯЗЫКА СИСТЕМЫ (PR #21: CI красный на трёх ОС).
//
// Стандартные диалоги Fyne (dialog.ShowError, dialog.ShowInformation) сами
// ставят кнопку «OK» и заголовок «Error» — через пакет lang, по языку
// системы. У владельца русская Windows: «ОК», «Ошибка»; на раннерах CI
// локаль C: «OK», «Error». Опись, снятая на русской системе, запомнила
// русские слова и краснела в CI.
//
// ПОЧЕМУ НЕ ЗАФИКСИРОВАТЬ ЯЗЫК (вариант А) — проверено по исходнику
// fyne.io/fyne/v2@v2.7.4/lang/lang.go: язык выбирается в init() пакета lang
// (AddTranslationsFS → updateLocalizer → go-locale GetLocales), то есть ДО
// любого кода теста, и t.Setenv("LANG") после этого ничего не даёт. На
// Windows go-locale спрашивает систему (GetUserDefaultLocaleName), переменные
// окружения не читает вовсе. Публичного способа выбрать язык нет
// (setupLang — неэкспортированный). Надёжно зафиксировать язык нельзя.
//
// ПОЭТОМУ ВАРИАНТ Б: слова, которые ставит САМА Fyne, сверяются не буквально,
// а по роли — «кнопка стандартного диалога Fyne», «заголовок стандартного
// диалога Fyne». Роль узнаётся по совпадению с ТЕКУЩИМ переводом Fyne
// (lang.L), а не по списку языков: на любом языке системы это то слово,
// которое Fyne сейчас поставит. Наш собственный текст в этих диалогах
// сверяется буквально, как везде.

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/lang"
)

const (
	fyneRoleOK    = "<кнопка стандартного диалога Fyne: OK>"
	fyneRoleError = "<заголовок стандартного диалога Fyne: Error>"
)

// osmotrFyneWordsEnv — «язык системы» для доказательства: в дочернем
// процессе все переводы Fyne подменяются чужими словами (osmotrForeignWords).
const osmotrFyneWordsEnv = "OSMOTR_FYNE_WORDS"

// osmotrLiteralEnv — только для канарейки: роль НЕ применяется, опись
// сверяется буквально, как до починки.
const osmotrLiteralEnv = "OSMOTR_FYNE_LITERAL"

// fyneRoles — заменяет в найденном слова Fyne их ролью. Только для форм со
// стандартными диалогами (osmotrForm.fyneStd).
func fyneRoles(rep *osmotrReport) {
	if os.Getenv(osmotrLiteralEnv) != "" {
		return
	}
	ok, errTitle := lang.L("OK"), lang.L("Error")
	for i, a := range rep.atoms {
		switch {
		case a.kind == "кнопка" && a.name == ok:
			rep.atoms[i].name = fyneRoleOK
		case a.kind == "подпись" && a.name == errTitle:
			rep.atoms[i].name = fyneRoleError
		}
	}
}

// fyneRolesInPairs — в разрешённых перекрытиях роль заменяется ТЕКУЩИМ
// словом Fyne: перекрытия меряются по настоящим именам, до fyneRoles.
func fyneRolesInPairs(pairs []string) []string {
	r := strings.NewReplacer(fyneRoleOK, lang.L("OK"), fyneRoleError, lang.L("Error"))
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = r.Replace(p)
	}
	return out
}

// osmotrForeignWords — слова, которых нет ни в одном языке Fyne: если прибор
// зелёный с ними, он зелёный на ЛЮБОМ языке системы, включая английский.
var osmotrForeignWords = map[string]string{
	"en": `{"OK": "OK", "Error": "Error"}`,
	"xx": `{"OK": "Okidoki", "Error": "Errare"}`,
}

// applyForeignFyneWords — в дочернем процессе подменяет переводы Fyne для
// ВСЕХ её языков (какой бы язык ни выбрала система), затем lang сама
// перевыбирает язык (updateLocalizer внутри AddTranslationsForLocale).
func applyForeignFyneWords() {
	words, ok := osmotrForeignWords[os.Getenv(osmotrFyneWordsEnv)]
	if !ok {
		return
	}
	for _, l := range []string{"en", "cs", "de", "el", "es", "fr", "ja", "pl", "pt", "pt-BR", "ru", "sv", "ta", "uk", "zh-Hans"} {
		if err := lang.AddTranslationsForLocale([]byte(words), fyne.Locale(l)); err != nil {
			panic(err)
		}
	}
}

// TestOsmotrFyneWordsAnyLanguage — ДОКАЗАТЕЛЬСТВО без английской Windows:
// настоящий TestOsmotrForms, формы «(ж)», в дочернем процессе с чужими
// словами Fyne — английскими («OK», «Error», как на раннерах CI) и
// несуществующими («Okidoki», «Errare»).
//
// С 06.11.2026 (сообщения выделяемые, msg.go) стандартных диалогов Fyne в
// программе нет — сторож TestMessagesOnlySelectable запрещает
// dialog.ShowInformation/ShowError. Доказательство теперь обратное
// прежнему: формы «(ж)» зелёные при ЛЮБЫХ словах Fyne и в буквальной описи
// (без роли). Канарейка — что подмена слов доехала до дочернего процесса:
// TestOsmotrFyneWordsProbe печатает там lang.L("OK"), и это обязано быть
// чужое слово; без неё «зелёный при чужих словах» мог бы значить «подмена
// не сработала».
func TestOsmotrFyneWordsAnyLanguage(t *testing.T) {
	if os.Getenv(osmotrFyneWordsEnv) != "" || os.Getenv(osmotrPlantEnv) != "" {
		t.Skip("дочерний процесс")
	}
	run := func(words string, literal bool) (string, error) {
		re := "^(" + regexp.QuoteMeta("TestOsmotrForms") + "|TestOsmotrFyneWordsProbe)$/^" + regexp.QuoteMeta("(ж)")
		cmd := exec.Command(os.Args[0], "-test.run", re, "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), osmotrFyneWordsEnv+"="+words)
		if literal {
			cmd.Env = append(cmd.Env, osmotrLiteralEnv+"=1")
		}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	for _, tc := range []struct{ words, ok, errTitle string }{
		{"en", "OK", "Error"}, {"xx", "Okidoki", "Errare"},
	} {
		for _, literal := range []bool{false, true} {
			out, err := run(tc.words, literal)
			passes := strings.Count(out, "--- PASS: TestOsmotrForms/(ж)")
			t.Logf("язык Fyne %q, буквально=%v: err=%v, подтестов (ж) PASS: %d", tc.words, literal, err, passes)
			if err != nil || passes != 8 {
				t.Errorf("прибор НЕ зелёный при словах Fyne %q/%q, буквально=%v (err=%v, PASS %d из 8):\n%s", tc.ok, tc.errTitle, literal, err, passes, out)
			}
			if !strings.Contains(out, osmotrProbeMark+tc.ok) {
				t.Errorf("подмена слов Fyne %q не доехала до дочернего процесса — доказательство ничего не значит:\n%s", tc.ok, out)
			}
		}
	}
}

const osmotrProbeMark = "слово Fyne «OK» здесь: "

// TestOsmotrFyneWordsProbe — только в дочернем процессе: печатает текущее
// слово Fyne «OK» после подмены (канарейка доезда подмены).
func TestOsmotrFyneWordsProbe(t *testing.T) {
	if os.Getenv(osmotrFyneWordsEnv) == "" {
		t.Skip("только в дочернем процессе")
	}
	applyForeignFyneWords()
	t.Log(osmotrProbeMark + lang.L("OK"))
}
