// Файл scripttext_test.go — программы awk и sed только из закрытого списка
// ТОЧНЫХ текстов (долги CI, раунд 5; AU-LOGIC Q1, Q2).
//
// Почему. awk и sed — сами интерпретаторы: `print "x" | cmd`, `system()`,
// `sed 1e cmd`, `s/x/y/ge` запускают оболочку мимо лексера. Проверка по
// подстрокам (раунд 4) пропускала формы, которых не перечисляла. Поэтому
// текст программы (первый операнд или значение -e) сверяется целиком: его
// sha256 обязан быть в allowedScriptTexts. Новый текст — видимая строка
// здесь, после ревью человеком. Подстановка в тексте — красная.
//
// Немота списка: запись без единого использования — красная; число
// разных текстов сверяется точно (wantScriptTexts).
package ciguard

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// allowedScriptTexts — «awk:<sha256>» / «sed:<sha256>» → откуда и зачем.
// Снято с файлов 30.09.2026.
var allowedScriptTexts = map[string]string{
	"awk:73c19bad099dfbbe57fc321bb7314e3c5affa10c4cbbea5cdc19011bc132459e": "check-history-keys.sh, scan(): поиск тел ключей PEM; без system/getline/print |",
	"awk:37c22fcc5700df9ded0292d151ebebb28990fdf3a05ae7bcb92d4deb800f315e": "dev-tools.sh: '{print $1}' — первое поле sha256sum",
	"awk:e660d2d7c0387805d3d86f7c8b70c1bdb656de872de692cc34b871e457ab5644": "release.yml ×3: '$0 != t' — убрать текущий тег из списка",
	"sed:b67d8931eb2f3ba244742690d5541e2e162845c4e9250b3e96ce196769d6a533": "check-history-keys.sh: 's/^/+/' — префикс строк образца",
	"sed:d8f09b2a6c529cde458f6a8ebac925422ec4f00e3e19510c60277a5c22f7a1b5": "check-history-keys.sh: 's/.\\{20\\}/& /g; s/^/+/' — пробелы в теле образца",
	"sed:7e74e1717f0817b9fb7ccd9355646e7ceca56793e16a23f9fbcfa17711b00ce2": "check-history-keys.sh: 's/^HEADERS //p' — число заголовков",
}

// wantScriptTexts — число разных текстов awk/sed в файлах.
const wantScriptTexts = 6

// scriptText — текст программы awk/sed из аргументов; ok=false, если его
// нет или он с подстановкой.
func scriptText(prog string, args []shWord) (text string, problem string) {
	valFlags := map[string]bool{}
	if prog == "awk" {
		valFlags["-v"], valFlags["-F"] = true, true
	}
	for k := 0; k < len(args); k++ {
		a := args[k]
		switch {
		case !a.quoted && valFlags[a.lit]:
			k++
		case !a.quoted && a.lit == "-e" && prog == "sed":
			if k+1 < len(args) {
				return textOf(args[k+1])
			}
			return "", "у -e нет текста"
		case !a.quoted && strings.HasPrefix(a.lit, "-") && a.lit != "-":
		default:
			return textOf(a)
		}
	}
	return "", "нет текста программы"
}

func textOf(w shWord) (string, string) {
	if w.dyn {
		return "", "текст программы с подстановкой — содержимое неизвестно"
	}
	return w.lit, ""
}

func scriptKey(prog, text string) string {
	h := sha256.Sum256([]byte(text))
	return prog + ":" + hex.EncodeToString(h[:])
}
