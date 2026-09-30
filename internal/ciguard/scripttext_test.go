// Файл scripttext_test.go — вызовы awk и sed только из закрытого списка
// ТОЧНЫХ ВЫЗОВОВ (долги CI, раунды 5–6; AU-LOGIC Q1, Q2, S1).
//
// Почему. awk и sed — сами интерпретаторы: `print "x" | cmd`, `system()`,
// `sed 1e cmd`, `s/x/y/ge`, `-f файл`, `--expression=`, `--source`
// запускают оболочку или чужой текст мимо лексера. Проверка подстрок
// (раунд 4) и проверка одного текста программы (раунд 5) пропускали формы,
// которых не знали: второй -e, длинные флаги, -fФАЙЛ. Третья форма одного
// класса — меняем устройство: сверяется ВЕСЬ вызов — имя, все флаги и
// тексты, слово в слово, как в файле (сырые слова лексера, через пробел).
// Ключ — sha256 этой последовательности. Новый вызов — видимая строка
// здесь, после ревью человеком. Перенаправления (`<`, `>`) в ключ не входят:
// вход закрыт pipeReaders, выход безвреден.
//
// Немота списка: запись без единого использования — красная; число
// разных вызовов (включая незнакомые) сверяется точно (wantToolCalls).
package ciguard

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// allowedToolCalls — «awk:<sha256>» / «sed:<sha256>» → вызов и зачем.
// Снято с файлов 30.09.2026.
var allowedToolCalls = map[string]string{
	"awk:4398c96d35f3efddefb7b0109d589212ebe80e5d088cb81e1d9b36f6ac12a5e9": "check-history-keys.sh, scan(): awk '<программа поиска тел PEM>' — без system/getline/print |",
	"awk:d81541cf02fc7ebca1947675467a0019a93e7829f937217af96222e2eb1e75a6": "dev-tools.sh: awk '{print $1}' — первое поле sha256sum",
	"awk:83334826ca45cbf2fb5067f87f1dab303034827073f062d55dcdd9c56c7e2bdf": "release.yml ×3: awk -v t=\"$GITHUB_REF_NAME\" '$0 != t' — убрать текущий тег",
	"sed:de5a76014cdd5082791a7e07990b5de51436da9ff9ae1e08c95f6b43de02bbdd": "check-history-keys.sh ×2: sed 's/^/+/' — префикс строк образца",
	"sed:c664450fff2c9640f6a3ec0748d325f264a07a70b27ea84b089bf151f2d1e555": "check-history-keys.sh: sed 's/.\\{20\\}/& /g; s/^/+/' — пробелы в теле образца",
	"sed:d604c36b219cef6077f9f2685a6416a23ba82343d3b7cbb8e352865101996056": "check-history-keys.sh: sed -n 's/^HEADERS //p' — число заголовков",
}

// wantToolCalls — число разных вызовов awk/sed в файлах.
const wantToolCalls = 6

// toolCallKey — ключ вызова: имя программы и sha256 сырых слов через пробел.
func toolCallKey(ws []shWord) string {
	raws := make([]string, len(ws))
	for i, w := range ws {
		raws[i] = w.raw
	}
	h := sha256.Sum256([]byte(strings.Join(raws, " ")))
	return ws[0].lit + ":" + hex.EncodeToString(h[:])
}
