// Файл actionlintversion_test.go — сторож второго списка, живущего в двух
// файлах: версии actionlint.
//
// scripts/dev-tools.sh объявлен ЕДИНЫМ источником версий инструментов, но
// release.yml держит свою строку `actionlint@v1.7.12`, и править release.yml
// запрещено. Пока расхождение ничем не краснеет, оно относится ровно к тому
// классу, ради которого заведён этот пакет: два числа в двух файлах, которые
// однажды разъедутся молча — и на теге будет разбирать workflow один линтер,
// а на PR другой.
//
// ci.yml сюда не попадает намеренно: он версию не хардкодит, а берёт её из
// $ACTIONLINT_VERSION, который кладёт в окружение сам dev-tools.sh. Если в
// ci.yml когда-нибудь появится литеральная версия, сторож увидит и её —
// поиск идёт по обоим workflow-файлам. Все три файла здесь только читаются.
package ciguard

import (
	"os"
	"regexp"
	"testing"
)

const (
	releaseYML  = "../../.github/workflows/release.yml"
	ciYML       = "../../.github/workflows/ci.yml"
	devToolsSH  = "../../scripts/dev-tools.sh"
	actionlintM = "github.com/rhysd/actionlint"
)

// Литеральная версия в вызове `go run github.com/rhysd/actionlint/...@vX.Y.Z`.
// Форма `@${ACTIONLINT_VERSION}` под это выражение не подходит и правильно не
// считается вхождением: там версии нет, там ссылка на единый источник.
var actionlintPinRe = regexp.MustCompile(regexp.QuoteMeta(actionlintM) + `/cmd/actionlint@(v[0-9]+\.[0-9]+\.[0-9]+)`)

// Объявление версии в единственном источнике.
var devToolsVersionRe = regexp.MustCompile(`(?m)^ACTIONLINT_VERSION="(v[0-9]+\.[0-9]+\.[0-9]+)"\s*$`)

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("не прочитать %s: %v", path, err)
	}
	return string(data)
}

func TestActionlintVersionSingleSource(t *testing.T) {
	m := devToolsVersionRe.FindStringSubmatch(readFile(t, devToolsSH))
	if m == nil {
		t.Fatalf("в %s не найдено объявление ACTIONLINT_VERSION=\"vX.Y.Z\" — тест перестал что-либо проверять", devToolsSH)
	}
	want := m[1]

	found := 0
	for _, path := range []string{releaseYML, ciYML} {
		for _, pin := range actionlintPinRe.FindAllStringSubmatch(readFile(t, path), -1) {
			found++
			if pin[1] != want {
				t.Errorf("версия actionlint разошлась: %s требует %s, а scripts/dev-tools.sh объявляет %s.\n"+
					"  На теге и на PR workflow разбирали бы разные линтеры, и ни одна проверка бы этого не показала.",
					path, pin[1], want)
			}
		}
	}

	// Ни одного литерального пина не найдено — значит регулярка перестала
	// попадать в текст (переписали вызов, перенесли строку), и сравнивать
	// больше нечего. Зелёным это быть не имеет права.
	if found == 0 {
		t.Fatalf("ни в %s, ни в %s не найдено ни одного вызова %s/cmd/actionlint@vX.Y.Z — тест перестал что-либо проверять",
			releaseYML, ciYML, actionlintM)
	}
}
