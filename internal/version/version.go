// Package version хранит номер версии и коммит, вшиваемые в бинарь через
// -ldflags -X при сборке (решение ядра: версия = git-тег, второй источник
// номера в код не заводим). Без -ldflags — значения по умолчанию ("dev"/
// "unknown"), README (раздел "Сборка") описывает точную команду.
package version

var (
	// Version — версия сборки, например "v1.2.3". Задаётся флагом:
	//   -X amnezia-admin/internal/version.Version=v1.2.3
	Version = "dev"
	// Commit — SHA коммита сборки. Задаётся флагом:
	//   -X amnezia-admin/internal/version.Commit=<sha>
	Commit = "unknown"
)

// String возвращает строку версии в единственной принятой форме (П19):
// "<Version, а если пусто — "dev"> (<первые 7 символов Commit, если
// len(Commit) >= 7, иначе Commit целиком>)".
func String() string {
	v := Version
	if v == "" {
		v = "dev"
	}
	c := Commit
	if len(c) >= 7 {
		c = c[:7]
	}
	return v + " (" + c + ")"
}
