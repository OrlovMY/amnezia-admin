package core

// Семейство WG (PR-W1, проект БК-ПРОТОКОЛЫ-AWG2-XRAY, Р3-3): контейнеры,
// которыми программа управляет одним и тем же способом — файл конфигурации
// сервера, clientsTable, утилита wg/awg и интерфейс. Одна таблица и одна
// развилка по ней; общего интерфейса драйвера до релиза нет (решение ядра).
//
// Всё, что попадает в серверные команды (имя файла, утилита, интерфейс),
// берётся ТОЛЬКО отсюда — извне ничего не подставляется.

import (
	"fmt"
	"path"
)

// WGFamily — строка таблицы семейства WG.
type WGFamily struct {
	Container string // имя контейнера Docker
	Dir       string // каталог данных в контейнере
	File      string // файл конфигурации сервера в Dir
	Tool      string // wg | awg
	Iface     string // wg0 | awg0
}

// wgFamilies — ЗАКРЫТЫЙ список. amnezia-awg2 — и AWG2, и AWG3: тот же образ,
// тот же /opt/amnezia/awg/awg0.conf, утилиты awg/awg-quick, интерфейс awg0
// (исходники amnezia-client dev 94b51df, awg/Dockerfile, configure_container.sh).
var wgFamilies = []WGFamily{
	{"amnezia-awg", "/opt/amnezia/awg", "wg0.conf", "wg", "wg0"},
	{"amnezia-wireguard", "/opt/amnezia/wireguard", "wg0.conf", "wg", "wg0"},
	{"amnezia-awg2", "/opt/amnezia/awg", "awg0.conf", "awg", "awg0"},
}

// casConfFiles — закрытый список имён файла конфигурации, которые
// принимает команда записи (аргумент $4 CASWriteScript).
var casConfFiles = map[string]bool{"wg0.conf": true, "awg0.conf": true}

// WGFamilyOf — строка таблицы для контейнера c. Контейнер вне таблицы —
// ошибка: его файл, утилита и интерфейс неизвестны, и угадывать их нельзя.
func WGFamilyOf(c *Container) (WGFamily, error) {
	if c == nil {
		return WGFamily{}, fmt.Errorf("контейнер не задан")
	}
	for _, f := range wgFamilies {
		if f.Container == c.Name {
			// W1, ревью SEC W-R1: каталог берётся из knownContainers (c.Dir), а
			// файл — отсюда. Две таблицы обязаны совпадать: расхождение — отказ,
			// а не запись «в чужой каталог».
			if c.Dir != f.Dir {
				return WGFamily{}, fmt.Errorf("контейнер %s: каталог %q расходится с таблицей семейства WG (%s) — команды не выполняются", c.Name, c.Dir, f.Dir)
			}
			return f, nil
		}
	}
	return WGFamily{}, fmt.Errorf("контейнер %s — не семейство WireGuard/AmneziaWG: файл конфигурации, утилита и интерфейс неизвестны", c.Name)
}

// WGFamilies — копия таблицы (канарейка обходит контейнеры семейства).
func WGFamilies() []WGFamily {
	return append([]WGFamily(nil), wgFamilies...)
}

// confPath — путь к файлу конфигурации сервера контейнера c.
func confPath(c *Container) (string, error) {
	f, err := WGFamilyOf(c)
	if err != nil {
		return "", err
	}
	return path.Join(c.Dir, f.File), nil
}

// catConf — содержимое файла конфигурации сервера.
func (s *Session) catConf(c *Container) (string, error) {
	p, err := confPath(c)
	if err != nil {
		return "", err
	}
	return s.catIn(c, p)
}
