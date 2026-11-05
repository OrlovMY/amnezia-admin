package core

// Маркер незавершённой установки/переноса на новый сервер (аудит AU
// GUI-TO-HOST M1). Пишется ДО первой записи на цель, обновляется по шагам и
// удаляется только при ИЗМЕРЕННОМ итоге (перенесено / не перенесено с
// известным состоянием). Если программу закрыли, ПК уснул или связь
// оборвалась — при следующем запуске (GUI, любая команда migrate CLI)
// человек видит, что итог прошлой установки неизвестен. Секретов в маркере
// нет: адрес, время, шаг, что поставлено.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// OpMarker — след незавершённой операции.
type OpMarker struct {
	Target    string    `json:"target"`    // адрес нового сервера
	Started   time.Time `json:"started"`   // начало установки
	Step      string    `json:"step"`      // последний начатый шаг
	Installed []string  `json:"installed"` // контейнеры плана / поставленные
	Tool      string    `json:"tool"`      // версия программы
}

// OpMarkerPath — путь маркера (шов теста): рядом с «Конфигурации».
var OpMarkerPath = func() (string, error) {
	d, err := UserConfigsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(d), "незавершённый-перенос.json"), nil
}

// WriteOpMarker — записать/обновить маркер (через временный файл, 0600).
func WriteOpMarker(m OpMarker) error {
	p, err := OpMarkerPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ReadOpMarker — маркер; (nil, nil) — маркера нет. Ошибка — маркер есть, но
// не прочитан: это «не знаем», а не «нет маркера».
func ReadOpMarker() (*OpMarker, error) {
	p, err := OpMarkerPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("маркер незавершённой операции %s не прочитан: %w", p, err)
	}
	var m OpMarker
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("маркер незавершённой операции %s повреждён: %w", p, err)
	}
	return &m, nil
}

// ClearOpMarker — удалить маркер (отсутствие — не ошибка).
func ClearOpMarker() error {
	p, err := OpMarkerPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Text — сообщение человеку.
func (m OpMarker) Text() string {
	inst := "—"
	if len(m.Installed) > 0 {
		inst = strings.Join(m.Installed, ", ")
	}
	return fmt.Sprintf("Прошлая установка Amnezia на %s не завершена (шаг «%s», начата %s, программа %s): итог неизвестен — программа была закрыта, ПК уснул или оборвалась связь до итога. "+
		"Контейнеры плана: %s. Проверьте новый сервер вручную (docker ps -a): что поставлено, перенесены ли клиенты. Если контейнеры есть, а клиентов нет — удалите их (docker rm -f …) и повторите перенос на чистый сервер, "+
		"или возьмите ключ «полный доступ» в приложении Amnezia и продолжите режимом «ключ vpn://».",
		m.Target, m.Step, m.Started.Local().Format("02.01.2006 15:04"), m.Tool, inst)
}
