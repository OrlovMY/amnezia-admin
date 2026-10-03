package core

import (
	"errors"
	"testing"
)

// TestPR3NotMovedIsNotBeforeWrite — A3б PR-3 (SEC F1 при выводе причины mv):
// строка «not moved: …» значит, что скрипт дошёл до mv, то есть запись
// начата; повтор под sudo недопустим, даже если в причине случайно окажутся
// и «Permission denied», и «docker.sock» (путь каталога — наши данные, но
// проверка не должна на это полагаться). Различение: настоящий отказ docker
// в доступе к сокету — «до записи».
func TestPR3NotMovedIsNotBeforeWrite(t *testing.T) {
	before := errors.New("stderr: permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock")
	after := errors.New("stderr: not moved: clientsTable: mv: cannot move to /srv/docker.sock/clientsTable: Permission denied")
	if !casDeniedBeforeWrite(before) {
		t.Error("отказ docker в доступе к сокету не распознан как «до записи»")
	}
	if casDeniedBeforeWrite(after) {
		t.Error("отказ mv после начатой записи распознан как «до записи» — был бы повтор под sudo")
	}
}
