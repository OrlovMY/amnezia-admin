package ciguard

// Сторож долга 02.10: прогон тестов пакета не пишет в настоящий каталог
// данных пользователя (см. internal/datadirguard).

import (
	"os"
	"testing"

	"amnezia-admin/internal/datadirguard"
)

func TestMain(m *testing.M) { os.Exit(datadirguard.Run(m, nil)) }
