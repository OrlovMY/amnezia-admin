package canary

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// NewSudoKeyMaker — PR4.2: на ТЕСТОВОМ сервере (ключ root) создаётся
// временный пользователь TempUser без root, которому docker доступен только
// через sudo. Пароль случайный и уходит на сервер ТОЛЬКО через stdin
// chpasswd (раунд 2, SEC S2): в тексте команды его нет, в /proc/*/cmdline
// сервера он не виден. Пользователь, существовавший ДО нас, не трогается:
// отказ без удаления. undo удаляет и проверяет, что удалён.
func NewSudoKeyMaker(remoteIn func(cmd string, stdin []byte) (string, error), host, port string, randHex func() (string, error)) func() ([]string, func() error, error) {
	return func() ([]string, func() error, error) {
		out, err := remoteIn(`id `+TempUser+` >/dev/null 2>&1 && echo EXISTS; echo DONE`, nil)
		if err != nil || !strings.Contains(out, "DONE") {
			return nil, nil, fmt.Errorf("не удалось проверить, есть ли %s: %v", TempUser, err)
		}
		if strings.Contains(out, "EXISTS") {
			return nil, nil, fmt.Errorf("пользователь %s уже есть на сервере — не наш, не трогаем; если он от прошлого прогона, удалите вручную: userdel %s", TempUser, TempUser)
		}
		pw, err := randHex()
		if err != nil {
			return nil, nil, err
		}
		undo := func() error {
			out, err := remoteIn(`userdel `+TempUser+` 2>/dev/null; rm -f /etc/sudoers.d/`+TempUser+`; id `+TempUser+
				` >/dev/null 2>&1 && echo STILL; test -e /etc/sudoers.d/`+TempUser+` && echo STILL; echo DONE`, nil)
			if err != nil || !strings.Contains(out, "DONE") || strings.Contains(out, "STILL") {
				return fmt.Errorf("удаление %s не подтверждено: %v %s", TempUser, err, oneLine(out))
			}
			return nil
		}
		create := `useradd -M -s /bin/sh ` + TempUser + ` && chpasswd && d=$(command -v docker) && echo "` + TempUser +
			` ALL=(root) NOPASSWD: $d" > /etc/sudoers.d/` + TempUser + ` && chmod 0440 /etc/sudoers.d/` + TempUser
		if _, err := remoteIn(create, []byte(TempUser+":"+pw+"\n")); err != nil {
			if uerr := undo(); uerr != nil {
				return nil, nil, fmt.Errorf("создание не удалось (%v), и %v", err, uerr)
			}
			return nil, nil, fmt.Errorf("useradd/chpasswd/sudoers: %v", err)
		}
		raw, _ := json.Marshal(map[string]any{"hostName": host, "port": port, "userName": TempUser, "password": pw})
		return []string{"AMNEZIA_KEY=vpn://" + base64.RawURLEncoding.EncodeToString(raw)}, undo, nil
	}
}
