package canary

// К4, контроль (PR-W1, проект Р3-4): роль старой версии играет сама
// канарейка — прежней командой записи без замка, как v0.2.0:
// `docker exec -i C sh -c 'cat > P.tmp && mv P.tmp P'`, отдельно для файла
// конфигурации и для clientsTable, без сверки сумм. Два писателя по
// RaceRounds записей: прочитать оба файла, дописать peer и запись таблицы,
// записать. Затем — сколько записей пропало. Файлы ВОЗВРАЩАЮТСЯ к
// состоянию до контроля той же прежней командой: старый писатель не
// применял изменения к работающему серверу, так что прежние файлы и
// работающий сервер снова согласованы.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// catFile — содержимое файла в контейнере (`docker exec C cat P`).
func (e *Env) catFile(path string) (string, error) {
	return e.Remote(e.docker + " exec " + e.Ctr.Name + " cat " + path)
}

// legacyWrite — прежняя запись v0.2.0: без замка, без сверки, общий .tmp.
func (e *Env) legacyWrite(path string, data []byte) error {
	_, err := e.RemoteIn(e.docker+" exec -i "+e.Ctr.Name+" sh -c 'cat > "+path+".tmp && mv "+path+".tmp "+path+"'", data)
	return err
}

// oldWriterRace — lost: сколько из total записей старого писателя пропало
// (нет в таблице или нет peer'а в файле конфигурации).
func (e *Env) oldWriterRace() (lost, total int, err error) {
	if e.RemoteIn == nil {
		return 0, 0, fmt.Errorf("команда со stdin не задана (RemoteIn)")
	}
	tblPath := e.Ctr.Dir + "/clientsTable"
	confBefore, err := e.catFile(e.conf())
	if err != nil {
		return 0, 0, fmt.Errorf("%s не прочитан: %w", e.fam.File, err)
	}
	tblBefore, tblErr := e.catFile(tblPath)
	tblExisted := tblErr == nil
	defer func() {
		// Возврат файлов — всегда; ошибка — наружу (Fail в race).
		if rerr := e.legacyWrite(e.conf(), []byte(confBefore)); rerr != nil && err == nil {
			err = fmt.Errorf("ВНИМАНИЕ: %s не возвращён после контроля: %w", e.fam.File, rerr)
		}
		// Таблицы до контроля не было — возвращается пустая: для программы
		// и для Amnezia пустая и отсутствующая таблица равнозначны (так же
		// поступает откат ядра).
		if !tblExisted {
			tblBefore = "[]"
		}
		if rerr := e.legacyWrite(tblPath, []byte(tblBefore)); rerr != nil && err == nil {
			err = fmt.Errorf("ВНИМАНИЕ: clientsTable не возвращена после контроля: %w", rerr)
		}
	}()

	type rec struct{ name, key string }
	var mu sync.Mutex
	var done []rec
	var firstErr error
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < e.RaceRounds; i++ {
				name := fmt.Sprintf("canary-o-%d-%02d", w, i)
				key, kerr := randKey()
				if kerr == nil {
					kerr = e.oldAdd(tblPath, name, key, 100+w*e.RaceRounds+i)
				}
				mu.Lock()
				if kerr != nil && firstErr == nil {
					firstErr = kerr
				}
				if kerr == nil {
					done = append(done, rec{name, key})
				}
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	if firstErr != nil {
		return 0, len(done), fmt.Errorf("прежняя запись не выполнилась: %w", firstErr)
	}
	conf, err := e.catFile(e.conf())
	if err != nil {
		return 0, len(done), fmt.Errorf("%s после контроля не прочитан: %w", e.fam.File, err)
	}
	tbl, err := e.catFile(tblPath)
	if err != nil {
		return 0, len(done), fmt.Errorf("clientsTable после контроля не прочитана: %w", err)
	}
	for _, r := range done {
		if !strings.Contains(conf, "PublicKey = "+r.key) || !strings.Contains(tbl, `"`+r.name+`"`) {
			lost++
		}
	}
	return lost, len(done), nil
}

// oldAdd — одна запись «старой версии»: прочитать, дописать, записать
// вслепую (оба файла по отдельности, без сверки и без замка).
func (e *Env) oldAdd(tblPath, name, key string, n int) error {
	conf, err := e.catFile(e.conf())
	if err != nil {
		return err
	}
	var tbl []map[string]any
	if raw, err := e.catFile(tblPath); err == nil && strings.TrimSpace(raw) != "" {
		if err := json.Unmarshal([]byte(raw), &tbl); err != nil {
			return fmt.Errorf("clientsTable не разобрана: %w", err)
		}
	}
	conf = strings.TrimRight(conf, "\n") + fmt.Sprintf("\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.250.%d.%d/32\n", key, n/250, n%250+1)
	tbl = append(tbl, map[string]any{"clientId": key, "userData": map[string]any{
		"clientName": name, "creationDate": time.Now().Format(time.RFC1123)}})
	out, err := json.MarshalIndent(tbl, "", "    ")
	if err != nil {
		return err
	}
	if err := e.legacyWrite(e.conf(), []byte(conf)); err != nil {
		return err
	}
	return e.legacyWrite(tblPath, out)
}

func randKey() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b[:]), nil
}
