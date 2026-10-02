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
// Ошибка несёт вывод команды (прогон 02.10: «Process exited with status 1»
// без причины не давал понять, что упало); oneLine маскирует ключи.
func (e *Env) legacyWrite(path string, data []byte) error {
	out, err := e.RemoteIn(e.docker+" exec -i "+e.Ctr.Name+" sh -c 'cat > "+path+".tmp && mv "+path+".tmp "+path+"'", data)
	if err != nil {
		if o := tailLine(out); o != "" {
			return fmt.Errorf("%s: %s", oneLine(err.Error()), o)
		}
		return fmt.Errorf("%s (вывода нет)", oneLine(err.Error()))
	}
	return nil
}

// OldRaceStats — итог контроля К4 (прежняя запись без замка).
type OldRaceStats struct {
	Done     int    // записей, о которых прежняя запись сказала «готово»
	Lost     int    // из Done нет на сервере — молчаливая потеря
	Collided int    // записей, упавших на общем .tmp (второй писатель увёл файл)
	Example  string // текст первой такой ошибки
}

// isTmpCollision — прежняя запись упала потому, что общий P.tmp увёл
// второй писатель (его mv прошёл раньше): mv не находит P.tmp. Это гонка
// v0.2.0 ровно так, как её видит человек (ошибка вместо записи). Иная
// ошибка — НЕ гонка: что случилось, неизвестно.
func isTmpCollision(err error) bool {
	s := err.Error()
	return strings.Contains(s, ".tmp") && strings.Contains(s, "mv") && strings.Contains(s, "No such file")
}

// tailLine — вывод команды одной строкой, КОНЕЦ (там сообщение mv/sh), не
// длиннее 200 знаков; ключи замаскированы (oneLine).
func tailLine(s string) string {
	s = strings.Join(strings.Fields(maskKeys(s)), " ")
	if r := []rune(s); len(r) > 200 {
		s = "…" + string(r[len(r)-200:])
	}
	return s
}

// oldWriterRace — итог контроля: сколько записей старого писателя пропало
// молча (нет в таблице или нет peer'а в файле конфигурации) и сколько упало
// на общем .tmp. Прочие ошибки записи — ошибка контроля (НЕ ПРОВЕРЕНО).
func (e *Env) oldWriterRace() (st OldRaceStats, err error) {
	lost, total := 0, 0
	defer func() { st.Lost, st.Done = lost, total }()
	if e.RemoteIn == nil {
		return st, fmt.Errorf("команда со stdin не задана (RemoteIn)")
	}
	tblPath := e.Ctr.Dir + "/clientsTable"
	confBefore, err := e.catFile(e.conf())
	if err != nil {
		return st, fmt.Errorf("%s не прочитан: %w", e.fam.File, err)
	}
	// SEC W-R3 (признак 2): «таблицы нет» — только по явному ответу
	// test -f; иная ошибка чтения — контроль НЕ выполняется (иначе при
	// возврате настоящая таблица заменилась бы пустой).
	tblBefore, existed, terr := e.tableBefore(tblPath)
	if terr != nil {
		return st, terr
	}
	if !existed {
		// Таблицы до контроля не было — возвращается пустая: для программы
		// и для Amnezia пустая и отсутствующая таблица равнозначны (так же
		// поступает откат ядра).
		tblBefore = "[]"
	}
	// SEC W-R4: возврат регистрируется СРАЗУ и в Cleanup — прерывание
	// посреди контроля (Ctrl+C) не оставляет мусорных записей; выполняется
	// один раз.
	var restoreOnce sync.Once
	var restoreErr error
	restore := func() error {
		restoreOnce.Do(func() {
			if rerr := e.legacyWrite(e.conf(), []byte(confBefore)); rerr != nil {
				restoreErr = fmt.Errorf("ВНИМАНИЕ: %s не возвращён после контроля: %w", e.fam.File, rerr)
			}
			if rerr := e.legacyWrite(tblPath, []byte(tblBefore)); rerr != nil && restoreErr == nil {
				restoreErr = fmt.Errorf("ВНИМАНИЕ: clientsTable не возвращена после контроля: %w", rerr)
			}
		})
		return restoreErr
	}
	e.Cleanup(restore)
	defer func() {
		// Возврат файлов — всегда; ошибка — наружу (Fail в race).
		if rerr := restore(); rerr != nil && err == nil {
			err = rerr
		}
	}()

	type rec struct{ name, key string }
	var mu sync.Mutex
	var done []rec
	// Одиночная прежняя запись ДО гонки (файл как есть, без изменений):
	// упала — прежняя запись на этом стенде не работает вовсе, гонка
	// ничего не скажет.
	if perr := e.legacyWrite(e.conf(), []byte(confBefore)); perr != nil {
		return st, fmt.Errorf("прежняя запись не выполнилась даже без гонки: %w", perr)
	}
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
				switch {
				case kerr != nil && isTmpCollision(kerr):
					st.Collided++
					if st.Example == "" {
						st.Example = kerr.Error()
					}
				case kerr != nil && firstErr == nil:
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
	total = len(done)
	if firstErr != nil {
		return st, fmt.Errorf("прежняя запись не выполнилась: %w", firstErr)
	}
	conf, err := e.catFile(e.conf())
	if err != nil {
		return st, fmt.Errorf("%s после контроля не прочитан: %w", e.fam.File, err)
	}
	tbl, err := e.catFile(tblPath)
	if err != nil {
		return st, fmt.Errorf("clientsTable после контроля не прочитана: %w", err)
	}
	for _, r := range done {
		if !strings.Contains(conf, "PublicKey = "+r.key) || !strings.Contains(tbl, `"`+r.name+`"`) {
			lost++
		}
	}
	return st, nil
}

// tableBefore — clientsTable до контроля: (текст, true) — есть; ("", false) —
// test -f ответил «no»; ошибка — всё прочее (ответ не yes/no, cat не
// выполнился): что с таблицей, неизвестно.
func (e *Env) tableBefore(tblPath string) (string, bool, error) {
	out, err := e.Remote(e.docker + " exec " + e.Ctr.Name + " sh -c 'test -f " + tblPath + " && echo yes || echo no'")
	switch {
	case err != nil:
		return "", false, fmt.Errorf("наличие clientsTable не выяснено (%v) — контроль не выполнялся", err)
	case strings.TrimSpace(out) == "no":
		return "", false, nil
	case strings.TrimSpace(out) != "yes":
		return "", false, fmt.Errorf("наличие clientsTable не выяснено (ответ %q) — контроль не выполнялся", oneLine(out))
	}
	tbl, err := e.catFile(tblPath)
	if err != nil {
		return "", false, fmt.Errorf("clientsTable есть, но не прочитана (%v) — контроль не выполнялся", err)
	}
	return tbl, true, nil
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
