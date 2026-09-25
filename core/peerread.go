package core

// ТРИ СОСТОЯНИЯ ПОКАЗАНИЯ ОДНОГО КЛИЕНТА (CLAUDE.md, «Незнание не выдаётся
// за знание»; задание НЕЗНАНИЕ-ТРАФИК).
//
// Раньше вызывающие брали показание так: `st := stats[cl.ClientID]`. Для
// клиента, которого нет в ответе `wg show wg0 dump`, Go возвращает нулевую
// PeerStat, и она уезжала к человеку измеренным нулём — «0 B / 0 B» и «—»
// (не подключался). Это признак 2 правила: значение по умолчанию вместо
// ответа, причём без всякого ветвления, которое можно было бы найти глазами.
//
// Когда клиента нет в ответе В БОЮ (установлено тестами на fakesrv, см.
// TestPeerAbsentInBattle*):
//   - клиент ОТКЛЮЧЁН: planDisableLocked вырезает его peer из wg0.conf и
//     применяет syncconf — это штатный путь, отсутствует каждый отключённый;
//   - применение изменения не удалось, и откат не вернул рантайм
//     (restore: «файлы восстановлены, но набор активных подключений не
//     совпадает») — запись в clientsTable есть, а сервер клиента не держит;
//   - запись в clientsTable есть, а peer'а в wg0.conf нет (ручная правка,
//     другой клиент управления).
//
// Поэтому форма ответа здесь — тип, а не соглашение: показание нельзя
// прочитать, не узнав, измерено ли оно (Measured возвращает ok), а НУЛЕВОЕ
// значение PeerReading{} означает «не знаем», а не «измерено ноль» — забытое
// поле не превращается в уверенный ноль.

// PeerState — что известно про клиента из ответа `wg show`.
type PeerState int

const (
	// PeerFailed — запрос статистики не удался. Нулевое значение типа
	// НАМЕРЕННО: незаполненное показание — незнание, а не ноль.
	PeerFailed PeerState = iota
	// PeerAbsent — сервер ответил, но этого ключа в ответе нет: работающий
	// wg клиента не держит (подключиться он сейчас не может), а сколько он
	// передал раньше, неизвестно.
	PeerAbsent
	// PeerMeasured — клиент есть в ответе; нулевой трафик здесь — настоящий
	// измеренный ноль.
	PeerMeasured
)

// PeerReading — показание одного клиента. Поле stat закрыто: достать
// числа можно только через Measured, то есть только вместе с ответом на
// вопрос «а измерено ли».
type PeerReading struct {
	State PeerState
	stat  PeerStat
}

// Measured возвращает измеренную статистику и true, если клиент есть в
// ответе сервера; иначе — нулевую PeerStat и false.
func (r PeerReading) Measured() (PeerStat, bool) {
	if r.State != PeerMeasured {
		return PeerStat{}, false
	}
	return r.stat, true
}

// ReadPeer — показание клиента clientID из ответа GetPeerStats. failed —
// запрос не удался (ошибка GetPeerStats); он ПЕРЕВЕШИВАЕТ содержимое stats:
// при отказе карта может быть пустой или частичной (признак 3 — порядок
// ветвей).
func ReadPeer(stats map[string]PeerStat, failed bool, clientID string) PeerReading {
	if failed {
		return PeerReading{State: PeerFailed}
	}
	st, ok := stats[clientID]
	if !ok {
		return PeerReading{State: PeerAbsent}
	}
	return PeerReading{State: PeerMeasured, stat: st}
}
