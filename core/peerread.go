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

// ---------- «Последнее подключение» в карточке перед необратимым действием ----------

// SeenState — ОДНО значение-исход для поля «Последнее подключение»
// карточек удаления/перевыпуска/отключения (GUI и CLI). Прежде карточка CLI
// держала его двумя независимыми bool рядом со строкой — четыре комбинации,
// противоречие между которыми разрешал только порядок switch при печати
// (ревью QA-01, задание НЕЗНАНИЕ-ТРАФИК).
type SeenState int

const (
	// SeenFailed — запрос не удался. Нулевое значение НАМЕРЕННО: незаполненный
	// исход — незнание, а не «не подключался».
	SeenFailed SeenState = iota
	// SeenDisabled — клиент отключён, и в ответе его нет: штатно, отключение
	// вырезает peer из рантайма. Стоит ВЫШЕ SeenAbsent (признак 3: частный
	// случай «отключён» иначе перехватывался общим «нет в ответе», и
	// владелец читал про неисправность там, где сам отключил клиента).
	SeenDisabled
	// SeenAbsent — сервер ответил, включённого клиента в ответе нет.
	SeenAbsent
	// SeenNever — клиент в ответе, рукопожатий не было.
	SeenNever
	// SeenWas — клиент в ответе, было рукопожатие (When).
	SeenWas
)

// LastSeen — исход классификации; When заполнен только при SeenWas.
type LastSeen struct {
	State SeenState
	When  string
}

// ClassifyLastSeen — ЕДИНСТВЕННОЕ место правила «нет в ответе ≠ не
// подключался»: и GUI (guiview.DeleteCardActivity), и CLI (buildCard)
// зовут его. hs и err — ровно то, что вернул Session.GetHandshakes;
// GetHandshakes кладёт в карту КАЖДЫЙ peer ответа, поэтому отсутствие ключа
// означает «нет в рантайме сервера». Порядок ветвей — часть правила: ошибка
// перевешивает карту; «отключён» — выше «нет в ответе».
func ClassifyLastSeen(hs map[string]string, err error, clientID string, disabled bool) LastSeen {
	if err != nil {
		return LastSeen{State: SeenFailed}
	}
	v, ok := hs[clientID]
	switch {
	case !ok && disabled:
		return LastSeen{State: SeenDisabled}
	case !ok:
		return LastSeen{State: SeenAbsent}
	case v == "" || v == "—":
		return LastSeen{State: SeenNever}
	}
	return LastSeen{State: SeenWas, When: v}
}
