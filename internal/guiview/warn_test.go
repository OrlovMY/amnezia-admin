package guiview

import (
	"strings"
	"testing"
)

// goldenWarningText — эталон раздела Г1 задания A3а, дословно. Строки
// "[Продолжить] [Отмена]" из блока задания сюда НЕ входят: это подписи
// кнопок, а не текст, — их проверяют TestWarnButtonLabels.
const goldenWarningText = `Проверьте, что с сервером не работает кто-то ещё

Если в это же время с этим сервером работает другая программа или другое окно — ваш администратор рядом или ваша же консольная версия, — изменения одного из вас будут потеряны молча: пользователь может исчезнуть из списка, выданные ему настройки перестанут работать, а «готово» увидят оба.

Работайте с сервером из одного места за раз. Если только что работали из другого — нажмите «Отмена», обновите список и начните заново.`

// TestWarningTextGolden — текст совпадает с эталоном ЦЕЛИКОМ, не Contains.
//
// ГРАНИЦА ТЕСТА, названная прямо: он сравнивает текст с копией того же
// текста, зафиксированной здесь же. Он ловит УДАЛЕНИЕ части и ПОДМЕНУ на
// бессодержательное; он НЕ ловит согласованную переписку, когда текст и
// эталон меняют вместе — тогда тест зелёный, а текст может стать любым.
// Тестами это не закрывается в принципе. Зелёный TestWarningTextGolden
// доказывает, что текст не изменился незаметно, а не что он хорош; состав и
// формулировки проверяет UX-01, понятность — владелец живьём.
func TestWarningTextGolden(t *testing.T) {
	if got := WarningText(); got != goldenWarningText {
		t.Errorf("WarningText() не совпадает с эталоном Г1.\nполучено:\n%s\n\nэталон:\n%s", got, goldenWarningText)
	}
	// Заголовок и тело — части того же текста, и склейка проверяется тоже:
	// иначе можно вернуть верный WarningText при разъехавшихся частях.
	if want := WarningTitle() + "\n\n" + WarningBody(); WarningText() != want {
		t.Errorf("WarningText() != WarningTitle()+\\n\\n+WarningBody()\nWarningText:\n%s\nсклейка:\n%s", WarningText(), want)
	}
}

// TestWarningTextHasThreeParts — в тексте присутствуют все три обязательные
// части, по якорным фрагментам, названным поимённо. Без любой из трёх текст
// не годится: часть 1 без части 2 — тревога без содержания ("будьте
// осторожны"), часть 2 без части 3 — испуг без выхода.
func TestWarningTextHasThreeParts(t *testing.T) {
	parts := []struct {
		part   string
		anchor string
	}{
		{"часть 1 (обстоятельства: две программы/два окна с одним сервером)",
			"с этим сервером работает другая программа или другое окно"},
		{"часть 2а (что произойдёт: изменения теряются молча)",
			"изменения одного из вас будут потеряны молча"},
		{"часть 2б (что произойдёт: оба увидят «готово»)",
			"«готово» увидят оба"},
		{"часть 3 (что делать: работать из одного места, обновить список)",
			"Работайте с сервером из одного места за раз"},
	}
	text := WarningText()
	for _, p := range parts {
		if !strings.Contains(text, p.anchor) {
			t.Errorf("в тексте предупреждения НЕТ %s — не найден якорь %q", p.part, p.anchor)
		}
	}
	// Запрещённые формулировки (Г1): тревога без содержания. Проверяются
	// здесь, а не только глазами UX-01, потому что появляются они именно
	// при спешной правке.
	for _, banned := range []string{"будьте осторожны", "возможны конфликты", "не рекомендуется"} {
		if strings.Contains(strings.ToLower(text), banned) {
			t.Errorf("в тексте запрещённая формулировка %q — она сообщает тревогу без содержания", banned)
		}
	}
}

// TestWarnButtonLabels — подписи кнопок предупреждения. "Отмена" обязана
// совпадать с подписью кнопки отказа диалогов операций: текст советует нажать
// «Отмена», и человек ищет на экране именно это слово.
func TestWarnButtonLabels(t *testing.T) {
	if got := WarnContinueLabel(); got != "Продолжить" {
		t.Errorf("WarnContinueLabel() = %q, want %q", got, "Продолжить")
	}
	if got := WarnCancelLabel(); got != "Отмена" {
		t.Errorf("WarnCancelLabel() = %q, want %q", got, "Отмена")
	}
}

// TestOpChangesServer — просмотровые операции не меняют сервер, изменяющие
// меняют. Отдельно от WarnDecision: если перепутать здесь, таблица ниже
// покраснеет по непонятной причине.
func TestOpChangesServer(t *testing.T) {
	for _, op := range []Op{OpOpenApp, OpSelectServer, OpRefreshList, OpShowDiff, OpShowConfig} {
		if op.ChangesServer() {
			t.Errorf("%v: ChangesServer() = true, хотя операция только смотрит", op)
		}
	}
	for _, op := range []Op{OpAddUser, OpRenameUser, OpToggleUser, OpRekeyUser, OpDeleteUser, OpApplyPlan} {
		if !op.ChangesServer() {
			t.Errorf("%v: ChangesServer() = false, хотя операция меняет сервер", op)
		}
	}
	// Неизвестное значение считается изменяющим: в сомнении предупредить
	// дешевле, чем промолчать перед потерей данных.
	if !Op(99).ChangesServer() {
		t.Error("неизвестная операция признана безопасной — должна считаться изменяющей")
	}
}

// TestWarnDecision — таблица решения "показывать или молчать". Прогоняются
// ОБА режима частоты: ответ владельца ("один раз за запуск", 18.09.2026)
// меняет одну строку вызова в cmd/gui, а не конструкцию, и смена решения не
// потребует новых тестов.
//
// Каждая строка независима: состояние сеанса задаётся в самой строке, а не
// накапливается прогонами — пакет состояния не хранит (см. WarnSession).
func TestWarnDecision(t *testing.T) {
	const srv = "сервер-А"
	const other = "сервер-Б"

	freshRun := WarnSession{}                               // ещё не предупреждали
	warnedHere := WarnSession{Warned: true, Server: srv}    // предупреждали про этот сервер
	warnedThere := WarnSession{Warned: true, Server: other} // предупреждали про другой

	cases := []struct {
		name   string
		op     Op
		freq   WarnFrequency
		sess   WarnSession
		server string
		want   bool
	}{
		// Только смотрит → молчать. Решение владельца: "Если он ничего не
		// трогает - молчать". Проверяется во всех сочетаниях сеанса и
		// режима, иначе "показывать всегда" пройдёт по части строк.
		{"смотрит: запуск программы, свежий сеанс", OpOpenApp, WarnOncePerRun, freshRun, srv, false},
		{"смотрит: выбор сервера, свежий сеанс", OpSelectServer, WarnOncePerRun, freshRun, srv, false},
		{"смотрит: обновление списка, свежий сеанс", OpRefreshList, WarnOncePerRun, freshRun, srv, false},
		{"смотрит: показ изменений (diff), свежий сеанс", OpShowDiff, WarnOncePerRun, freshRun, srv, false},
		{"смотрит: просмотр конфига, свежий сеанс", OpShowConfig, WarnOncePerRun, freshRun, srv, false},
		{"смотрит: обновление списка, режим «каждый раз»", OpRefreshList, WarnEveryTime, freshRun, srv, false},
		{"смотрит: diff, режим «каждый раз»", OpShowDiff, WarnEveryTime, freshRun, srv, false},
		{"смотрит: выбор сервера после предупреждения", OpSelectServer, WarnOncePerRun, warnedHere, srv, false},
		{"смотрит: выбор другого сервера", OpSelectServer, WarnOncePerRun, warnedThere, srv, false},

		// Первое изменение в запуске → показать. Все пять операций.
		{"изменение: создание, первое за запуск", OpAddUser, WarnOncePerRun, freshRun, srv, true},
		{"изменение: переименование, первое за запуск", OpRenameUser, WarnOncePerRun, freshRun, srv, true},
		{"изменение: включение/выключение, первое за запуск", OpToggleUser, WarnOncePerRun, freshRun, srv, true},
		{"изменение: перевыпуск конфига, первое за запуск", OpRekeyUser, WarnOncePerRun, freshRun, srv, true},
		{"изменение: удаление, первое за запуск", OpDeleteUser, WarnOncePerRun, freshRun, srv, true},

		// ШЕСТАЯ точка записи — "Применить" в окне изменений. Два сценария
		// частоты, названные прямо, потому что перепутать их легко:
		//
		// (1) человек пошёл СРАЗУ в "Показать изменения" (кнопка есть в
		// каждой форме) и применяет план первым действием за запуск —
		// предупреждения он ещё не видел, и оно ОБЯЗАНО быть. Без этой
		// строки самый осторожный человек остался бы без предупреждения
		// вовсе;
		//
		// (2) человек прошёл путь "кнопка операции → предупреждение →
		// показать изменения → применить" — предупреждение уже показано в
		// этом сеансе, и второй раз подряд оно не показывается.
		{"шестая точка: применение плана первым действием за запуск (сразу в «Показать изменения»)",
			OpApplyPlan, WarnOncePerRun, freshRun, srv, true},
		{"шестая точка: применение плана после уже показанного предупреждения в этом сеансе",
			OpApplyPlan, WarnOncePerRun, warnedHere, srv, false},
		{"шестая точка: применение плана на другом сервере", OpApplyPlan, WarnOncePerRun, warnedThere, srv, true},
		{"шестая точка: применение плана, режим «каждый раз»", OpApplyPlan, WarnEveryTime, warnedHere, srv, true},

		// Второе изменение в том же сеансе и том же сервере → молчать.
		{"второе изменение в сеансе: создание", OpAddUser, WarnOncePerRun, warnedHere, srv, false},
		{"второе изменение в сеансе: удаление", OpDeleteUser, WarnOncePerRun, warnedHere, srv, false},
		{"второе изменение в сеансе: перевыпуск", OpRekeyUser, WarnOncePerRun, warnedHere, srv, false},

		// Смена сервера → показать снова. Сеанс привязан к серверу: гонка
		// возможна на каждом сервере отдельно, и человек, перешедший на
		// другой сервер, про новый ещё не предупреждён.
		{"смена сервера: создание на другом сервере", OpAddUser, WarnOncePerRun, warnedThere, srv, true},
		{"смена сервера: удаление на другом сервере", OpDeleteUser, WarnOncePerRun, warnedThere, srv, true},
		{"смена сервера: переименование на другом сервере", OpRenameUser, WarnOncePerRun, warnedThere, srv, true},

		// Режим «каждый раз» — второй режим параметра, прогоняется целиком.
		{"каждый раз: первое изменение", OpAddUser, WarnEveryTime, freshRun, srv, true},
		{"каждый раз: второе изменение в сеансе", OpAddUser, WarnEveryTime, warnedHere, srv, true},
		{"каждый раз: удаление после предупреждения", OpDeleteUser, WarnEveryTime, warnedHere, srv, true},
		{"каждый раз: смена сервера", OpDeleteUser, WarnEveryTime, warnedThere, srv, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := WarnDecision(c.op, c.freq, c.sess, c.server)
			if got != c.want {
				t.Errorf("WarnDecision(%v, freq=%d, sess=%+v, server=%q) = %v, want %v",
					c.op, c.freq, c.sess, c.server, got, c.want)
			}
		})
	}
}

// TestAfterWarned — состояние сеанса после показа: отмечен и запомнен сервер.
// Вместе с WarnDecision даёт "доезд": после AfterWarned повторное решение по
// тому же серверу — молчать, по другому — показать.
func TestAfterWarned(t *testing.T) {
	s := AfterWarned("сервер-А")
	if !s.Warned || s.Server != "сервер-А" {
		t.Fatalf("AfterWarned = %+v, want {Warned:true Server:\"сервер-А\"}", s)
	}
	if WarnDecision(OpDeleteUser, WarnOncePerRun, s, "сервер-А") {
		t.Error("после AfterWarned повторное изменение на том же сервере всё ещё показывает предупреждение")
	}
	if !WarnDecision(OpDeleteUser, WarnOncePerRun, s, "сервер-Б") {
		t.Error("после AfterWarned изменение на ДРУГОМ сервере молчит — сеанс не привязан к серверу")
	}
}
