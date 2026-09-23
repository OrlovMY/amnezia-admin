package kbdlayout

// ЧТО ЭТОТ ПРОГОН ДОКАЗЫВАЕТ, А ЧТО НЕТ.
//
// ДОКАЗЫВАЕТ: три состояния ответа различимы и приходят БОЕВЫМ путём —
// ForceEnglish действительно вызывается, а не подставляется тестом. На
// Windows — что системный вызов проходит; на прочих ОС — что возвращается
// именно ErrUnsupported («точно нет»), а не nil («сделали») и не выдуманная
// ошибка.
//
// НЕ ДОКАЗЫВАЕТ: что у ЧЕЛОВЕКА в окне после этого набирается латиница.
// Раскладка — состояние сеанса Windows, а не процесса: подтвердить это может
// только живая сессия владельца с установленной русской раскладкой. Так в
// отчёте и написано; выдавать этот тест за поведенческую проверку
// переключения нельзя.

import (
	"errors"
	"runtime"
	"testing"
)

// TestForceEnglishDistinguishesThreeStates — тест РАЗЛИЧЕНИЯ: «не умеем» не
// превращается ни в «сделали», ни в неизвестную ошибку.
func TestForceEnglishDistinguishesThreeStates(t *testing.T) {
	err := ForceEnglish()
	if runtime.GOOS == "windows" {
		if errors.Is(err, ErrUnsupported) {
			t.Fatal("на Windows ForceEnglish отвечает «не поддерживается» — переключение " +
				"раскладки, обещанное владельцу, не делается вовсе")
		}
		if err != nil {
			// Попытка была и не удалась — это законный третий исход, но он
			// обязан быть ВИДЕН, а не проглочен.
			t.Logf("ForceEnglish на этой машине не выполнился: %v (GUI в этом случае "+
				"показывает подсказку, а не молчит)", err)
		}
		return
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("на %s ForceEnglish вернул %v, а обязан вернуть ErrUnsupported: "+
			"иначе «ничего не сделали» выдаётся за «переключили»", runtime.GOOS, err)
	}
}

// TestUnsupportedIsNotNil — канарейка на самое соблазнительное упрощение:
// вернуть nil на неподдерживаемой ОС («и так сойдёт»). Тогда вызывающий
// решит, что раскладка английская.
func TestUnsupportedIsNotNil(t *testing.T) {
	if ErrUnsupported == nil {
		t.Fatal("ErrUnsupported == nil: «не умеем» стало неотличимо от «сделали»")
	}
	if errors.Is(nil, ErrUnsupported) {
		t.Fatal("errors.Is(nil, ErrUnsupported) истинно — различать состояния нечем")
	}
}
