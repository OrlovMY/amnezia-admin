//go:build windows

package kbdlayout

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// layoutEnglishUS — идентификатор раскладки «English (United States)»,
// строкой, как того требует LoadKeyboardLayoutW.
const layoutEnglishUS = "00000409"

const (
	// klfActivate — загрузить раскладку И СДЕЛАТЬ ЕЁ ТЕКУЩЕЙ.
	klfActivate = 0x00000001
	// klfSetForProcess — применить ко ВСЕМ потокам процесса, а не только к
	// вызывающему: диалог Fyne живёт в потоке интерфейса, а ForceEnglish
	// зовётся оттуда же, но полагаться на это молча не стоит.
	klfSetForProcess = 0x00000100
)

var (
	user32                  = windows.NewLazySystemDLL("user32.dll")
	procLoadKeyboardLayoutW = user32.NewProc("LoadKeyboardLayoutW")
	procActivateKeyboard    = user32.NewProc("ActivateKeyboardLayout")
)

// forceEnglish грузит и активирует раскладку US. Ошибки НЕ глотаются: и
// отсутствие user32.dll, и нулевой HKL возвращаются наружу, чтобы GUI мог
// сказать человеку правду вместо молчаливой видимости успеха.
func forceEnglish() error {
	if err := procLoadKeyboardLayoutW.Find(); err != nil {
		return fmt.Errorf("user32.dll!LoadKeyboardLayoutW недоступна: %w", err)
	}
	name, err := windows.UTF16PtrFromString(layoutEnglishUS)
	if err != nil {
		return fmt.Errorf("идентификатор раскладки %s не преобразован: %w", layoutEnglishUS, err)
	}
	hkl, _, callErr := procLoadKeyboardLayoutW.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(klfActivate|klfSetForProcess),
	)
	if hkl == 0 {
		return fmt.Errorf("LoadKeyboardLayout(%s) не вернул раскладку: %w", layoutEnglishUS, callErr)
	}
	if err := procActivateKeyboard.Find(); err != nil {
		// Раскладка уже загружена и активирована флагом KLF_ACTIVATE —
		// но сообщить о неполной попытке честнее, чем промолчать.
		return fmt.Errorf("user32.dll!ActivateKeyboardLayout недоступна: %w", err)
	}
	if ok, _, callErr := procActivateKeyboard.Call(hkl, uintptr(klfSetForProcess)); ok == 0 {
		return fmt.Errorf("ActivateKeyboardLayout не выполнен: %w", callErr)
	}
	return nil
}
