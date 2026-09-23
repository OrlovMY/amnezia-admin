//go:build windows

package kbdlayout

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
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
	// name больше нигде не используется, а это LazyProc.Call, а не
	// syscall.Syscall: спецправило, сохраняющее указатель живым на время
	// вызова, здесь не действует, и сборщик вправе освободить буфер (ревью
	// SEC-01).
	runtime.KeepAlive(name)
	if hkl == 0 {
		// callErr у LazyProc.Call не бывает nil и при успехе равен «The
		// operation completed successfully» — подставлять его в текст отказа
		// значит сбивать с толку. Поэтому он попадает в сообщение, только
		// если это НАСТОЯЩАЯ ошибка.
		return fmt.Errorf("LoadKeyboardLayout(%s) не вернул раскладку%s", layoutEnglishUS, reason(callErr))
	}
	if err := procActivateKeyboard.Find(); err != nil {
		// Раскладка уже загружена и активирована флагом KLF_ACTIVATE —
		// но сообщить о неполной попытке честнее, чем промолчать.
		return fmt.Errorf("user32.dll!ActivateKeyboardLayout недоступна: %w", err)
	}
	if ok, _, callErr := procActivateKeyboard.Call(hkl, uintptr(klfSetForProcess)); ok == 0 {
		return fmt.Errorf("ActivateKeyboardLayout не выполнен%s", reason(callErr))
	}
	return nil
}

// reason превращает errno от LazyProc.Call в добавку к сообщению. Windows
// возвращает из GetLastError ERROR_SUCCESS, когда «всё хорошо», и текст «The
// operation completed successfully» в отказе читается как издевательство —
// поэтому в таком случае говорится прямо, что кода ошибки нет, а не
// подставляется успех вместо причины.
func reason(err error) string {
	var errno syscall.Errno
	if err == nil || (errors.As(err, &errno) && errno == 0) {
		return " (код ошибки система не сообщила)"
	}
	return ": " + err.Error()
}
