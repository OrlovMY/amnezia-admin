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

// ---------- где проверка ВОЗМОЖНА, а где проверять негде ----------

var (
	procGetProcessWindowStation = user32.NewProc("GetProcessWindowStation")
	procGetUserObjectInfoW      = user32.NewProc("GetUserObjectInformationW")
)

// uoiName — код запроса «имя объекта» для GetUserObjectInformationW.
const uoiName = 2

// windowStationName возвращает имя оконной станции процесса.
//
// ЗАЧЕМ ЭТО ЗДЕСЬ. ActivateKeyboardLayout в сеансе БЕЗ интерактивной оконной
// станции (служба, часть раннеров CI) законно возвращает 0, и прогон
// покраснел бы не из-за нашего кода, а из-за среды. Ложное покраснение чинят
// ослаблением проверки — мы это уже проходили. Поэтому «проверить негде» —
// отдельное состояние, и оно устанавливается ФАКТОМ, а не догадкой:
// интерактивная станция называется WinSta0.
//
// Ошибка отдаётся наружу: «не смогли узнать» — это тоже не «всё хорошо».
func windowStationName() (string, error) {
	if err := procGetProcessWindowStation.Find(); err != nil {
		return "", fmt.Errorf("user32.dll!GetProcessWindowStation недоступна: %w", err)
	}
	if err := procGetUserObjectInfoW.Find(); err != nil {
		return "", fmt.Errorf("user32.dll!GetUserObjectInformationW недоступна: %w", err)
	}
	hwinsta, _, callErr := procGetProcessWindowStation.Call()
	if hwinsta == 0 {
		return "", fmt.Errorf("GetProcessWindowStation не вернул станцию%s", reason(callErr))
	}
	buf := make([]uint16, 256)
	var needed uint32
	ok, _, callErr := procGetUserObjectInfoW.Call(
		hwinsta,
		uintptr(uoiName),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)*2),
		uintptr(unsafe.Pointer(&needed)),
	)
	runtime.KeepAlive(buf)
	runtime.KeepAlive(&needed)
	if ok == 0 {
		return "", fmt.Errorf("GetUserObjectInformationW не выполнен%s", reason(callErr))
	}
	return windows.UTF16ToString(buf), nil
}
