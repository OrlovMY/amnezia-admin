// amnezia-admin-gui — графическая оболочка для администрирования сервера Amnezia VPN.
// Вся логика — в пакете core, здесь только Fyne UI.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/guiview"
	"amnezia-admin/internal/version"
)

type ui struct {
	win        fyne.Window
	sess       *core.Session
	containers []core.Container
	cur        *core.Container

	clients    []core.ClientEntry
	handshakes map[string]string
	peerStats  map[string]core.PeerStat

	// activityFailed, statsFailed — ТРЕТЬЕ СОСТОЯНИЕ колонок «Активность» и
	// «Трафик» (задание A1, место № 2): последний запрос `wg show` за этими
	// данными не удался. Без отдельных признаков пустая карта неотличима от
	// «у всех клиентов ноль», и человек читает «0 B / 0 B» как измеренную
	// величину. Обновляются там же, где handshakes/peerStats, — то есть при
	// ошибке чтения списка остаются от прошлого чтения, как и сами данные.
	activityFailed bool
	statsFailed    bool

	table       *widget.Table
	status      *widget.Label
	protoSelect *widget.Select
	selectedRow int

	// canManage — решение guiview.ViewState для ТЕКУЩЕГО протокола (u.cur),
	// обновляется в конце refresh() ДО setBusy(false) (FIX-VIEW, Э3а):
	// setBusy(false) включает кнопки управления, только если canManage
	// (иначе они остаются Disable() — Д3), а рендер колонок активности/
	// трафика в таблице пишет "—" вместо "?"/"0 B" при !canManage.
	canManage bool

	// warnSess, warnFreq — предупреждение о гонке при одновременной работе
	// (A3а). Состояние сеанса хранится ЗДЕСЬ, а не в guiview: пакет решений
	// без Fyne обязан оставаться чистым, иначе его таблица начнёт зависеть от
	// порядка прогонов. warnFreq — режим частоты; ответ владельца 18.09.2026
	// — "один раз за запуск", и смена его решения стоит правки этой одной
	// строки в main(), а не переделки конструкции.
	warnSess guiview.WarnSession
	warnFreq guiview.WarnFrequency

	// Кнопки главного экрана — поля, чтобы setBusy(true/false) могла
	// Disable()/Enable() их во время любой серверной операции (от нажатия до
	// fyne.Do с результатом), включая refresh(): мьютекс в core защищает
	// данные, но без блокировки кнопок повторный клик — это уже вторая
	// операция поверх ещё не завершившейся первой (BE-01, ревью, Е2).
	refreshBtn, addBtn, renameBtn, toggleBtn, regenBtn, delBtn *widget.Button

	// сортировка таблицы пользователей по клику на заголовок колонки;
	// primary — активная (со стрелкой в заголовке), secondary — tie-breaker
	// от предыдущего primary. Персистентно (ui.json рядом с exe), глобально
	// для приложения (не per-protocol).
	sortPrimary      core.SortColumn
	sortPrimaryDir   core.SortDir
	sortSecondary    core.SortColumn
	sortSecondaryDir core.SortDir
}

func main() {
	defer logPanic()
	a := app.New()
	w := a.NewWindow("Amnezia Admin " + version.String())
	w.Resize(fyne.NewSize(980, 620))

	// warnFreq: выбор владельца от 18.09.2026 — "один раз за запуск"
	// (сброс при смене сервера). Второй режим — guiview.WarnEveryTime.
	u := &ui{win: w, selectedRow: -1, warnFreq: guiview.WarnOncePerRun}
	u.sortPrimary, u.sortPrimaryDir, u.sortSecondary, u.sortSecondaryDir = loadSortState()
	w.SetContent(u.connectScreen())
	w.ShowAndRun()
}

// logPanic пишет панику в crash.log рядом с exe — окно без консоли, иначе падение невидимо
func logPanic() {
	if r := recover(); r != nil {
		dir := filepath.Dir(os.Args[0])
		msg := fmt.Sprintf("%s\npanic: %v\n\n%s\n", time.Now().Format(time.RFC3339), r, debug.Stack())
		os.WriteFile(filepath.Join(dir, "crash.log"), []byte(msg), 0644)
		panic(r)
	}
}

// goSafe запускает фоновую операцию с логированием паники
func goSafe(fn func()) {
	go func() {
		defer logPanic()
		fn()
	}()
}

// ---------- экран подключения ----------

func (u *ui) connectScreen() fyne.CanvasObject {
	return u.connectScreenWithStatus("")
}

// connectScreenWithStatus — connectScreen() с предзаполненным статусом в
// info-лейбле; используется после "Забыть ключ сервера" (R2, Е1) — экран
// подключения, куда возвращает вторая (подтверждающая) диалоговая форма,
// сразу показывает "Ключ сервера забыт. Нажмите «Подключиться»..." (С3,
// UI-01, "Статус после").
func (u *ui) connectScreenWithStatus(status string) fyne.CanvasObject {
	keyEntry := widget.NewMultiLineEntry()
	keyEntry.SetPlaceHolder("Вставьте админский ключ vpn://...")
	keyEntry.Wrapping = fyne.TextWrapBreak
	if k := os.Getenv("AMNEZIA_KEY"); k != "" {
		keyEntry.SetText(k)
	}

	info := widget.NewLabel(status)
	info.Wrapping = fyne.TextWrapWord

	var connectBtn *widget.Button
	connectBtn = widget.NewButtonWithIcon("Подключиться", theme.LoginIcon(), func() {
		key := strings.TrimSpace(keyEntry.Text)
		if key == "" {
			info.SetText("Ключ пустой.")
			return
		}
		u.attemptConnect(key, nil, connectBtn, info)
	})

	title := widget.NewLabelWithStyle("Amnezia Admin", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	// Строка версии под заголовком (Г3 PR-6а) — вариант на ревью UI-01;
	// альтернатива: вписать version.String() прямо в текст title.
	versionLabel := widget.NewLabelWithStyle(version.String(), fyne.TextAlignCenter, fyne.TextStyle{})
	hint := widget.NewLabel("Нужен админский ключ — внутри него SSH-доступ к серверу.\nПользовательский (share) ключ не подойдёт.")
	hint.Wrapping = fyne.TextWrapWord

	form := container.NewVBox(title, versionLabel, hint, keyEntry, connectBtn, info)

	if vaultBlock := u.savedVaultsBlock(connectBtn, info); vaultBlock != nil {
		form.Add(vaultBlock)
	}

	return container.NewCenter(container.NewGridWrap(fyne.NewSize(560, 400), form))
}

// savedVaultsBlock строит блок «Или загрузить из сохранённых» под кнопкой
// «Подключиться», если в каталоге "Настройки" есть сохранённые ключи (.avlt).
// Настоящие метки серверов зашифрованы и неизвестны до ввода пина, поэтому
// в списке показываются только порядковые "Сервер N" (порядок — по имени файла).
func (u *ui) savedVaultsBlock(connectBtn *widget.Button, info *widget.Label) fyne.CanvasObject {
	vaults := core.ListVaults(core.DefaultVaultDir())
	if len(vaults) == 0 {
		return nil
	}
	label := widget.NewLabel("Или загрузить из сохранённых:")
	names := make([]string, len(vaults))
	for i := range vaults {
		names[i] = fmt.Sprintf("Сервер %d", i+1)
	}
	if len(vaults) == 1 {
		btn := widget.NewButton(names[0], func() {
			u.showVaultPinDialog(vaults[0], names[0], connectBtn, info)
		})
		return container.NewVBox(label, btn)
	}
	sel := widget.NewSelect(names, nil)
	sel.OnChanged = func(_ string) {
		i := sel.SelectedIndex()
		if i < 0 || i >= len(vaults) {
			return
		}
		path, lbl := vaults[i], names[i]
		sel.ClearSelected()
		u.showVaultPinDialog(path, lbl, connectBtn, info)
	}
	return container.NewVBox(label, sel)
}

// showVaultPinDialog запрашивает пин-код для сохранённого ключа и, если он
// верен, сразу выполняет подключение. Argon2 на прод-параметрах занимает
// около секунды — расшифровка идёт в фоне (goSafe), кнопка на время
// заблокирована. Неверный пин не закрывает диалог — только очищает поле и
// показывает сообщение об ошибке (и остаток попыток), чтобы можно было
// повторить.
//
// Throttle (10 неверных попыток подряд → блокировка на 5 минут, персистентно
// в throttle.json per-vault) проверяется до расшифровки и обновляется сразу
// после неё: неудача пишется на диск НЕМЕДЛЕННО (fail-closed), до того, как
// решаем, показывать ли "осталось попыток" или переключаться в отсчёт блокировки.
//
// Время для throttle — ОНЛАЙН, не локальные часы: при открытии диалога один
// раз запрашивается сетевое время (core.FetchNetworkTime) и фиксируется в
// core.TrustedClock (T0 + монотонное смещение) — see core/onlinetime.go.
// Дальше "сейчас" для CheckThrottle/RegisterFailure/RegisterSuccess и для
// самого обратного отсчёта берётся из clock.Now(), а не time.Now(), — перевод
// системных часов пользователем не сбрасывает и не продлевает блокировку.
// Если сеть недоступна — открытие невозможно (fail-closed: приложению в
// любом случае нужен интернет для SSH, так что это не новое ограничение).
//
// Ограничение (не устраняется online-time и не должно заявляться в UI):
// удаление throttle.json или откат его резервной копии по-прежнему сбрасывает
// счётчик попыток — это anti-casual слой, не защита от целенаправленной
// атаки на файловую систему.
func (u *ui) showVaultPinDialog(path, label string, connectBtn *widget.Button, info *widget.Label) {
	vaultDir := core.DefaultVaultDir()
	vaultName := filepath.Base(path)

	pinEntry := widget.NewEntry()
	pinEntry.Password = true
	pinEntry.SetPlaceHolder("Пин-код")
	statusLabel := widget.NewLabel("")
	statusLabel.Wrapping = fyne.TextWrapWord

	// throttleAttempts — сколько попыток даётся до блокировки (держим в
	// синхроне с core.throttleMaxFails; вынести в core.ExportedConst не стали,
	// т.к. это единственное место в GUI, где нужно число "осталось попыток").
	const throttleAttempts = 10

	var d dialog.Dialog
	var openBtn *widget.Button
	var retryBtn *widget.Button
	var ticker *time.Ticker
	var clock *core.TrustedClock // nil, пока онлайн-время не получено
	// countdownGen — поколение текущего обратного отсчёта: goroutine тикера
	// сверяет его перед каждым обновлением UI и завершается сама, если
	// диалог запустил новый отсчёт или был закрыт (не полагаемся на
	// сравнение указателей *time.Ticker, которое легко перепутать).
	countdownGen := 0
	stopTicker := func() {
		countdownGen++
		if ticker != nil {
			ticker.Stop()
			ticker = nil
		}
	}

	// startCountdown переключает диалог в режим обратного отсчёта блокировки:
	// кнопка "Открыть" дизейблена, статус обновляется раз в секунду, по
	// истечении блокировка снимается автоматически. "Сейчас" для расчёта
	// остатка — доверенное онлайн-время (clock.Now()), НЕ time.Now(): иначе
	// перевод локальных часов во время отображения отсчёта исказил бы его.
	var startCountdown func(until time.Time)
	startCountdown = func(until time.Time) {
		stopTicker()
		myGen := countdownGen
		openBtn.Disable()
		update := func() bool {
			remaining := until.Sub(clock.Now())
			if remaining <= 0 {
				statusLabel.SetText("")
				openBtn.Enable()
				return false
			}
			sec := int(remaining.Round(time.Second) / time.Second)
			statusLabel.SetText(fmt.Sprintf("Слишком много попыток. Повторите через %d:%02d", sec/60, sec%60))
			return true
		}
		if !update() {
			return
		}
		ticker = time.NewTicker(time.Second)
		tk := ticker
		goSafe(func() {
			for range tk.C {
				done := false
				fyne.Do(func() {
					if countdownGen != myGen {
						done = true // диалог закрыт или отсчёт перезапущен — эта goroutine больше не актуальна
						return
					}
					if !update() {
						done = true
					}
				})
				if done {
					tk.Stop()
					return
				}
			}
		})
	}

	// submit — общее действие и для кнопки "Открыть", и для Enter в поле
	// пина (единственное поле формы). Если кнопка дизейблена (throttle-блок,
	// нет онлайн-времени или уже идёт расшифровка) — Enter, как и клик,
	// ничего не делает.
	//
	// Fail-closed инвариант: submit() — ЕДИНСТВЕННЫЙ путь к core.OpenVault и
	// core.CheckThrottle в этом диалоге (кнопка "Открыть" вызывает его же,
	// Enter в pinEntry — тоже его же). Guard "clock == nil" гарантирует, что
	// ни расшифровка, ни throttle-проверка не выполнятся, пока не получено
	// онлайн-время: до этого openBtn изначально Disable()-нута (см. ниже) и
	// включается только внутри acquireOnlineTime ПОСЛЕ успешного
	// FetchNetworkTime (clock уже не nil к этому моменту). Единственный
	// другой вызов CheckThrottle в файле — тоже внутри acquireOnlineTime,
	// тоже после присвоения clock.
	submit := func() {
		if openBtn.Disabled() || clock == nil {
			return
		}
		pin := pinEntry.Text
		if blocked, remaining := core.CheckThrottle(core.LoadThrottle(vaultDir, vaultName), clock.Now()); blocked {
			startCountdown(clock.Now().Add(remaining))
			return
		}
		openBtn.Disable()
		statusLabel.SetText("Расшифровываю...")
		goSafe(func() {
			data, err := core.LoadVault(path)
			var payload core.VaultPayload
			var vinfo core.VaultInfo
			if err == nil {
				payload, vinfo, err = core.OpenVaultInfo(pin, data)
			}
			if err != nil {
				now := clock.Now()
				st := core.RegisterFailure(core.LoadThrottle(vaultDir, vaultName), now)
				_ = core.SaveThrottle(vaultDir, vaultName, st) // fail-closed: пишем счётчик до любого дальнейшего ветвления
				fyne.Do(func() {
					pinEntry.SetText("")
					if blocked, remaining := core.CheckThrottle(st, now); blocked {
						startCountdown(now.Add(remaining))
						return
					}
					msg := "Неправильный пин-код или файл повреждён."
					if !errors.Is(err, core.ErrVaultBadPinOrCorrupt) {
						msg = err.Error() // прочая ошибка (например чтение файла) — показываем как есть
					}
					if left := throttleAttempts - st.Fails; left > 0 {
						msg += fmt.Sprintf(" Осталось попыток: %d.", left)
					}
					statusLabel.SetText(msg)
					openBtn.Enable()
				})
				return
			}
			_ = core.SaveThrottle(vaultDir, vaultName, core.RegisterSuccess())
			// vc — контекст открытого хранилища для attemptConnect (Е1):
			// ExpectedFingerprint (payload.HostKeyFingerprint), перезапечатывание
			// после первого подтверждённого подключения (если поле было пусто) и
			// кнопка "Забыть ключ сервера" на диалоге ErrHostKeyChanged/Mismatch.
			// pin — указатель на ЭТУ переменную (уникальна для данного вызова
			// submit()); обнуляется в attemptConnect/confirmForgetHostKey сразу
			// после того, как он больше не нужен (SEC-01, С3, п.2).
			vc := &vaultCtx{path: path, pin: &pin, info: vinfo, payload: payload}
			fyne.Do(func() {
				stopTicker()
				d.Hide()
				u.attemptConnect(payload.Key, vc, connectBtn, info)
			})
		})
	}
	openBtn = widget.NewButtonWithIcon("Открыть", theme.LoginIcon(), submit)
	openBtn.Disable() // включится только после успешного получения онлайн-времени
	// единственное поле формы — Enter сразу выполняет submit (как нажатие "Открыть")
	pinEntry.OnSubmitted = func(string) { submit() }

	// acquireOnlineTime получает доверенное время (один сетевой запрос за
	// сессию диалога) и либо запускает обычный throttle-флоу, либо, если
	// сети нет, сообщает об этом без упоминания "серверов времени" —
	// приложению в любом случае нужен интернет для SSH, поэтому это не
	// новое ограничение, а fail-closed поведение при его отсутствии.
	var acquireOnlineTime func()
	acquireOnlineTime = func() {
		retryBtn.Hide()
		openBtn.Disable()
		statusLabel.SetText("Проверка подключения...")
		goSafe(func() {
			// 8с — общий дедлайн на весь acquire (core.FetchNetworkTime теперь
			// опрашивает все хосты параллельно, а не по очереди, поэтому этого
			// достаточно независимо от размера пула — раньше при
			// последовательном переборе 5 хостов по 4с могло уходить до ~20с).
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			onlineNow, err := core.FetchNetworkTime(ctx)
			fyne.Do(func() {
				if err != nil {
					clock = nil
					statusLabel.SetText("Подключение к интернету не обнаружено.")
					retryBtn.Show()
					return
				}
				tc := core.NewTrustedClock(onlineNow)
				clock = &tc
				if blocked, remaining := core.CheckThrottle(core.LoadThrottle(vaultDir, vaultName), clock.Now()); blocked {
					startCountdown(clock.Now().Add(remaining))
					return
				}
				statusLabel.SetText("")
				openBtn.Enable()
			})
		})
	}
	retryBtn = widget.NewButtonWithIcon("Повторить", theme.ViewRefreshIcon(), func() { acquireOnlineTime() })
	retryBtn.Hide()

	content := container.NewVBox(
		widget.NewLabel(label),
		pinEntry,
		statusLabel,
		openBtn,
		retryBtn,
	)
	d = dialog.NewCustom("Введите пин-код", "Отмена", content, u.win)
	d.SetOnClosed(stopTicker) // не течь тикером, если пользователь закрыл диалог во время отсчёта
	d.Resize(fyne.NewSize(380, 280))
	d.Show()

	acquireOnlineTime()
}

// vaultCtx — контекст открытого хранилища (.avlt), нужный attemptConnect для
// (1) подстановки ExpectedFingerprint из payload.HostKeyFingerprint, (2)
// перезапечатывания файла новым отпечатком после первого подтверждённого
// подключения, если поле было пусто (v1 или v2 без отпечатка), и (3) кнопки
// "Забыть ключ сервера" на диалоге ErrHostKeyChanged/ErrHostKeyMismatch (R2,
// С3-позиция-ядра.md). nil — ключ введён вручную, хранилища нет: диалог
// смены ключа тогда показывается БЕЗ кнопки "Забыть" (Forget действует
// только "при открытии из хранилища" — Е1 задания PR-4).
//
// pin — указатель на переменную с пином из showVaultPinDialog.submit():
// живёт в памяти ровно до момента, когда он больше не нужен — либо сразу
// после перезапечатывания при успешном подключении, либо сразу после вызова
// core.ForgetHostKey при отказе (SEC-01, С3, п.2: "отдельного ввода пина не
// требовать... пин обнуляется сразу после; если обнулён — спросить заново").
// Пин нигде не сохраняется на диск и не логируется (В2 п.5).
type vaultCtx struct {
	path    string
	pin     *string
	info    core.VaultInfo
	payload core.VaultPayload
}

// attemptConnect декодирует ключ, подключается по SSH (с проверкой ключа
// хоста, PR-4) и переключает экран. vc == nil — ключ введён вручную: после
// первого успешного подключения предлагает сохранить ключ в хранилище
// (offerSaveKey). vc != nil — ключ открыт из хранилища: ExpectedFingerprint
// берётся из vc.payload.HostKeyFingerprint, а после первого подключения (там,
// где это поле было пусто) отпечаток дописывается в файл.
func (u *ui) attemptConnect(key string, vc *vaultCtx, connectBtn *widget.Button, info *widget.Label) {
	connectBtn.Disable()
	info.SetText("Декодирую ключ и подключаюсь по SSH...")

	knownHostsPath := filepath.Join(core.DefaultVaultDir(), "known_hosts")

	goSafe(func() {
		cfg, err := core.DecodeVpnKey(key)
		if err != nil {
			u.connectFail(connectBtn, info, "Ошибка декодирования ключа: "+err.Error())
			return
		}
		creds, err := core.CredsFromConfig(cfg)
		if err != nil {
			u.connectFail(connectBtn, info, err.Error())
			return
		}

		expectedFp := ""
		if vc != nil {
			expectedFp = vc.payload.HostKeyFingerprint
		}
		// Prompt/OnChanged вызываются СИНХРОННО внутри ssh.Dial (см. эту же
		// горутину goSafe) — обновлять UI можно только через fyne.Do; Prompt
		// дополнительно блокируется на канале, дожидаясь ответа человека
		// (иначе ssh.Dial получил бы решение раньше, чем оно принято).
		sess, err := core.ConnectWithHostKey(creds, core.HostKeyPolicy{
			KnownHostsPath: knownHostsPath,
			Prompt:         u.hostKeyPrompt,
			OnChanged: func(host, knownFp, presentedFp string) {
				u.hostKeyChangedDialog(host, knownFp, presentedFp, knownHostsPath, vc, connectBtn, info)
			},
			ExpectedFingerprint: expectedFp,
		})
		if err != nil {
			// ErrHostKeyChanged уже показал диалог через OnChanged выше (core
			// зовёт его сама перед возвратом ошибки). ErrHostKeyMismatch core
			// НЕ сопровождает вызовом OnChanged (С1: сигнатура ядра, аргументы
			// нужны только для "изменился") — но UI-01/С3 требует ТОТ ЖЕ
			// диалог и для "не совпал с хранилищем" ("отдельным термином не
			// показывать"). Структурные поля (адрес, оба отпечатка) — из
			// *core.HostKeyError через errors.As (ревью PR-4-Б, круг 1,
			// SEC-01 Medium: раньше "полученный" отпечаток добывался
			// регэкспом из текста ошибки — тот же класс хрупкости, что
			// чинили у ErrCASMismatch в PR-3; core/hostkey.go правлен по
			// явному разрешению ядра, никакой другой код core не тронут).
			var hke *core.HostKeyError
			if vc != nil && errors.Is(err, core.ErrHostKeyMismatch) && errors.As(err, &hke) {
				u.hostKeyChangedDialog(hke.Addr, hke.KnownFp, hke.PresentedFp, knownHostsPath, vc, connectBtn, info)
			}
			u.connectFail(connectBtn, info, "SSH не удался: "+err.Error())
			return
		}
		containers, err := sess.FindContainers()
		if err != nil {
			sess.Close()
			u.connectFail(connectBtn, info, err.Error())
			return
		}

		if vc != nil && vc.payload.HostKeyFingerprint == "" {
			// v1-хранилище (или v2, сохранённое ДО подтверждения ключа) — это
			// первое подтверждённое подключение, отпечаток узнаём только
			// сейчас (Е1). Ошибка перезапечатывания не фатальна — соединение
			// остаётся, просто отпечаток не будет запечатан на этот раз.
			if resealErr := reseal(vc, sess.HostKeyFingerprint); resealErr != nil {
				fyne.Do(func() {
					if u.status != nil {
						u.status.SetText("Не удалось сохранить отпечаток ключа в хранилище: " + resealErr.Error())
					}
				})
			}
		}
		if vc != nil && vc.pin != nil {
			*vc.pin = "" // пин больше не нужен (SEC-01, В2 п.5)
		}

		fyne.Do(func() {
			u.sess = sess
			u.containers = containers
			u.cur = &u.containers[0]
			for i := range u.containers {
				if u.containers[i].Managed {
					u.cur = &u.containers[i]
					break
				}
			}
			u.win.SetContent(u.mainScreen())
			u.refresh()
			if vc == nil {
				u.offerSaveKey(key, creds.Host, sess.HostKeyFingerprint)
			}
		})
	})
}

// reseal перезапечатывает .avlt хранилища vc с только что принятым
// отпечатком ключа хоста fp — теми же параметрами Argon2 и той же
// привязкой к машине, что были при открытии (vc.info из OpenVaultInfo), тем
// же пином, которым файл был открыт (используется ДО его обнуления в
// attemptConnect).
func reseal(vc *vaultCtx, fp string) error {
	if vc.pin == nil {
		return fmt.Errorf("пин недоступен")
	}
	payload := vc.payload
	payload.HostKeyFingerprint = fp
	data, err := core.SealVault(*vc.pin, payload, vc.info.Params, vc.info.MachineBind)
	if err != nil {
		return err
	}
	return core.WriteVaultFile(vc.path, data)
}

// hostKeyPrompt — core.HostKeyPolicy.Prompt для GUI (Е1 задания PR-4):
// показывает диалог "Неизвестный сервер" и ждёт ответ по каналу. Вызывается
// синхронно внутри ssh.Dial из фоновой горутины (goSafe) — диалог
// показываем через fyne.Do, результат ждём по chan bool, иначе Fyne
// упал бы на обращении к UI из чужой горутины, а ssh.Dial получил бы ответ
// раньше, чем человек его дал.
func (u *ui) hostKeyPrompt(host, fingerprint string) bool {
	result := make(chan bool, 1)
	fyne.Do(func() {
		body := widget.NewLabel(fmt.Sprintf(
			"Сервер: %s\nОтпечаток ключа: %s\n\nСверьте отпечаток с тем, что показывает сервер (например, ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub).",
			host, fingerprint,
		))
		body.Wrapping = fyne.TextWrapWord
		d := dialog.NewCustomConfirm("Неизвестный сервер", "Доверять и запомнить", "Отмена", body, func(ok bool) {
			result <- ok
		}, u.win)
		d.Resize(fyne.NewSize(480, 240))
		d.Show()
	})
	return <-result
}

// hostKeyChangedDialog показывает диалог "Ключ сервера изменился" (UI-01,
// дословно; С3-позиция-ядра.md) — и для ErrHostKeyChanged (данные из
// OnChanged), и для ErrHostKeyMismatch при открытии из хранилища (тот же
// диалог, отдельным термином не показывается — С3: "«Не совпал с
// хранилищем при пустом known_hosts» — тот же диалог «изменился»"). vc ==
// nil (ключ введён вручную, хранилища нет) — кнопки "Забыть ключ сервера…"
// нет: принять сменившийся ключ нельзя в любом случае (правка 4.5 PQ-01),
// а "забыть" в CLI/без-хранилища не заводится (SEC-01).
func (u *ui) hostKeyChangedDialog(host, knownFp, presentedFp, knownHostsPath string, vc *vaultCtx, connectBtn *widget.Button, info *widget.Label) {
	fyne.Do(func() {
		// Каждый отпечаток на своей строке (ревью PR-4-Б, круг 1, UI-01
		// Low) — слова текста С3 не менялись, только разбивка строк для
		// читаемости; длинные SHA256:… в одну строку с преамбулой сливались
		// визуально.
		body := widget.NewLabel(fmt.Sprintf(
			"Сервер %s.\nСохранённый отпечаток: %s\nПолученный: %s\nТак бывает после переустановки сервера. "+
				"Если вы его не переустанавливали — возможна подмена: не подключайтесь.",
			host, knownFp, presentedFp,
		))
		body.Wrapping = fyne.TextWrapWord

		content := container.NewVBox(body)
		var d dialog.Dialog
		// forgetClicked различает "закрыто нажатием «Забыть ключ сервера…»"
		// (пин ещё нужен — его использует confirmForgetHostKey сразу после
		// d.Hide() ниже) от любого другого закрытия диалога ("Закрыть",
		// Escape, крестик — все они одинаково идут через SetOnClosed). Во
		// втором случае ссылка на пин в vc сбрасывается сразу (ревью PR-4-Б,
		// круг 1, SEC-01 Low): решение "не забывать ключ сейчас" принято,
		// дальше этот pin в vc не понадобится — незачем держать на него
		// ссылку дольше, чем нужно (В2 п.5, общий принцип).
		forgetClicked := false
		if vc != nil {
			forgetBtn := widget.NewButton("Забыть ключ сервера…", func() {
				forgetClicked = true
				d.Hide()
				u.confirmForgetHostKey(host, knownHostsPath, vc, connectBtn, info)
			})
			content.Add(forgetBtn)
		}
		d = dialog.NewCustom("Ключ сервера изменился", "Закрыть", content, u.win)
		if vc != nil {
			d.SetOnClosed(func() {
				if !forgetClicked {
					vc.pin = nil
				}
			})
		}
		d.Resize(fyne.NewSize(480, 280))
		d.Show()
	})
}

// confirmForgetHostKey — второй, отдельный диалог подтверждения (UX-01:
// "Действие живёт только на диалоге «Ключ сервера изменился». Второй шаг —
// отдельный диалог."), дословный текст — С3-позиция-ядра.md. "Забыть" зовёт
// core.ForgetHostKey (правка координатора 2026-09-14 23:58: снимает ОБА
// следа — .avlt и known_hosts) и, вне зависимости от исхода, обнуляет пин
// (vc.pin) — дальше подключение этим вызовом не устанавливается (SEC-01, п.
// 2-3 в С3-позиция-ядра.md). Если пин уже обнулён (например, повторный клик
// после того, как первая попытка уже его использовала) — просит открыть
// хранилище заново, ForgetHostKey с пустым пином не зовём.
func (u *ui) confirmForgetHostKey(host, knownHostsPath string, vc *vaultCtx, connectBtn *widget.Button, info *widget.Label) {
	if vc == nil || vc.pin == nil || *vc.pin == "" {
		info.SetText("Пин уже сброшен — откройте сохранённый ключ ещё раз и подключитесь заново.")
		return
	}
	msg := widget.NewLabel(fmt.Sprintf(
		"Забыть ключ сервера %s? Утилита сотрёт сохранённый отпечаток — в хранилище и в файле known_hosts. "+
			"Подключение сейчас установлено не будет: при следующем подключении вы увидите новый отпечаток и решите, доверять ли ему. "+
			"Делайте это, только если сами переустанавливали сервер.", host,
	))
	msg.Wrapping = fyne.TextWrapWord
	dialog.NewCustomConfirm("Забыть ключ сервера?", "Забыть", "Отмена", msg, func(ok bool) {
		if !ok {
			return
		}
		pin := *vc.pin
		*vc.pin = ""
		connectBtn.Disable()
		info.SetText("Забываю ключ сервера...")
		goSafe(func() {
			err := core.ForgetHostKey(pin, vc.path, knownHostsPath, host)
			fyne.Do(func() {
				if err != nil {
					// Различение по ТИПУ ошибки (core.ErrForgetVault /
					// core.ErrForgetKnownHosts), не по тексту (ревью PR-4-Б,
					// круг 1, SEC-01 Medium: прежняя эвристика
					// strings.Contains(err.Error(), "хранилищ") приписывала
					// голую ошибку ОС от WriteVaultFile known_hosts —
					// человеку советовали удалить строку, которая ни при
					// чём, хранилище оставалось со старым отпечатком,
					// следующая попытка снова давала Mismatch → снова
					// Forget → снова тот же сбой — замкнутый круг).
					// Тексты — дополнение ядра к С3, 2026-09-15 03:20.
					var msg string
					switch {
					case errors.Is(err, core.ErrForgetVault):
						// Ничего не забыто — known_hosts не тронут, .avlt
						// остался со старым отпечатком. Повторить тот же
						// Forget можно сразу, инструкция "удалите строку"
						// здесь была бы в принципе неверной.
						msg = fmt.Sprintf("Не удалось изменить хранилище %s: %s. Ключ сервера не забыт — повторите.", vc.path, err.Error())
					case errors.Is(err, core.ErrForgetKnownHosts):
						// .avlt уже перезапечатан (отпечаток стёрт) — только
						// здесь уместна инструкция про ручную правку файла.
						msg = fmt.Sprintf("Не удалось изменить %s: %s. Удалите строку «%s» из файла вручную и подключитесь заново.", knownHostsPath, err.Error(), host)
					default:
						// Защитный рубеж — этот case не должен встречаться
						// (ForgetHostKey всегда оборачивает свою ошибку
						// одним из двух типов), но молчать о сбое нельзя.
						msg = fmt.Sprintf("Не удалось забыть ключ сервера: %s.", err.Error())
					}
					connectBtn.Enable()
					info.SetText(msg)
					return
				}
				u.win.SetContent(u.connectScreenWithStatus("Ключ сервера забыт. Нажмите «Подключиться» — будет показан новый отпечаток."))
			})
		})
	}, u.win).Show()
}

func (u *ui) connectFail(btn *widget.Button, info *widget.Label, msg string) {
	fyne.Do(func() {
		info.SetText(msg)
		btn.Enable()
	})
}

// offerSaveKey предлагает сохранить только что использованный (введённый
// вручную) ключ в зашифрованное хранилище .avlt — сразу с отпечатком ключа
// хоста, принятым при ЭТОМ подключении (hostKeyFingerprint ==
// sess.HostKeyFingerprint, Е1 задания PR-4): новое хранилище с самого начала
// v2-полноценно, второй вопрос про ключ хоста при следующем открытии не
// нужен. Отказ ("Не сохранять") просто закрывает диалог без побочных
// эффектов.
func (u *ui) offerSaveKey(key, defaultLabel, hostKeyFingerprint string) {
	labelEntry := widget.NewEntry()
	labelEntry.SetText(defaultLabel)
	pinEntry := widget.NewEntry()
	pinEntry.Password = true
	pinRepeat := widget.NewEntry()
	pinRepeat.Password = true
	bindCheck := widget.NewCheck("Привязать к этой учётке Windows (файл нельзя перенести на другой ПК или учётную запись)", nil)
	bindHint := canvas.NewText("Рекомендуется: украденный файл будет бесполезен на другом компьютере.", color.NRGBA{R: 0x80, G: 0x80, B: 0x80, A: 0xff})
	bindHint.TextSize = theme.CaptionTextSize()
	statusLabel := widget.NewLabel("")
	statusLabel.Wrapping = fyne.TextWrapWord
	mismatchLabel := canvas.NewText("Пины не совпадают", color.NRGBA{R: 0xd9, G: 0x2d, B: 0x20, A: 0xff})
	mismatchLabel.TextStyle = fyne.TextStyle{Bold: true}
	mismatchLabel.Hide()

	var d dialog.Dialog
	var saveBtn *widget.Button
	busy := false

	// checkMismatch — живая индикация по мере ввода: как только оба поля
	// пина непусты и различаются, показываем предупреждение и не даём
	// сохранить; финальная проверка (ValidatePin + совпадение) в submit()
	// остаётся как подстраховка. Пины НЕ тримятся при сравнении — пробелы
	// значимы.
	checkMismatch := func() {
		p1, p2 := pinEntry.Text, pinRepeat.Text
		mismatch := p1 != "" && p2 != "" && p1 != p2
		if mismatch {
			mismatchLabel.Show()
		} else {
			mismatchLabel.Hide()
		}
		if busy {
			return
		}
		if mismatch {
			saveBtn.Disable()
		} else {
			saveBtn.Enable()
		}
	}
	pinEntry.OnChanged = func(string) { checkMismatch() }
	pinRepeat.OnChanged = func(string) { checkMismatch() }

	submit := func() {
		if saveBtn.Disabled() {
			return
		}
		pin := pinEntry.Text
		if err := core.ValidatePin(pin); err != nil {
			statusLabel.SetText(err.Error())
			return
		}
		if pin != pinRepeat.Text {
			statusLabel.SetText("Пин-коды не совпадают.")
			return
		}
		label := strings.TrimSpace(labelEntry.Text)
		if label == "" {
			label = defaultLabel
		}
		machineBind := bindCheck.Checked
		busy = true
		saveBtn.Disable()
		statusLabel.SetText("Шифрую...")
		goSafe(func() {
			payload := core.VaultPayload{
				Label:              label,
				Key:                key,
				Created:            time.Now().Format(time.RFC3339),
				HostKeyFingerprint: hostKeyFingerprint,
			}
			data, err := core.SealVault(pin, payload, core.ProdArgonParams, machineBind)
			if err == nil {
				_, err = core.SaveVault(core.DefaultVaultDir(), data)
			}
			fyne.Do(func() {
				busy = false
				if err != nil {
					statusLabel.SetText(err.Error())
					saveBtn.Enable()
					return
				}
				d.Hide()
				n := len(core.ListVaults(core.DefaultVaultDir()))
				if u.status != nil {
					u.status.SetText(fmt.Sprintf("Ключ сохранён (Сервер %d).", n))
				}
			})
		})
	}
	saveBtn = widget.NewButtonWithIcon("Сохранить", theme.ConfirmIcon(), submit)

	// Enter-навигация: метка → пин → повтор пина → submit (как клик по кнопке)
	labelEntry.OnSubmitted = func(string) { u.win.Canvas().Focus(pinEntry) }
	pinEntry.OnSubmitted = func(string) { u.win.Canvas().Focus(pinRepeat) }
	pinRepeat.OnSubmitted = func(string) { submit() }

	content := container.NewVBox(
		widget.NewLabel("Сохранить этот ключ для быстрого подключения в следующий раз?"),
		widget.NewForm(
			widget.NewFormItem("Метка", labelEntry),
			widget.NewFormItem("Пин-код", pinEntry),
			widget.NewFormItem("Повтор пина", pinRepeat),
		),
		mismatchLabel,
		bindCheck,
		bindHint,
		statusLabel,
		saveBtn,
	)
	d = dialog.NewCustom("Сохранить ключ?", "Не сохранять", content, u.win)
	d.Resize(fyne.NewSize(460, 360))
	d.Show()
}

// ---------- главный экран ----------

func (u *ui) mainScreen() fyne.CanvasObject {
	// status и table должны существовать до protoSelect:
	// SetSelectedIndex вызывает callback, который делает refresh()
	u.status = widget.NewLabel("")
	u.status.Wrapping = fyne.TextWrapWord
	u.buildTable()

	names := make([]string, len(u.containers))
	for i, c := range u.containers {
		names[i] = guiview.ProtoLabel(c) // единственное место этой подписи (Д2, Э1)
	}
	u.protoSelect = widget.NewSelect(names, func(_ string) {
		i := u.protoSelect.SelectedIndex()
		if i >= 0 && i < len(u.containers) {
			u.cur = &u.containers[i]
			u.selectedRow = -1
			// выделение относилось к строке из СТАРОГО списка — в новом
			// списке той же строки может не быть (или там другой клиент)
			u.table.UnselectAll()
			u.refresh()
		}
	})
	for i := range u.containers {
		if &u.containers[i] == u.cur {
			u.protoSelect.SetSelectedIndex(i)
		}
	}

	server := widget.NewLabel(fmt.Sprintf("Сервер: %s@%s", u.sess.Creds.User, u.sess.Creds.Host))

	refreshBtn := widget.NewButtonWithIcon("Обновить", theme.ViewRefreshIcon(), func() { u.refresh() })
	addBtn := widget.NewButtonWithIcon("Создать", theme.ContentAddIcon(), func() { u.addDialog() })
	renameBtn := widget.NewButtonWithIcon("Переименовать", theme.DocumentCreateIcon(), func() { u.renameSelected() })
	toggleBtn := widget.NewButtonWithIcon("Вкл/Выкл", theme.MediaPauseIcon(), func() { u.toggleSelected() })
	regenBtn := widget.NewButtonWithIcon("Перевыпустить", theme.MediaReplayIcon(), func() { u.regenerateSelected() })
	delBtn := widget.NewButtonWithIcon("Удалить", theme.DeleteIcon(), func() { u.deleteSelected() })
	addBtn.Importance = widget.HighImportance
	u.refreshBtn, u.addBtn, u.renameBtn, u.toggleBtn, u.regenBtn, u.delBtn = refreshBtn, addBtn, renameBtn, toggleBtn, regenBtn, delBtn

	top := container.NewBorder(nil, nil,
		container.NewHBox(server, widget.NewLabel("Протокол:"), u.protoSelect),
		container.NewHBox(refreshBtn, addBtn, renameBtn, toggleBtn, regenBtn, delBtn),
	)
	return container.NewBorder(top, u.status, nil, nil, u.table)
}

// tableHeaders — колонки таблицы пользователей. columnSort[i] — сортируемый
// ключ этой колонки, или core.SortNone, если колонка не сортируется (клик
// игнорируется): "#" (презентационный номер строки) и "Публичный ключ".
// ---------- персистентность сортировки таблицы (ui.json) ----------
//
// Состояние сортировки (какая колонка primary/secondary и в каком
// направлении) хранится в ui.json рядом с exe, в той же портативной папке
// "Настройки", что vault-файлы и throttle.json — НЕ в fyne app.Preferences
// (тот пишет в %APPDATA% и ломает портативность). Формат — плоский JSON,
// запись атомарна (tmp+rename). Битый/отсутствующий файл — тихий откат к
// дефолту (Активность, по убыванию), без паники.

type sortStateJSON struct {
	Primary      string `json:"primary"`
	PrimaryDir   string `json:"primaryDir"`
	Secondary    string `json:"secondary"`
	SecondaryDir string `json:"secondaryDir"`
}

var sortColumnNames = map[core.SortColumn]string{
	core.SortNone:          "none",
	core.SortByName:        "name",
	core.SortByCreated:     "created",
	core.SortByActivityCol: "activity",
	core.SortByTraffic:     "traffic",
}

func sortColumnFromName(s string) (core.SortColumn, bool) {
	for col, name := range sortColumnNames {
		if name == s {
			return col, true
		}
	}
	return core.SortNone, false
}

func sortDirName(d core.SortDir) string {
	if d == core.Desc {
		return "desc"
	}
	return "asc"
}

func sortDirFromName(s string) core.SortDir {
	if s == "desc" {
		return core.Desc
	}
	return core.Asc
}

func uiStatePath() string {
	return filepath.Join(core.DefaultVaultDir(), "ui.json")
}

// loadSortState читает ui.json; при отсутствии файла, битом JSON или
// нераспознанной primary-колонке возвращает дефолт: Активность по убыванию,
// без secondary (то же поведение, что было до появления сортировки по клику).
func loadSortState() (primary core.SortColumn, primaryDir core.SortDir, secondary core.SortColumn, secondaryDir core.SortDir) {
	defPrimary, defPrimaryDir, defSecondary, defSecondaryDir := core.SortByActivityCol, core.Desc, core.SortNone, core.Asc
	data, err := os.ReadFile(uiStatePath())
	if err != nil {
		return defPrimary, defPrimaryDir, defSecondary, defSecondaryDir
	}
	var st sortStateJSON
	if err := json.Unmarshal(data, &st); err != nil {
		return defPrimary, defPrimaryDir, defSecondary, defSecondaryDir
	}
	primary, ok := sortColumnFromName(st.Primary)
	if !ok || primary == core.SortNone {
		return defPrimary, defPrimaryDir, defSecondary, defSecondaryDir
	}
	secondary, ok = sortColumnFromName(st.Secondary)
	if !ok {
		secondary = core.SortNone
	}
	return primary, sortDirFromName(st.PrimaryDir), secondary, sortDirFromName(st.SecondaryDir)
}

// saveSortState записывает текущее состояние сортировки атомарно (tmp+rename).
// Ошибка молча логируется через crash.log не пишется — это некритичная UX-настройка,
// поэтому просто игнорируем ошибку записи (нет диалога, не мешаем работе).
func saveSortState(primary core.SortColumn, primaryDir core.SortDir, secondary core.SortColumn, secondaryDir core.SortDir) {
	dir := core.DefaultVaultDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	st := sortStateJSON{
		Primary:      sortColumnNames[primary],
		PrimaryDir:   sortDirName(primaryDir),
		Secondary:    sortColumnNames[secondary],
		SecondaryDir: sortDirName(secondaryDir),
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	path := uiStatePath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
	}
}

var tableHeaders = []string{"#", "Имя", "Создан", "Активность", "Трафик ↓/↑", "Публичный ключ"}
var tableColumnSort = []core.SortColumn{
	core.SortNone, core.SortByName, core.SortByCreated, core.SortByActivityCol, core.SortByTraffic, core.SortNone,
}

// tappableLabel — widget.Label, которую можно кликнуть. В Fyne 2.7
// widget.Table не даёт штатного колбэка на клик по заголовку колонки:
// Table.Tapped() резолвит только ячейки данных (columnAt/rowAt), а тап по
// строке заголовка возвращает noCellMatch, если StickyRowCount не настроен
// (по умолчанию для NewTableWithHeaders — не настроен). Рабочий способ,
// подтверждённый исходниками fyne.io/fyne/v2/widget (Table.CreateHeader
// принимает произвольный fyne.CanvasObject) — сделать сам объект заголовка
// кликабельным виджетом: тогда драйвер Fyne при хит-тесте находит именно
// его (самый вложенный Tappable под курсором), а не Table.Tapped.
type tappableLabel struct {
	widget.Label
	onTap func()
}

func newTappableLabel() *tappableLabel {
	l := &tappableLabel{}
	l.TextStyle = fyne.TextStyle{Bold: true}
	l.ExtendBaseWidget(l)
	return l
}

func (l *tappableLabel) Tapped(*fyne.PointEvent) {
	if l.onTap != nil {
		l.onTap()
	}
}

func (l *tappableLabel) TappedSecondary(*fyne.PointEvent) {}

func (u *ui) buildTable() {
	headers := tableHeaders
	widths := []float32{40, 280, 165, 140, 150, 280}

	u.table = widget.NewTableWithHeaders(
		func() (int, int) { return len(u.clients), len(headers) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.TableCellID, o fyne.CanvasObject) {
			l := o.(*widget.Label)
			l.TextStyle = fyne.TextStyle{}
			if id.Row >= len(u.clients) {
				l.SetText("")
				return
			}
			cl := u.clients[id.Row]
			switch id.Col {
			case 0:
				l.SetText(fmt.Sprintf("%d", id.Row+1))
			case 1:
				l.TextStyle = fyne.TextStyle{Bold: true, Italic: cl.Disabled()}
				l.SetText(cl.Name())
			case 2:
				created := cl.Created()
				if r := []rune(created); len(r) > 19 {
					created = string(r[:19])
				}
				l.SetText(created)
			case 3:
				// Все ветки (в том числе «запрос активности не удался» —
				// A1, место № 2) — в guiview.ActivityText, рядом с текстом
				// трафика: в cmd/gui строку не проверяет ни один тест.
				l.SetText(guiview.ActivityText(u.canManage, u.activityFailed, cl.Disabled(), u.handshakes[cl.ClientID]))
			case 4:
				l.SetText(guiview.TrafficText(u.canManage, u.statsFailed, u.peerStats[cl.ClientID]))
			case 5:
				l.SetText(cl.ClientID)
			}
		},
	)
	u.table.CreateHeader = func() fyne.CanvasObject {
		return newTappableLabel()
	}
	u.table.UpdateHeader = func(id widget.TableCellID, o fyne.CanvasObject) {
		hl := o.(*tappableLabel)
		if id.Row >= 0 || id.Col < 0 || id.Col >= len(headers) {
			hl.SetText("")
			hl.onTap = nil
			return
		}
		text := headers[id.Col]
		col := tableColumnSort[id.Col]
		if col != core.SortNone && col == u.sortPrimary {
			if u.sortPrimaryDir == core.Desc {
				text += " ▼"
			} else {
				text += " ▲"
			}
		}
		hl.SetText(text)
		if col == core.SortNone {
			hl.onTap = nil
		} else {
			colCopy := col
			hl.onTap = func() { u.onHeaderTapped(colCopy) }
		}
	}
	for i, w := range widths {
		u.table.SetColumnWidth(i, w)
	}
	u.table.OnSelected = func(id widget.TableCellID) {
		u.selectedRow = id.Row
	}
}

// onHeaderTapped обрабатывает клик по заголовку сортируемой колонки: тот же
// столбец — меняем направление; другой столбец — он становится новым primary
// (asc по умолчанию), а прежний primary сдвигается в secondary (tie-breaker,
// сохраняя своё последнее направление). Пересортировка — по уже загруженным
// u.clients/u.peerStats, без обращения к серверу.
func (u *ui) onHeaderTapped(col core.SortColumn) {
	if u.sortPrimary == col {
		if u.sortPrimaryDir == core.Asc {
			u.sortPrimaryDir = core.Desc
		} else {
			u.sortPrimaryDir = core.Asc
		}
	} else {
		u.sortSecondary = u.sortPrimary
		u.sortSecondaryDir = u.sortPrimaryDir
		u.sortPrimary = col
		u.sortPrimaryDir = core.Asc
	}
	saveSortState(u.sortPrimary, u.sortPrimaryDir, u.sortSecondary, u.sortSecondaryDir)
	u.applySort()
	if u.table != nil {
		u.table.Refresh()
	}
}

// applySort пересортировывает уже загруженный u.clients по текущему
// primary/secondary — общая точка применения сортировки и для refresh(),
// и для клика по заголовку (сеть не трогаем, сортируем то, что уже есть).
func (u *ui) applySort() {
	core.SortClientsMultiKey(u.clients, u.peerStats, u.sortPrimary, u.sortPrimaryDir, u.sortSecondary, u.sortSecondaryDir)
}

// setBusy блокирует (true) или разблокирует (false) все шесть кнопок главного
// экрана и protoSelect на время серверной операции — от нажатия до fyne.Do с
// результатом (BE-01, ревью, Е2). Мьютекс в core защищает данные сервера, но
// не UI: без этой блокировки повторный клик, например, по "Удалить" запускает
// вторую операцию поверх ещё не завершившейся первой — со уже устаревшим
// selectedRow.
func (u *ui) setBusy(busy bool) {
	if b := u.refreshBtn; b != nil {
		if busy {
			b.Disable()
		} else {
			b.Enable()
		}
	}
	// Кнопки управления пользователями: во время операции — всегда Disable()
	// (как и раньше); по её завершении — Enable() только если протокол
	// управляемый (u.canManage, решение guiview.ViewState для u.cur — Д3).
	// Для !canManage они остаются недоступны ПОСТОЯННО, а не только на время
	// сетевого запроса — иначе после refresh() кнопки для XRay/DNS снова
	// становились бы кликабельными, и отказ был бы виден только по клику
	// (диалог-заглушка в обработчике), а не по внешнему виду кнопки.
	for _, b := range []*widget.Button{u.addBtn, u.renameBtn, u.toggleBtn, u.regenBtn, u.delBtn} {
		if b == nil {
			continue
		}
		if busy || !u.canManage {
			b.Disable()
		} else {
			b.Enable()
		}
	}
	if u.protoSelect == nil {
		return
	}
	if busy {
		u.protoSelect.Disable()
	} else {
		u.protoSelect.Enable()
	}
}

// refresh перечитывает пользователей с сервера (в фоне) для ЛЮБОГО
// amnezia-* контейнера, управляемого или нет (FIX-VIEW: до этой правки
// !Managed обрывался ранним guard'ом — "LoadClients для !Managed падает",
// предпосылка не проверялась и была неверна; см. секцию А задания).
//
// refresh() НЕ содержит собственных условий по Container.Managed (Э3а,
// решение ядра 15.09): что грузить (LoadClientsView — всегда), нужна ли
// серверная статистика (wg show), доступно ли управление и что написать в
// статусе — решает ТОЛЬКО guiview.ViewState по результату LoadClientsView.
// Так табличный тест на подмену ViewState (Э3б) реально ловит регресс: если
// бы refresh() держал свой параллельный guard "if !cur.Managed", подмена в
// guiview его бы не увидела.
//
// Снимок cur делается дважды: один раз здесь (для запроса к нужному
// протоколу) и повторно сверяется с u.cur внутри fyne.Do — если пользователь
// успел переключить протокол, пока запрос летел по сети, устаревший ответ
// отбрасывается и не перерисовывает таблицу поверх уже актуальных данных.
// setBusy(false) снимается безусловно при завершении КАЖДОГО запроса (в т.ч.
// устаревшего) — если протокол переключили во время загрузки, второй
// (актуальный) refresh() всё равно уже успел выставить busy=true заново
// своим собственным вызовом в начале функции.
func (u *ui) refresh() {
	if u.table == nil || u.status == nil {
		return // экран ещё строится
	}
	cur := u.cur
	u.setBusy(true)
	u.status.SetText("Загружаю список пользователей...")
	goSafe(func() {
		clients, existed, err := u.sess.LoadClientsView(cur)
		view := guiview.ViewState(*cur, clients, existed, err)

		// Ошибки обоих запросов статистики НЕ ОТБРАСЫВАЮТСЯ (A1, место № 2):
		// прежде `if s, statErr := …; statErr == nil { stats = s }` не имел
		// ветви на ошибку, stats оставалась пустой картой, и ниже она
		// читалась как измеренный нуль трафика.
		var hs map[string]string
		var hsErr, statsErr error
		stats := map[string]core.PeerStat{}
		if view.LoadStats {
			hs, hsErr = u.sess.GetHandshakes(cur)
			if s, peerErr := u.sess.GetPeerStats(cur); peerErr != nil {
				statsErr = peerErr
			} else {
				stats = s
			}
		}

		fyne.Do(func() {
			// setBusy(false) — определяет ТЕКУЩЕЕ u.canManage (обновлённое
			// ниже, если ответ не устарел) и лишь потом снимает занятость —
			// поэтому вызван через defer, а не первой строкой: иначе кнопки
			// на мгновение включались бы по CanManage от ПРЕДЫДУЩЕГО
			// протокола (BE-01, ревью, Medium).
			defer u.setBusy(false)
			if cur != u.cur {
				return // протокол сменился ещё раз, пока шёл запрос — ответ устарел
			}
			u.canManage = view.CanManage
			if err != nil && view.CanManage {
				// Управляемый протокол, ошибка чтения: поведение НЕ меняем
				// относительно d6b3a5a/8c20da1 (Г2 п.5) — таблица сохраняет
				// последние успешно загруженные данные, меняется только
				// статус. A1, место № 4: статус теперь ГОВОРИТ, что данные
				// от прошлого чтения (guiview.View.StaleShown и текст
				// Status), таблица по-прежнему не очищается и кнопки не
				// блокируются. Диалог удаления при этом снимком больше не
				// питается — он спрашивает сервер при открытии
				// (deleteSelected), поэтому устаревание u.handshakes
				// решения об удалении больше не определяет. Для непроверяемых протоколов ошибка/отсутствие
				// файла — другое решение (Д3, П4: u.clients = nil, без
				// числа в статусе) — это ветка ниже (err или !existed
				// естественно даёт clients == nil от LoadClientsView).
				u.status.SetText(view.Status)
				return
			}
			u.clients = clients
			u.handshakes = hs
			u.peerStats = stats
			u.activityFailed = hsErr != nil
			u.statsFailed = statsErr != nil
			// применяем текущую (сохранённую/выбранную кликом по заголовку)
			// сортировку — переключение протокола не должно сбрасывать её на дефолт
			u.applySort()
			// widget.Table в Fyne после смены данных иногда не перерисовывает
			// видимые (уже отрисованные ранее) ячейки, если таблица осталась
			// проскроллена не в начало — без явного Refresh+ScrollToTop
			// таблица выглядит пустой, пока пользователь не проскроллит вручную.
			u.table.Refresh()
			u.table.ScrollToTop()
			u.status.SetText(view.Status)
		})
	})
}

// ---------- «Показать изменения» (Е2) ----------

// diffOrNote — текст для diff-окна: пустой diff означает "файл не меняется"
// (core.Plan.Diff, например wg0.conf при RenameUser) — печатать это явно,
// иначе пустое поле рядом с непустым выглядит как будто что-то сломалось.
func diffOrNote(diff string) string {
	if diff == "" {
		return "(без изменений)"
	}
	return diff
}

// newDiffGrid строит widget.TextGrid (моноширинный по устройству — UI-01,
// ревью, High: widget.MultiLineEntry монoширинность не гарантировал) с
// построчной раскраской: "+" — цвет успеха темы, "-" — цвет ошибки темы (оба
// автоматически согласованы со светлой/тёмной темой в МОМЕНТ ПОСТРОЕНИЯ).
// TextGrid, в отличие от Entry, read-only по своей природе — Disable() не
// нужен (UI-01, ревью, Medium: единственное содержимое окна не должно
// выглядеть приглушённым).
//
// Названное решение (UI-01, ревью круга 2, Low): theme.Color() вычисляется
// ОДИН раз здесь, а не через подписку на смену темы — если пользователь
// переключит тему ОС/приложения, пока diff-окно открыто, раскраска этого
// открытого окна останется от прежней темы до его переоткрытия. Осознанно не
// чиним: diff-окно — короткоживущее модальное окно (секунды-минуты между
// «Показать изменения» и «Применить»/«Закрыть»), а подписка TextGrid на
// fyne.Settings().AddChangeListener ради этого случая добавляет постоянно
// живущий колбэк и его отписку по закрытии диалога — сложность несоразмерна
// вероятности "открыл diff-окно и посреди этого переключил системную тему".
func newDiffGrid(diff string) *widget.TextGrid {
	grid := widget.NewTextGridFromString(diffOrNote(diff))
	if diff == "" {
		return grid
	}
	addStyle := &widget.CustomTextGridStyle{FGColor: theme.Color(theme.ColorNameSuccess)}
	delStyle := &widget.CustomTextGridStyle{FGColor: theme.Color(theme.ColorNameError)}
	for row := range grid.Rows {
		switch {
		case strings.HasPrefix(grid.RowText(row), "+"):
			grid.SetRowStyle(row, addStyle)
		case strings.HasPrefix(grid.RowText(row), "-"):
			grid.SetRowStyle(row, delStyle)
		}
	}
	return grid
}

// newPlanStatusLabel — надпись прогресса построения плана ВНУТРИ диалога
// подтверждения (UX-01, ревью, Medium): пока «Показать изменения» строит
// план в фоне, сам диалог подтверждения — модальное окно, и статус главного
// экрана (u.status) им закрыт и не виден пользователю.
func newPlanStatusLabel() *widget.Label {
	l := widget.NewLabel("")
	l.Wrapping = fyne.TextWrapWord
	return l
}

// isCASRefusal распознаёт отказ CAS (core/txn.go: checkCAS/casCheckFile) через
// errors.Is(err, core.ErrCASMismatch) (review PR-2, carryover 1 — раньше
// распознавание шло по русским подстрокам текста ошибки, что ломалось при
// любой правке формулировки). В обоих случаях (расхождение контрольной
// суммы и невозможность её проверить) план построен по УЖЕ неактуальному
// чтению, поэтому его нельзя молча повторно "Применить" — план устарел, а не
// произошёл преходящий сбой вроде сети.
func isCASRefusal(err error) bool {
	return errors.Is(err, core.ErrCASMismatch)
}

// showDiffWindow показывает окно с построчными diff'ами обоих файлов плана
// и кнопкой «Применить» (дублирующая «Закрыть» кнопка — встроенный dismiss
// диалога). «Применить» вызывает sess.Apply(plan) ТОГО ЖЕ плана, что был
// построен Plan*-вызовом до открытия окна: CAS поймает, если сервер
// изменился, пока окно было открыто — в этом случае (isCASRefusal) кнопку
// «Применить» обратно не включаем (UX-01, ревью, High): план устарел, повтор
// того же плана всегда провалится тем же образом, нужно закрыть окно и
// начать заново. Для прочих ошибок (сеть, права и т.п.) повтор осмыслен —
// кнопка включается снова. При успехе onApplied получает результат Apply
// (nil для всех действий, кроме add/rekey) — вызывающий код сам решает, что
// делать дальше (showConfigDialog, refresh, текст статуса), диалог
// закрывается сам.
func (u *ui) showDiffWindow(title string, plan *core.Plan, onApplied func(*core.NewUser)) {
	wgDiff, tblDiff := plan.Diff()
	wgGrid := newDiffGrid(wgDiff)
	tblGrid := newDiffGrid(tblDiff)

	statusLabel := widget.NewLabel("")
	statusLabel.Wrapping = fyne.TextWrapWord

	var d dialog.Dialog
	var applyBtn *widget.Button
	applyBtn = widget.NewButtonWithIcon("Применить", theme.ConfirmIcon(), func() {
		// A3а, ШЕСТАЯ точка записи: предупреждение о гонке непосредственно
		// перед sess.Apply. Окно изменений общее для всех пяти операций, и
		// путь "сначала посмотреть, что изменится, потом применить" —
		// единственный, которым идёт самый осторожный человек. Без этого
		// вызова именно он писал бы на сервер без предупреждения.
		// При "Отмена" окно изменений остаётся открытым, кнопка "Применить"
		// не Disable()-ится (её Disable стоит ВНУТРИ) — человек возвращается
		// к тому же плану и закрывает окно сам кнопкой "Закрыть".
		u.confirmRaceWarning(guiview.OpApplyPlan, func() {
			applyBtn.Disable()
			u.setBusy(true)
			statusLabel.Importance = widget.MediumImportance
			statusLabel.SetText("Применяю...")
			goSafe(func() {
				nu, err := u.sess.Apply(plan)
				fyne.Do(func() {
					u.setBusy(false)
					if err != nil {
						if isCASRefusal(err) {
							// Цвет отказа (UI-01, ревью круга 2, Low) — состояние
							// должно отличаться от "Применяю..." не только
							// словами: DangerImportance == theme.ColorNameError.
							statusLabel.Importance = widget.DangerImportance
							statusLabel.SetText("План устарел: сервер изменился, пока окно было открыто. Закройте окно и повторите операцию.")
							return // applyBtn остаётся Disabled — повтор того же плана бессмыслен
						}
						statusLabel.Importance = widget.MediumImportance
						statusLabel.SetText("")
						applyBtn.Enable()
						dialog.ShowError(err, u.win)
						return
					}
					d.Hide()
					if onApplied != nil {
						onApplied(nu)
					}
				})
			})
		})
	})

	// container.NewScroll — TextGrid не имеет собственной прокрутки (UI-01,
	// ревью, High): без неё длинный diff обрезался без доступа к остатку, ни
	// по вертикали, ни по горизонтали. Не редкий случай — lineDiff не
	// минимален, и при rekey/удалении раннего peer'а в "изменившуюся"
	// середину попадают все последующие блоки [Peer] (~4 строки на
	// пользователя); на сервере с 20+ пользователями это сотни строк в
	// панели высотой ~250px. container.NewScroll даёт прокрутку в обе
	// стороны по умолчанию (ScrollBoth) — низ и правый край доступны.
	content := container.NewBorder(
		nil,
		container.NewVBox(applyBtn, statusLabel),
		nil, nil,
		container.NewVSplit(
			container.NewBorder(
				widget.NewLabelWithStyle(plan.Container.Dir+"/wg0.conf", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
				nil, nil, nil, container.NewScroll(wgGrid)),
			container.NewBorder(
				widget.NewLabelWithStyle(plan.Container.Dir+"/clientsTable", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
				nil, nil, nil, container.NewScroll(tblGrid)),
		),
	)
	d = dialog.NewCustom("Изменения перед применением: "+title, "Закрыть", content, u.win)
	d.Resize(fyne.NewSize(700, 520))
	d.Show()
}

// ---------- предупреждение о гонке при одновременной работе (A3а) ----------

// warnServerID — то, что для предупреждения считается "сервером": отпечаток
// ключа хоста текущего соединения. Он уникален для сервера и уже показывается
// человеку в диалогах доверия ключу, то есть секретом не является; здесь он
// только сравнивается и никуда не печатается. При переподключении к другому
// серверу отпечаток другой — предупреждение показывается снова.
// Два следствия этого выбора, записанные явно, чтобы их потом не "починили"
// как дефекты (наблюдения UX-01, 19.09.2026):
//
//  1. СМЕНА КОНТЕЙНЕРА/ПРОТОКОЛА на том же сервере предупреждения НЕ
//     повторяет — отпечаток тот же. Это ВЕРНО и сделано намеренно: гонка
//     живёт на сервере (один SSH, одни файлы), а не на контейнере, и второе
//     предупреждение при переключении протокола было бы шумом.
//  2. ОТКЛЮЧИТЬСЯ И ПОДКЛЮЧИТЬСЯ К ТОМУ ЖЕ СЕРВЕРУ заново без перезапуска
//     программы — предупреждения не будет: warnSess живёт на ui и переживает
//     экран подключения. Решение владельца "один раз за запуск" соблюдено
//     дословно; это единственное место, где "запуск" и "сеанс работы с
//     сервером" расходятся. Менять — только решением владельца.
func (u *ui) warnServerID() string {
	if u.sess == nil {
		return ""
	}
	return u.sess.HostKeyFingerprint
}

// confirmRaceWarning — предупреждение о гонке перед необратимой операцией op:
// вызывает do ТОЛЬКО если человек согласился продолжить.
//
// Почему вызов стоит в обработчике кнопки, а не при открытии формы: у каждой
// операции две точки, обе называются "перед операцией", и при частоте "один
// раз за запуск" показ на открытии формы отделил бы предупреждение от записи
// минутой заполнения полей — человек нажал бы "Создать", и в момент, когда
// данные уходят на сервер, он был бы уже не предупреждён и в этот запуск не
// был бы. Реальное действие — запись, а не открытие окна.
//
// "Отмена": do не вызывается, core не трогается, на сервере и локально не
// меняется ничего, и ФОРМА ОПЕРАЦИИ ОСТАЁТСЯ ОТКРЫТОЙ — человек возвращается
// к тому, что заполнял, и закрывает её сам, если захочет. Закрывать за
// человека заполненную форму — потеря его работы, а предупреждение заведено
// ровно ради того, чтобы работу не терять.
//
// Ни текста, ни подписей кнопок здесь нет намеренно: всё приходит из
// internal/guiview, потому что в cmd/gui нет ни одного теста и запуск GUI
// требует дисплея — литерал здесь был бы строкой, которую не видит ни одна
// проверка. За этим следит сторож internal/guiview/warnguard_test.go.
func (u *ui) confirmRaceWarning(op guiview.Op, do func()) {
	server := u.warnServerID()
	if !guiview.WarnDecision(op, u.warnFreq, u.warnSess, server) {
		do()
		return
	}

	body := widget.NewLabel(guiview.WarningBody())
	body.Wrapping = fyne.TextWrapWord

	var d dialog.Dialog
	contBtn := widget.NewButtonWithIcon(guiview.WarnContinueLabel(), theme.ConfirmIcon(), func() {
		// Сеанс отмечается только здесь, на "Продолжить": человек, который
		// прочитал и отказался, при следующей попытке увидит предупреждение
		// снова — он до записи так и не дошёл.
		u.warnSess = guiview.AfterWarned(server)
		d.Hide()
		do()
	})
	contBtn.Importance = widget.HighImportance

	content := container.NewVBox(body, container.NewHBox(contBtn))
	d = dialog.NewCustom(guiview.WarningTitle(), guiview.WarnCancelLabel(), content, u.win)
	d.Resize(fyne.NewSize(560, 300))
	d.Show()
}

// ---------- создание ----------

func (u *ui) addDialog() {
	if !u.cur.Managed {
		dialog.ShowInformation("Недоступно",
			fmt.Sprintf("Создание пользователей для %s не поддерживается.", u.cur.Proto), u.win)
		return
	}
	entry := widget.NewEntry()
	entry.SetPlaceHolder("Иванов Иван")
	form := widget.NewForm(widget.NewFormItem("Имя", entry))

	var d dialog.Dialog
	onCreated := func(nu *core.NewUser) {
		u.status.SetText(fmt.Sprintf("Пользователь %q создан (IP %s).", nu.Name, nu.IP))
		u.showConfigDialog(nu, "создан")
		u.refresh()
	}
	create := func() {
		name := strings.TrimSpace(entry.Text)
		if name == "" {
			return
		}
		// A3а: предупреждение о гонке непосредственно перед записью на
		// сервер. При "Отмена" форма остаётся открытой — d.Hide() внутри.
		u.confirmRaceWarning(guiview.OpAddUser, func() {
			d.Hide()
			u.setBusy(true)
			u.status.SetText(fmt.Sprintf("Создаю пользователя %q...", name))
			goSafe(func() {
				nu, err := u.sess.AddUser(u.cur, name)
				fyne.Do(func() {
					if err != nil {
						u.setBusy(false)
						u.status.SetText("")
						dialog.ShowError(err, u.win)
						return
					}
					onCreated(nu)
				})
			})
		})
	}
	createBtn := widget.NewButtonWithIcon("Создать", theme.ConfirmIcon(), create)
	createBtn.Importance = widget.HighImportance
	planStatus := newPlanStatusLabel()
	diffBtn := widget.NewButton("Показать изменения", func() {
		name := strings.TrimSpace(entry.Text)
		if name == "" {
			return
		}
		u.setBusy(true)
		planStatus.SetText("Считаю изменения...")
		goSafe(func() {
			plan, err := u.sess.PlanAddUser(u.cur, name)
			fyne.Do(func() {
				u.setBusy(false)
				planStatus.SetText("")
				if err != nil {
					dialog.ShowError(err, u.win)
					return
				}
				u.showDiffWindow(fmt.Sprintf("создание %q", name), plan, func(nu *core.NewUser) {
					d.Hide()
					onCreated(nu)
				})
			})
		})
	})
	// единственное поле формы — Enter эквивалентен нажатию "Создать"
	entry.OnSubmitted = func(string) { create() }
	content := container.NewVBox(form, container.NewHBox(createBtn, diffBtn), planStatus)
	d = dialog.NewCustom("Новый пользователь", "Отмена", content, u.win)
	d.Resize(fyne.NewSize(420, 200))
	d.Show()
}

// writeConfigFile сохраняет клиентский конфиг в "Конфигурации\<Имя>.conf"
// (перезаписывая, если уже есть) и возвращает абсолютный путь.
func (u *ui) writeConfigFile(nu *core.NewUser) (string, error) {
	if err := os.MkdirAll("Конфигурации", 0755); err != nil {
		return "", err
	}
	fileName := filepath.Join("Конфигурации", core.SanitizeName(nu.Name)+".conf")
	if err := os.WriteFile(fileName, []byte(nu.Config), 0600); err != nil {
		return "", err
	}
	abs, _ := filepath.Abs(fileName)
	return abs, nil
}

// showConfigDialog показывает готовый клиентский конфиг в виде QR-кода
// (для сканирования приложением AmneziaWG на телефоне) и кнопку сохранения
// .conf на диск. Используется и после создания нового пользователя, и после
// перевыпуска (re-key) — verb это причастие в диалоге ("создан"/"перевыпущен").
func (u *ui) showConfigDialog(nu *core.NewUser, verb string) {
	var qrObj fyne.CanvasObject
	if png, err := core.QRPNG(nu.Config, 256); err == nil {
		res := fyne.NewStaticResource(core.SanitizeName(nu.Name)+"-qr.png", png)
		img := canvas.NewImageFromResource(res)
		img.FillMode = canvas.ImageFillOriginal
		img.SetMinSize(fyne.NewSize(256, 256))
		qrObj = img
	} else {
		l := widget.NewLabel("Не удалось построить QR-код: " + err.Error())
		l.Wrapping = fyne.TextWrapWord
		qrObj = l
	}

	savedLabel := widget.NewLabel("")
	savedLabel.Wrapping = fyne.TextWrapWord

	var saveBtn *widget.Button
	saveBtn = widget.NewButtonWithIcon("Сохранить .conf", theme.DocumentSaveIcon(), func() {
		abs, err := u.writeConfigFile(nu)
		if err != nil {
			dialog.ShowError(err, u.win)
			return
		}
		saveBtn.Disable()
		savedLabel.SetText("Сохранено: " + abs)
		if u.status != nil {
			u.status.SetText(fmt.Sprintf("Конфиг сохранён: %s", abs))
		}
	})

	hint := widget.NewLabel("Отсканируйте QR в приложении AmneziaWG на телефоне или импортируйте файл.")
	hint.Wrapping = fyne.TextWrapWord

	content := container.NewVBox(
		widget.NewLabelWithStyle(fmt.Sprintf("Пользователь %q %s (IP %s).", nu.Name, verb, nu.IP), fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		container.NewCenter(qrObj),
		hint,
		saveBtn,
		savedLabel,
	)
	d := dialog.NewCustom("Конфиг готов", "Закрыть", content, u.win)
	d.Resize(fyne.NewSize(380, 480))
	d.Show()
}

// ---------- переименование ----------

func (u *ui) renameSelected() {
	if !u.cur.Managed {
		dialog.ShowInformation("Недоступно",
			fmt.Sprintf("Переименование пользователей для %s не поддерживается.", u.cur.Proto), u.win)
		return
	}
	idx := u.selectedRow
	if idx < 0 || idx >= len(u.clients) {
		dialog.ShowInformation("Не выбран пользователь", "Выберите строку в таблице.", u.win)
		return
	}
	victim := u.clients[idx]
	entry := widget.NewEntry()
	entry.SetText(victim.Name())
	form := widget.NewForm(widget.NewFormItem("Новое имя", entry))

	var d dialog.Dialog
	onRenamed := func(newName string) {
		u.selectedRow = -1
		u.status.SetText(fmt.Sprintf("Пользователь %q переименован в %q.", victim.Name(), newName))
		u.refresh()
	}
	save := func() {
		newName := strings.TrimSpace(entry.Text)
		if newName == "" {
			return
		}
		// A3а: предупреждение о гонке непосредственно перед записью на
		// сервер. При "Отмена" форма остаётся открытой — d.Hide() внутри.
		u.confirmRaceWarning(guiview.OpRenameUser, func() {
			d.Hide()
			u.setBusy(true)
			u.status.SetText(fmt.Sprintf("Переименовываю %q...", victim.Name()))
			goSafe(func() {
				err := u.sess.RenameUser(u.cur, victim.ClientID, newName)
				fyne.Do(func() {
					if err != nil {
						u.setBusy(false)
						u.status.SetText("")
						dialog.ShowError(err, u.win)
						return
					}
					onRenamed(newName)
				})
			})
		})
	}
	saveBtn := widget.NewButtonWithIcon("Сохранить", theme.ConfirmIcon(), save)
	saveBtn.Importance = widget.HighImportance
	planStatus := newPlanStatusLabel()
	diffBtn := widget.NewButton("Показать изменения", func() {
		newName := strings.TrimSpace(entry.Text)
		if newName == "" {
			return
		}
		u.setBusy(true)
		planStatus.SetText("Считаю изменения...")
		goSafe(func() {
			plan, err := u.sess.PlanRename(u.cur, victim.ClientID, newName)
			fyne.Do(func() {
				u.setBusy(false)
				planStatus.SetText("")
				if err != nil {
					dialog.ShowError(err, u.win)
					return
				}
				u.showDiffWindow(fmt.Sprintf("переименование %q → %q", victim.Name(), newName), plan, func(_ *core.NewUser) {
					d.Hide()
					onRenamed(newName)
				})
			})
		})
	})
	// единственное поле формы — Enter эквивалентен нажатию "Сохранить"
	entry.OnSubmitted = func(string) { save() }
	content := container.NewVBox(form, container.NewHBox(saveBtn, diffBtn), planStatus)
	d = dialog.NewCustom(fmt.Sprintf("Переименовать %q", victim.Name()), "Отмена", content, u.win)
	d.Resize(fyne.NewSize(420, 200))
	d.Show()
}

// ---------- отключение/включение ----------

func (u *ui) toggleSelected() {
	if !u.cur.Managed {
		dialog.ShowInformation("Недоступно",
			fmt.Sprintf("Управление пользователями для %s не поддерживается.", u.cur.Proto), u.win)
		return
	}
	idx := u.selectedRow
	if idx < 0 || idx >= len(u.clients) {
		dialog.ShowInformation("Не выбран пользователь", "Выберите строку в таблице.", u.win)
		return
	}
	victim := u.clients[idx]
	enable := victim.Disabled()
	title := "Отключить пользователя?"
	verb := "Отключаю"
	verbDone := "отключён"
	noun := "отключение"
	if enable {
		title = "Включить пользователя?"
		verb = "Включаю"
		verbDone = "включён"
		noun = "включение"
	}

	var d dialog.Dialog
	onToggled := func() {
		u.selectedRow = -1
		u.status.SetText(fmt.Sprintf("Пользователь %q %s.", victim.Name(), verbDone))
		u.refresh()
	}
	apply := func() {
		// A3а: предупреждение о гонке непосредственно перед записью на
		// сервер. При "Отмена" форма остаётся открытой — d.Hide() внутри.
		u.confirmRaceWarning(guiview.OpToggleUser, func() {
			d.Hide()
			u.setBusy(true)
			u.status.SetText(fmt.Sprintf("%s %q...", verb, victim.Name()))
			goSafe(func() {
				err := u.sess.SetEnabled(u.cur, victim.ClientID, enable)
				fyne.Do(func() {
					if err != nil {
						u.setBusy(false)
						u.status.SetText("")
						dialog.ShowError(err, u.win)
						return
					}
					onToggled()
				})
			})
		})
	}
	okBtn := widget.NewButtonWithIcon("Да", theme.ConfirmIcon(), apply)
	okBtn.Importance = widget.HighImportance
	planStatus := newPlanStatusLabel()
	diffBtn := widget.NewButton("Показать изменения", func() {
		u.setBusy(true)
		planStatus.SetText("Считаю изменения...")
		goSafe(func() {
			plan, err := u.sess.PlanSetEnabled(u.cur, victim.ClientID, enable)
			fyne.Do(func() {
				u.setBusy(false)
				planStatus.SetText("")
				if err != nil {
					dialog.ShowError(err, u.win)
					return
				}
				u.showDiffWindow(fmt.Sprintf("%s %q", noun, victim.Name()), plan, func(_ *core.NewUser) {
					d.Hide()
					onToggled()
				})
			})
		})
	})
	content := container.NewVBox(
		widget.NewLabel(fmt.Sprintf("Пользователь: %s\nКлюч: %s", victim.Name(), victim.ClientID)),
		container.NewHBox(okBtn, diffBtn),
		planStatus,
	)
	d = dialog.NewCustom(title, "Отмена", content, u.win)
	d.Resize(fyne.NewSize(420, 200))
	d.Show()
}

// ---------- перевыпуск конфига (re-key) ----------

func (u *ui) regenerateSelected() {
	if !u.cur.Managed {
		dialog.ShowInformation("Недоступно",
			fmt.Sprintf("Перевыпуск конфигов для %s не поддерживается.", u.cur.Proto), u.win)
		return
	}
	idx := u.selectedRow
	if idx < 0 || idx >= len(u.clients) {
		dialog.ShowInformation("Не выбран пользователь", "Выберите строку в таблице.", u.win)
		return
	}
	victim := u.clients[idx]

	var d dialog.Dialog
	onRegenerated := func(nu *core.NewUser) {
		u.selectedRow = -1
		u.status.SetText(fmt.Sprintf("Конфиг для %q перевыпущен.", nu.Name))
		u.showConfigDialog(nu, "перевыпущен")
		u.refresh()
	}
	apply := func() {
		// A3а: предупреждение о гонке непосредственно перед записью на
		// сервер. При "Отмена" форма остаётся открытой — d.Hide() внутри.
		u.confirmRaceWarning(guiview.OpRekeyUser, func() {
			d.Hide()
			u.setBusy(true)
			u.status.SetText(fmt.Sprintf("Перевыпускаю конфиг для %q...", victim.Name()))
			goSafe(func() {
				nu, err := u.sess.RegenerateUser(u.cur, victim.ClientID)
				fyne.Do(func() {
					if err != nil {
						u.setBusy(false)
						u.status.SetText("")
						dialog.ShowError(err, u.win)
						return
					}
					onRegenerated(nu)
				})
			})
		})
	}
	okBtn := widget.NewButtonWithIcon("Перевыпустить", theme.ConfirmIcon(), apply)
	okBtn.Importance = widget.HighImportance
	planStatus := newPlanStatusLabel()
	diffBtn := widget.NewButton("Показать изменения", func() {
		u.setBusy(true)
		planStatus.SetText("Считаю изменения...")
		goSafe(func() {
			plan, err := u.sess.PlanRekey(u.cur, victim.ClientID)
			fyne.Do(func() {
				u.setBusy(false)
				planStatus.SetText("")
				if err != nil {
					dialog.ShowError(err, u.win)
					return
				}
				u.showDiffWindow(fmt.Sprintf("перевыпуск конфига %q", victim.Name()), plan, func(nu *core.NewUser) {
					d.Hide()
					onRegenerated(nu)
				})
			})
		})
	})
	content := container.NewVBox(
		widget.NewLabel(fmt.Sprintf("Перевыпустить конфиг для %s? Старый конфиг перестанет работать, пользователю нужно установить новый.", victim.Name())),
		container.NewHBox(okBtn, diffBtn),
		planStatus,
	)
	d = dialog.NewCustom("Перевыпустить конфиг?", "Отмена", content, u.win)
	d.Resize(fyne.NewSize(460, 200))
	d.Show()
}

// ---------- удаление ----------

// errProtoSwitched — протокол переключили, пока летел запрос активности для
// карточки удаления. Это НЕ «подключений не было», а «узнать не удалось»:
// третье состояние, которое карточка и так умеет печатать.
var errProtoSwitched = errors.New("протокол переключён, пока шёл запрос активности")

func (u *ui) deleteSelected() {
	if !u.cur.Managed {
		dialog.ShowInformation("Недоступно",
			fmt.Sprintf("Удаление пользователей для %s не поддерживается.", u.cur.Proto), u.win)
		return
	}
	idx := u.selectedRow
	if idx < 0 || idx >= len(u.clients) {
		dialog.ShowInformation("Не выбран пользователь", "Выберите строку в таблице.", u.win)
		return
	}
	victim := u.clients[idx]
	// Снимок контейнера, как в refresh(): всё, что летит в goroutine,
	// берёт cur, а не читает u.cur из другого потока.
	cur := u.cur
	msg := fmt.Sprintf("Имя: %s\nСоздан: %s\nКлюч: %s", victim.Name(), victim.Created(), victim.ClientID)

	var d dialog.Dialog
	onDeleted := func() {
		u.selectedRow = -1
		u.status.SetText(fmt.Sprintf("Пользователь %q удалён.", victim.Name()))
		u.refresh()
	}
	apply := func() {
		// A3а: предупреждение о гонке непосредственно перед записью на
		// сервер. При "Отмена" форма остаётся открытой — d.Hide() внутри.
		u.confirmRaceWarning(guiview.OpDeleteUser, func() {
			d.Hide()
			u.setBusy(true)
			u.status.SetText(fmt.Sprintf("Удаляю %q...", victim.Name()))
			goSafe(func() {
				// cur, а не u.cur: это ЕДИНСТВЕННЫЙ вызов диалога, который
				// ПИШЕТ на сервер, и он тоже читался из goroutine. Конвенция
				// снимка (см. refresh()) была применена к соседним двум
				// вызовам и пропущена ровно у необратимого (ревью BE-01).
				err := u.sess.DeleteByID(cur, victim.ClientID)
				fyne.Do(func() {
					if err != nil {
						u.setBusy(false)
						u.status.SetText("")
						dialog.ShowError(err, u.win)
						return
					}
					onDeleted()
				})
			})
		})
	}
	okBtn := widget.NewButtonWithIcon("Удалить", theme.DeleteIcon(), apply)
	okBtn.Importance = widget.DangerImportance
	planStatus := newPlanStatusLabel()
	diffBtn := widget.NewButton("Показать изменения", func() {
		u.setBusy(true)
		planStatus.SetText("Считаю изменения...")
		goSafe(func() {
			plan, err := u.sess.PlanDelete(cur, victim.ClientID)
			fyne.Do(func() {
				u.setBusy(false)
				planStatus.SetText("")
				if err != nil {
					dialog.ShowError(err, u.win)
					return
				}
				u.showDiffWindow(fmt.Sprintf("удаление %q", victim.Name()), plan, func(_ *core.NewUser) {
					d.Hide()
					onDeleted()
				})
			})
		})
	})
	// СВЕЖИЙ ЗАПРОС АКТИВНОСТИ ПРИ ОТКРЫТИИ ДИАЛОГА (A1, места № 1 и № 4;
	// решение ядра 19.09.2026) — ровно так, как это давно сделано в CLI
	// (cmd/cli/confirm.go, buildCard).
	//
	// ПОЧЕМУ НЕ ИЗ СНИМКА u.handshakes. Снимок обновляется только успешным
	// refresh(); при ошибке чтения он остаётся от прошлого раза (ранний
	// выход выше), и клиент, подключившийся после последнего успешного
	// чтения, выглядел бы в карточке как «подключений не было». Plan* этого
	// не ловит: он перечитывает СУЩЕСТВОВАНИЕ клиента, а решение строится на
	// его АКТИВНОСТИ. Прямой вызов делает гарантию механической: нам больше
	// не нужно надеяться, что человек прочтёт предупреждение об устаревании.
	// Цена — один запрос к серверу, и он приходится на момент перед
	// НЕОБРАТИМЫМ действием.
	//
	// ПОЧЕМУ НЕДОСТУПНЫ ОБЕ КНОПКИ, А НЕ ОДНА (ревью BE-01). Блокировать
	// только «Удалить» бессмысленно: рядом стоит «Показать изменения», и за
	// ней PlanDelete → окно изменений → «Применить» → sess.Apply, то есть
	// НЕОБРАТИМОЕ ДЕЙСТВИЕ ЗАВЕРШАЕТСЯ ЦЕЛИКОМ, пока метка ещё говорит
	// «Узнаю, подключался ли клиент...». Это ровно та ШЕСТАЯ ТОЧКА ЗАПИСИ,
	// которую A3а нашёл и закрыл предупреждением, — путь самого осторожного
	// человека, который сначала смотрит, что изменится. Окно, где
	// подтвердить можно раньше ответа, появилось бы вторым выходом.
	okBtn.Disable()
	diffBtn.Disable()
	activity := widget.NewLabel("Узнаю, подключался ли клиент...")
	activity.Wrapping = fyne.TextWrapWord
	goSafe(func() {
		hs, hsErr := u.sess.GetHandshakes(cur)
		fyne.Do(func() {
			// Сверка снимка — конвенция этого файла (см. refresh()): ответ
			// про ДРУГОЙ контейнер отвечает не на тот вопрос, а ключа victim
			// в нём нет, и это напечаталось бы как «Подключений не было».
			// Сегодня случай недостижим (диалог модальный), но конвенция
			// стоит двух строк и переживёт снятие модальности.
			if cur != u.cur {
				hs, hsErr = nil, errProtoSwitched
			}
			activity.SetText(guiview.DeleteCardActivity(hs, victim.ClientID, hsErr))
			okBtn.Enable()
			diffBtn.Enable()
		})
	})
	content := container.NewVBox(
		widget.NewLabel(msg),
		activity,
		container.NewHBox(okBtn, diffBtn),
		planStatus,
	)
	d = dialog.NewCustom("Удалить пользователя?", "Отмена", content, u.win)
	d.Resize(fyne.NewSize(460, 280))
	d.Show()
}
