package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

// Файл clienthost.go — адрес сервера в конфигах клиентов (требование
// владельца: «Новые ключи надо генерировать с DNS-именем, а не с IP»).
// Если в админском ключе IP, перед первой выдачей конфига (создание,
// перевыпуск) спрашиваем имя. Выбор запоминается внутри зашифрованного
// хранилища .avlt (VaultPayload.ClientHost / ClientHostKeepIP); пин к этому
// моменту уже стёрт из памяти (SEC-01), поэтому для записи он спрашивается
// заново — «не запоминать» тоже можно, тогда выбор живёт до конца сеанса.

// guiClientHostResolver — резолвер сверки имени (шов для тестов).
var guiClientHostResolver core.Resolver = core.SystemResolver

// clientHostView — окно выбора имени (для тестов).
type clientHostView struct {
	d       dialog.Dialog
	entry   *widget.Entry
	status  *widget.Label
	checkBt *widget.Button
	keepBt  *widget.Button
	// confirm — окно «имя указывает не туда / не проверено — всё равно?»
	confirm dialog.Dialog
	text    string // текст исхода проверки, показанный в confirm
}

// applyClientHostSetting — при подключении: выбор из хранилища (или его
// отсутствие) → адрес в конфигах и нужно ли спрашивать.
func (u *ui) applyClientHostSetting(sess *core.Session, set core.ClientHostSetting) {
	host, ask := core.DecideClientHost(sess.Creds.Host, set)
	if host != sess.Creds.Host {
		sess.ClientHost = host
	}
	u.clientHostAsk = ask
	sess.ClientHostDecided = !ask
	// сохранённое имя не применяем молча: перепроверка перед первой выдачей
	u.clientHostRecheck = set.Host != ""
}

// needClientHostGate — нужно ли пройти ворота перед выдачей конфига.
func (u *ui) needClientHostGate() bool { return u.clientHostAsk || u.clientHostRecheck }

// withIPNote — к строке о выдаче конфига дописывается предупреждение,
// если конфиг выдан с IP (при каждой выдаче, а не раз за сеанс — QA-01).
func (u *ui) withIPNote(st string) string {
	if u.sess != nil && core.IsIPHost(u.sess.EndpointHost()) {
		return st + " " + core.ClientHostIPWarning(u.sess.EndpointHost())
	}
	return st
}

// endpointNote — строка состояния об адресе в выданном конфиге: IP —
// предупреждение; имя — какое.
func (u *ui) endpointNote() string {
	if u.sess == nil {
		return ""
	}
	h := u.sess.EndpointHost()
	if core.IsIPHost(h) {
		return core.ClientHostIPWarning(h)
	}
	return "Адрес сервера в конфиге: " + h
}

// ensureClientHost — ворота перед выдачей конфига. Спрашивать не нужно —
// next() сразу; иначе окно выбора, next() — после выбора, «Отмена» —
// конфиг не выдаётся.
func (u *ui) ensureClientHost(next func()) {
	if u.sess == nil {
		next()
		return
	}
	if u.clientHostAsk {
		u.clientHostShown = u.clientHostDialog(next)
		return
	}
	if u.clientHostRecheck {
		u.recheckSavedClientHost(next)
		return
	}
	next()
}

// recheckSavedClientHost — З3: имя из хранилища перепроверяется один раз за
// сеанс. Совпало — строка в статусе и дальше; иначе — окно с исходом и
// явным «Использовать» (как при первом выборе).
func (u *ui) recheckSavedClientHost(next func()) {
	name, serverIP := u.sess.ClientHost, u.sess.ServerIP()
	u.status.SetText("Проверяю сохранённый адрес для клиентов " + name + "...")
	goSafe(func() {
		chk := core.CheckClientHost(name, serverIP, guiClientHostResolver)
		fyne.Do(func() {
			if chk.Status == core.ClientHostMatch {
				u.clientHostRecheck = false
				u.status.SetText("Адрес для клиентов " + name + " (сохранено ранее): " + chk.Text())
				next()
				return
			}
			u.clientHostRecheckTx = chk.Text()
			lbl := widget.NewLabel("Адрес для клиентов " + name + " сохранён ранее.\n\n" + chk.Text() + "\n\nВсё равно выдать конфиг с этим именем?")
			lbl.Wrapping = fyne.TextWrapWord
			u.clientHostRecheckDl = dialog.NewCustomConfirm("Сохранённое имя не подтверждено", "Использовать", "Нет", lbl, func(ok bool) {
				if ok {
					u.clientHostRecheck = false
					next()
				}
			}, u.win)
			u.clientHostRecheckDl.Resize(fyne.NewSize(460, 240))
			u.clientHostRecheckDl.Show()
		})
	})
}

func (u *ui) clientHostDialog(next func()) *clientHostView {
	v := &clientHostView{}
	ip := u.sess.Creds.Host
	expl := widget.NewLabel(fmt.Sprintf(
		"В админском ключе адрес сервера — IP %s. Конфиг клиента с IP при переезде сервера придётся перевыпускать каждому клиенту. "+
			"С DNS-именем достаточно перевести DNS на новый сервер.\n\n"+
			"Укажите имя, которое указывает на этот сервер (например vpn.example.com). Программа проверит, что имя ведёт сюда.", ip))
	expl.Wrapping = fyne.TextWrapWord
	v.entry = widget.NewEntry()
	v.entry.SetPlaceHolder("vpn.example.com")
	v.status = widget.NewLabel("")
	v.status.Wrapping = fyne.TextWrapWord

	done := func(set core.ClientHostSetting) {
		v.d.Hide()
		u.setClientHost(set, next)
	}
	check := func() {
		name, err := core.NormalizeClientHost(v.entry.Text)
		if err != nil {
			v.status.SetText(err.Error())
			return
		}
		v.status.SetText("Проверяю имя...")
		v.checkBt.Disable()
		serverIP := u.sess.ServerIP()
		goSafe(func() {
			chk := core.CheckClientHost(name, serverIP, guiClientHostResolver)
			fyne.Do(func() {
				v.checkBt.Enable()
				v.status.SetText(chk.Text())
				if chk.Status == core.ClientHostMatch {
					done(core.ClientHostSetting{Host: name})
					return
				}
				// другие адреса / не удалось — только после явного «да»
				v.text = chk.Text()
				title := "Имя указывает на другой сервер"
				if chk.Status == core.ClientHostUnknown {
					title = "Имя проверить не удалось"
				}
				lbl := widget.NewLabel(chk.Text() + "\n\nВсё равно использовать это имя в конфигах клиентов?")
				lbl.Wrapping = fyne.TextWrapWord
				v.confirm = dialog.NewCustomConfirm(title, "Использовать", "Нет", lbl, func(ok bool) {
					if ok {
						done(core.ClientHostSetting{Host: name})
					}
				}, u.win)
				v.confirm.Resize(fyne.NewSize(460, 220))
				v.confirm.Show()
			})
		})
	}
	v.checkBt = widget.NewButton("Проверить и использовать", check)
	v.checkBt.Importance = widget.HighImportance
	v.keepBt = widget.NewButton("Оставить IP", func() { done(core.ClientHostSetting{KeepIP: true}) })
	v.entry.OnSubmitted = func(string) { check() }
	content := container.NewVBox(expl, v.entry, container.NewHBox(v.checkBt, v.keepBt), v.status)
	v.d = dialog.NewCustom("Адрес сервера для клиентов", "Отмена", content, u.win)
	v.d.Resize(fyne.NewSize(500, 320))
	v.d.Show()
	u.focusField(v.entry)
	return v
}

// setClientHost — выбор сделан: применить к сеансу, предложить запомнить в
// хранилище (если сеанс открыт из него), затем next().
func (u *ui) setClientHost(set core.ClientHostSetting, next func()) {
	u.sess.ClientHost = set.Host
	u.sess.ClientHostDecided = true
	u.clientHostAsk = false
	u.clientHostRecheck = false // только что проверено человеком
	u.clientHostSet = set
	if set.KeepIP && u.status != nil {
		u.status.SetText(core.ClientHostIPWarning(u.sess.Creds.Host))
	}
	if u.vaultPath == "" {
		next()
		return
	}
	u.clientHostPinShown = u.clientHostPinDialog(set, next)
}

// clientHostPinDialog — запомнить выбор в .avlt: пин спрашивается заново и
// сначала ПРОВЕРЯЕТСЯ расшифровкой (иначе файл перезапечатался бы другим
// пином); payload берётся из только что расшифрованного файла.
func (u *ui) clientHostPinDialog(set core.ClientHostSetting, next func()) dialog.Dialog {
	pin := widget.NewEntry()
	pin.Password = true
	pin.SetPlaceHolder("Пин-код")
	st := widget.NewLabel("Чтобы программа запомнила выбор для этого сервера, введите пин-код хранилища. «Не запоминать» — выбор действует до закрытия программы.")
	st.Wrapping = fyne.TextWrapWord
	path := u.vaultPath
	var d dialog.Dialog
	save := func() {
		p := pin.Text
		pin.SetText("")
		st.SetText("Сохраняю...")
		goSafe(func() {
			err := saveClientHostToVault(path, p, set)
			p = ""
			fyne.Do(func() {
				if err != nil {
					st.SetText("Не сохранено: " + err.Error())
					return
				}
				d.Hide()
				if u.status != nil && !set.KeepIP {
					u.status.SetText("Адрес для клиентов " + set.Host + " сохранён в хранилище.")
				}
				next()
			})
		})
	}
	pin.OnSubmitted = func(string) { save() }
	saveBt := widget.NewButton("Запомнить", save)
	saveBt.Importance = widget.HighImportance
	skipBt := widget.NewButton("Не запоминать", func() { d.Hide(); next() })
	d = dialog.NewCustomWithoutButtons("Запомнить выбор?",
		container.NewVBox(st, pin, container.NewHBox(saveBt, skipBt)), u.win)
	d.Resize(fyne.NewSize(460, 220))
	d.Show()
	u.focusField(pin)
	return d
}

// saveClientHostToVault — расшифровать (проверка пина), дописать выбор,
// перезапечатать теми же параметрами.
var saveClientHostToVault = func(path, pin string, set core.ClientHostSetting) error {
	if pin == "" {
		return fmt.Errorf("пин не введён")
	}
	payload, info, err := throttledVaultDecrypt(path, pin)
	if err != nil {
		return err
	}
	payload.ClientHost, payload.ClientHostKeepIP = set.Host, set.KeepIP
	data, err := core.SealVaultExisting(pin, payload, info.Params, info.MachineBind)
	if err != nil {
		return err
	}
	return core.WriteVaultFile(path, data)
}

// clientHostNow — онлайн-время для счётчика попыток (как в основном диалоге
// пин-кода: перевод часов не сбрасывает блокировку). Шов для тестов.
var clientHostNow = func() (time.Time, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return core.FetchNetworkTime(ctx)
}

// throttledVaultDecrypt — расшифровка под ТЕМ ЖЕ счётчиком неверных попыток
// (throttle.json, per-vault), что и основной ввод пина (SEC-01 по PR #50):
// второй диалог пина не должен давать неограниченный перебор. Fail-closed:
// нет онлайн-времени или счётчик не читается/не пишется — расшифровки нет.
func throttledVaultDecrypt(path, pin string) (core.VaultPayload, core.VaultInfo, error) {
	dir, name := pinVaultDir(), filepath.Base(path)
	now, err := clientHostNow()
	if err != nil {
		return core.VaultPayload{}, core.VaultInfo{}, fmt.Errorf("подключение к интернету не обнаружено — ввод пина закрыт")
	}
	cur, err := core.LoadThrottle(dir, name)
	if err != nil {
		return core.VaultPayload{}, core.VaultInfo{}, err
	}
	if blocked, rem := core.CheckThrottle(cur, now); blocked {
		return core.VaultPayload{}, core.VaultInfo{}, fmt.Errorf("ввод пина заблокирован после неверных попыток, осталось %s", rem.Round(time.Second))
	}
	payload, info, derr := vaultDecrypt(path, pin)
	if derr != nil {
		st := core.RegisterFailure(cur, now)
		if serr := core.SaveThrottle(dir, name, st); serr != nil {
			return core.VaultPayload{}, core.VaultInfo{}, serr
		}
		msg := "неправильный пин-код или файл повреждён"
		if !errors.Is(derr, core.ErrVaultBadPinOrCorrupt) {
			msg = derr.Error()
		}
		if blocked, rem := core.CheckThrottle(st, now); blocked {
			return core.VaultPayload{}, core.VaultInfo{}, fmt.Errorf("%s; ввод пина заблокирован на %s", msg, rem.Round(time.Second))
		}
		return core.VaultPayload{}, core.VaultInfo{}, fmt.Errorf("%s. Осталось попыток: %d", msg, pinThrottleAttempts-st.Fails)
	}
	_ = core.SaveThrottle(dir, name, core.RegisterSuccess())
	return payload, info, nil
}

// pinThrottleAttempts — попыток до блокировки (как throttleAttempts в
// showVaultPinDialog и core.throttleMaxFails).
const pinThrottleAttempts = 10
