// amnezia-admin — консольная утилита администрирования сервера Amnezia VPN.
//
// Запуск без аргументов — интерактивный режим: вводите ключ vpn://,
// утилита определяет сервер, протоколы и показывает меню доступных команд.
//
// Также поддерживаются подкоманды для скриптов:
//
//	amnezia-admin decode -key vpn://...
//	amnezia-admin list   -key vpn://...
//	amnezia-admin add    -key vpn://... -name Vasya
//	amnezia-admin del    -key vpn://... -name Vasya
//	amnezia-admin rename -key vpn://... -name Vasya -newname "Vasya Ivanov"
//	amnezia-admin toggle -key vpn://... -name Vasya
//	amnezia-admin rekey  -key vpn://... -name Vasya
//	amnezia-admin show-config -key vpn://... -name Vasya [-print]
//	amnezia-admin backup -key vpn://... [-o файл.aabk] (-password-file файл | -no-password)
//	amnezia-admin backup-info [-password-file файл] файл.aabk
//	amnezia-admin restore -key vpn://НОВОГО-сервера... -file файл.aabk [-password-file файл] [-apply] [-address-changes] [-skip-xray] [-replace-users] [-yes]
//	amnezia-admin version
//	amnezia-admin check
//
// Подкоманда check печатает признаки окружения (ОС, архитектура, библиотека
// C, библиотеки графики, графическая сессия) и говорит заранее, запустится
// ли графическая версия; ключ, сеть и права администратора ей не нужны.
//
// Флаг -dry-run (для add/del/rename/toggle/rekey) показывает diff wg0.conf и
// clientsTable, которые получились бы после операции, ничего не записывая на
// сервер:
//
//	amnezia-admin add -key vpn://... -name Vasya -dry-run
//
// Необратимые команды (del, rekey и toggle в сторону отключения) требуют
// подтверждения: у терминала печатают карточку (сервер/контейнер/имя/дата
// создания/последнее подключение/ключ) и спрашивают "y/n"; без терминала —
// только флаг -yes (для скриптов), без него — отказ. -dry-run побеждает
// -yes: план печатается, ничего не пишется, вопрос не задаётся.
//
//	amnezia-admin del -key vpn://... -name Vasya -yes
//
// Коды возврата: 0 — успех; 1 — ошибка; 2 — отказ из-за отсутствия
// подтверждения (нет терминала и нет -yes, либо явный отказ "n" у терминала).
// Подкоманда check возвращает 0 всегда — в том числе когда графическая
// версия не запустится и когда что-то определить не удалось: это факт об
// окружении, а не ошибка утилиты.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"amnezia-admin/core"
	"amnezia-admin/internal/envcheck"
	"amnezia-admin/internal/guiview"
	"amnezia-admin/internal/version"
)

// ---------- печать конфига vpn:// (A2, SEC-01) ----------
//
// Раньше decode и пункт меню «5» печатали json.MarshalIndent(cfg) целиком.
// В конфиге лежит ключ "password", и в нём — ПАРОЛЬ ROOT ЛИБО ПРИВАТНЫЙ
// SSH-КЛЮЧ: core/hostkey.go:144 выбирает способ входа по
// strings.Contains(creds.Password, "PRIVATE KEY"), то есть одно из двух там
// всегда. Напечатанный пароль root отозвать нельзя — он уходит в
// перенаправленный вывод, в журнал, в запись терминала и в скриншот.
//
// Приём — перечислять ДОПУСТИМОЕ, а не недопустимое: список способов утечь
// бесконечен, список полей, которые человеку имеет право показать, конечен.
// Вывод строится ИЗ КОНФИГА (печатается имя каждого фактического ключа,
// сколько бы их ни было), а списки управляют ТОЛЬКО значениями — человек,
// читающий decode, должен видеть, какие поля в ключе есть: это и есть
// диагностика. Что в них лежит, мы не знаем, и потому не показываем:
// «не знаем, секретное ли» → не «наверное, нет», а «показываем факт
// существования, скрываем содержимое».
//
// ДВА СПИСКА, И ЗАПРЕЩАЮЩИЙ СИЛЬНЕЕ РАЗРЕШАЮЩЕГО. Проверка на
// configDeniedKeys идёт ДО проверки на configAllowedKeys. Если бы "password"
// скрывался лишь потому, что его нет в разрешающем списке, защитой было бы
// ОТСУТСТВИЕ строки, а отсутствие строки никто не охраняет: одно слово,
// когда-нибудь дописанное в разрешающий список «для диагностики», открыло бы
// пароль root, и в диффе это выглядело бы невинно. При двух списках такое
// добавление не даёт эффекта, а удаление "password" из запрещающего — видимое
// удаление строки, и его ловит тест TestDecodeMasksPassword.
//
// Формат вывода НЕ меняется: это по-прежнему отступованный JSON-объект,
// разбираемый как JSON. decode объявлен подкомандой для скриптов (шапка
// файла), и его вывод — договор, а не украшение; меняются только значения.
// Порядок ключей детерминирован: encoding/json сортирует ключи map по имени.
var (
	// configAllowedKeys — закрытый список ключей, значения которых печатаются
	// как есть. Ровно то, что продукт вообще умеет читать из конфига
	// (core/core.go:104–107) за вычетом password; containers обнаруживаются
	// НА СЕРВЕРЕ (core.FindContainers), а не берутся из ключа. Расширяется
	// только решением ядра — одной видимой строкой диффа.
	configAllowedKeys = map[string]bool{
		"hostName": true,
		"userName": true,
		"port":     true,
	}
	// configDeniedKeys — явный запрещающий список. В "password" лежит пароль
	// root либо приватный SSH-ключ (core/hostkey.go:144).
	configDeniedKeys = map[string]bool{
		"password": true,
	}
)

// configHiddenPlaceholder — та же форма, что в core/txn.go:maskSecrets,
// чтобы в продукте не завелось двух разных плейсхолдеров.
const configHiddenPlaceholder = "<скрыто>"

// redactConfig возвращает копию конфига, пригодную к печати: имена всех
// фактических ключей сохранены, значения — по спискам выше.
//
// Три состояния поля различимы, и это требование, а не вкус: «скрыто» и
// «пусто» — разные факты, и человек, читающий вывод, обязан их различать,
// иначе он решит, что пароля в ключе нет, и пойдёт искать несуществующую
// проблему.
//
//	поле отсутствует в конфиге → строки нет вовсе;
//	поле есть и пусто          → "password": "";
//	поле есть и скрыто         → "password": "<скрыто>".
//
// Маскированное значение — строка независимо от исходного типа: если поле
// было массивом или объектом, оно становится строкой. Это осознанно —
// показать структуру значения значит показать часть значения.
func redactConfig(cfg map[string]any) map[string]any {
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		// Пустая строка — не секрет (скрывать нечего), и она обязана
		// отличаться от скрытого значения: см. три состояния выше.
		if s, ok := v.(string); ok && s == "" {
			out[k] = ""
			continue
		}
		switch {
		case configDeniedKeys[k]: // ДО проверки на разрешённость — см. шапку
			out[k] = configHiddenPlaceholder
		case configAllowedKeys[k]:
			out[k] = v
		default:
			out[k] = configHiddenPlaceholder
		}
	}
	return out
}

// printConfig печатает конфиг через redactConfig. Единственная точка печати
// конфига в CLI: и decode, и пункт меню «5» идут через неё.
// json.Encoder с SetEscapeHTML(false), а не json.MarshalIndent: последний
// экранирует "<" и ">" в </>, и плейсхолдер печатался бы как
// "<скрыто>" — не та форма, что в core/txn.go:maskSecrets, и не та,
// что утверждена UI-01. Отступ прежний (два пробела), вывод остаётся
// разбираемым JSON: обе формы разбираются в одну и ту же строку.
func printConfig(w io.Writer, cfg map[string]any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(redactConfig(cfg)); err != nil {
		// Молчаливое «ничего не напечатали» неотличимо от пустого конфига —
		// говорим прямо, но без содержимого конфига в тексте ошибки.
		fmt.Fprintln(w, "не удалось собрать вывод конфига")
	}
}

func pad(s string, n int) string {
	if d := n - len([]rune(s)); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// listUsers печатает таблицу пользователей в w и возвращает отсортированный
// по активности slice — тот же порядок, что показан в таблице (нумерация
// "#" в выводе соответствует индексам этого slice), чтобы вызывающий код мог
// резолвить номер строки без повторного LoadClients. w — параметр (не
// os.Stdout напрямую) начиная с PR-4 (Е3): interactive() передаёт os.Stdout,
// run() — свой stdout io.Writer, чтобы TestNonTTYUnknownHostNeedsHostkey мог
// перехватить вывод подкоманды list без чтения реального os.Stdout.
func listUsers(w io.Writer, s *core.Session, c *core.Container) ([]core.ClientEntry, error) {
	if c.Support == core.SupportUnknown {
		// QA раунд 1: незнакомый — не «протокол»
		return nil, fmt.Errorf("незнакомый контейнер %s: программа не знает, что это за протокол, поэтому ничего в нём не читает и не меняет", c.Name)
	}
	if core.IsXRay(c) && c.Dir != "" {
		// XRay: и при «только просмотр» — список с причиной, а не ошибка
		// (живая проверка 04.10).
		return listXRay(w, s, c)
	}
	if !c.Managed() && c.Reason != "" {
		// AL-01: причина экземпляра (XRay с незнакомым server.json, AWG2) —
		// подпись та же, что в списке протоколов и в GUI.
		return nil, fmt.Errorf("%s", guiview.ProtoLabel(*c))
	}
	if !c.Managed() {
		return nil, fmt.Errorf("для протокола %s управление пользователями не реализовано (поддерживаются AmneziaWG, WireGuard и XRay)", c.Title())
	}
	if core.IsXRay(c) {
		return listXRay(w, s, c)
	}
	clients, err := s.LoadClients(c)
	if err != nil {
		return nil, err
	}
	// Ошибка статистики НЕ ОТБРАСЫВАЕТСЯ (задание НЕЗНАНИЕ-ТРАФИК, место
	// № 2). Прежде здесь подставлялась пустая карта, и таблица печатала всем
	// «0 B / 0 B» и «—» как измерение. Показание каждой строки берётся через
	// core.ReadPeer — оно различает «запрос не удался», «клиента нет в
	// ответе» и «измерено».
	stats, statsErr := s.GetPeerStats(c)
	statsFailed := statsErr != nil
	core.SortByActivity(clients, stats)

	if len(clients) == 0 {
		fmt.Fprintln(w, "В clientsTable записей нет.")
	} else {
		// «Активность» — 18 знаков; при записи с неизвестной включённостью
		// ячейка «<время> (вкл/откл: ?)» длиннее (раунд 3, Я1), и колонка
		// расширяется, иначе строка разъехалась бы с шапкой.
		actW := 18
		for _, cl := range clients {
			if cl.EnabledState() == core.EnabledUnknown {
				actW = len([]rune("2006-01-02 15:04 "+textListEnabledUnknown)) + 2
				break
			}
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, cHead(pad("#", 4)+pad("Имя", 34)+pad("Создан", 21)+pad("Активность", actW)+pad("Трафик ↓/↑", 24)+"Публичный ключ"))
		fmt.Fprintln(w, cDim(strings.Repeat("─", 4+34+21+actW+24+44)))
		absent := 0                 // включённые клиенты, которых нет в ответе `wg show`
		var unknownEnabled []string // включён ли — неизвестно (У1)
		for i, cl := range clients {
			created := core.CreatedText(cl.Created())
			r := core.ReadPeer(stats, statsFailed, cl.ClientID)
			switch cl.EnabledState() {
			case core.EnabledActive:
				if r.State == core.PeerAbsent {
					absent++
				}
			case core.EnabledUnknown:
				unknownEnabled = append(unknownEnabled, cl.Name())
			}
			act := listActivityText(cl.EnabledState(), r)
			hs := cDim(pad(act, actW))
			// Зелёный — только ТОЧНО активному (раунд 3, SEC): у клиента с
			// неизвестным состоянием показание измерено, но «активен» не
			// утверждается.
			if _, ok := r.Measured(); ok && cl.EnabledState() == core.EnabledActive && act != "—" {
				hs = cOK(pad(act, actW))
			}
			traffic := listTrafficText(cl.EnabledState(), r)
			name := cl.Name()
			if cl.Disabled() {
				name = cDim(pad(name, 34))
			} else {
				name = pad(name, 34)
			}
			fmt.Fprintln(w, cNum(pad(strconv.Itoa(i+1), 4))+name+cDim(pad(created, 21))+hs+pad(traffic, 24)+cDim(cl.ClientID))
		}
		fmt.Fprintln(w, cDim("Трафик и активность — с момента перезапуска сервера."))
		if note := listStatsNote(statsFailed, absent); note != "" {
			fmt.Fprintln(w, cWarn(note))
		}
		if note := core.EnabledUnknownNote(unknownEnabled); note != "" {
			fmt.Fprintln(w, cWarn(note))
		}
	}

	// Сироты печатаются только когда они есть, поэтому молчание здесь —
	// утверждение «сирот нет». Не удалось проверить — говорим об этом
	// (A1б, признак 2), иначе отказ чтения выглядит чистым сервером.
	orphans, orphErr := s.OrphanPeers(c, clients)
	if note := orphanNote(orphErr); note != "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, cWarn(note))
	}
	if len(orphans) > 0 {
		fmt.Fprintf(w, "\nPeers в wg0.conf без имени в clientsTable: %d\n", len(orphans))
		for _, o := range orphans {
			fmt.Fprintln(w, "  ", o)
		}
	}
	return clients, nil
}

// orphanNote — строка о несостоявшейся проверке peers без имени; "" — если
// проверка состоялась. Причина печатается: она уже прошла маскировку
// секретов на границе (core.sshRunner), а без неё человеку нечего чинить.
func orphanNote(err error) string {
	if err == nil {
		return ""
	}
	return "Проверить peers в wg0.conf без имени в clientsTable не удалось: " + err.Error() +
		". Есть ли такие — неизвестно."
}

// listActivityText — ячейка «Активность» таблицы list, без раскраски.
//
//	отключён            → "(откл.)"
//	не измерено          → "?"   запрос не удался ИЛИ клиента нет в ответе
//	измерено, без рукопожатия → "—"   сервер ответил: не подключался
//	иначе                → время последнего рукопожатия
//
// Прежде «?» не было вовсе: пустая карта при отказе и отсутствующий ключ
// давали нулевое время, то есть «—» — «не подключался» (признак 1).
func listActivityText(enabled core.EnabledState, r core.PeerReading) string {
	if enabled == core.EnabledDisabled {
		return "(откл.)"
	}
	reading := listActivityReading(r)
	if enabled == core.EnabledUnknown {
		// У1: не «активен» и не «отключён»; причина — под таблицей
		// (EnabledUnknownNote). Раунд 3 (UX-01, Я1): пометка добавляется к
		// показанию, а не заменяет его.
		return reading + " " + textListEnabledUnknown
	}
	return reading
}

func listActivityReading(r core.PeerReading) string {
	st, ok := r.Measured()
	switch {
	case !ok:
		return "?"
	case st.LastHandshake.IsZero():
		return "—"
	default:
		return st.LastHandshake.Format("2006-01-02 15:04")
	}
}

// listTrafficText — ячейка «Трафик ↓/↑» таблицы list. Число печатается
// только измеренному клиенту; честный измеренный ноль остаётся «0 B / 0 B».
func listTrafficText(enabled core.EnabledState, r core.PeerReading) string {
	if enabled == core.EnabledDisabled {
		return "(откл.)"
	}
	st, ok := r.Measured()
	if !ok {
		return "?"
	}
	return core.HumanBytes(st.RxBytes) + " / " + core.HumanBytes(st.TxBytes)
}

// listStatsNote — строка под таблицей, называющая ПРИЧИНУ «?». В ячейке
// обе причины незнания выглядят одинаково (величина неизвестна в обоих
// случаях), но действие человека разное: при отказе запроса — повторить
// позже; при отсутствии клиента в ответе — это рассинхрон записи и
// работающего сервера, клиент сейчас подключиться не может, и об этом надо
// знать. Отключённые клиенты сюда не считаются: их отсутствие штатное.
func listStatsNote(statsFailed bool, absent int) string {
	switch {
	case statsFailed:
		return "Статистику с сервера получить не удалось: активность и трафик неизвестны («?»)."
	case absent > 0:
		// Текст UX-01: без внутреннего жаргона и с тем, что делать.
		return fmt.Sprintf("Клиентов нет в статистике сервера: %d. Подключиться они сейчас не могут; "+
			"их активность и трафик неизвестны («?»). Возможно, конфигурация сервера не применилась — "+
			"проверьте сервер, прежде чем удалять.", absent)
	}
	return ""
}

// saveUserConfig — см. listUsers про параметр w (Е3).
//
// A4в: каталог больше не относительный («Конфигурации» рядом с текущим
// каталогом), а каталог данных пользователя ОС — см. core.UserConfigsDir.
// Не удалось его определить — это ошибка, а не запись куда попало.
func saveUserConfig(w io.Writer, u *core.NewUser, proto string) error {
	dir, err := core.UserConfigsDir()
	if err != nil {
		return saveFailed(w, u, err)
	}
	return saveUserConfigTo(w, dir, u, proto)
}

// saveUserConfigTo вынесена из saveUserConfig с ЯВНЫМ каталогом затем, чтобы
// тест подставлял свой и не писал в настоящий каталог данных владельца — тот
// же приём, что с writeCrashLog(dir,…) в cmd/gui (A4).
func saveUserConfigTo(w io.Writer, dir string, u *core.NewUser, proto string) error {
	res, err := core.SaveUserConfig(dir, u)
	abs, createdDir := res.Path, res.DirWasMissing
	if err != nil {
		return saveFailed(w, u, err)
	}
	fmt.Fprintln(w)
	if u.IP == "" {
		// XRay: адреса у клиента нет
		fmt.Fprintln(w, cOK(fmt.Sprintf("Пользователь %q готов (протокол %s).", u.Name, proto)))
	} else {
		fmt.Fprintln(w, cOK(fmt.Sprintf("Пользователь %q создан (IP %s, протокол %s).", u.Name, u.IP, proto)))
	}
	fmt.Fprintln(w, "Конфиг сохранён: "+cAccent(abs))
	if res.Occupied != "" {
		// К-1: имя занято конфигом другого клиента — его файл не тронут
		fmt.Fprintln(w, cWarn(guiview.OccupiedText(res.Occupied, filepath.Base(abs))))
	}
	if createdDir {
		// Одноразовая подсказка: каталога не было, значит в новое место
		// сохраняется впервые (ревью UX-01).
		fmt.Fprintln(w, cDim(core.FirstSaveHint))
	}
	if u.FileExt() == ".json" {
		fmt.Fprintln(w, "Импортируйте файл в приложение Amnezia (Импорт → выбрать файл) или передайте клиенту ссылку vless:// (amnezia-admin show-config -name … -print).")
	} else {
		fmt.Fprintln(w, "Импортируйте файл в приложение AmneziaWG или Amnezia (Импорт → выбрать .conf).")
	}
	if u.Note != "" {
		// PR-W3 (Р3-2): строка честности amnezia-awg2 — при каждой выдаче.
		fmt.Fprintln(w, cWarn(u.Note))
	}
	return nil
}

// saveFailed печатает, ЧТО ДЕЛАТЬ, когда сохранить конфиг не удалось, и
// возвращает исходную ошибку (код возврата и печать самой ошибки прежние).
//
// ЗАЧЕМ ОТДЕЛЬНЫЙ ТЕКСТ (ревью UX-01). К этому месту пользователь на сервере
// УЖЕ СОЗДАН: и sess.AddUser, и sess.RegenerateUser отработали. Конфиг с
// этого момента существует только в памяти процесса и больше нигде не
// печатается — молча выйти с ошибкой значит потерять ключи клиента. A4в
// завёл ветвь отказа (это правильнее тихой записи куда попало) и обязан
// сказать, как из неё выйти.
//
// Сам конфиг сюда НЕ печатается: это секрет (приватный ключ клиента), и
// решение печатать его в поток вывода принимает владелец, а не эта функция.
func saveFailed(w io.Writer, u *core.NewUser, err error) error {
	fmt.Fprintln(w)
	fmt.Fprintln(w, core.SaveFailedAdvice(u.Name))
	// Своё у CLI — только КАК перевыпустить; смысл совета общий с GUI.
	fmt.Fprintf(w, "Команда: amnezia-admin rekey -key vpn://... -name %q "+
		"(в интерактивном режиме — пункт «Перевыпустить конфиг»).\n", u.Name)
	return err
}

// printContainers — список протоколов сервера в трёх состояниях (PR-W2):
// подпись — guiview.ProtoLabel, та же, что в GUI. withNotes — показать
// подпись состояния; без него — только имя протокола (выбор при смене).
func printContainers(containers []core.Container, withNotes bool) {
	for i, c := range containers {
		label := c.Title()
		if withNotes {
			label = guiview.ProtoLabel(c)
		}
		fmt.Printf("  %s %s %s\n", cNum(strconv.Itoa(i+1)+"."), label, cDim("["+c.Name+"]"))
	}
}

// printPlan печатает построчный diff по обоим файлам плана в формате
// "--- <path> (было) / +++ <path> (станет)" — общая функция для -dry-run
// (Е1) и её регресс-теста (Е4: TestDryRunFlagPrintsDiffAndWritesNothing),
// который вызывает её напрямую на плане, собранном на fakesrv.
func printPlan(w io.Writer, p *core.Plan) {
	wgDiff, tblDiff := p.Diff()
	dir := p.Container.Dir
	printFileDiff(w, p.ConfPath(), wgDiff)
	printFileDiff(w, dir+"/clientsTable", tblDiff)
	if n := p.Note(); n != "" {
		fmt.Fprintln(w, n) // Н-4, раунд 5: что правится только запись — прямо
	}
}

func printFileDiff(w io.Writer, path, diff string) {
	fmt.Fprintf(w, "--- %s (было)\n+++ %s (станет)\n", path, path)
	if diff == "" {
		fmt.Fprintln(w, "(без изменений)")
		return
	}
	fmt.Fprint(w, diff)
}

// runDryRun строит план для cmd (add/del/rename/toggle/rekey) и печатает его
// diff через printPlan, ничего не записывая на сервер — тело -dry-run веток
// main() (Е1), вынесенное в отдельную функцию (ревью BE-01, круг 2, Medium):
// сама обвязка флага (разбор, пять веток, break после печати) раньше ничем
// не стереглась, тест звал только printPlan напрямую. Для add/rekey конфиг
// с приватным ключом (plan.result.Config) не печатается и не сохраняется —
// план ещё не применён, конфиг с ним мог бы и не заработать.
func runDryRun(w io.Writer, sess *core.Session, cur *core.Container, cmd, name, newname string) error {
	printAndDone := func(plan *core.Plan) error {
		printPlan(w, plan)
		fmt.Fprintln(w, "Ничего не записано (dry-run).")
		return nil
	}
	switch cmd {
	case "add":
		plan, err := sess.PlanAddUser(cur, name)
		if err != nil {
			return err
		}
		return printAndDone(plan)
	case "del":
		// вне интерактивного списка номер строки ничего не значит —
		// принимаем только имя или публичный ключ (см. core.ResolveNonNumeric)
		clients, err := sess.LoadClients(cur)
		if err != nil {
			return err
		}
		idx, err := resolveByFlag(w, clients, name)
		if err != nil {
			return err
		}
		plan, err := sess.PlanDelete(cur, clients[idx].ClientID)
		if err != nil {
			return err
		}
		return printAndDone(plan)
	case "rename":
		clients, err := sess.LoadClients(cur)
		if err != nil {
			return err
		}
		idx, err := resolveByFlag(w, clients, name)
		if err != nil {
			return err
		}
		plan, err := sess.PlanRename(cur, clients[idx].ClientID, newname)
		if err != nil {
			return err
		}
		return printAndDone(plan)
	case "toggle":
		clients, err := sess.LoadClients(cur)
		if err != nil {
			return err
		}
		idx, err := resolveByFlag(w, clients, name)
		if err != nil {
			return err
		}
		enable := clients[idx].Disabled()
		plan, err := sess.PlanSetEnabled(cur, clients[idx].ClientID, enable)
		if err != nil {
			return err
		}
		return printAndDone(plan)
	case "rekey":
		clients, err := sess.LoadClients(cur)
		if err != nil {
			return err
		}
		idx, err := resolveByFlag(w, clients, name)
		if err != nil {
			return err
		}
		plan, err := sess.PlanRekey(cur, clients[idx].ClientID)
		if err != nil {
			return err
		}
		return printAndDone(plan)
	default:
		return fmt.Errorf("-dry-run не поддержан для команды %q", cmd)
	}
}

// ---------- интерактивный режим ----------

// textListEnabledUnknown — ячейка «Активность» list, когда неизвестно,
// включён ли клиент (У1, раунд 2).
const textListEnabledUnknown = "(вкл/откл: ?)"

// textInputEnded — строка при конце ввода в меню (долг У6, текст UX-01).
const textInputEnded = "Ввод закончился — выход."

// errInputEnded — ask() встретил конец ввода: меню разматывается до
// interactive() паникой с этим значением. Паника, а не пустая строка: ask
// зовут и внутри пунктов меню («Имя нового пользователя»), и пустой ответ
// там продолжил бы действие так, будто человек что-то ответил.
var errInputEnded = errors.New("ввод закончился")

// interactive — меню. Возвращает код выхода: 0 — штатно, 2 — ввод
// закончился (EOF на stdin). Прежде ошибка чтения отбрасывалась, пустая
// строка уходила в switch как «неизвестный выбор», и меню печаталось
// бесконечно (У6).
func interactive() (code int) {
	defer func() {
		if r := recover(); r != nil {
			if r != errInputEnded {
				panic(r)
			}
			fmt.Println()
			fmt.Fprintln(os.Stderr, textInputEnded)
			code = 2
		}
	}()
	in := bufio.NewReader(os.Stdin)
	ask := func(prompt string) string {
		fmt.Print(prompt)
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			panic(errInputEnded)
		}
		return strings.TrimSpace(line)
	}

	fmt.Println(cTitle("=== Amnezia Admin " + version.String() + " ==="))
	key := os.Getenv("AMNEZIA_KEY")
	if key == "" {
		key = ask("Вставьте админский ключ (vpn://...): ")
	} else {
		fmt.Println("Ключ взят из переменной окружения AMNEZIA_KEY.")
	}
	cfg, err := core.DecodeVpnKey(key)
	if err != nil {
		fmt.Println(cErr("Ошибка декодирования ключа: ") + err.Error())
		pause(in)
		return
	}
	creds, err := core.CredsFromConfig(cfg)
	if err != nil {
		printErr(err)
		pause(in)
		return
	}

	fmt.Printf("Сервер: %s@%s:%s — подключаюсь...\n", creds.User, creds.Host, creds.Port)
	knownHostsPath := filepath.Join(core.DefaultVaultDir(), "known_hosts")
	sess, err := core.ConnectWithHostKey(creds, core.HostKeyPolicy{
		KnownHostsPath: knownHostsPath,
		Prompt:         cliHostKeyPrompt(in, os.Stdout),
		OnChanged:      cliHostKeyChanged(os.Stdout, knownHostsPath),
	})
	if err != nil {
		fmt.Println(cErr("SSH не удался: ") + err.Error())
		pause(in)
		return
	}
	defer sess.Close()

	containers, err := sess.FindContainers()
	if err != nil {
		printErr(err)
		pause(in)
		return
	}
	fmt.Println()
	fmt.Println(cHead("Установленные протоколы:"))
	printContainers(containers, true)

	cur := &containers[0]
	for i := range containers {
		if containers[i].Managed() {
			cur = &containers[i]
			break
		}
	}

	for {
		title := fmt.Sprintf(" Протокол: %s ", guiview.ProtoLabel(*cur))
		width := 58
		side := (width - len([]rune(title))) / 2
		if side < 3 {
			side = 3
		}
		fmt.Println()
		fmt.Println()
		fmt.Println(cDim(strings.Repeat("═", side)) + cTitle(title) + cDim(strings.Repeat("═", side)))
		item := func(n, text string) { fmt.Println("  " + cNum(n+".") + " " + text) }
		item("1", "Показать пользователей")
		if cur.Managed() {
			item("2", "Создать пользователя")
			item("3", "Удалить пользователя")
			item("6", "Переименовать пользователя")
			item("7", "Отключить/включить пользователя")
			item("8", "Перевыпустить конфиг")
			if core.IsXRay(cur) {
				item("9", "Сохранить конфиг клиента XRay (собирается с сервера)")
			}
		}
		if len(containers) > 1 {
			item("4", "Сменить протокол/контейнер")
		}
		item("5", "Показать данные ключа (JSON)")
		item("0", "Выход")
		fmt.Println(cDim(strings.Repeat("─", width)))

		switch ask("Выбор: ") {
		case "1":
			if _, err := listUsers(os.Stdout, sess, cur); err != nil {
				printErr(err)
			}
		case "2":
			name := ask("Имя нового пользователя: ")
			if core.IsXRay(cur) {
				if _, err := runXRayAdd(in, os.Stdout, os.Stderr, true, false, sess, cur, name); err != nil {
					printErr(err)
				}
				break
			}
			u, err := sess.AddUser(cur, name)
			if err != nil {
				printErr(err)
				break
			}
			if err := saveUserConfig(os.Stdout, u, cur.Proto); err != nil {
				printErr(err)
			}
		case "3":
			if !cur.Managed() {
				printErr(fmt.Errorf("удаление пользователей для %s не поддерживается этой программой", cur.Title()))
				break
			}
			// listUsers возвращает список в том же (отсортированном) порядке,
			// что и напечатанная таблица — номер строки резолвится по нему же,
			// без повторного LoadClients (иначе порядок/индексы могут разъехаться).
			clients, err := listUsers(os.Stdout, sess, cur)
			if err != nil {
				printErr(err)
				break
			}
			ident := ask("\nКого удалить (имя, публичный ключ или номер строки: #3; просто «3» — это имя): ")
			if ident == "" {
				break
			}
			idx := resolveInteractive(os.Stdout, clients, ident)
			if idx < 0 {
				break
			}
			victim := clients[idx]
			if core.IsXRay(cur) {
				if _, err := runXRayAction(in, os.Stdout, os.Stderr, true, false, sess, cur, "del", victim); err != nil {
					printErr(err)
				}
				break
			}
			card := buildCard(sess, cur, victim, "удалить")
			proceed, _ := confirmOrExit(in, os.Stdout, os.Stderr, true, false, card)
			if !proceed {
				break
			}
			if err := sess.DeleteByID(cur, victim.ClientID); err != nil {
				printErr(err)
			} else {
				fmt.Println(cOK(fmt.Sprintf("Пользователь %q удалён.", victim.Name())))
			}
		case "6":
			if !cur.Managed() {
				printErr(fmt.Errorf("переименование пользователей для %s не поддерживается этой программой", cur.Title()))
				break
			}
			clients, err := listUsers(os.Stdout, sess, cur)
			if err != nil {
				printErr(err)
				break
			}
			ident := ask("\nКого переименовать (имя, публичный ключ или номер строки: #3; просто «3» — это имя): ")
			if ident == "" {
				break
			}
			idx := resolveInteractive(os.Stdout, clients, ident)
			if idx < 0 {
				break
			}
			victim := clients[idx]
			newName := ask(fmt.Sprintf("Новое имя для %q: ", victim.Name()))
			if newName == "" {
				break
			}
			if err := sess.RenameUser(cur, victim.ClientID, newName); err != nil {
				printErr(err)
			} else {
				fmt.Println(cOK(fmt.Sprintf("Пользователь %q переименован в %q.", victim.Name(), strings.TrimSpace(newName))))
			}
		case "7":
			if !cur.Managed() {
				printErr(fmt.Errorf("управление пользователями для %s не поддерживается этой программой", cur.Title()))
				break
			}
			clients, err := listUsers(os.Stdout, sess, cur)
			if err != nil {
				printErr(err)
				break
			}
			ident := ask("\nКого отключить/включить (имя, публичный ключ или номер строки: #3; просто «3» — это имя): ")
			if ident == "" {
				break
			}
			idx := resolveInteractive(os.Stdout, clients, ident)
			if idx < 0 {
				break
			}
			victim := clients[idx]
			if core.IsXRay(cur) {
				if _, err := runXRayAction(in, os.Stdout, os.Stderr, true, false, sess, cur, "toggle", victim); err != nil {
					printErr(err)
				}
				break
			}
			// Неизвестная включённость (У1): enable = false — ОТКЛЮЧЕНИЕ,
			// разрешено (раунд 4, решение ядра): итог от прежней записи не
			// зависит и исправляет её.
			enable := victim.Disabled()
			if enable {
				// включение — вопрос как раньше, без карточки (Г3: вопрос
				// при включении не трогаем, владелец им уже пользуется).
				verb := "включить"
				if ask(fmt.Sprintf("%s пользователя %q? (y/n): ", capitalizeFirst(verb), victim.Name())) != "y" {
					fmt.Println("Отменено.")
					break
				}
			} else {
				card := buildCard(sess, cur, victim, "отключить")
				proceed, _ := confirmOrExit(in, os.Stdout, os.Stderr, true, false, card)
				if !proceed {
					break
				}
			}
			if note, err := sess.SetEnabledNoted(cur, victim.ClientID, enable); err != nil {
				printErr(err)
			} else if enable {
				fmt.Println(cOK(fmt.Sprintf("Пользователь %q включён.", victim.Name())))
			} else {
				fmt.Println(cOK(fmt.Sprintf("Пользователь %q отключён.", victim.Name())))
				if note != "" {
					fmt.Println(note)
				}
			}
		case "8":
			if !cur.Managed() {
				printErr(fmt.Errorf("перевыпуск конфигов для %s не поддерживается этой программой", cur.Title()))
				break
			}
			clients, err := listUsers(os.Stdout, sess, cur)
			if err != nil {
				printErr(err)
				break
			}
			ident := ask("\nКому перевыпустить конфиг (имя, публичный ключ или номер строки: #3; просто «3» — это имя): ")
			if ident == "" {
				break
			}
			idx := resolveInteractive(os.Stdout, clients, ident)
			if idx < 0 {
				break
			}
			victim := clients[idx]
			if victim.EnabledState() == core.EnabledUnknown {
				// У1: до вопроса и карточки — действие всё равно невозможно
				printErr(core.EnabledUnknownError(victim))
				break
			}
			if core.IsXRay(cur) {
				if _, err := runXRayAction(in, os.Stdout, os.Stderr, true, false, sess, cur, "rekey", victim); err != nil {
					printErr(err)
				}
				break
			}
			card := buildCard(sess, cur, victim, "перевыпустить конфиг")
			proceed, _ := confirmOrExit(in, os.Stdout, os.Stderr, true, false, card)
			if !proceed {
				break
			}
			u, err := sess.RegenerateUser(cur, victim.ClientID)
			if err != nil {
				printErr(err)
				break
			}
			if err := saveUserConfig(os.Stdout, u, cur.Proto); err != nil {
				printErr(err)
			}
		case "9":
			if !core.IsXRay(cur) || !cur.Managed() {
				break
			}
			clients, err := listUsers(os.Stdout, sess, cur)
			if err != nil {
				printErr(err)
				break
			}
			ident := ask("\nЧей конфиг сохранить (имя или номер строки: #3): ")
			if ident == "" {
				break
			}
			idx := resolveInteractive(os.Stdout, clients, ident)
			if idx < 0 {
				break
			}
			nu, err := sess.XRayClientConfig(cur, clients[idx].ClientID)
			if err != nil {
				printErr(err)
				break
			}
			if err := saveUserConfig(os.Stdout, nu, cur.Proto); err != nil {
				printErr(err)
			}
		case "4":
			printContainers(containers, false)
			if n, e := strconv.Atoi(ask("Номер: ")); e == nil && n >= 1 && n <= len(containers) {
				cur = &containers[n-1]
			}
		case "5":
			printConfig(os.Stdout, cfg)
		case "0", "q", "exit":
			return
		}
	}
}

func pause(in *bufio.Reader) {
	fmt.Print("Нажмите Enter для выхода...")
	in.ReadString('\n')
}

// ---------- CLI-режим ----------

func main() {
	if len(os.Args) < 2 {
		os.Exit(interactive())
	}
	knownHostsPath := filepath.Join(core.DefaultVaultDir(), "known_hosts")
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, knownHostsPath))
}

// run — точка входа CLI-подкоманд (Е3 задания PR-4, правка 4.15 PQ-01):
// вынесена из main(), чтобы её можно было прогнать в тесте
// (TestNonTTYUnknownHostNeedsHostkey — сценарий без TTY против fakesrv)
// без os.Exit, который убил бы тестовый процесс. main() вызывает run() с
// os.Args[1:]/os.Stdin/os.Stdout/os.Stderr и реальным known_hosts
// (core.DefaultVaultDir()); все os.Exit(code) внутри веток switch заменены
// на return code, а confirmOrExit/confirmSubcommand (PR-5) получают потоки
// run() (stdin/stdout/stderr), а не os.Stdin/os.Stdout/os.Stderr напрямую —
// тесты PR-5 (TestNonTTYWithoutYesExit2 и др.) это не трогает, они и раньше
// звали confirmOrExit/confirmSubcommand напрямую со своими буферами.
//
// stdinIsTTY() по-прежнему проверяет РЕАЛЬНЫЙ os.Stdin (единственный
// TTY-детектор пакета — confirm.go, PR-5, второй не заводим) — это НЕ то же
// самое, что переданный сюда stdin io.Reader: последний источник для чтения
// ответов на вопросы (в тестах — bytes.Buffer/strings.Reader), а
// stdinIsTTY() решает, задавать ли вопрос вообще. В тестовом процессе
// os.Stdin не терминал, поэтому stdinIsTTY() там всегда false — как и было
// в TestNonTTYWithoutYesExit2 до этого рефакторинга.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, knownHostsPath string) int {
	cmd := args[0]

	// version/-version/--version — до flag.NewFlagSet и до любой работы с
	// ключом/сетью/known_hosts (ПР-6а, Г2): run() иначе требует -key ради
	// печати номера версии. Лишние аргументы игнорируются (П19).
	if cmd == "version" || cmd == "-version" || cmd == "--version" {
		fmt.Fprintln(stdout, "amnezia-admin "+version.String())
		return 0
	}

	// check — по тем же причинам здесь же: проверка окружения, требующая
	// административного ключа, бессмысленна, а ниже run() требует -key.
	// Код всегда 0: «графический интерфейс не запустится» — не ошибка
	// утилиты, а факт об окружении, и коды 1/2 остаются договором со
	// скриптами (PR-4-Б, PR-5). Лишние аргументы игнорируются — как у
	// version.
	if cmd == "check" {
		envcheck.Report(envcheck.Detect(envcheck.OSDeps()), stdout)
		return 0
	}

	// backup-info — только файл копии: ни ключа, ни сети.
	if cmd == "backup-info" {
		return runBackupInfo(stdout, stderr, args[1:])
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	key := fs.String("key", os.Getenv("AMNEZIA_KEY"), "админский ключ vpn://...")
	name := fs.String("name", "", "имя пользователя (для add/del/rename/toggle)")
	newname := fs.String("newname", "", "новое имя (для rename)")
	dryRun := fs.Bool("dry-run", false, "показать изменения wg0.conf и clientsTable, ничего не записывая")
	yes := fs.Bool("yes", false, "выполнить необратимое действие (del/rekey/toggle-отключение; у XRay — любое действие, перезапускающее XRay) без вопроса (для скриптов)")
	printConf := fs.Bool("print", false, "show-config: напечатать содержимое конфига (с ПРИВАТНЫМ ключом клиента) — только если ключ сервера сверен и совпал")
	printUnverified := fs.Bool("print-unverified", false, "show-config: напечатать содержимое, даже если ключ сервера не совпал или не сверен")
	hostkey := fs.String("hostkey", "", "ожидаемый отпечаток ключа сервера SHA256:… (обязателен без терминала для нового сервера)")
	container := fs.String("container", "", "контейнер протокола (например amnezia-awg2); по умолчанию — первый управляемый")
	outFile := fs.String("o", "", "backup: файл копии (по умолчанию — каталог данных пользователя, «Резервные копии»)")
	backupFile := fs.String("file", "", "restore: файл копии .aabk")
	apply := fs.Bool("apply", false, "restore: выполнить замену (без флага — только предпросмотр)")
	addrChanges := fs.Bool("address-changes", false, "restore: продолжить, хотя адрес выдачи другой или не проверен")
	pwFile := fs.String("password-file", "", "backup/restore: файл с паролем копии (пароль аргументом не передаётся)")
	noPw := fs.Bool("no-password", false, "backup: сохранить копию без пароля (файл НЕ зашифрован)")
	skipXRay := fs.Bool("skip-xray", false, "restore: перенести без XRay (XRay на новом сервере останется прежним)")
	replaceUsers := fs.Bool("replace-users", false, "restore: записать, хотя на новом сервере есть пользователи или конфликты с копией (без терминала и с -yes — обязателен в этом случае)")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		// Код 1 — обычная ошибка (флаг ошибся, а не "не подтверждено");
		// 2 занят решением PR-5 "нет терминала и нет -yes"/"y/n ответил
		// нет" — смешивать эти два смысла нельзя (ревью PR-4-Б, круг 1,
		// BE-01 Low: скрипт, различающий "неверные аргументы" от "человек
		// сознательно отказался", не должен получать один и тот же код для
		// обоих случаев).
		return 1
	}

	if *key == "" {
		fmt.Fprintln(stderr, "Не задан ключ: -key vpn://... или переменная AMNEZIA_KEY")
		return 1
	}
	cfg, err := core.DecodeVpnKey(*key)
	if err != nil {
		fmt.Fprintln(stderr, "Ошибка декодирования ключа:", err)
		return 1
	}
	if cmd == "decode" {
		printConfig(stdout, cfg)
		return 0
	}

	creds, err := core.CredsFromConfig(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "Ошибка:", err)
		return 1
	}

	isTTY := stdinIsTTY()
	sess, err := core.ConnectWithHostKey(creds, hostKeyPolicyForCLI(stdin, stdout, stderr, isTTY, *hostkey, knownHostsPath))
	if err != nil {
		if !isTTY && errors.Is(err, core.ErrHostKeyUnknown) {
			fmt.Fprintln(stderr, "SSH:", err)
			fmt.Fprintln(stderr, "Без терминала подключение к новому серверу требует явного отпечатка: -hostkey SHA256:...")
			return 2
		}
		fmt.Fprintln(stderr, "SSH:", err)
		return 1
	}
	defer sess.Close()

	containers, err := sess.FindContainers()
	if err != nil {
		fmt.Fprintln(stderr, "Ошибка:", err)
		return 1
	}
	cur := &containers[0]
	for i := range containers {
		if containers[i].Managed() {
			cur = &containers[i]
			break
		}
	}
	// -container (PR-W1): выбрать протокол явно — канарейка проходит по
	// всем контейнерам семейства WG. Нет такого на сервере — отказ, а не
	// молчаливый выбор другого.
	if *container != "" {
		cur = nil
		for i := range containers {
			if containers[i].Name == *container {
				cur = &containers[i]
			}
		}
		if cur == nil {
			var names []string
			for _, c := range containers {
				names = append(names, c.Name)
			}
			fmt.Fprintf(stderr, "Ошибка: контейнера %s на сервере нет (есть: %s)\n", *container, strings.Join(names, ", "))
			return 1
		}
	}

	switch cmd {
	case "backup":
		// Ctrl+C — то же, что «Отмена»: копия не сохраняется, временный
		// файл удаляется
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return runBackup(ctx, stdin, stdout, stderr, isTTY, sess, *outFile, *pwFile, *noPw, time.Now())
	case "restore":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return runRestore(ctx, stdin, stdout, stderr, isTTY, sess, *backupFile, *pwFile, *apply, *addrChanges, *skipXRay, *replaceUsers, *yes, time.Now())
	case "list":
		_, err = listUsers(stdout, sess, cur)
	case "add":
		if *dryRun {
			err = runDryRun(stdout, sess, cur, cmd, *name, *newname)
			break
		}
		if core.IsXRay(cur) && cur.Managed() {
			code, e := runXRayAdd(stdin, stdout, stderr, isTTY, *yes, sess, cur, *name)
			if e == nil && code != 0 {
				return code
			}
			err = e
			break
		}
		u, e := sess.AddUser(cur, *name)
		if e == nil {
			e = saveUserConfig(stdout, u, cur.Proto)
		}
		err = e
	case "del":
		if *dryRun {
			err = runDryRun(stdout, sess, cur, cmd, *name, *newname)
			break
		}
		// вне интерактивного списка номер строки ничего не значит —
		// принимаем только имя или публичный ключ (см. core.ResolveNonNumeric)
		clients, e := sess.LoadClients(cur)
		if e != nil {
			err = e
			break
		}
		idx, e := resolveByFlag(stdout, clients, *name)
		if e != nil {
			err = e
			break
		}
		if core.IsXRay(cur) {
			code, e := runXRayAction(stdin, stdout, stderr, isTTY, *yes, sess, cur, cmd, clients[idx])
			if e == nil && code != 0 {
				return code
			}
			err = e
			break
		}
		if proceed, code := confirmSubcommand(stdin, stdout, stderr, isTTY, *yes, cmd, clients[idx], sess, cur, "удалить"); !proceed {
			return code
		}
		err = sess.DeleteByID(cur, clients[idx].ClientID)
		if err == nil {
			fmt.Fprintf(stdout, "Пользователь %q удалён.\n", *name)
		}
	case "rename":
		if *dryRun {
			err = runDryRun(stdout, sess, cur, cmd, *name, *newname)
			break
		}
		// вне интерактивного списка номер строки ничего не значит —
		// принимаем только имя или публичный ключ (см. core.ResolveNonNumeric)
		clients, e := sess.LoadClients(cur)
		if e != nil {
			err = e
			break
		}
		idx, e := resolveByFlag(stdout, clients, *name)
		if e != nil {
			err = e
			break
		}
		err = sess.RenameUser(cur, clients[idx].ClientID, *newname)
		if err == nil {
			fmt.Fprintf(stdout, "Пользователь %q переименован в %q.\n", *name, strings.TrimSpace(*newname))
		}
	case "toggle":
		if *dryRun {
			err = runDryRun(stdout, sess, cur, cmd, *name, *newname)
			break
		}
		// вне интерактивного списка номер строки ничего не значит —
		// принимаем только имя или публичный ключ (см. core.ResolveNonNumeric)
		clients, e := sess.LoadClients(cur)
		if e != nil {
			err = e
			break
		}
		idx, e := resolveByFlag(stdout, clients, *name)
		if e != nil {
			err = e
			break
		}
		if core.IsXRay(cur) {
			code, e := runXRayAction(stdin, stdout, stderr, isTTY, *yes, sess, cur, cmd, clients[idx])
			if e == nil && code != 0 {
				return code
			}
			err = e
			break
		}
		// Неизвестная включённость: enable = false — отключение, разрешено
		// (раунд 4, решение ядра).
		enable := clients[idx].Disabled()
		if proceed, code := confirmSubcommand(stdin, stdout, stderr, isTTY, *yes, cmd, clients[idx], sess, cur, "отключить"); !proceed {
			return code
		}
		var note string
		note, err = sess.SetEnabledNoted(cur, clients[idx].ClientID, enable)
		if err == nil {
			if enable {
				fmt.Fprintf(stdout, "Пользователь %q включён.\n", *name)
			} else {
				fmt.Fprintf(stdout, "Пользователь %q отключён.\n", *name)
			}
			if note != "" {
				fmt.Fprintln(stdout, note) // Н-4: правилась только запись
			}
		}
	case "rekey":
		if *dryRun {
			err = runDryRun(stdout, sess, cur, cmd, *name, *newname)
			break
		}
		// вне интерактивного списка номер строки ничего не значит —
		// принимаем только имя или публичный ключ (см. core.ResolveNonNumeric)
		clients, e := sess.LoadClients(cur)
		if e != nil {
			err = e
			break
		}
		idx, e := resolveByFlag(stdout, clients, *name)
		if e != nil {
			err = e
			break
		}
		if core.IsXRay(cur) {
			code, e := runXRayAction(stdin, stdout, stderr, isTTY, *yes, sess, cur, cmd, clients[idx])
			if e == nil && code != 0 {
				return code
			}
			err = e
			break
		}
		if clients[idx].EnabledState() == core.EnabledUnknown {
			// У1: до карточки подтверждения — действие всё равно невозможно
			err = core.EnabledUnknownError(clients[idx])
			break
		}
		if proceed, code := confirmSubcommand(stdin, stdout, stderr, isTTY, *yes, cmd, clients[idx], sess, cur, "перевыпустить конфиг"); !proceed {
			return code
		}
		u, e := sess.RegenerateUser(cur, clients[idx].ClientID)
		if e == nil {
			e = saveUserConfig(stdout, u, cur.Proto)
		}
		err = e
	case "show-config":
		if core.IsXRay(cur) && cur.Managed() {
			err = showXRayConfig(stdout, sess, cur, *name, *printConf || *printUnverified)
			break
		}
		err = showConfig(stdout, sess, cur, *name, *printConf, *printUnverified)
	default:
		err = fmt.Errorf("неизвестная команда %q (decode | list | add | del | rename | toggle | rekey | show-config | backup | backup-info | restore)", cmd)
	}
	if err != nil {
		fmt.Fprintln(stderr, errText(err, func(x string) string { return x }))
		return 1
	}
	return 0
}
