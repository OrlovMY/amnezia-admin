package main

import (
	"errors"
	"fmt"
	"io"

	"amnezia-admin/core"
	"amnezia-admin/internal/guiview"
)

// errConfigNotSaved — конфиг клиента в каталогах поиска не найден (код 1,
// текст — тот же, что в GUI).
var errConfigNotSaved = errors.New("конфиг не найден")

// errUnverifiedNotPrinted — -print при несовпавшем или не сверенном ключе
// сервера: содержимое не напечатано.
var errUnverifiedNotPrinted = errors.New("содержимое НЕ напечатано: ключ сервера в файле не совпал с этим сервером или не сверен (см. выше). " +
	"Если вы уверены в файле, повторите с -print-unverified")

// legacyConfigDirs — каталоги прежних версий (тесты уводят во временный).
var legacyConfigDirs = core.LegacyConfigDirs

// showConfig — `show-config -name X [-print]`: сохранённый на этом
// компьютере конфиг клиента, найденный по ПУБЛИЧНОМУ ключу (имени файла не
// доверяем), и его сверка с сервером. Содержимое (с приватным ключом)
// печатается ТОЛЬКО по -print — по явной просьбе человека. QR в терминал не
// выводится.
func showConfig(w io.Writer, sess *core.Session, cur *core.Container, ident string, printContent, printUnverified bool) error {
	clients, err := sess.LoadClients(cur)
	if err != nil {
		return err
	}
	idx, err := resolveByFlag(w, clients, ident)
	if err != nil {
		return err
	}
	cl := clients[idx]
	dir, dirErr := core.UserConfigsDir()
	sc := core.FindSavedConfigIn(append([]core.SavedDir{{Path: dir, Err: dirErr}}, legacyConfigDirs()...), cl.ClientID)
	switch sc.State {
	case core.SavedNotFound:
		fmt.Fprintln(w, guiview.SavedNotFoundText(sc.Searched))
		fmt.Fprintf(w, "Перевыпустить: amnezia-admin rekey -name %q\n", cl.Name())
		return errConfigNotSaved
	case core.SavedFound:
	default:
		return errors.New(guiview.SavedUnreadableText(sc.Why))
	}
	fmt.Fprintln(w, guiview.SavedFoundText(sc))
	sp, perr := sess.ClientPeerParams(cur, cl)
	ch := core.CheckSavedConfig(sc.Config, sp, perr)
	fmt.Fprintln(w, guiview.SavedCheckText(ch))
	// SEC-01 R1-b: содержимое — только при совпавшем ключе сервера; иначе —
	// лишь по отдельному согласию -print-unverified.
	if printContent && ch.ServerKey != core.CheckSame && !printUnverified {
		return errUnverifiedNotPrinted
	}
	if printContent || printUnverified {
		fmt.Fprintln(w, "--- содержимое (приватный ключ клиента — никому не пересылайте) ---")
		fmt.Fprint(w, sc.Config)
	}
	return nil
}
