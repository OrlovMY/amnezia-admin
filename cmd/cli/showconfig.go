package main

import (
	"errors"
	"fmt"
	"io"

	"amnezia-admin/core"
	"amnezia-admin/internal/guiview"
)

// errConfigNotSaved — конфиг клиента на этом компьютере не сохранялся (код 1,
// текст — тот же, что в GUI).
var errConfigNotSaved = errors.New("конфиг не найден")

// showConfig — `show-config -name X [-print]`: сохранённый на этом
// компьютере конфиг клиента, найденный по ПУБЛИЧНОМУ ключу (имени файла не
// доверяем), и его сверка с сервером. Содержимое (с приватным ключом)
// печатается ТОЛЬКО по -print — по явной просьбе человека. QR в терминал не
// выводится.
func showConfig(w io.Writer, sess *core.Session, cur *core.Container, ident string, printContent bool) error {
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
	sc := core.FindSavedConfig(dir, dirErr, cl.ClientID)
	switch sc.State {
	case core.SavedNotFound:
		fmt.Fprintln(w, guiview.SavedNotFoundText)
		fmt.Fprintf(w, "Перевыпустить: amnezia-admin rekey -name %q\n", cl.Name())
		return errConfigNotSaved
	case core.SavedFound:
	default:
		return errors.New(guiview.SavedUnreadableText(sc.Why))
	}
	fmt.Fprintln(w, guiview.SavedFoundText(sc))
	psk, addr, perr := sess.ClientPeerParams(cur, cl)
	fmt.Fprintln(w, guiview.SavedCheckText(core.CheckSavedConfig(sc.Config, psk, addr, perr)))
	if printContent {
		fmt.Fprintln(w, "--- содержимое (приватный ключ клиента — никому не пересылайте) ---")
		fmt.Fprint(w, sc.Config)
	}
	return nil
}
