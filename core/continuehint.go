package core

import "strings"

// ContinueHintOptions — из чего собирается команда продолжения переноса на
// уже поставленный сервер (migrate -to-host в CLI и режим «новый чистый
// сервер» в GUI — один источник, аудит AU GUI-TO-HOST M3).
type ContinueHintOptions struct {
	// SrcKeyFile — файл ключа источника; "" — заглушка «<файл с ключом
	// источника>».
	SrcKeyFile string
	// KeyPath — файл ключа нового сервера.
	KeyPath string
	// AddressChanges — адрес выдачи требовал подтверждения.
	AddressChanges bool
	// PasswordFile — файл пароля автокопии; PasswordAsk — пароль был, но
	// файла нет (GUI): заглушка «<файл с паролем автокопии>»; NoPassword —
	// автокопия без пароля.
	PasswordFile string
	PasswordAsk  bool
	NoPassword   bool
	SkipXRay     bool
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// ContinueHint — команда для sh и PowerShell. Ключи — только файлами
// (-key-file/-to-key-file, в argv не попадают); все флаги, без которых
// повтор остановится там же: -address-changes, -replace-users (на цели уже
// могут быть клиенты), слой автокопии, -skip-xray, -apply.
func ContinueHint(o ContinueHintOptions) (sh, ps string) {
	type arg struct {
		v     string
		quote bool
	}
	args := []arg{{"amnezia-admin", false}, {"migrate", false}, {"-key-file", false}}
	if o.SrcKeyFile != "" {
		args = append(args, arg{o.SrcKeyFile, true})
	} else {
		args = append(args, arg{"<файл с ключом источника>", false})
	}
	args = append(args, arg{"-to-key-file", false}, arg{o.KeyPath, true})
	if o.AddressChanges {
		args = append(args, arg{"-address-changes", false})
	}
	args = append(args, arg{"-replace-users", false})
	switch {
	case o.PasswordFile != "":
		args = append(args, arg{"-password-file", false}, arg{o.PasswordFile, true})
	case o.PasswordAsk:
		args = append(args, arg{"-password-file", false}, arg{"<файл с паролем автокопии>", false})
	case o.NoPassword:
		args = append(args, arg{"-no-password", false})
	}
	if o.SkipXRay {
		args = append(args, arg{"-skip-xray", false})
	}
	args = append(args, arg{"-apply", false})
	var a, b []string
	for _, x := range args {
		if x.quote {
			a, b = append(a, shQuote(x.v)), append(b, psQuote(x.v))
		} else {
			a, b = append(a, x.v), append(b, x.v)
		}
	}
	return strings.Join(a, " "), strings.Join(b, " ")
}
