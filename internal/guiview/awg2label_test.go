package guiview

import (
	"strings"
	"testing"

	"amnezia-admin/core"
)

// AWG2Formats — образцы awg0.conf на КАЖДОЕ состояние формата W3 (вторая ось)
// с самыми длинными причинами: незнакомый ключ предельной длины, строка с
// большим номером, нет обязательного параметра. Те же образцы длинных причин
// берёт TestProtoLabelFits (cmd/gui).
func AWG2Formats() map[string]core.AWGFormat {
	head := "[Interface]\nPrivateKey = k\nAddress = 10.8.1.1/24\nListenPort = 51820\n"
	pad := strings.Repeat("Jc = 4\n", 99990)
	return map[string]core.AWGFormat{
		"не прочитан":          {State: core.FormatUnreadable},
		"3.1":                  core.ParseAWGFormat(head + "S3 = 15\nS4 = 25\nH1 = 1-2\nH2 = 3-4\nH3 = 5-6\nH4 = 7-8\nHeaderProtectionKey = x\n"),
		"2":                    core.ParseAWGFormat(head + "S3 = 15\nS4 = 25\nH1 = 100-200\n"),
		"не определена":        core.ParseAWGFormat(head + "Jc = 4\n"),
		"незнакомый ключ 32":   core.ParseAWGFormat(head + strings.Repeat("Q", 32) + " = 1\n"),
		"строка 99995 без «=»": core.ParseAWGFormat(head + pad + "мусор\n"),
		"нет ListenPort":       core.ParseAWGFormat("[Interface]\nPrivateKey = k\nAddress = 10.8.1.1/24\n"),
		"пуст":                 core.ParseAWGFormat(""),
	}
}

// TestAWG2LabelSameAsProtoLabel — сведение W2+W3: подпись amnezia-awg2,
// которую строит ProtoLabel из Proto/Support/Reason контейнера (как его
// заполняет FindContainers), дословно равна AWGVersionLabel формата — на
// каждом состоянии. Две оси (Support W2 и формат W3) не сливаются: известный
// формат — SupportYes без суффикса, прочие — «— только просмотр: <причина>».
func TestAWG2LabelSameAsProtoLabel(t *testing.T) {
	fs := AWG2Formats()
	if len(fs) < 8 {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: состояний %d", len(fs))
	}
	for _, v := range []string{"3.1", "2"} {
		if fs[v].State != core.FormatKnown || fs[v].Version != v {
			t.Errorf("образец %s: %+v", v, fs[v])
		}
	}
	states := map[core.FormatState]bool{}
	for name, f := range fs {
		states[f.State] = true
		c := core.Container{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg", Proto: core.AWGName(f), Reason: core.AWGReason(f), Support: core.SupportKnownNo}
		if f.State == core.FormatKnown {
			c.Support = core.SupportYes
		}
		got, want := ProtoLabel(c), core.AWGVersionLabel(f)
		if got != want {
			t.Errorf("%s: ProtoLabel %q, AWGVersionLabel %q", name, got, want)
		}
		if (f.State == core.FormatKnown) == strings.Contains(got, "— только просмотр") {
			t.Errorf("%s: состояние %v, подпись %q", name, f.State, got)
		}
		// AU-UX Л1: версия — только у известного формата; у только-просмотра
		// (незнакомый ключ, неполный, НЕ ПРОЧИТАННЫЙ файл) слова «версия» нет,
		// и две подписи не звучат одинаково.
		if f.State != core.FormatKnown && strings.Contains(got, "версия") {
			t.Errorf("%s: у только-просмотра версия не пишется: %q", name, got)
		}
	}
	if len(states) != 4 {
		t.Errorf("покрыто состояний формата %d из 4", len(states))
	}
}
