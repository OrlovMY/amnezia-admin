package core

// Швы для core/hostdiag_test.go (пакет core_test).

// Probe — разобранный вывод пробы (для тестов).
type Probe = probe

func DiagContainerScriptForTest(iface, sbin string) string { return diagContainerScript(iface, sbin) }
func DiagHostScriptForTest(mod, prof string) string        { return diagHostScript(mod, prof) }
func ParseProbeForTest(out string) Probe                   { return parseProbe(out, nil) }
func ClassifyIPTablesForTest(p Probe) DiagFinding          { return classifyIPTables(p) }
func ProbeGetForTest(p Probe, k string) string             { return p.get(k) }
func ProbeAllForTest(p Probe, k string) []string           { return p.kv[k] }
