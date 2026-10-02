package core

// KnownContainers — все имена закрытого списка (с синонимами) такими, какими
// их вернул бы FindContainers. Для проверок вида (ширина подписи и т. п.).
func KnownContainers() []Container {
	var out []Container
	for _, t := range containerTypes {
		for _, n := range t.Names {
			c, _, _ := lookupContainer(n)
			out = append(out, c)
		}
	}
	return out
}
