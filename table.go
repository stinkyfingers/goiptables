package goiptables

type Table string

const (
	Filter Table = "filter"
	Nat    Table = "nat"
	Mangle Table = "mangle"
	Raw    Table = "raw"
)

// tableIsValid returns true if a Table is permitted by iptables
func tableIsValid(name Table) bool {
	validTables := []Table{Filter, Nat, Mangle, Raw}
	for _, t := range validTables {
		if t == name {
			return true
		}
	}
	return false
}
