package goiptables

type Policy struct {
	Target string `short:"-" long:"-"`
	Table  string `short"t" long:"table"` // filter is default
}
