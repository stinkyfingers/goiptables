package goiptables

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strconv"
)

// Tags:
// short: the single char flag, if it exists
// long: the full-text flag
// flag: add -<short> <flag> (e.g. -m conntrack)
// - and <empty>: skip field
// _: include field in marshalling, without including a flag (e.g. RuleNumber)

// TODO ! inversions

type Rule struct {
	RuleNumber string `short:"_" long:"_"`
	Table      Table  `short:"t" long:"table"` // filter is default
	Chain      Chain  `short:"-" long:"-"`
	Action     Action `short:"-" long:"-"`

	RuleSpecifications RuleSpecifications `short:"-" long:"-"`
	MatchExtensions    MatchExtensions    `short:"-" long:"-"`
	TargetExtensions   TargetExtensions   `short:"-" long:"-"`
}

type RuleSpecifications struct {
	Protocol     string `short:"p" long:"protocol"`
	Source       string `short:"s" long:"source"`
	Destination  string `short:"d" long:"destination"`
	Jump         string `short:"j" long:"jump"` // Target
	Goto         string `short:"g" long:"goto"`
	InInterface  string `short:"i" long:"in-interface"`
	OutInterface string `short:"o" long:"out-interface"`
	Fragment     string `short:"f" long:"fragment"`
	Match        string `short:"m" long:"match"`
	SetCounters  string `short:"c" long:"set-counters" length:"2"`
}

type Action string

const (
	InsertAction Action = "insert"
	AppendAction Action = "append"
	DeleteAction Action = "delete"
	PolicyAction Action = "policy"
)

// Marshal converts a Rule into its C-style command-line args
func (r *Rule) Marshal() ([]string, error) {
	var args []string
	type valSet struct {
		key   reflect.StructTag
		value reflect.Value
	}
	vals := []valSet{{reflect.StructTag(""), reflect.ValueOf(r).Elem()}}
	for {
		if len(vals) == 0 {
			break
		}
		current := vals[0]
		vals = vals[1:]

		// if struct, add values to queue
		if current.value.Kind() == reflect.Struct {
			for i := 0; i < current.value.NumField(); i++ {
				vals = append(vals, valSet{
					current.value.Type().Field(i).Tag,
					current.value.Field(i),
				})
			}
			// flagged sub struct, skip if fields are "nil", else add "-short flag"
			if current.key.Get("short") != "" && current.key.Get("short") != "-" && !isNil(current.value) {
				args = append(args, buildFlag(current.key.Get("flag")), current.key.Get("short"))
			}
			continue
		}

		tag := current.key.Get("short")

		// skip omitted tags
		if tag == "" || tag == "-" {
			continue
		}

		// skip empty values
		if current.value.String() == reflect.Zero(current.value.Type()).String() {
			continue
		}
		if tag == "_" {
			// no-flag append
			args = append(args, current.value.String())
		} else {
			// regular append
			args = append(args, buildFlag(tag), current.value.String())
		}
	}
	return args, nil
}

// isNil returns true if all the values recursively in a struct are not set
// NOTE: only evaluates strings
func isNil(v reflect.Value) bool {
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Kind() == reflect.Struct {
			if !isNil(v.Field(i)) {
				return false
			} else {
				continue // struct is nil
			}
		}
		switch v.Field(i).Type().Name() {
		case "string":
			if v.Field(i).String() != "" { // evals strings; not empty -> not nil
				return false
			}
		case "bool":
			if v.Field(i).Bool() { // evals bool; true -> not empty
				return false
			}
		}
	}
	return true
}

// buildFlag returns a standard C-style flag for a flag name (e.g. -a or --atype)
func buildFlag(identifier string) string {
	dash := "-"
	if len(identifier) > 1 {
		dash = "--"
	}
	return fmt.Sprintf("%s%s", dash, identifier)
}

// Unmarshal converts a single line from ListRules into a Rule
func Unmarshal(data []byte) (Rule, error) {
	var rule Rule
	ruleValue := reflect.ValueOf(&rule).Elem()

	line := bytes.Split(data, []byte(" "))
	line = rule.handleAction(line)

	type valSet struct {
		key   reflect.StructTag
		value reflect.Value
	}
	var vals []valSet

	for i := 0; i < ruleValue.NumField(); i++ {
		vals = append(vals, valSet{ruleValue.Type().Field(i).Tag, ruleValue.Field(i)})
	}

Outer:
	for {
		if len(vals) == 0 {
			break
		}
		current := vals[0]
		vals = vals[1:]

		// kind is struct, assign fields to vals pool
		if current.value.Kind() == reflect.Struct {
			for i := 0; i < current.value.NumField(); i++ {
				vals = append(vals, valSet{
					current.value.Type().Field(i).Tag,
					current.value.Field(i),
				})
			}
			continue
		}

		if current.key.Get("short") == "-" || current.key.Get("short") == "" {
			continue
		}

		// assign
		for index := range line {
			if index+1 >= len(line) {
				break
			}

			// arg flag matches struct tag
			if bytes.Contains(line[index], []byte("-")) && current.key.Get("short") == string(bytes.Trim(line[index], "-")) {
				// array args - pass as space-separated length
				length, err := lengthTag(current.key)
				if err != nil {
					return rule, err
				}
				var value []byte
				for j := index + 1; j <= index+length; j++ {
					value = append(value, line[j]...)
					value = append(value, []byte(" ")...)
				}
				assignValue(bytes.TrimSpace(value), current.value)
				continue Outer
			}
		}
	}
	return rule, nil
}

// assignValue assigns b to value val
func assignValue(b []byte, val reflect.Value) error {
	if !val.CanSet() {
		return errors.New("cannot set struct field")
	}

	switch val.Kind().String() {
	case "string":
		val.SetString(string(b))
	case "int":
		i, err := strconv.Atoi(string(b))
		if err != nil {
			return err
		}
		val.SetInt(int64(i))
	default:
		return errors.New("unsupported field type")
	}
	return nil
}

// lengthTag parses the length from the struct tag as an int
func lengthTag(key reflect.StructTag) (int, error) {
	length := 1
	lengthStr := key.Get("length")
	if lengthStr == "" || lengthStr == "1" {
		return length, nil
	}
	return strconv.Atoi(lengthStr)
}

// handleAction sets a rule's Action and Chain, if they are in the line input
func (r *Rule) handleAction(line [][]byte) [][]byte {
	if len(line) < 2 {
		return line
	}
	switch string(line[0]) {
	case "-I":
		r.Action = InsertAction
	case "-A":
		r.Action = AppendAction
	case "-D":
		r.Action = DeleteAction
	case "-P":
		r.Action = PolicyAction
	default:
		return line
	}
	r.Chain = Chain{Name: string(line[1])}
	return line[2:]
}
