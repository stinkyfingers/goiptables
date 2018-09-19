package goiptables

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strconv"
)

type Rule struct {
	RuleNumber string `short:"-" long:"-"`
	Table      Table  `short:"t" long:"table"` // filter is default

	RuleSpecifications RuleSpecifications
	MatchExtensions    MatchExtensions `short:"-" long:"-"`
	TargetExtensions   TargetExtensions
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

type MatchExtensions struct {
	// TODO complete
	DestPort string `short:"dport" long:"dport"`
}

type TargetExtensions struct {
	// TODO
}

func (r *RuleSpecifications) parse() ([]string, error) {
	var arr []string
	ty := reflect.TypeOf(r).Elem()
	value := reflect.ValueOf(r).Elem()

	for i := 0; i < ty.NumField(); i++ {
		flag := ty.Field(i).Tag.Get("short")
		if flag == "-" {
			continue
		}

		switch value.Field(i).Type().String() {
		case "string":
			v := value.Field(i).String()
			if len(v) == 0 {
				continue
			}
			arr = append(arr, fmt.Sprintf("-%s", flag), v)

		default:
			return arr, errors.New("unsupported struct field type")
		}
	}
	return arr, nil
}

func (m *MatchExtensions) parse() ([]string, error) {
	var arr []string
	ty := reflect.TypeOf(m).Elem()
	value := reflect.ValueOf(m).Elem()

	for i := 0; i < ty.NumField(); i++ {
		flag := ty.Field(i).Tag.Get("short")
		if flag == "-" {
			continue
		}

		switch value.Field(i).Type().String() {
		case "string":
			v := value.Field(i).String()
			if len(v) == 0 {
				continue
			}
			arr = append(arr, fmt.Sprintf("--%s", flag), v)

		default:
			return arr, errors.New("unsupported struct field type")
		}
	}
	return arr, nil
}

func (t *TargetExtensions) parse() ([]string, error) {
	var arr []string
	ty := reflect.TypeOf(t).Elem()
	value := reflect.ValueOf(t).Elem()

	for i := 0; i < ty.NumField(); i++ {
		flag := ty.Field(i).Tag.Get("short")
		if flag == "-" {
			continue
		}

		switch value.Field(i).Type().String() {
		case "string":
			v := value.Field(i).String()
			if len(v) == 0 {
				continue
			}
			arr = append(arr, fmt.Sprintf("--%s", flag), v)

		default:
			return arr, errors.New("unsupported struct field type")
		}
	}
	return arr, nil
}

// parseListRules parses the []byte output from iptables list functions
func parseListRules(table Table, output []byte) ([]Rule, []Policy, error) {
	var rules []Rule
	var policies []Policy

	lines := bytes.Split(output, []byte("\n"))
	for _, line := range lines {
		arr := bytes.Split(line, []byte(" "))
		if len(arr) < 2 {
			continue
		}
		switch string(arr[0]) {
		case "-P":
			// policy
			policies = append(policies, Policy{Target: string(arr[1])})
		case "-A":
			// appended rule
			fallthrough
		case "-I":
			// inserted rule
			rule, err := parseLine(arr[2:])
			if err != nil {
				return rules, policies, err
			}
			rules = append(rules, rule)

		default:
			// unknown
			return rules, policies, errors.New("unknown command")
		}

	}

	return rules, policies, nil
}

// parseLine converts a single line from ListRules into a Rule
func parseLine(line [][]byte) (Rule, error) {
	var rule Rule
	ruleValue := reflect.ValueOf(&rule).Elem()

	type valSet struct {
		key   reflect.StructTag
		value reflect.Value
	}
	var vals []valSet

	for i := 0; i < ruleValue.NumField(); i++ {
		vals = append(vals, valSet{ruleValue.Type().Field(i).Tag, ruleValue.Field(i)})
	}

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

			if current.key.Get("short") == string(bytes.Trim(line[index], "-")) {
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
				break
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
