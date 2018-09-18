package goiptables

import (
	"bytes"
	"errors"
	"fmt"
	// "log"
	"reflect"
	"strconv"
)

type Rule struct {
	RuleNumber string `short:"-" long:"-"`
	Table      Table  `short"t" long:"table"` // filter is default
	Stats      Stats  `short:"c" long:"set-counters" length:"2"`

	RuleSpecifications RuleSpecifications
	MatchExtensions    MatchExtensions `short:"-" long:"-"`
	TargetExtensions   TargetExtensions
}

type Stats struct {
	Packets int
	Bytes   int
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

func parseList(table Table, output []byte) ([]Rule, []Policy, error) {
	var rules []Rule
	var policies []Policy
	// TODO

	return rules, policies, nil
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
			rules = append(rules, parseLine(arr[2:]))

		default:
			// unknown
			return rules, policies, errors.New("unknown command")
		}

	}

	return rules, policies, nil
}

// TODO - clean this mess up
// parseLine decodes a single line returned from iptables list functions
func parseLine(line [][]byte) Rule {
	rule := &Rule{}

	ruleType := reflect.TypeOf(rule).Elem()
	// ruleValue := reflect.ValueOf(rule).Elem()
	ruleSpecType := reflect.TypeOf(&rule.RuleSpecifications).Elem()
	ruleSpecValue := reflect.ValueOf(&rule.RuleSpecifications).Elem()
	matchExtType := reflect.TypeOf(&rule.MatchExtensions).Elem()
	matchExtValue := reflect.ValueOf(&rule.MatchExtensions).Elem()
	targeExtType := reflect.TypeOf(&rule.TargetExtensions).Elem()
	targetExtValue := reflect.ValueOf(&rule.TargetExtensions).Elem()

	for index, item := range line {

		// stats
		for i := 0; i < ruleType.NumField(); i++ {
			switch string(bytes.Trim(item, "-")) {
			case "c":
				p, _ := strconv.Atoi(string(line[index+1]))
				b, _ := strconv.Atoi(string(line[index+2]))
				rule.Stats = Stats{b, p}
			default:
			}

		}
		// rule spec
		for i := 0; i < ruleSpecType.NumField(); i++ {
			if ruleSpecType.FieldByIndex([]int{i}).Tag.Get("short") == string(bytes.Trim(item, "-")) {
				if ruleSpecValue.FieldByIndex([]int{i}).CanAddr() && len(line) > index+1 {
					ruleSpecValue.FieldByIndex([]int{i}).SetString(string(line[index+1]))
				}

			}
		}
		// match ext
		for i := 0; i < matchExtType.NumField(); i++ {
			if matchExtType.FieldByIndex([]int{i}).Tag.Get("short") == string(bytes.Trim(item, "-")) {
				if matchExtValue.FieldByIndex([]int{i}).CanAddr() && len(line) > index+1 {
					matchExtValue.FieldByIndex([]int{i}).SetString(string(line[index+1]))
				}

			}
		}

		// target ext
		for i := 0; i < targeExtType.NumField(); i++ {
			if targeExtType.FieldByIndex([]int{i}).Tag.Get("short") == string(bytes.Trim(item, "-")) {
				if targetExtValue.FieldByIndex([]int{i}).CanAddr() && len(line) > index+1 {
					targetExtValue.FieldByIndex([]int{i}).SetString(string(line[index+1]))
				}

			}
		}

	}
	return *rule
}
