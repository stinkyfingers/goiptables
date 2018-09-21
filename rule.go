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
	Account     `flag:"m" short:"account"`
	AddrType    `flag:"m" short:"addrtype"`
	Ah          `flag:"m" short:"ah"`
	Childlevel  `flag:"m" short:"childlevel"`
	Comment     `flag:"m" short:"comment"`
	Condition   `flag:"m" short:"condition"`
	Connbytes   `flag:"m" short:"connbytes"`
	Connlimit   `flag:"m" short:"connlimit"`
	Connmark    `flag:"m" short:"connmark"`
	Connrate    `flag:"m" short:"connrate"`
	Conntrack   `flag:"m" short:"conntrack"`
	Dccp        `flag:"m" short:"dccp"`
	Dscp        `flag:"m" short:"dscp"`
	DstLimit    `flag:"m" short:"dstlimit"`
	Ecn         `flag:"m" short:"ecn"`
	Esp         `flag:"m" short:"esp"`
	Fuzzy       `flag:"m" short:"fuzzy"`
	HashLimit   `flag:"m" short:"hashlimit"`
	Helper      `flag:"m" short:"helper"`
	Icmp        `flag:"m" short:"icmp"`
	IpRange     `flag:"m" short:"iprange"`
	Ipv4Options `flag:"m" short:"ipv4options"`
	Length      `flag:"m" short:"length"`
	Limit       `flag:"m" short:"limit"`
	Mac         `flag:"m" short:"mac"`
	Mark        `flag:"m" short:"mark"`
	MPort       `flag:"m" short:"mport"`
	MultiPort   `flag:"m" short:"multiport"`
	Nth         `flag:"m" short:"nth"`
	Osf         `flag:"m" short:"osf"`
	Owner       `flag:"m" short:"owner"`
	PhysDev     `flag:"m" short:"physdev"`
	PktType     `flag:"m" short:"pkttype"`
	Policy      `flag:"m" short:"policy"`
	Psd         `flag:"m" short:"psd"`
	Quota       `flag:"m" short:"quota"`
	Random      `flag:"m" short:"random"`
	Realm       `flag:"m" short:"realm"`
	Recent      `flag:"m" short:"recent"`
	Sctp        `flag:"m" short:"sctp"`
	Set         `flag:"m" short:"set"`
	State       `flag:"m" short:"state"`
	String      `flag:"m" short:"string"`
	Tcp         `flag:"m" short:"tcp"`
	Tcpmss      `flag:"m" short:"tcpmss"`
	Time        `flag:"m" short:"time"`
	Tos         `flag:"m" short:"tos"`
	Ttl         `flag:"m" short:"ttl"`
	U32         `flag:"m" short:"u32"`
	Udp         `flag:"m" short:"udp"`
}

type TargetExtensions struct {
	Balance       `flag:"m" short:"balance"`
	Classify      `flag:"m" short:"classify"`
	Clusterip     `flag:"m" short:"clusterip"`
	Connmark      `flag:"m" short:"connmark"`
	Dnat          `flag:"m" short:"dnat"`
	Dscp          `flag:"m" short:"dscp"`
	Ecn           `flag:"m" short:"ecn"`
	Ipmark        `flag:"m" short:"ipmark"`
	Ipv4optsstrip `flag:"m" short:"ipv4optsstrip"`
	Log           `flag:"m" short:"log"`
	Mark          `flag:"m" short:"mark"`
	Masquerade    `flag:"m" short:"masquerade"`
	Mirror        `flag:"m" short:"mirror"`
	Netmap        `flag:"m" short:"netmap"`
	Nfqueue       `flag:"m" short:"nfqueue"`
	Notrack       `flag:"m" short:"notrack"`
	Redirect      `flag:"m" short:"redirect"`
	Reject        `flag:"m" short:"reject"`
	Same          `flag:"m" short:"same"`
	Set           `flag:"m" short:"set"`
	Snat          `flag:"m" short:"snat"`
	Tcpmss        `flag:"m" short:"tcpmss"`
	Tos           `flag:"m" short:"tos"`
	Ttl           `flag:"m" short:"ttl"`
	Ulog          `flag:"m" short:"ulog"`
	Xor           `flag:"m" short:"xor"`
}

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
			rule, err := Unmarshal(bytes.Join(arr[2:], []byte(" ")))
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

// Unmarshal converts a single line from ListRules into a Rule
func Unmarshal(data []byte) (Rule, error) {
	var rule Rule
	ruleValue := reflect.ValueOf(&rule).Elem()

	line := bytes.Split(data, []byte(" "))

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
