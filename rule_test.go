package goiptables

import (
	"reflect"
	"testing"
)

func TestParseListRules(t *testing.T) {
	output := []byte(`
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A INPUT -i lo -j ACCEPT`)
	expectedPolicies := []Policy{
		{Target: "INPUT"},
		{Target: "FORWARD"},
		{Target: "OUTPUT"},
	}
	expectedRules := []Rule{
		{RuleSpecifications: RuleSpecifications{Jump: "ACCEPT", InInterface: "lo"}},
	}

	rules, policies, err := parseListRules(Filter, output)
	if err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(policies, expectedPolicies) {
		t.Errorf("expected policies %v\n got %v\n", expectedPolicies, policies)
	}
	if !reflect.DeepEqual(rules, expectedRules) {
		t.Errorf("expected policies %v\n got %v\n", expectedRules, rules)
	}
}

func TestParseRule(t *testing.T) {
	expected := []Rule{{
		Table: "filter",
		RuleSpecifications: RuleSpecifications{
			Match:       "dccp",
			SetCounters: "10 2",
		},
		MatchExtensions: MatchExtensions{
			Dccp: Dccp{
				DstPort: "22",
			},
		},
	}}
	output := []byte("-A INPUT -t filter c 10 2 -m dccp --dport 22")
	rule, _, err := parseListRules("filter", output)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(expected, rule) {
		t.Errorf("error parsing rule, got \n%v\n, wanted \n%v\n", rule, expected)
	}
}

func TestUnmarshal(t *testing.T) {
	data := []byte("-t filter -i lo -j ACCEPT -c 2 10")
	rule, err := Unmarshal(data)
	if err != nil {
		t.Error(err)
	}

	// assert
	if rule.RuleSpecifications.Jump != "ACCEPT" {
		t.Errorf("expected Jump to be 'ACCEPT', got %s", rule.RuleSpecifications.Jump)
	}
	if rule.RuleSpecifications.InInterface != "lo" {
		t.Errorf("expected InInterface to be 'lo', got %s", rule.RuleSpecifications.InInterface)
	}
	t.Log("RULE... ", rule)
}

func TestMarshal(t *testing.T) {
	r := Rule{
		RuleNumber: "2",
		Table:      "filter",
		RuleSpecifications: RuleSpecifications{
			Match:       "dccp",
			SetCounters: "10 2",
		},
		MatchExtensions: MatchExtensions{
			Dccp: Dccp{
				DstPort: "22",
			},
			Conntrack: Conntrack{
				Ctstate: "ESTABLISHED",
			},
		},
	}

	expected := []string{"2", "-t", "filter", "-m", "dccp", "-c", "10 2", "-m", "conntrack", "-m", "dccp", "--ctstate", "ESTABLISHED", "--dport", "22"}

	j, err := r.Marshal()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(j, expected) {
		t.Errorf("error marshalling; expected \n%v\n, got \n%v\n", expected, j)
	}
}

func TestIsNil(t *testing.T) {
	var n bool

	s := Connlimit{}
	n = isNil(reflect.ValueOf(s))
	if !n {
		t.Error("expected struct to be nil")
	}

	s.ConnlimitMask = "value"
	n = isNil(reflect.ValueOf(s))
	if n {
		t.Error("expected struct to not be nil")
	}

	// custom struct
	type foo struct {
		f string
	}
	type bar struct {
		i   string
		foo foo
	}
	bar1 := bar{
		"3",
		foo{"foofoo"},
	}
	n = isNil(reflect.ValueOf(bar1))
	if n {
		t.Error("expected struct to not be nil")
	}

	var bar2 bar
	n = isNil(reflect.ValueOf(bar2))
	if !n {
		t.Error("expected struct to be nil")
	}
}
