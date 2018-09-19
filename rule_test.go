package goiptables

import (
	"reflect"
	"testing"
)

func TestArgs(t *testing.T) {
	expected := []string{"-j", "ACCEPT", "-i", "lo"}
	rule := &Rule{
		RuleNumber: "1",
		RuleSpecifications: RuleSpecifications{
			InInterface: "lo",
			Jump:        "ACCEPT",
		},
	}
	arr, err := rule.RuleSpecifications.parse()
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(expected, arr) {
		t.Errorf("args not as expected; got %v, wanted %v", arr, expected)
	}
}

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

func TestParseLine(t *testing.T) {
	line := [][]byte{[]byte("-t"), []byte("filter"), []byte("-i"), []byte("lo"), []byte("-j"), []byte("ACCEPT"), []byte("-c"), []byte("2"), []byte("10")}
	rule, err := parseLine(line)
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

func TestParseRule(t *testing.T) {
	r := []Rule{{
		Table: "filter",
		RuleSpecifications: RuleSpecifications{
			Match:       "dccp",
			SetCounters: "10 2",
		},
		MatchExtensions: MatchExtensions{
			DestPort: "22",
		},
	}}
	output := []byte("-A INPUT -t filter c 10 2 -m dccp --dport 22")
	rule, _, err := parseListRules("filter", output)
	if err != nil {
		t.Error(err)
	}
	if !reflect.DeepEqual(r, rule) {
		t.Errorf("error parsing rule, got \n%v\n, wanted \n%v\n", rule, r)
	}
}
