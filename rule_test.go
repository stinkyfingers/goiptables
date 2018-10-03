package goiptables

import (
	"reflect"
	"testing"
)

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

func TestUnmarshalThorough(t *testing.T) {
	tests := []struct {
		rule     string
		expected Rule
	}{
		{
			rule:     `-A INPUT -s 8.8.8.8 -j DROP`,
			expected: Rule{RuleSpecifications: RuleSpecifications{Source: "8.8.8.8", Jump: "DROP"}, Chain: Chain{Name: "INPUT"}, Action: AppendAction},
		},
		{
			rule:     `-I OUTPUT -i eth0 -p tcp -s 8.8.8.8 -j DROP`,
			expected: Rule{RuleSpecifications: RuleSpecifications{InInterface: "eth0", Protocol: "tcp", Source: "8.8.8.8", Jump: "DROP"}, Chain: Chain{Name: "OUTPUT"}, Action: InsertAction},
		},
	}

	for _, test := range tests {
		rule, err := Unmarshal([]byte(test.rule))
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(rule, test.expected) {
			t.Errorf("marshal error, got \n%v\n, expected \n%v\n", rule, test.expected)
		}
	}
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

func TestHandleAction(t *testing.T) {
	var r Rule
	line := [][]byte{[]byte("-I"), []byte("OUTPUT"), []byte("-j"), []byte("DROP")}
	newLine := [][]byte{[]byte("-j"), []byte("DROP")}
	line = r.handleAction(line)
	if !reflect.DeepEqual(line, newLine) {
		t.Errorf("expected line to be truncated, got \n%v", line)
	}
	if r.Action != InsertAction {
		t.Errorf("expected insert action, got %s", r.Action)
	}
	if r.Chain.Name != "OUTPUT" {
		t.Errorf("expected output chain, got %s", r.Chain)
	}
}
