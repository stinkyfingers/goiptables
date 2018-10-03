package goiptables

import (
	"reflect"
	"testing"
)

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

func TestBuildFlag(t *testing.T) {
	tests := []struct {
		str, expected string
	}{
		{"c", "-c"},
		{"conntrack", "--conntrack"},
	}
	for _, test := range tests {
		result := buildFlag(test.str)
		if result != test.expected {
			t.Errorf("error building flag. expected %s, got %s", test.expected, result)
		}
	}
}

func TestUnmarshal(t *testing.T) {
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
		{
			rule:     `-t filter -i lo -j ACCEPT -c 2 10`,
			expected: Rule{RuleSpecifications: RuleSpecifications{Jump: "ACCEPT", InInterface: "lo", SetCounters: "2 10"}, Table: "filter"},
		},
	}

	for i, test := range tests {
		rule, err := Unmarshal([]byte(test.rule))
		if err != nil {
			t.Error(err)
		}
		if !reflect.DeepEqual(rule, test.expected) {
			t.Errorf("unmarshal error, got \n%v\n, expected \n%v\n on test %d", rule, test.expected, i)
		}
	}
}

func TestAssignValue(t *testing.T) {
	type foo struct {
		Str string
		I   int
	}
	var f foo

	tests := []struct {
		b []byte
		v reflect.Value
	}{
		{b: []byte("foo"), v: reflect.ValueOf(&f).Elem().Field(0)},
		{b: []byte("1"), v: reflect.ValueOf(&f).Elem().Field(1)},
	}

	for _, test := range tests {
		err := assignValue(test.b, test.v)
		if err != nil {
			t.Error(err)
		}
	}
}

func TestLengthTag(t *testing.T) {
	tag := reflect.StructTag(`length:"2"`)
	i, err := lengthTag(tag)
	if err != nil {
		t.Error(err)
	}
	if i != 2 {
		t.Errorf("expected length tag to be %d, got %d", 2, i)
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
