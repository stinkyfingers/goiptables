package goiptables

import (
	"testing"
)

func TestCommands(t *testing.T) {
	chain := &Chain{Name: "INPUT"}

	// iptables -I INPUT 1 -i lo -j ACCEPT
	rule := Rule{
		RuleNumber: "1",
		RuleSpecifications: RuleSpecifications{
			InInterface: "lo",
			Jump:        "ACCEPT",
		},
	}
	err := chain.Insert(rule)
	if err != nil {
		t.Error(err)
	}

	// iptables -A INPUT -p udp --dport 53 -j ACCEPT
	rule2 := Rule{
		RuleSpecifications: RuleSpecifications{
			Protocol: "udp",
			Jump:     "ACCEPT",
		},
		MatchExtensions: MatchExtensions{
			DestPort: "53",
		},
	}

	err = chain.Append(rule2)
	if err != nil {
		t.Error(err)
	}

	str, err := chain.List()
	if err != nil {
		t.Error(err)
	}
	t.Log(str)

	rules, policies, err := chain.ListRules()
	if err != nil {
		t.Error(err)
	}

	t.Log(rules, policies)

	err = chain.Flush()
	if err != nil {
		t.Error(err)
	}
}
