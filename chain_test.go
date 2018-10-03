package goiptables

import (
	"os/exec"
	"testing"
)

func TestCommands(t *testing.T) {
	if !iptablesIsInstalled() {
		t.Skip("iptables not installed")
	}
	var err error
	chain := &Chain{Name: "INPUT"}

	// iptables -I INPUT 1 -i lo -j ACCEPT
	rule := Rule{
		RuleNumber: "1",
		RuleSpecifications: RuleSpecifications{
			InInterface: "lo",
			Jump:        "ACCEPT",
		},
	}
	err = chain.Insert(rule)
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
			MultiPort: MultiPort{
				DstPorts: "53",
			},
		},
	}

	err = chain.Append(rule2)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	str, err := chain.List()
	if err != nil {
		t.Error(err)
	}
	t.Log(str)

	rules, err := chain.ListRules()
	if err != nil {
		t.Error(err)
	}
	t.Log(rules)

	err = chain.Flush()
	if err != nil {
		t.Error(err)
	}
}

func TestAppendCommand(t *testing.T) {
	if !iptablesIsInstalled() {
		t.Skip("iptables not installed")
	}
	chain := &Chain{Name: "INPUT"}

	// error
	rule := Rule{
		RuleNumber: "1",
		RuleSpecifications: RuleSpecifications{
			InInterface: "lo",
			Jump:        "ACCEPT",
		},
	}
	err := chain.Append(rule)
	if err == nil {
		t.Error("expected error, got nil")
	}
	chain.Flush()

	// ok
	rule.RuleNumber = ""
	err = chain.Append(rule)
	if err != nil {
		t.Error(err)
	}
	chain.Flush()
}

func TestListCommand(t *testing.T) {
	if !iptablesIsInstalled() {
		t.Skip("iptables not installed")
	}
	chain := &Chain{Name: "INPUT"}
	out, err := chain.List()
	if err != nil {
		t.Error(err)
	}
	if len(out) == 0 {
		t.Error("expected list output, got nil")
	}
}

func TestListRulesCommand(t *testing.T) {
	if !iptablesIsInstalled() {
		t.Skip("iptables not installed")
	}
	chain := &Chain{Name: "INPUT"}
	rules, err := chain.ListRules()
	if err != nil {
		t.Error(err)
	}
	if len(rules) < 1 {
		t.Errorf("expected listed rules, got %d", len(rules))
	}
}

func iptablesIsInstalled() bool {
	_, err := exec.Command("iptables", "-V").Output()
	if err != nil {
		return false
	}
	return true
}
