package goiptables

import (
	"fmt"
	"os/exec"
)

type Chain struct {
	Name    string
	Table   Table
	Options []Option
	Target  string
}

type Option string

type command string

// User-specifiable options
const (
	NumericOutput Option = "-n"
	Zero          Option = "-Z"
)

const (
	appendCommand      command = "-A"
	checkCommand       command = "-C"
	deleteCommand      command = "-D"
	insertCommand      command = "-I"
	replaceCommand     command = "-R"
	listCommand        command = "-L"
	listRulesCommand   command = "-S"
	flushCommand       command = "-F"
	zeroCommand        command = "-Z"
	newChainCommand    command = "-N"
	deleteChainCommand command = "-X"
	policyCommand      command = "-P"
	renameChainCommand command = "-E"
)

// Append appends a Rule to a Chain
func (c *Chain) Append(rule Rule) error {
	args, err := rule.RuleSpecifications.parse()
	if err != nil {
		return err
	}
	_, err = c.runCommand(appendCommand, args...)
	return err
}

func (c *Chain) Check(rule Rule) error {
	args, err := rule.RuleSpecifications.parse()
	if err != nil {
		return err
	}
	_, err = c.runCommand(checkCommand, args...)
	return err
}

// Delete removes a Rule from the specified Chain by its RuleSpecification
func (c *Chain) Delete(rule Rule) error {
	args, err := rule.RuleSpecifications.parse()
	if err != nil {
		return err
	}
	_, err = c.runCommand(deleteCommand, args...)
	return err
}

// DeleteByRuleNum removes a Rule from the specified Chain by RuleNumber
func (c *Chain) DeleteByRuleNum(rule Rule) error {
	_, err := c.runCommand(deleteCommand, rule.RuleNumber)
	return err
}

// Insert inserts one rule as the rule number given by rule.RuleNumber.
// 1 is the default ruleNumber if none is specified
func (c *Chain) Insert(rule Rule) error {
	args, err := rule.RuleSpecifications.parse()
	if err != nil {
		return err
	}
	if rule.RuleNumber == "" {
		rule.RuleNumber = "1"
	}
	args = append([]string{rule.RuleNumber}, args...)
	_, err = c.runCommand(insertCommand, args...)
	return err
}

// Replace replaces a Rule in the Chain
func (c *Chain) Replace(rule Rule) error {
	args, err := rule.RuleSpecifications.parse()
	if err != nil {
		return err
	}
	_, err = c.runCommand(replaceCommand, append([]string{rule.RuleNumber}, args...)...)
	return err
}

// List lists all Rules in the Chain and output a string
// If no Chain.Name is specified, Rules in all Chains will be listed
func (c *Chain) List() (string, error) {
	out, err := c.runCommand(listCommand, "-v")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ListRules lists all Rules in the Chain
// If no Chain.Name is specified, Rules in all Chains will be listed
func (c *Chain) ListRules() ([]Rule, []Policy, error) {
	out, err := c.runCommand(listRulesCommand, "-v")
	if err != nil {
		return nil, nil, err
	}
	return parseListRules(c.Table, out)
}

// Flush removes all Rules in the Chain
// If no Chain.Name is specified, all Chains will be Flushed
func (c *Chain) Flush() error {
	_, err := c.runCommand(flushCommand)
	return err
}

// Zero the packet and byte counters in all chains
func (c *Chain) Zero(rule Rule) error {
	_, err := c.runCommand(zeroCommand, rule.RuleNumber)
	return err
}

// NewChain creats a new user-defined chain of given Chain.Name
func (c *Chain) NewChain() error {
	_, err := c.runCommand(newChainCommand)
	return err
}

// DeleteChain deletes the optional user-specified Chain.
// The Chain must be empty
// If no Chain.Name is pecified, every user-defined Chain will be deleted
func (c *Chain) DeleteChain() error {
	_, err := c.runCommand(deleteChainCommand)
	return err
}

// Policy sets the policy for the given Chain to the Policy.Target.
// Only built-in chains can have POlicies
func (c *Chain) Policy(policy Policy) error {
	_, err := c.runCommand(policyCommand, policy.Target)
	return err
}

// RenameChain renames the Chain to the specified name
func (c *Chain) RenameChain(name string) error {
	_, err := c.runCommand(renameChainCommand, name)
	return err
}

func (c *Chain) runCommand(cmd command, args ...string) ([]byte, error) {
	command := exec.Command(iptablesCommand, append([]string{string(cmd), c.Name}, args...)...)
	out, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("%s; %s", err.Error(), string(out))
	}
	return out, nil
}
