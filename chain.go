package goiptables

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
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
	args, err := rule.Marshal()
	if err != nil {
		return err
	}
	_, err = c.runCommand(appendCommand, args...)
	return err
}

// Checks if rule exists in Chain
func (c *Chain) Check(rule Rule) error {
	args, err := rule.Marshal()
	if err != nil {
		return err
	}
	_, err = c.runCommand(checkCommand, args...)
	return err
}

// Delete removes a Rule from the specified Chain by its RuleSpecification
func (c *Chain) Delete(rule Rule) error {
	args, err := rule.Marshal()
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
	if rule.RuleNumber == "" {
		rule.RuleNumber = "1"
	}
	args, err := rule.Marshal()
	if err != nil {
		return err
	}

	_, err = c.runCommand(insertCommand, args...)
	return err
}

// Replace replaces a Rule in the Chain
func (c *Chain) Replace(rule Rule) error {
	args, err := rule.Marshal()
	if err != nil {
		return err
	}
	_, err = c.runCommand(replaceCommand, args...)
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
func (c *Chain) ListRules() ([]Rule, error) {
	out, err := c.runCommand(listRulesCommand, "-v")
	if err != nil {
		return nil, err
	}
	// return parseListRules(c.Table, out)
	var rules []Rule
	lines := bytes.Split(out, []byte("\n"))
	for _, line := range lines {
		rule, err := Unmarshal(line)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
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

// runCommand is the primary Chain command func; sends stdout & stderr to the function's []byte and err return values
func (c *Chain) runCommand(cmd command, args ...string) ([]byte, error) {
	cmdArgs := append([]string{string(cmd), c.Name}, args...)
	command := exec.Command(iptablesCommand, cmdArgs...)

	// pipe stdout & stderr
	outPipe, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	defer outPipe.Close()
	errPipe, err := command.StderrPipe()
	if err != nil {
		return nil, err
	}
	defer errPipe.Close()
	outChan := make(chan []byte)
	go pipe(outPipe, outChan)
	errChan := make(chan []byte)
	go pipe(errPipe, errChan)

	// run cmd
	err = command.Start()
	if err != nil {
		return nil, err
	}

	// read out & err
	if errBytes := <-errChan; len(errBytes) > 0 {
		return nil, fmt.Errorf("%s", errBytes)
	}
	if outBytes := <-outChan; len(outBytes) > 0 {
		return outBytes, nil
	}

	err = command.Wait()
	return nil, err
}

// pipe reads from r and sends bytes on ch when r closes
func pipe(r io.ReadCloser, ch chan []byte) {
	var b []byte
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		b = append(b, scanner.Bytes()...)
	}
	ch <- b
}
