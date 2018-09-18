package goiptables

import (
	"net/http"
	"testing"
	"time"
)

func TestCreateChainRules(t *testing.T) {
	chain := Chain{
		Name:  "TEST_CHAIN",
		Table: "filter",
	}
	rule := Rule{
		RuleSpecifications: RuleSpecifications{
			Jump:        "REJECT",
			Destination: "google.com",
		},
	}

	input := &Chain{
		Name:   "OUTPUT",
		Target: "TEST_CHAIN",
	}

	jumpRule := Rule{RuleSpecifications: RuleSpecifications{Jump: "TEST_CHAIN"}}

	_, err := http.Get("http://google.com")
	if err != nil {
		t.Error(err)
	}

	err = chain.NewChain()
	if err != nil {
		t.Error(err)
	}

	err = input.Append(jumpRule)
	if err != nil {
		t.Error(err)
	}

	err = chain.Append(rule)
	if err != nil {
		t.Error(err)
	}

	canReach := make(chan bool)
	go func() {
		_, err = http.Get("http://google.com")
		if err == nil {
			canReach <- true
		} else {
			canReach <- false
		}
	}()

	time.AfterFunc(time.Second*2, func() {
		canReach <- false
	})

	if <-canReach {
		t.Error("expected not to reach google")
	}

	// err = input.Delete(jumpRule)
	// if err != nil {
	// 	t.Error(err)
	// }

	// err = chain.Delete(rule)
	// if err != nil {
	// 	t.Error(err)
	// }

	// err = chain.DeleteChain()
	// if err != nil {
	// 	t.Error(err)
	// }
}
