[Godoc](https://godoc.org/github.com/stinkyfingers/goiptables)

# Goiptable #
goiptables is a wrapper around Linux's iptables. 
1) Assure that it is installed:
`yum install iptables`
`apt-get install iptables`
2) Build things - you'll need to run as root.

### Usage ###
**Insert a rule into the INPUT chain:**

```
chain := &Chain{
	Name: "INPUT",
	Table: "filter"
}
```
```
rule := Rule{
	RuleNumber: "1",
	RuleSpecifications: RuleSpecifications{
		InInterface: "lo",
		Jump:        "ACCEPT",
	},
}
```
```
err := chain.Insert(rule)
```

**Append a rule to the OUTPUT chain:**

```
rule := Rule{
	RuleSpecifications: RuleSpecifications{
		InInterface: "lo",
		Jump:        "ACCEPT",
	},
}
```
```
err := Append(rule)
```

*note: the Append() function does not strip the rule number*

**Flush chain:**

```
err := chain.Flush()
```

**Marshal a rule (convert a Rule object into a string):**
```
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
```
str, err := r.Marshal()
...yields: `2 -t filter -m dccp -c 10 2 -m conntrack -m dccp --ctstate ESTABLISHED --dport 22`

**Unmarshal a rule**
`str := "-I OUTPUT -i eth0 -p tcp -s 8.8.8.8 -j DROP"`
`rule, err := Unmarshal(str)`
...yields

```
Rule{
	RuleSpecifications: RuleSpecifications{
		Protocol: "tcp", 
		Source: "8.8.8.8", 
		Jump: "DROP",
	}, 
	Chain: Chain{
		Name: "OUTPUT",
	}, 
	Action: InsertAction,
}
```