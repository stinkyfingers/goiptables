package goiptables

type MatchExtensions struct {
	Account     `flag:"m" short:"account"`
	AddrType    `flag:"m" short:"addrtype"`
	Ah          `flag:"m" short:"ah"`
	Childlevel  `flag:"m" short:"childlevel"`
	Comment     `flag:"m" short:"comment"`
	Condition   `flag:"m" short:"condition"`
	Connbytes   `flag:"m" short:"connbytes"`
	Connlimit   `flag:"m" short:"connlimit"`
	Connmark    `flag:"m" short:"connmark"`
	Connrate    `flag:"m" short:"connrate"`
	Conntrack   `flag:"m" short:"conntrack"`
	Dccp        `flag:"m" short:"dccp"`
	Dscp        `flag:"m" short:"dscp"`
	DstLimit    `flag:"m" short:"dstlimit"`
	Ecn         `flag:"m" short:"ecn"`
	Esp         `flag:"m" short:"esp"`
	Fuzzy       `flag:"m" short:"fuzzy"`
	HashLimit   `flag:"m" short:"hashlimit"`
	Helper      `flag:"m" short:"helper"`
	Icmp        `flag:"m" short:"icmp"`
	IpRange     `flag:"m" short:"iprange"`
	Ipv4Options `flag:"m" short:"ipv4options"`
	Length      `flag:"m" short:"length"`
	Limit       `flag:"m" short:"limit"`
	Mac         `flag:"m" short:"mac"`
	Mark        `flag:"m" short:"mark"`
	MPort       `flag:"m" short:"mport"`
	MultiPort   `flag:"m" short:"multiport"`
	Nth         `flag:"m" short:"nth"`
	Osf         `flag:"m" short:"osf"`
	Owner       `flag:"m" short:"owner"`
	PhysDev     `flag:"m" short:"physdev"`
	PktType     `flag:"m" short:"pkttype"`
	Policy      `flag:"m" short:"policy"`
	Psd         `flag:"m" short:"psd"`
	Quota       `flag:"m" short:"quota"`
	Random      `flag:"m" short:"random"`
	Realm       `flag:"m" short:"realm"`
	Recent      `flag:"m" short:"recent"`
	Sctp        `flag:"m" short:"sctp"`
	Set         `flag:"m" short:"set"`
	State       `flag:"m" short:"state"`
	String      `flag:"m" short:"string"`
	Tcp         `flag:"m" short:"tcp"`
	Tcpmss      `flag:"m" short:"tcpmss"`
	Time        `flag:"m" short:"time"`
	Tos         `flag:"m" short:"tos"`
	Ttl         `flag:"m" short:"ttl"`
	U32         `flag:"m" short:"u32"`
	Udp         `flag:"m" short:"udp"`
}

type TargetExtensions struct {
	Balance       `flag:"m" short:"balance"`
	Classify      `flag:"m" short:"classify"`
	Clusterip     `flag:"m" short:"clusterip"`
	Connmark      `flag:"m" short:"connmark"`
	Dnat          `flag:"m" short:"dnat"`
	Dscp          `flag:"m" short:"dscp"`
	Ecn           `flag:"m" short:"ecn"`
	Ipmark        `flag:"m" short:"ipmark"`
	Ipv4optsstrip `flag:"m" short:"ipv4optsstrip"`
	Log           `flag:"m" short:"log"`
	Mark          `flag:"m" short:"mark"`
	Masquerade    `flag:"m" short:"masquerade"`
	Mirror        `flag:"m" short:"mirror"`
	Netmap        `flag:"m" short:"netmap"`
	Nfqueue       `flag:"m" short:"nfqueue"`
	Notrack       `flag:"m" short:"notrack"`
	Redirect      `flag:"m" short:"redirect"`
	Reject        `flag:"m" short:"reject"`
	Same          `flag:"m" short:"same"`
	Set           `flag:"m" short:"set"`
	Snat          `flag:"m" short:"snat"`
	Tcpmss        `flag:"m" short:"tcpmss"`
	Tos           `flag:"m" short:"tos"`
	Ttl           `flag:"m" short:"ttl"`
	Ulog          `flag:"m" short:"ulog"`
	Xor           `flag:"m" short:"xor"`
}

// MATCH EXTENSIONS

type Account struct {
	AccountAddress string `short:"aaddr" long:"aaddr"`
	AccountName    string `short:"aname" long:"aname"`
	AccountShort   string `short:"ashort" long:"ashort"`
}
type AddrType struct {
	SrcType string `short:"src-type" long:"src-type"`
	DstType string `short:"dst-type" long:"dst-type"`
}
type Ah struct {
	AhSpi string `short:"ahspi" long:"ahspi"`
}
type Childlevel struct {
	ChildLevel string `short:"childlevel" long:"childlevel"`
}
type Comment struct {
	Comment string `short:"comment" long:"comment"`
}
type Condition struct {
	Condition string `short:"condition" long:"condition"`
}
type Connbytes struct {
	Connbytes     string `short:"connbytes" long:"connbytes"`
	ConnbytesDir  string `short:"connbytes-dir" long:"connbytes-dir"`
	ConnbytesMode string `short:"connbytes-mode" long:"connbytes-mode"`
}
type Connlimit struct {
	ConnlimitAbove string `short:"connlimit-above" long:"connlimit-above"`
	ConnlimitMask  string `short:"connlimit-mask" long:"connlimit-mask"`
}
type Connmark struct {
	Mark        string `short:"mark" long:"mark"`
	SetMark     string `short:"set-mark" long:"set-mark"`
	SaveMark    string `short:"save-mark" long:"save-mark"`
	RestoreMark string `short:"restore-mark" long:"restore-mark"`
}
type Connrate struct {
	Connrate string `short:"connrate" long:"connrate"`
}
type Conntrack struct {
	Ctstate   string `short:"ctstate" long:"ctstate"`
	Ctproto   string `short:"ctproto" long:"ctproto"`
	Ctorigdst string `short:"ctorigdst" long:"ctorigdst"`
	Ctorigsrc string `short:"ctorigsrc" long:"ctorigsrc"`
	Ctreplsrc string `short:"ctreplsrc" long:"ctreplsrc"`
	Ctrepldst string `short:"ctrepldst" long:"ctrepldst"`
	Ctstatus  string `short:"ctstatus" long:"ctstatus"`
	Cstexpire string `short:"ctexpire" long:"ctexpire"`
}
type Dccp struct {
	SrcPort     string `short:"sport" long:"source-port"`
	DstPort     string `short:"dport" long:"dest-port"`
	DccpTypes   string `short:"dccp-types" long:"dccp-types"`
	DccpOptions string `short:"dccp-option" long:"dccp-option"`
}

type Dscp struct {
	Dscp         string `short:"dscp" long:"dscp"`
	DscpClass    string `short:"dscp-class" long:"dscp-class"`
	SetDscp      string `short:"set-dscp" long:"set-dscp"`
	SetDscpClass string `short:"set-dscp-class" long:"set-dscp-class"`
}

type DstLimit struct {
	DstLimit                 string `short:"dstlimit" long:"dstlimit"`
	DstLimitMode             string `short:"dstlimit-mode" long:"dstlimit-mode"`
	DstLimitName             string `short:"dstlimit-name" long:"dstlimit-name"`
	DstLimitBurst            string `short:"dstlimit-burst" long:"dstlimit-burst"`
	DstLimitHtableSize       string `short:"dstlimit-htable-size" long:"dstlimit-htable-size"`
	DstLimitHtableMax        string `short:"dstlimit-htable-max" long:"dstlimit-max"`
	DstLimitHtableGcinterval string `short:"dstlimit-htable-gcinterval" long:"dstlimit-htable-gcinterval"`
	DstLimitHtableExpire     string `short:"dstlimit-htable-expire" long:"dstlimit-htable-expire"`
}
type Ecn struct {
	EcpTcpCwr    string `short:"ecn-tcp-cwr" long:"ecn-tcp-cwr"`
	EcnTcpEce    string `short:"ecn-tcp-ece" long:"ecn-tcp-ece"`
	EcnIpEct     string `short:"ecn-ip-ect" long:"ecn-ip-ect"`
	EcnTcpRemove string `short:"ecn-tcp-remove" long:"ecn-tcp-remove"`
}

type Esp struct {
	EspSpi string `short:"espspi" long:"espspi"`
}

type Fuzzy struct {
	LowerLimit string `short:"lower-limit" long:"lower-limit"`
	UpperLimit string `short:"upper-limit" long:"upper-limit"`
}

type HashLimit struct {
	HashLimit                 string `short:"hashlimit" long:"hashlimit"`
	HashLimitBurst            string `short:"hashlimit-burst" long:"hashlimit-burst"`
	HashLimitMode             string `short:"hashlimit-mode" long:"hashlimit-mode"`
	HashLimitName             string `short:"hashlimit-name" long:"hashlimit-name"`
	HashLimitHtableSize       string `short:"hashlimit-htable-size" long:"hashlimit-htable-size"`
	HashLimitHtableMax        string `short:"hashlimit-htable-max" long:"hashlimit-htable-max"`
	HashLimitHtableExpire     string `short:"hashlimit-htable-expire" long:"hashlimit-htable-expire"`
	HashLimitHtableGcinterval string `short:"hashlimit-htable-gcinterval" long:"hashlimit-htable-gcinterval"`
}
type Helper struct {
	Helper string `short:"helper" long:"helper"`
}
type Icmp struct {
	IcmpType string `short:"icmp-type" long:"icmp-type"`
}
type IpRange struct {
	SrcRange string `short:"src-range" long:"src-range"`
	DstRange string `short:"dst-range" long:"dst-range"`
}
type Ipv4Options struct {
	Ssrr   string `short:"ssrr" long:"ssrr"`
	Lsrr   string `short:"lsrr" long:"lsrr"`
	NoSrr  string `short:"no-srr" long:"no-srr"`
	Rr     bool   `short:"rr" long:"rr"` // TODO
	Ts     bool   `short:"ts" long:"ts"`
	Ra     bool   `short:"ra" long:"ra"`
	AnyOpt bool   `short:"any-opt" long:"any-opt"`
}
type Length struct {
	Length string `short:"length" long:"length"`
}
type Limit struct {
	Limit      string `short:"limit" long:"limit"`
	LimitBurst string `short:"limit-burst" long:"limit-burst"`
}
type Mac struct {
	MacSource string `short:"mac-source" long:"mac-source"`
}
type Mark struct {
	Mark    string `short:"mark" long:"mark"`
	SetMark string `short:"set-mark" long:"set-mark"`
}
type MPort struct {
	SrcPorts string `short:"source-ports" long:"source-ports"`
	DstPorts string `short:"destination-ports" long:"destination-ports"`
	Ports    string `short:"ports" long:"ports"`
}
type MultiPort struct {
	SrcPorts string `short:"source-ports" long:"source-ports"`
	DstPorts string `short:"destination-ports" long:"destination-ports"`
	Ports    string `short:"ports" long:"ports"`
}
type Nth struct {
	Every   string `short:"ports" long:"ports"`
	Counter string `short:"counter" long:"counter"`
	Start   string `short:"start" long:"start"`
	Packet  string `short:"packet" long:"packet"`
}
type Osf struct {
	Smart   string `short:"smart" long:"smart"`
	Netlink string `short:"netlink" long:"netlink"`
	Genre   string `short:"genre" long:"genre"`
}
type Owner struct {
	UidOwner string `short:"uid-owner" long:"uid-owner"`
	GidOwner string `short:"gid-owner" long:"gid-owner"`
	PidOwner string `short:"pid-owner" long:"pid-owner"`
	SidOwner string `short:"sid-owner" long:"sid-owner"`
	CmdOwner string `short:"cmd-owner" long:"cmd-owner"`
}
type PhysDev struct {
	PhysDevIn        string `short:"physdev-in" long:"physdev-in"`
	PhysDevOut       string `short:"physdev-out" long:"physdev-out"`
	PhysDevIsIn      string `short:"physdev-is-in" long:"physdev-is-in"`
	PhysDevIsOut     string `short:"physdev-is-out" long:"physdev-is-out"`
	PhysDevIsBridged string `short:"physdev-is-bridged" long:"physdev-is-bridged"`
}
type PktType struct {
	PktType string `short:"pkt-type" long:"pkt-type"`
}
type Policy struct {
	// TODO check against docs
	Table  string `short:"table" long:"table"`
	Chain  string `short:"chain" long:"chain"`
	Target string `short:"target" long:"target"`
}
type RulePolicy struct {
	Dir       string `short:"dir" long:"dir"`
	Pol       string `short:"pol" long:"pol"`
	Strict    string `short:"strict" long:"strict"`
	ReqId     string `short:"reqid" long:"reqid"`
	Spi       string `short:"spi" long:"spi"`
	Proto     string `short:"proto" long:"proto"`
	Mode      string `short:"mode" long:"mode"`
	TunnelSrc string `short:"tunnel-src" long:"tunnel-src"`
	TunnelDst string `short:"tunnel-dst" long:"tunnel-dst"`
	Next      string `short:"next" long:"next"`
}
type Psd struct {
	PsdWeightThreshold string `short:"psd-weight-threshold" long:"psd-weight-threshold"`
	PsdDelayThreshold  string `short:"psd-delay-threshold" long:"psd-delay-threshold"`
	PsdLoPortsWeight   string `short:"psd-lo-ports-weight" long:"psd-lo-ports-weight"`
	PsdHiPortsWeight   string `short:"psd-hi-ports-weight" long:"psd-hi-ports-weight"`
}
type Quota struct {
	Quota string `short:"quota" long:"quota"`
}
type Random struct {
	Average string `short:"average" long:"average"`
}
type Realm struct {
	Realm string `short:"realm" long:"realm"`
}
type Recent struct {
	Name     string `short:"name" long:"name"`
	Set      string `short:"set" long:"set"`
	Rcheck   string `short:"rcheck" long:"rcheck"`
	Update   string `short:"update" long:"update"`
	Remove   string `short:"remove" long:"remove"`
	Seconds  string `short:"seconds" long:"seconds"`
	Hitcount string `short:"hitcount" long:"hitcount"`
	Rttl     string `short:"rttl" long:"rttl"`
}
type Sctp struct {
	SourcePort, Sport      string `short:"source-port,--sport" long:"source-port,--sport"`
	DestinationPort, Dport string `short:"destination-port,--dport" long:"destination-port,--dport"`
	ChunkTypes             string `short:"chunk-types" long:"chunk-types"`
}
type Set struct {
	Set    string `short:"set" long:"set"`
	AddSet string `short:"add-set" long:"add-set"`
	DelSet string `short:"del-set" long:"del-set"`
}
type State struct {
	State string `short:"state" long:"state"`
}
type String struct {
	Algo   string `short:"algo" long:"algo"`
	From   string `short:"from" long:"from"`
	To     string `short:"to" long:"to"`
	String string `short:"string" long:"string"`
}
type Tcp struct {
	SourcePort      string `short:"source-port" long:"source-port"`
	DestinationPort string `short:"destination-port" long:"destination-port"`
	TcpFlags        string `short:"tcp-flags" long:"tcp-flags"`
	Syn             string `short:"syn" long:"syn"`
	TcpOption       string `short:"tcp-option" long:"tcp-option"`
	Mss             string `short:"mss" long:"mss"`
}
type Tcpmss struct {
	Mss            string `short:"mss" long:"mss"`
	SetMss         string `short:"set-mss" long:"set-mss"`
	ClampMssToPmtu string `short:"clamp-mss-to-pmtu" long:"clamp-mss-to-pmtu"`
}
type Time struct {
	Timestart string `short:"timestart" long:"timestart"`
	Timestop  string `short:"timestop" long:"timestop"`
	Days      string `short:"days" long:"days"`
	Datestart string `short:"datestart" long:"datestart"`
	Datestop  string `short:"datestop" long:"datestop"`
}
type Tos struct {
	Tos    string `short:"tos" long:"tos"`
	SetTos string `short:"set-tos" long:"set-tos"`
}
type Ttl struct {
	TtlEq  string `short:"ttl-eq" long:"ttl-eq"`
	TtlGt  string `short:"ttl-gt" long:"ttl-gt"`
	TtlLt  string `short:"ttl-lt" long:"ttl-lt"`
	TtlSet string `short:"ttl-set" long:"ttl-set"`
	TtlDec string `short:"ttl-dec" long:"ttl-dec"`
	TtlInc string `short:"ttl-inc" long:"ttl-inc"`
}
type U32 struct {
}
type Udp struct {
	SourcePort      string `short:"source-port" long:"source-port"`
	DestinationPort string `short:"destination-port" long:"destination-port"`
}

// TARGET EXTENSIONS

type Balance struct {
	ToDestination string `short:"to-destination" long:"to-destination"`
}
type Classify struct {
	SetClass string `short:"set-class" long:"set-class"`
}
type Clusterip struct {
	New        string `short:"new" long:"new"`
	Hashmode   string `short:"hashmode" long:"hashmode"`
	Clustermac string `short:"clustermac" long:"clustermac"`
	TotalNodes string `short:"total-nodes" long:"total-nodes"`
	LocalNode  string `short:"local-node" long:"local-node"`
	HashInit   string `short:"hash-init" long:"hash-init"`
}

type Dnat struct {
	ToDestination string `short:"to-destination" long:"to-destination"`
}
type Ipmark struct {
	Addr    string `short:"addr" long:"addr"`
	AndMask string `short:"and-mask" long:"and-mask"`
	OrMask  string `short:"or-mask" long:"or-mask"`
}
type Ipv4optsstrip struct {
}
type Log struct {
	LogLevel       string `short:"log-level" long:"log-level"`
	LogPrefix      string `short:"log-prefix" long:"log-prefix"`
	LogTcpSequence string `short:"log-tcp-sequence" long:"log-tcp-sequence"`
	LogTcpOptions  string `short:"log-tcp-options" long:"log-tcp-options"`
	LogIpOptions   string `short:"log-ip-options" long:"log-ip-options"`
	LogUid         string `short:"log-uid" long:"log-uid"`
}
type Masquerade struct {
	ToPorts string `short:"to-ports" long:"to-ports"`
}
type Mirror struct {
}
type Netmap struct {
	To string `short:"to" long:"to"`
}
type Nfqueue struct {
	QueueNum string `short:"queue-num" long:"queue-num"`
}
type Notrack struct {
}
type Redirect struct {
	ToPorts string `short:"to-ports" long:"to-ports"`
}
type Reject struct {
	RejectWith string `short:"reject-with" long:"reject-with"`
}
type Same struct {
	To    string `short:"to" long:"to"`
	Nodst string `short:"nodst" long:"nodst"`
}
type Snat struct {
	ToSource string `short:"to-source" long:"to-source"`
}
type Ulog struct {
	UlogNlgroup    string `short:"ulog-nlgroup" long:"ulog-nlgroup"`
	UlogPrefix     string `short:"ulog-prefix" long:"ulog-prefix"`
	UlogCprange    string `short:"ulog-cprange" long:"ulog-cprange"`
	UlogQthreshold string `short:"ulog-qthreshold" long:"ulog-qthreshold"`
}
type Xor struct {
	Key       string `short:"key" long:"key"`
	BlockSize string `short:"block-size" long:"block-size"`
}
