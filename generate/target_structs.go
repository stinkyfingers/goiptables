package goiptables
type Balance struct {
	ToDestination string `short:"to-destination" long:"to-destination"`
}
type Classify struct {
	SetClass string `short:"set-class" long:"set-class"`
}
type Clusterip struct {
	New string `short:"new" long:"new"`
	Hashmode string `short:"hashmode" long:"hashmode"`
	Clustermac string `short:"clustermac" long:"clustermac"`
	TotalNodes string `short:"total-nodes" long:"total-nodes"`
	LocalNode string `short:"local-node" long:"local-node"`
	HashInit string `short:"hash-init" long:"hash-init"`
}
type Connmark struct {
	SetMark string `short:"set-mark" long:"set-mark"`
	SaveMark string `short:"save-mark" long:"save-mark"`
	RestoreMark string `short:"restore-mark" long:"restore-mark"`
}
type Dnat struct {
	ToDestination string `short:"to-destination" long:"to-destination"`
}
type Dscp struct {
	SetDscp string `short:"set-dscp" long:"set-dscp"`
	SetDscpClass string `short:"set-dscp-class" long:"set-dscp-class"`
}
type Ecn struct {
	EcnTcpRemove string `short:"ecn-tcp-remove" long:"ecn-tcp-remove"`
}
type Ipmark struct {
	Addr string `short:"addr" long:"addr"`
	AndMask string `short:"and-mask" long:"and-mask"`
	OrMask string `short:"or-mask" long:"or-mask"`
}
type Ipv4optsstrip struct {
}
type Log struct {
	LogLevel string `short:"log-level" long:"log-level"`
	LogPrefix string `short:"log-prefix" long:"log-prefix"`
	LogTcpSequence string `short:"log-tcp-sequence" long:"log-tcp-sequence"`
	LogTcpOptions string `short:"log-tcp-options" long:"log-tcp-options"`
	LogIpOptions string `short:"log-ip-options" long:"log-ip-options"`
	LogUid string `short:"log-uid" long:"log-uid"`
}
type Mark struct {
	SetMark string `short:"set-mark" long:"set-mark"`
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
type IcmpNetUnreachable struct {
}
type IcmpHostUnreachable struct {
}
type IcmpPortUnreachable struct {
}
type IcmpProtoUnreachable struct {
}
type IcmpNetProhibited struct {
}
type Same struct {
	To string `short:"to" long:"to"`
	Nodst string `short:"nodst" long:"nodst"`
}
type Set struct {
	AddSet string `short:"add-set" long:"add-set"`
	DelSet string `short:"del-set" long:"del-set"`
}
type Snat struct {
	ToSource string `short:"to-source" long:"to-source"`
}
type Tarpit struct {
}
type Note: struct {
}
type Tcpmss struct {
}
type 1) struct {
}
type 2) struct {
}
type 3) struct {
	SetMss string `short:"set-mss" long:"set-mss"`
	ClampMssToPmtu string `short:"clamp-mss-to-pmtu" long:"clamp-mss-to-pmtu"`
}
type Tos struct {
	SetTos string `short:"set-tos" long:"set-tos"`
}
type Trace struct {
}
type Ttl struct {
	TtlSet string `short:"ttl-set" long:"ttl-set"`
	TtlDec string `short:"ttl-dec" long:"ttl-dec"`
	TtlInc string `short:"ttl-inc" long:"ttl-inc"`
}
type Ulog struct {
	UlogNlgroup string `short:"ulog-nlgroup" long:"ulog-nlgroup"`
	UlogPrefix string `short:"ulog-prefix" long:"ulog-prefix"`
	UlogCprange string `short:"ulog-cprange" long:"ulog-cprange"`
	UlogQthreshold string `short:"ulog-qthreshold" long:"ulog-qthreshold"`
}
type Xor struct {
	Key string `short:"key" long:"key"`
	BlockSize string `short:"block-size" long:"block-size"`
}
type TargetExtensions struct {
	Balance `flag:"m" short:"balance"`
	Classify `flag:"m" short:"classify"`
	Clusterip `flag:"m" short:"clusterip"`
	Connmark `flag:"m" short:"connmark"`
	Dnat `flag:"m" short:"dnat"`
	Dscp `flag:"m" short:"dscp"`
	Ecn `flag:"m" short:"ecn"`
	Ipmark `flag:"m" short:"ipmark"`
	Ipv4optsstrip `flag:"m" short:"ipv4optsstrip"`
	Log `flag:"m" short:"log"`
	Mark `flag:"m" short:"mark"`
	Masquerade `flag:"m" short:"masquerade"`
	Mirror `flag:"m" short:"mirror"`
	Netmap `flag:"m" short:"netmap"`
	Nfqueue `flag:"m" short:"nfqueue"`
	Notrack `flag:"m" short:"notrack"`
	Redirect `flag:"m" short:"redirect"`
	Reject `flag:"m" short:"reject"`
	IcmpNetUnreachable `flag:"m" short:"icmpnetunreachable"`
	IcmpHostUnreachable `flag:"m" short:"icmphostunreachable"`
	IcmpPortUnreachable `flag:"m" short:"icmpportunreachable"`
	IcmpProtoUnreachable `flag:"m" short:"icmpprotounreachable"`
	IcmpNetProhibited `flag:"m" short:"icmpnetprohibited"`
	Same `flag:"m" short:"same"`
	Set `flag:"m" short:"set"`
	Snat `flag:"m" short:"snat"`
	Tarpit `flag:"m" short:"tarpit"`
	Note: `flag:"m" short:"note:"`
	Tcpmss `flag:"m" short:"tcpmss"`
	1) `flag:"m" short:"1)"`
	2) `flag:"m" short:"2)"`
	3) `flag:"m" short:"3)"`
	Tos `flag:"m" short:"tos"`
	Trace `flag:"m" short:"trace"`
	Ttl `flag:"m" short:"ttl"`
	Ulog `flag:"m" short:"ulog"`
	Xor `flag:"m" short:"xor"`
}