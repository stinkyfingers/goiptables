package goiptables
type Account struct {
	Aaddr string `short:"aaddr" long:"aaddr"`
	Aname string `short:"aname" long:"aname"`
	Ashort string `short:"ashort" long:"ashort"`
}
type Addrtype struct {
}
type Unspec struct {
	SrcType string `short:"src-type" long:"src-type"`
	DstType string `short:"dst-type" long:"dst-type"`
}
type Ah struct {
	Ahspi string `short:"ahspi" long:"ahspi"`
}
type Childlevel struct {
	Childlevel string `short:"childlevel" long:"childlevel"`
}
type Comment struct {
	Comment string `short:"comment" long:"comment"`
}
type Condition struct {
	Condition string `short:"condition" long:"condition"`
}
type Connbytes struct {
	Connbytes string `short:"connbytes" long:"connbytes"`
	ConnbytesDir string `short:"connbytes-dir" long:"connbytes-dir"`
	ConnbytesMode string `short:"connbytes-mode" long:"connbytes-mode"`
}
type Connlimit struct {
	ConnlimitAbove string `short:"connlimit-above" long:"connlimit-above"`
	ConnlimitMask string `short:"connlimit-mask" long:"connlimit-mask"`
}
type Connmark struct {
	Mark string `short:"mark" long:"mark"`
}
type Connrate struct {
	Connrate string `short:"connrate" long:"connrate"`
}
type Conntrack struct {
	Ctstate string `short:"ctstate" long:"ctstate"`
	Ctproto string `short:"ctproto" long:"ctproto"`
	Ctorigsrc string `short:"ctorigsrc" long:"ctorigsrc"`
	Ctorigdst string `short:"ctorigdst" long:"ctorigdst"`
	Ctreplsrc string `short:"ctreplsrc" long:"ctreplsrc"`
	Ctrepldst string `short:"ctrepldst" long:"ctrepldst"`
	Ctstatus string `short:"ctstatus" long:"ctstatus"`
	Ctexpire string `short:"ctexpire" long:"ctexpire"`
}
type Dccp struct {
	SourcePort,Sport string `short:"source-port,--sport" long:"source-port,--sport"`
	DestinationPort,Dport string `short:"destination-port,--dport" long:"destination-port,--dport"`
	DccpTypes string `short:"dccp-types" long:"dccp-types"`
	DccpOption string `short:"dccp-option" long:"dccp-option"`
}
type Dscp struct {
	Dscp string `short:"dscp" long:"dscp"`
	DscpClass string `short:"dscp-class" long:"dscp-class"`
}
type Dstlimit struct {
	Dstlimit string `short:"dstlimit" long:"dstlimit"`
	DstlimitMode string `short:"dstlimit-mode" long:"dstlimit-mode"`
	DstlimitName string `short:"dstlimit-name" long:"dstlimit-name"`
}
type Ecn struct {
	EcnTcpCwr string `short:"ecn-tcp-cwr" long:"ecn-tcp-cwr"`
	EcnTcpEce string `short:"ecn-tcp-ece" long:"ecn-tcp-ece"`
	EcnIpEct string `short:"ecn-ip-ect" long:"ecn-ip-ect"`
}
type Esp struct {
	Espspi string `short:"espspi" long:"espspi"`
}
type Fuzzy struct {
	LowerLimit string `short:"lower-limit" long:"lower-limit"`
	UpperLimit string `short:"upper-limit" long:"upper-limit"`
}
type Hashlimit struct {
	Hashlimit string `short:"hashlimit" long:"hashlimit"`
	HashlimitBurst string `short:"hashlimit-burst" long:"hashlimit-burst"`
	HashlimitMode string `short:"hashlimit-mode" long:"hashlimit-mode"`
	HashlimitName string `short:"hashlimit-name" long:"hashlimit-name"`
	HashlimitHtableSize string `short:"hashlimit-htable-size" long:"hashlimit-htable-size"`
	HashlimitHtableMax string `short:"hashlimit-htable-max" long:"hashlimit-htable-max"`
	HashlimitHtableExpire string `short:"hashlimit-htable-expire" long:"hashlimit-htable-expire"`
	HashlimitHtableGcinterval string `short:"hashlimit-htable-gcinterval" long:"hashlimit-htable-gcinterval"`
}
type Helper struct {
	Helper string `short:"helper" long:"helper"`
}
type Icmp struct {
	IcmpType string `short:"icmp-type" long:"icmp-type"`
}
type Iprange struct {
	SrcRange string `short:"src-range" long:"src-range"`
	DstRange string `short:"dst-range" long:"dst-range"`
}
type Ipv4options struct {
	Ssrr string `short:"ssrr" long:"ssrr"`
	Lsrr string `short:"lsrr" long:"lsrr"`
	NoSrr string `short:"no-srr" long:"no-srr"`
	Rr string `short:"rr" long:"rr"`
	Ts string `short:"ts" long:"ts"`
	Ra string `short:"ra" long:"ra"`
	AnyOpt string `short:"any-opt" long:"any-opt"`
}
type Length struct {
	Length string `short:"length" long:"length"`
}
type Limit struct {
	Limit string `short:"limit" long:"limit"`
	LimitBurst string `short:"limit-burst" long:"limit-burst"`
}
type Mac struct {
	MacSource string `short:"mac-source" long:"mac-source"`
}
type Mark struct {
	Mark string `short:"mark" long:"mark"`
}
type Mport struct {
	SourcePorts string `short:"source-ports" long:"source-ports"`
	DestinationPorts string `short:"destination-ports" long:"destination-ports"`
	Ports string `short:"ports" long:"ports"`
}
type Multiport struct {
	SourcePorts string `short:"source-ports" long:"source-ports"`
	DestinationPorts string `short:"destination-ports" long:"destination-ports"`
	Ports string `short:"ports" long:"ports"`
}
type Nth struct {
	Every string `short:"every" long:"every"`
}
type Osf struct {
	Log string `short:"log" long:"log"`
	Smart string `short:"smart" long:"smart"`
	Netlink string `short:"netlink" long:"netlink"`
	Genre string `short:"genre" long:"genre"`
}
type Owner struct {
	UidOwner string `short:"uid-owner" long:"uid-owner"`
	GidOwner string `short:"gid-owner" long:"gid-owner"`
	PidOwner string `short:"pid-owner" long:"pid-owner"`
	SidOwner string `short:"sid-owner" long:"sid-owner"`
	CmdOwner string `short:"cmd-owner" long:"cmd-owner"`
}
type Physdev struct {
	PhysdevIn string `short:"physdev-in" long:"physdev-in"`
	PhysdevOut string `short:"physdev-out" long:"physdev-out"`
	PhysdevIsIn string `short:"physdev-is-in" long:"physdev-is-in"`
	PhysdevIsOut string `short:"physdev-is-out" long:"physdev-is-out"`
	PhysdevIsBridged string `short:"physdev-is-bridged" long:"physdev-is-bridged"`
}
type Pkttype struct {
	PktType string `short:"pkt-type" long:"pkt-type"`
}
type Policy struct {
	Dir string `short:"dir" long:"dir"`
	Pol string `short:"pol" long:"pol"`
	Strict string `short:"strict" long:"strict"`
	Reqid string `short:"reqid" long:"reqid"`
	Spi string `short:"spi" long:"spi"`
	Proto string `short:"proto" long:"proto"`
	Mode string `short:"mode" long:"mode"`
	TunnelSrc string `short:"tunnel-src" long:"tunnel-src"`
	TunnelDst string `short:"tunnel-dst" long:"tunnel-dst"`
	Next string `short:"next" long:"next"`
}
type Psd struct {
	PsdWeightThreshold string `short:"psd-weight-threshold" long:"psd-weight-threshold"`
	PsdDelayThreshold string `short:"psd-delay-threshold" long:"psd-delay-threshold"`
	PsdLoPortsWeight string `short:"psd-lo-ports-weight" long:"psd-lo-ports-weight"`
	PsdHiPortsWeight string `short:"psd-hi-ports-weight" long:"psd-hi-ports-weight"`
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
	Name string `short:"name" long:"name"`
	Set string `short:"set" long:"set"`
	Rcheck string `short:"rcheck" long:"rcheck"`
	Update string `short:"update" long:"update"`
	Remove string `short:"remove" long:"remove"`
	Seconds string `short:"seconds" long:"seconds"`
	Hitcount string `short:"hitcount" long:"hitcount"`
	Rttl string `short:"rttl" long:"rttl"`
}
type Sctp struct {
	SourcePort,Sport string `short:"source-port,--sport" long:"source-port,--sport"`
	DestinationPort,Dport string `short:"destination-port,--dport" long:"destination-port,--dport"`
	ChunkTypes string `short:"chunk-types" long:"chunk-types"`
}
type Set struct {
	Set string `short:"set" long:"set"`
}
type State struct {
	State string `short:"state" long:"state"`
}
type String struct {
	Algo string `short:"algo" long:"algo"`
	From string `short:"from" long:"from"`
	To string `short:"to" long:"to"`
	String string `short:"string" long:"string"`
}
type Tcp struct {
	SourcePort string `short:"source-port" long:"source-port"`
	DestinationPort string `short:"destination-port" long:"destination-port"`
	TcpFlags string `short:"tcp-flags" long:"tcp-flags"`
	Syn string `short:"syn" long:"syn"`
	TcpOption string `short:"tcp-option" long:"tcp-option"`
	Mss string `short:"mss" long:"mss"`
}
type Tcpmss struct {
	Mss string `short:"mss" long:"mss"`
}
type Time struct {
	Timestart string `short:"timestart" long:"timestart"`
	Timestop string `short:"timestop" long:"timestop"`
	Days string `short:"days" long:"days"`
	Datestart string `short:"datestart" long:"datestart"`
	Datestop string `short:"datestop" long:"datestop"`
}
type Tos struct {
	Tos string `short:"tos" long:"tos"`
}
type Ttl struct {
	TtlEq string `short:"ttl-eq" long:"ttl-eq"`
	TtlGt string `short:"ttl-gt" long:"ttl-gt"`
	TtlLt string `short:"ttl-lt" long:"ttl-lt"`
}
type U32 struct {
}
type Udp struct {
	SourcePort string `short:"source-port" long:"source-port"`
	DestinationPort string `short:"destination-port" long:"destination-port"`
}
type Unclean struct {
}
type MatchExtensions struct {
	Account `flag:"m" short:"account"`
	Addrtype `flag:"m" short:"addrtype"`
	Unspec `flag:"m" short:"unspec"`
	Ah `flag:"m" short:"ah"`
	Childlevel `flag:"m" short:"childlevel"`
	Comment `flag:"m" short:"comment"`
	Condition `flag:"m" short:"condition"`
	Connbytes `flag:"m" short:"connbytes"`
	Connlimit `flag:"m" short:"connlimit"`
	Connmark `flag:"m" short:"connmark"`
	Connrate `flag:"m" short:"connrate"`
	Conntrack `flag:"m" short:"conntrack"`
	Dccp `flag:"m" short:"dccp"`
	Dscp `flag:"m" short:"dscp"`
	Dstlimit `flag:"m" short:"dstlimit"`
	Ecn `flag:"m" short:"ecn"`
	Esp `flag:"m" short:"esp"`
	Fuzzy `flag:"m" short:"fuzzy"`
	Hashlimit `flag:"m" short:"hashlimit"`
	Helper `flag:"m" short:"helper"`
	Icmp `flag:"m" short:"icmp"`
	Iprange `flag:"m" short:"iprange"`
	Ipv4options `flag:"m" short:"ipv4options"`
	Length `flag:"m" short:"length"`
	Limit `flag:"m" short:"limit"`
	Mac `flag:"m" short:"mac"`
	Mark `flag:"m" short:"mark"`
	Mport `flag:"m" short:"mport"`
	Multiport `flag:"m" short:"multiport"`
	Nth `flag:"m" short:"nth"`
	Osf `flag:"m" short:"osf"`
	Owner `flag:"m" short:"owner"`
	Physdev `flag:"m" short:"physdev"`
	Pkttype `flag:"m" short:"pkttype"`
	Policy `flag:"m" short:"policy"`
	Psd `flag:"m" short:"psd"`
	Quota `flag:"m" short:"quota"`
	Random `flag:"m" short:"random"`
	Realm `flag:"m" short:"realm"`
	Recent `flag:"m" short:"recent"`
	Sctp `flag:"m" short:"sctp"`
	Set `flag:"m" short:"set"`
	State `flag:"m" short:"state"`
	String `flag:"m" short:"string"`
	Tcp `flag:"m" short:"tcp"`
	Tcpmss `flag:"m" short:"tcpmss"`
	Time `flag:"m" short:"time"`
	Tos `flag:"m" short:"tos"`
	Ttl `flag:"m" short:"ttl"`
	U32 `flag:"m" short:"u32"`
	Udp `flag:"m" short:"udp"`
	Unclean `flag:"m" short:"unclean"`
}