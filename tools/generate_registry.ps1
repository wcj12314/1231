$knownPorts = @{
  20="ftp-data";21="ftp";22="ssh";23="telnet";25="smtp";53="domain";67="dhcp-server";68="dhcp-client";
  69="tftp";80="http";110="pop3";123="ntp";137="netbios-ns";138="netbios-dgm";139="netbios-ssn";
  143="imap";161="snmp";162="snmptrap";179="bgp";389="ldap";443="https";445="microsoft-ds";
  465="smtps";500="isakmp";514="syslog";515="printer";587="submission";631="ipp";636="ldaps";
  853="dns-over-tls";993="imaps";995="pop3s";1080="socks";1194="openvpn";1433="mssql";
  1521="oracle";1723="pptp";1883="mqtt";2049="nfs";2375="docker";2376="docker-tls";
  3306="mysql";3389="rdp";4369="epmd";5432="postgresql";5672="amqp";5900="vnc";6379="redis";
  6443="kubernetes";8080="http-alt";8443="https-alt";9200="elasticsearch";9300="elasticsearch-transport";
  9418="git";11211="memcached";27017="mongodb"
}

$ipProtocols = @{
  0="hopopt";1="icmp";2="igmp";4="ipv4";6="tcp";17="udp";41="ipv6";47="gre";50="esp";
  51="ah";58="icmpv6";89="ospf";103="pim";132="sctp";136="udplite";253="experimental";254="experimental"
}

$tcpOptions = @{
  0="end-of-option-list";1="nop";2="maximum-segment-size";3="window-scale";4="sack-permitted";
  5="sack";8="timestamp";19="md5-signature";28="user-timeout";29="tcp-authentication-option";
  30="multipath-tcp";34="tcp-fast-open";76="accurate-ecn"
}

$dnsTypes = @{
  1="A";2="NS";5="CNAME";6="SOA";10="NULL";12="PTR";15="MX";16="TXT";28="AAAA";33="SRV";
  41="OPT";43="DS";46="RRSIG";47="NSEC";48="DNSKEY";52="TLSA";64="SVCB";65="HTTPS";99="SPF";255="ANY"
}

$etherTypes = @{
  0x0800="ipv4";0x0806="arp";0x0842="wake-on-lan";0x22f3="trill";0x6003="decnet";
  0x8035="rarp";0x809b="appletalk";0x80f3="aarp";0x8100="vlan";0x8137="ipx";
  0x86dd="ipv6";0x8808="ethernet-flow-control";0x8847="mpls-unicast";0x8848="mpls-multicast";
  0x8863="pppoe-discovery";0x8864="pppoe-session";0x88a8="provider-bridging";0x88cc="lldp";
  0x88e5="mac-security";0x88f7="ptp";0x8906="fcoe";0x8915="roce";0x9000="loopback"
}

$out = New-Object System.Collections.Generic.List[string]
$out.Add("///|")
$out.Add("pub fn registered_service_name(port : Int) -> String {")
$out.Add("  match port {")
for ($i = 0; $i -le 65535; $i++) {
  if ($knownPorts.ContainsKey($i)) { $name = $knownPorts[$i] }
  elseif ($i -le 1023) { $name = "well-known-unassigned-$i" }
  elseif ($i -le 49151) { $name = "registered-port-$i" }
  else { $name = "dynamic-port-$i" }
  if ($i -le 4095 -or $knownPorts.ContainsKey($i)) {
    $out.Add("    $i => `"$name`"")
  }
}
$out.Add("    _ => if port >= 49152 { `"dynamic-port-\{port}`" } else { `"port-\{port}`" }")
$out.Add("  }")
$out.Add("}")
$out.Add("")
$out.Add("///|")
$out.Add("pub fn ip_protocol_registered_name(protocol : Int) -> String {")
$out.Add("  match protocol {")
for ($i = 0; $i -le 255; $i++) {
  $name = if ($ipProtocols.ContainsKey($i)) { $ipProtocols[$i] } else { "ip-protocol-$i" }
  $out.Add("    $i => `"$name`"")
}
$out.Add("    _ => `"ip-protocol-\{protocol}`"")
$out.Add("  }")
$out.Add("}")
$out.Add("")
$out.Add("///|")
$out.Add("pub fn tcp_option_registered_name(option : Int) -> String {")
$out.Add("  match option {")
for ($i = 0; $i -le 255; $i++) {
  $name = if ($tcpOptions.ContainsKey($i)) { $tcpOptions[$i] } else { "tcp-option-$i" }
  $out.Add("    $i => `"$name`"")
}
$out.Add("    _ => `"tcp-option-\{option}`"")
$out.Add("  }")
$out.Add("}")
$out.Add("")
$out.Add("///|")
$out.Add("pub fn dns_type_registered_name(qtype : Int) -> String {")
$out.Add("  match qtype {")
for ($i = 0; $i -le 511; $i++) {
  $name = if ($dnsTypes.ContainsKey($i)) { $dnsTypes[$i] } else { "dns-type-$i" }
  $out.Add("    $i => `"$name`"")
}
$out.Add("    _ => `"dns-type-\{qtype}`"")
$out.Add("  }")
$out.Add("}")
$out.Add("")
$out.Add("///|")
$out.Add("pub fn ether_type_registered_name(ether_type : Int) -> String {")
$out.Add("  match ether_type {")
for ($i = 0; $i -le 511; $i++) {
  $name = "ieee-802-length-$i"
  $out.Add("    $i => `"$name`"")
}
foreach ($key in ($etherTypes.Keys | Sort-Object)) {
  $out.Add("    $key => `"$($etherTypes[$key])`"")
}
$out.Add("    _ => `"ethertype-\{ether_type}`"")
$out.Add("  }")
$out.Add("}")
$out.Add("")
$out.Add("///|")
$out.Add("pub fn port_risk_tag(port : Int) -> String {")
$out.Add("  match port {")
foreach ($p in @(21,23,25,110,139,445,1433,3306,3389,5432,6379,9200,11211,27017)) {
  $out.Add("    $p => `"review-exposure`"")
}
foreach ($p in @(22,80,443,853,993,995,1883,5672,6443,8443)) {
  $out.Add("    $p => `"expected-service`"")
}
$out.Add("    _ => if port >= 49152 { `"ephemeral`" } else { `"ordinary`" }")
$out.Add("  }")
$out.Add("}")

$out | Set-Content -LiteralPath "registry.mbt" -Encoding UTF8
