#!/bin/bash -e
pcap=test.pcap
log=out.txt

args=(
	--quiet
	--interface   "dump:$pcap"
	--source-mac  02:00:00:00:00:f0
	--router-mac  02-00-00-00-00-0F
	--source-ip   2001:db8::1
	--source-port 64000
)

ecode=0
dotest () {
	echo "=== Running test: $id ==="
	./fi6s "${args[@]}" "${args2[@]}" || :
	tcpdump -nn -v -r "$pcap" >$log 2>/dev/null
	if ! grep -aP "$regex" $log; then
		echo "FAILED, actual dump:"
		cat $log
		ecode=1
	else
		echo "Passed."
	fi
	echo
}

##

id="ICMP"
args2=(--icmp 100::x)
regex='2001:db8::1 > 100::a: \[icmp6 sum ok\] ICMP6, echo request'
dotest

id="ICMP with TTL"
args2=(--icmp 2001:db8::b00b --ttl 126)
regex='IP6 \(hlim 126,.* ICMP6, echo request'
dotest

id="TCP"
args2=(-b -p 1 100::x)
regex='2001:db8::1\.64000 > 100::b\.1: Flags \[S\], cksum [^ ]+ \(correct\).*, length 0'
dotest

id="UDP 53"
args2=(-bu -p 53 100::x)
regex='2001:db8::1\.64000 > 100::c\.53: \[udp sum ok\] [^ ]+ TXT [^ ]+ version\.bind\.'
dotest

id="UDP no banner"
args2=(-u -p 404 100::x)
regex='2001:db8::1\.64000 > 100::4\.404: \[udp sum ok\] UDP, length 0$'
dotest

##

echo "=== Done ==="
rm -f $pcap $log
exit $ecode
