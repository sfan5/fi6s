#!/bin/bash -e
if=dummy0
if [ ! -e /sys/class/net/$if ]; then
	ip l add $if type dummy
	ip l set $if up
	ip r add 100::/64 dev $if
fi

args=(
	--interface   $if
	--source-mac  02:00:00:00:00:f0
	--router-mac  02-00-00-00-00-0F
	--source-ip   2001:db8::1
	--source-port 64000
)

echo "ICMP:"
./fi6s "${args[@]}" --icmp 100::x
echo "TCP:"
./fi6s "${args[@]}" -b -p 1 100::x
echo "UDP:"
./fi6s "${args[@]}" -bu -p 53 100::x
