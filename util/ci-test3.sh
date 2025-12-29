#!/bin/bash -e
ns=test
hi=eh0
ha=fd00::1
gi=eg0
gm=0e:11:11:11:11:11
ga=fd00::2

_cleanup () {
	local pids=$(ip netns pids $ns | tr '\n' ' ')
	echo
	echo "killing: $pids"
	[ -n "$pids" ] && kill $pids
	ip netns del $ns
}
trap "_cleanup" EXIT
ip netns add $ns
ip l add $hi type veth peer name $gi
ip l set dev $gi netns $ns
ip netns exec $ns ip l set $gi address $gm up
ip netns exec $ns ip a add $ga/120 dev $gi
ip l set $hi up
ip a add $ha/120 dev $hi
ip netns exec $ns python3 -m http.server -d /var/empty 8080 &

# random wait time until stuff(?) is set up(???)
while ! ping -q -w1 -c1 $ga; do
	sleep 1
done
echo "namespace setup ok"
echo

## ICMP

./fi6s --interface $hi --router-mac $gm --icmp $ga | tee out.txt
if ! grep -q "^icmp up " out.txt; then
	echo "1: FAILED!"
	exit 1
fi
echo "1: Passed."

## TCP with banner

./fi6s --interface $hi --router-mac $gm --show-closed -b -p 512,8080 $ga | tee out.txt
if ! grep -q "^banner tcp 8080 .*SimpleHTTP.*Python" out.txt; then
	echo "2: FAILED!"
	exit 1
fi
if ! grep -q "^tcp closed 512 " out.txt; then
	echo "2: FAILED!"
	exit 1
fi
echo "2: Passed."

##

exit 0
