#!/bin/bash -e
args=(
	--interface "dump:/dev/null"
	--source-mac 02:00:00:00:00:f0
	--router-mac 02-00-00-00-00-0F
	--source-ip  2001:db8::1
)

ntest=0
try () {
	((ntest+=1))
	echo
	echo "-> fi6s $*"
	./fi6s "${args[@]}" "$@" 2>&1 | tee out.txt
}

check_out () {
	if ! grep -iq "$1" out.txt; then
		echo "#$ntest: FAILED!"
		exit 1
	fi
	echo "#$ntest: Passed"
}

##

printf '%s\n' >in.txt \
	2001::/112 2002::/112 2003::/114 2004::1 2004::2 2004::3

try --max-rate 123 --print-summary @in.txt
check_out "covering 147459 addr"

##

printf '%s\n' >in.txt \
	cafe::xxx:xxxx:xxxx:xxxx babe::/69

try --print-summary @in.txt
check_out "covering 1729382256910270464 addr"
check_out "largest.*/68\b"
check_out "smallest.*/69\b"

##

try --print-summary c0ff:ee::1/48-64
check_out "covering 65536 addr"

##

try --icmp 3ffe::/48
check_out "tremendous amount of time"

##

try --icmp fe80::ffff
check_out "Warning:.*are link-local "

##

try --icmp ff02::2
check_out "Warning:.*are multicast "

exit 0
