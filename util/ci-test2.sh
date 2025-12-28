#!/bin/bash -e
##
args=(
	--interface   lo
	--router-mac  01:01:01:01:01:01
	--source-ip   ::1
)

./fi6s "${args[@]}" --icmp ::1 | tee out.txt
if ! grep -q "^icmp up 0 ::1 " out.txt; then
	echo "1: FAILED!"
	exit 1
fi
echo "1: Passed."

##

printf '%s\n' >in.txt \
	2001::/112 2002::/112 2003::/114 2004::1 2004::2 2004::3

./fi6s --max-rate 123 --print-summary @in.txt | tee out.txt
if ! grep -q "covering 147459 address" out.txt; then
	echo "2: FAILED!"
	exit 1
fi
echo "2: Passed."

##

exit 0
