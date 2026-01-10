#!/bin/bash -e
olddir=$PWD
tmpdir=$(mktemp -d)
cd "$tmpdir"
trap 'rm -rf "$tmpdir"' EXIT

export LC_ALL=C
args=(
	# avoid sending anything even if ran as root
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
	if [ -n "$notee" ]; then
		"$olddir/fi6s" "${args[@]}" "$@" >out.txt
		wc -l out.txt
	elif [ -n "$nostderr" ]; then
		"$olddir/fi6s" "${args[@]}" "$@" | tee out.txt
	else
		"$olddir/fi6s" "${args[@]}" "$@" 2>&1 | tee out.txt
	fi
}

check_out () {
	if ! grep -iq "$1" out.txt; then
		echo "#$ntest: FAILED!"
		exit 1
	fi
	echo "#$ntest: Passed"
}

cmp_out () {
	if ! diff -duw out.txt "$1"; then
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

try --print-summary 1010::/99
check_out "packets with 74 octet"

##

try --print-summary --max-rate 88888888 --icmp 1010::/99
check_out "expected to use 41\.[0-9] Gbit"

##

printf '%s\n' >in.txt \
	2605:: 2606::x 2607::2/46-48

nostderr=1 try --print-hosts @in.txt
sort out.txt >2 && mv 2 out.txt
(
	echo '2605::'
	printf '2606::%s\n' '' 1 2 3 4 5 6 7 8 9 a b c d e f
	printf '2607:%s:2\n' '' '0:1:' '0:2:' '0:3:'
) | sort >expected_out.txt

cmp_out expected_out.txt

##

for opt in 1 0; do

	notee=1 try --randomize-hosts $opt --print-hosts 2c0f::xxxx
	check_out "^2c0f::$"
	check_out "^2c0f::1$"
	check_out "^2c0f::7fff$"
	check_out "^2c0f::fffe$"
	check_out "^2c0f::ffff$"

	if [ $(wc -l <out.txt) -ne $(sort -u out.txt | wc -l) ]; then
		echo "duplicates found!"
		exit 1
	fi

done

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
