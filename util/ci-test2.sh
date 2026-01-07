#!/bin/bash -e
args=(
	--interface   lo
	--router-mac  01:01:01:01:01:01
	--source-ip   ::1
)

./fi6s "${args[@]}" --icmp ::1 --output-format binary -o out.bin

./fi6s --readscan out.bin -o out.txt

if ! grep -q "^icmp up 0 ::1 " out.txt; then
	echo "FAILED!"
	exit 1
fi
echo "Passed."
exit 0
