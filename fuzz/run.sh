#!/bin/bash
export AFL_SKIP_CPUFREQ=1
export AFL_TMPDIR=/dev/shm
exe=./fi6s-fuzz
exeargs=(udp 53)

# minimize corpus first
if [ ! -d sample_min ]; then
	mkdir sample_min
	afl-cmin.bash -T 4 -i sample/ -o sample_min/ -- "$exe" "${exeargs[@]}"
	echo; echo
	sleep 5
fi

exec afl-fuzz \
	-t 100 -i sample_min/ -o out/ "$@" \
	-- "$exe" "${exeargs[@]}"
