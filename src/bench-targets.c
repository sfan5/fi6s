// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "target.h"

// adjust as needed
#define BSZ 100

#define REQUIRE(expr) do { if(!(expr)) { \
	fprintf(stderr, "fail at %s:%d\n", __func__, __LINE__); __builtin_trap(); \
	} } while(0)

int main(int argc, char *argv[])
{
	srand(time(NULL));

	REQUIRE(target_gen_init() == 0);
	if(argc > 1 && argv[1][0] == 'n')
		target_gen_set_randomized(0);
	else
		target_gen_set_randomized(1);

	{
		int z = 0;
		char buf[32];
		struct targetspec t;
		for(int off = 0; off < 10; off++) {
			snprintf(buf, sizeof(buf), "3ffe:%d::/%d", ++z, BSZ + off);
			REQUIRE(target_parse(buf, &t) == 0);
			target_gen_add(&t);
		}
	}

	REQUIRE(target_gen_finish_add() == 0);
	if(argc > 1 && argv[1][0] == 's') {
		target_gen_print_summary(-1, 1);
		return 0;
	}

	clock_t t1, t0 = clock();
	uint8_t addr[16];
	uint64_t naddr = 0;
	while(target_gen_next(addr) == 0) {
		naddr++;
	}
	t1 = clock();

	float secs = (t1 - t0) / (float)CLOCKS_PER_SEC;
	printf("total %ld\n", naddr);
	printf("time %.2fs\n", secs);
	printf("speed %ldk/s\n", (long)(naddr / secs) / 1000);

	return 0;
}
