#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "target.h"

struct targetstate {
	int used;
	struct targetspec spec;
	uint8_t cur[16];
};

static void shuffle(void *buf, int stride, int n);
static void fill_cache(void);
static void next_addr(struct targetstate *t, uint8_t *dst);


static int randomize = 1;

static uint8_t *cache;
static int cache_i;
static int cache_size;

struct targetstate targets[MAX_TARGETS];
static int targets_i;


void target_gen_init(void)
{
	cache = malloc(16*RANDOMIZE_SIZE);
	if(!cache)
		abort();
	cache_i = 0;
	cache_size = 0;

	targets_i = 0;
	for(int i = 0; i < MAX_TARGETS; i++)
		targets[i].used = 0;
}

void target_gen_set_randomized(int v)
{
	randomize = v ? 1 : 0;
}

void target_gen_fini(void)
{
	free(cache);
}

int target_gen_add(const struct targetspec *s)
{
	int i = -1;
	for(int j = 0; j < MAX_TARGETS; j++) {
		if(targets[j].used)
			continue;
		i = j;
		break;
	}
	if(i == -1)
		return -1;
	targets[i].used = 1;
	memcpy(&targets[i].spec, s, sizeof(struct targetspec));
	memset(targets[i].cur, 0, 16);
	return 0;
}

int target_gen_next(uint8_t *dst)
{
	if(cache_i == cache_size) {
		fill_cache();
		if(cache_size == 0)
			return -1;
		if(randomize)
			shuffle(cache, 16, cache_size);
	}
	memcpy(dst, &cache[cache_i*16], 16);
	cache_i++;
	return 0;
}

static void shuffle(void *_buf, int stride, int n)
{
	char tmp[stride], *buf = (char*) _buf;
	for(int i = n-1; i > 0; i--) {
		int j = rand() % (i+1);
		memcpy(tmp, &buf[stride * j], stride);
		memcpy(&buf[stride * j], &buf[stride * i], stride);
		memcpy(&buf[stride * i], tmp, stride);
	}
}

static void fill_cache(void)
{
	cache_i = 0;
	cache_size = 0;
	while(1) {
		int any = 0;
		for(int i = 0; i < MAX_TARGETS; i++) {
			if(!targets[i].used)
				continue;
			any = 1;
			next_addr(&targets[i], &cache[cache_size*16]);
			cache_size++;
			if(cache_size == RANDOMIZE_SIZE)
				goto out;
		}
		if(!any)
			goto out;
	}
	out:
	return;
}

static void next_addr(struct targetstate *t, uint8_t *dst)
{
	int carry = 0;
	// copy what we currently have into dst
	for(int i = 0; i < 16; i++)
		dst[i] = t->spec.addr[i] | t->cur[i];
	// do manual addition on t->cur while ignoring positions set in t->spec.mask
	for(int i = 15; i >= 0; i--) {
		for(int j = 1; j != (1 << 8); j <<= 1) {
			if(t->spec.mask[i] & j)
				continue;
			if(t->cur[i] & j) {
				t->cur[i] &= ~j; // unset & carry
				carry = 1;
			} else {
				t->cur[i] |= j; // set & exit
				carry = 0;
				goto out;
			}
		}
	}
	out:
	// if there's carry left over, delete target so this isn't called again
	if(carry == 1)
		t->used = 0;
}
