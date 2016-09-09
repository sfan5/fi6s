#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "target.h"

struct targetstate {
	int used:1, done:1;
	struct targetspec spec;
	uint8_t cur[16];
};

static void shuffle(void *buf, int stride, int n);
static void fill_cache(void);
static void next_addr(struct targetstate *t, uint8_t *dst);
static void progress_single(const struct targetstate *t, uint32_t *total, uint32_t *rem);


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

float target_gen_progress(void)
{
	// What we do here is beyond horrible:
	// We go through the bitmasks and assemble the number of hosts total and remaining
	// Those are added together and used to calculate the percentage (don't forget the cache though!)
	// This obviously fails horribly if you intend to scan more than 2**32 hosts
	uint32_t total = 0, rem = 0;
	for(int i = 0; i < MAX_TARGETS; i++) {
		if(!targets[i].used)
			continue;
		progress_single(&targets[i], &total, &rem);
	}
	rem += cache_size - cache_i;
	return (total == 0 || rem == 0) ? 1.0 : ( (total - rem) / (float) total );
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
	targets[i].done = 0;
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
			if(!targets[i].used || targets[i].done)
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
	int any = 0;
	for(int i = 15; i >= 0; i--) {
		for(int j = 1; j != (1 << 8); j <<= 1) {
			if(t->spec.mask[i] & j)
				continue;
			any = 1;
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
	// mark target as done
	// if there's carry left over or if there's the mask has all bits set
	if(!any || carry == 1)
		t->done = 1;
}

static void progress_single(const struct targetstate *t, uint32_t *total, uint32_t *rem)
{
	int bits = 0;
	uint32_t _rem = 0;
	for(int i = 15; i >= 0; i--) {
		for(int j = 1; j != (1 << 8); j <<= 1) {
			if(t->spec.mask[i] & j)
				continue;
			bits++;
			_rem |= !!(t->cur[i] & j);
			_rem <<= 1;
		}
	}
	*total += 1 << bits;
	*rem += _rem;
}
