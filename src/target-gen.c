#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include "target.h"
#include "util.h"

struct targetstate {
	int done:1;
	uint64_t delayed_start;
	struct targetspec spec;
	uint8_t cur[16];
};

static void shuffle(void *buf, int stride, int n);
static uint64_t rand64();
static int popcount(uint32_t x);
static void fill_cache(void);
static void next_addr(struct targetstate *t, uint8_t *dst);
static void progress_single(const struct targetstate *t, uint64_t *total, uint64_t *done);


static int randomize = 1;
static int mode_streaming = 0;

static uint8_t *cache;
static int cache_i;
static int cache_size;

static FILE *targets_from;

static struct targetstate *targets;
static unsigned int targets_i, targets_size;
#define REALLOC_TARGETS() \
	realloc_if_needed((void**) &targets, sizeof(struct targetstate), targets_i, &targets_size)


int target_gen_init(void)
{
	cache = calloc(16, TARGET_RANDOMIZE_SIZE);
	if(!cache)
		abort();
	cache_i = 0;
	cache_size = 0;

	targets = NULL;
	targets_i = targets_size = 0;
	return REALLOC_TARGETS();
}

void target_gen_set_randomized(int v)
{
	randomize = !!v;
}

void target_gen_set_streaming(FILE *f)
{
	mode_streaming = f != NULL;
	targets_from = f;
}

float target_gen_progress(void)
{
	if(mode_streaming)
		return -1.0f;

	// Since we have no feedback from the scanner, we do something pretty bad:
	// We go through the bitmasks and assemble the number of hosts total and done
	// Those are added together and used to calculate the percentage (don't forget the cache though)
	// It only took two^Wthree tries to get this right!
	uint64_t total = 0, done = 0;
	for(int i = 0; i < targets_i; i++)
		progress_single(&targets[i], &total, &done);
	done -= cache_size - cache_i;

	return (done * 1000 / total) / 1000.0f;
}

void target_gen_fini(void)
{
	free(cache);
	free(targets);
	if(mode_streaming)
		fclose(targets_from);
}

int target_gen_add(const struct targetspec *s)
{
	if(mode_streaming)
		return -1;

	int i = targets_i++;
	if(REALLOC_TARGETS() < 0)
		return -1;

	targets[i].done = 0;
	targets[i].delayed_start = 0;
	memcpy(&targets[i].spec, s, sizeof(struct targetspec));
	memset(targets[i].cur, 0, 16);

	return 0;
}

int target_gen_finish_add(void)
{
	if(mode_streaming)
		return 0;
	if(targets_i == 0)
		return -1;

#if TARGET_EVEN_SPREAD
	// find "longest" target
	uint64_t max = 0;
	for(int i = 0; i < targets_i; i++) {
		uint64_t tmp = 0, junk = 0;
		progress_single(&targets[i], &tmp, &junk);
		if(tmp > max)
			max = tmp;
	}
	// adjust starting point of other targets
	for(int i = 0; i < targets_i; i++) {
		uint64_t tmp = 0, junk = 0;
		progress_single(&targets[i], &tmp, &junk);
		if(tmp == max)
			continue;
		// set begin randomly between the first and last possible starting point
		targets[i].delayed_start = rand64() % (max - tmp + 1);
	}
#endif

	if(randomize)
		shuffle(targets, sizeof(struct targetstate), targets_i);

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

void target_gen_print_summary(int max_rate, int nports)
{
	if(mode_streaming) {
		printf("???\n");
		return;
	}

	uint64_t total = 0;
	int largest = 128, smallest = 0;
	for(int i = 0; i < targets_i; i++) {
		const struct targetstate *t = &targets[i];

		uint64_t junk = 0;
		progress_single(t, &total, &junk);

		int maskbits = 0;
		for(int j = 0; j < 4; j++)
			maskbits += popcount(((uint32_t*) t->spec.mask)[j]);
		if(maskbits < largest)
			largest = maskbits;
		if(maskbits > smallest)
			smallest = maskbits;
	}

	printf("%d target(s) loaded, covering %" PRIu64 " addresses.\n", targets_i, total);
	printf("Largest target equivalent to /%d subnet, smallest eq. /%d.\n", largest, smallest);

	if(max_rate != -1) {
		uint32_t dur = total / (unsigned int)max_rate;
		dur *= nports;

		int n1, n2;
		const char *f1, *f2;
		if(dur > 7*24*60*60) {
			n1 = dur / (7*24*60*60), n2 = dur % (7*24*60*60) / (24*60*60);
			f1 = "weeks", f2 = "days";
		} else if(dur > 24*60*60) {
			n1 = dur / (24*60*60), n2 = dur % (24*60*60) / (60*60);
			f1 = "days", f2 = "hours";
		} else if(dur > 60*60) {
			n1 = dur / (60*60), n2 = dur % (60*60) / (60);
			f1 = "hours", f2 = "minutes";
		} else {
			n1 = dur / (60), n2 = dur % (60);
			f1 = "minutes", f2 = "seconds";
		}

		printf("At %d PPS and %d port(s), estimated scan duration is ", max_rate, nports);
		if(n1 > 0 && n2 == 0)
			printf("%d %s.\n", n1, f1);
		else
			printf("%d %s %d %s.\n", n1, f1, n2, f2);
	}
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

static uint64_t rand64()
{
	uint64_t ret = 0;
#if RAND_MAX >= INT32_MAX
	// only 62-bits of randomness, but this is good enough
	ret ^= ((uint64_t) rand()) << 31;
	ret ^= (uint64_t) rand();
#elif RAND_MAX >= INT16_MAX
	// only 60-bits of randomness, but this is good enough
	ret ^= ((uint64_t) rand()) << 45;
	ret ^= ((uint64_t) rand()) << 30;
	ret ^= ((uint64_t) rand()) << 15;
	ret ^= (uint64_t) rand();
#else
#error built-in rand() does not provide enough randomness.
#endif

	return ret;
}

static int popcount(uint32_t x)
{
    int c = 0;
    for (; x; x >>= 1)
        c += x & 1;
    return c;
}

static void fill_cache(void)
{
	cache_i = 0;
	cache_size = 0;

	if(mode_streaming) {
		char buf[128];
		while(cache_size < TARGET_RANDOMIZE_SIZE) {
			if(fgets(buf, sizeof(buf), targets_from) == NULL)
				break;

			trim_string(buf, " \t\r\n");
			if(buf[0] == '#' || buf[0] == '\0')
				continue; // skip comments and empty lines

			if(parse_ipv6(buf, &cache[cache_size*16]) < 0) {
				fprintf(stderr, "Failed to parse target IP \"%s\".\n", buf);
				break;
			}
			cache_size++;
		}
		return;
	}

	while(1) {
		int any = 0;
		for(int i = 0; i < targets_i; i++) {
			if(targets[i].done)
				continue;
			if(targets[i].delayed_start > 0) {
				targets[i].delayed_start--;
				continue;
			}

			any = 1;
			next_addr(&targets[i], &cache[cache_size*16]);
			cache_size++;
			if(cache_size == TARGET_RANDOMIZE_SIZE)
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
		for(unsigned int j = 1; j != (1 << 8); j <<= 1) {
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
	// mark target as done if there's carry left over or the mask has all bits set
	if(!any || carry == 1)
		t->done = 1;
}

static void progress_single(const struct targetstate *t, uint64_t *total, uint64_t *done)
{
	uint64_t _total = 0, _done = 0;
	for(int i = 0; i < 16; i++) {
		for(unsigned int j = (1 << 7); j != 0; j >>= 1) {
			if(t->spec.mask[i] & j)
				continue;
			_total <<= 1;
			_total |= 1;
			_done <<= 1;
			_done |= !!(t->cur[i] & j);
		}
	}
	*total += _total + 1;
	if(t->done) // cur wraps around to zero when the target is complete
		*done += _total + 1;
	else
		*done += _done;
}
