// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include "target.h"
#include "util.h"

// recommend to check `t->bits > 64` first
#define TARGET_ADDR_COUNT(t) ( UINT64_C(1) << (128 - (t)->bits) )

struct targetstate {
	struct targetspec spec;
	uint8_t cur[16];
	uint64_t delayed_start;
	uint8_t bits; // number of bits *set* in netmask
	unsigned done : 1;
};

static int cmp_target(const void *a, const void *b);
static void dump_targets(int ndump);
static void shuffle(void *buf, unsigned int stride, int n);
static void fill_cache(void);
static void next_addr(struct targetstate *t, uint8_t *dst);
static int count_mask_bits(const struct targetstate *t);
static void count_total(const struct targetstate *t, uint64_t *total, bool *overflowed);
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
	for(int i = 0; i < targets_i; i++) {
		struct targetstate tmp = targets[i];
		progress_single(&tmp, &total, &done);
	}
	// This code isn't thread-safe (the scan thread is happily mutating everything)
	// so fail safe on bogus values.
	if(total == 0 || done > total)
		return -1.0f;
	unsigned int in_cache = cache_size - cache_i;
	if(done < in_cache)
		return 0.0f;
	else
		done -= in_cache;

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

	unsigned int i = targets_i++;
	if(REALLOC_TARGETS() < 0)
		return -1;

	memset(&targets[i], 0, sizeof(struct targetstate));
	memcpy(&targets[i].spec, s, sizeof(struct targetspec));
	return 0;
}

static int cmp_target(const void *a, const void *b)
{
	const struct targetstate *ta = a, *tb = b;
	// mask bits ascending => biggest target first
	return (ta->bits > tb->bits) - (ta->bits < tb->bits);
}

static void dump_targets(int ndump)
{
	FILE *to = stderr;
	char buf[IPV6_STRING_MAX];
	for(int i = 0; i < targets_i && i < ndump; i++) {
		const struct targetstate *t = &targets[i];
		ipv6_string(buf, t->spec.addr);
		fprintf(to, "[%d] = { %s, ", i, buf);
		ipv6_string(buf, t->spec.mask);
		fprintf(to, "%s, ", buf);
		ipv6_string(buf, t->cur);
		fprintf(to, "%s, %#" PRIx64 ", %d, %d }\n", buf,
			t->delayed_start, (int)t->bits, (int)t->done);
	}
	if (targets_i > ndump)
		fprintf(to, "...\n");
}

int target_gen_finish_add(void)
{
	if(mode_streaming)
		return 0;
	if(targets_i == 0)
		return -1;

	// find biggest target size (least bits in mask)
	uint8_t min_bits = 128;
	for(int i = 0; i < targets_i; i++) {
		targets[i].bits = count_mask_bits(&targets[i]);
		if(targets[i].bits < min_bits)
			min_bits = targets[i].bits;
	}
	if(TARGET_EVEN_SPREAD && min_bits > 64 && min_bits != 128) {
		const uint64_t nmax = UINT64_C(1) << (128 - min_bits);
		// adjust starting point of other targets
		for(int i = 0; i < targets_i; i++) {
			if(targets[i].bits == min_bits)
				continue;
			assert(targets[i].bits > min_bits);
			const uint64_t nthis = TARGET_ADDR_COUNT(&targets[i]);
			// randomly between the first and last possible starting point
			targets[i].delayed_start = rand64() % (nmax - nthis + 1);
		}
	}

	// since we'll be iterating the array often, optimize most-used ones first
	qsort(targets, targets_i, sizeof(struct targetstate), cmp_target);

	if(randomize) {
		// still randomize but only within same "class"
		int start = 0;
		while(start < targets_i) {
			void *t0 = &targets[start];
			int end = start;
			while(end < targets_i && cmp_target(t0, &targets[end]) == 0)
				end++;
			shuffle(t0, sizeof(struct targetstate), end - start);
			start = end;
		}
	}

	log_debug("%u target(s) loaded", targets_i);
#ifndef NDEBUG
	dump_targets(6);
#endif
	return 0;
}

int target_gen_peek(uint8_t *dst)
{
	if(cache_i == cache_size) {
		fill_cache();
		if(cache_size == 0)
			return -1;
		if(randomize)
			shuffle(cache, 16, cache_size);
	}
	memcpy(dst, &cache[cache_i*16], 16);
	return 0;
}

int target_gen_next(uint8_t *dst)
{
	if (target_gen_peek(dst) == 0) {
		cache_i++;
		return 0;
	}
	return -1;
}

void target_gen_print_summary(int max_rate, int nports)
{
	if(mode_streaming) {
		return;
	}

	uint64_t total = 0;
	bool total_overflowed = false;
	int largest = 128, smallest = 0;
	for(int i = 0; i < targets_i; i++) {
		const struct targetstate *t = &targets[i];

		count_total(t, &total, &total_overflowed);

		int maskbits = count_mask_bits(t);
		if(maskbits < largest)
			largest = maskbits;
		if(maskbits > smallest)
			smallest = maskbits;
	}

	printf("%d target(s) loaded, covering ", targets_i);
	if (total_overflowed)
		printf("more than 2^64 addresses.\n");
	else
		printf("%" PRIu64 " addresses.\n", total);
	if (targets_i == 1)
		printf("Target is equivalent to a /%d subnet.\n", largest);
	else if (largest != 128)
		printf("Largest target is equivalent to /%d subnet, smallest /%d.\n", largest, smallest);

	if(max_rate != -1) {
		if (total_overflowed)
			goto over;
		assert(nports >= 1);
		uint64_t dur64;
#if __has_builtin(__builtin_mul_overflow)
		if (__builtin_mul_overflow(total, (uint64_t)nports, &dur64))
			goto over;
#else
		dur64 = total * (uint64_t)nports;
		if (dur64 < total)
			goto over;
#endif
		assert(max_rate >= 1);
		dur64 /= (uint64_t)max_rate;
		if (dur64 > UINT32_MAX)
			goto over;
		const uint32_t dur = dur64;

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

		if (0) {
over:
			printf("At %d PPS and %d port(s) the estimated scan duration is ", max_rate, nports);
			// might be a lie if total_overflowed (max_rate can be very large), but this is insane anyway.
			printf("more than 100 years.\n");
		} else {
			printf("At %d PPS and %d port(s) the estimated scan duration is ", max_rate, nports);
			if(n1 == 0)
				printf("%d %s.\n", n2, f2);
			else if(n2 == 0)
				printf("%d %s.\n", n1, f1);
			else
				printf("%d %s %d %s.\n", n1, f1, n2, f2);
		}
	}
}

int target_gen_sanity_check(void)
{
	/* Target size check */
	uint64_t total = 0;
	bool overflowed = false;
	for(int i = 0; i < targets_i; i++) {
		const struct targetstate *t = &targets[i];
		count_total(t, &total, &overflowed);
	}

	const uint64_t limit = UINT64_C(1) << TARGET_SANITY_MAX_BITS;
	if (overflowed || total >= limit) {
		fprintf(stderr, "Error: You are trying to scan ");
		if (overflowed)
			fprintf(stderr, "more than 2^64");
		else
			fprintf(stderr, "%" PRIu64, total);
		fprintf(stderr, " addresses. Refusing.\n"
			"\n"
			"Even under ideal conditions this would take a tremendous amount of "
			"time (check with --print-summary).\nYou were probably expecting to "
			"scan an IPv6 subnet exhaustively just like you can with IPv4.\n"
			"In practice common sizes like /64 would take more than tens of "
			"thousands YEARS to enumerate.\nYou will need to rethink your approach. "
			"Good advice on IPv6 scanning can be found on the internet.\n"
			"\n"
			"In case you were hoping to scan stochastically, note that the way "
			"fi6s randomizes targets is not suited for this.\nAs an alternative "
			"you can have an external program generate IPs and use --stream-targets.\n"
		);
		return -1;
	}

	/* Target address check */
	bool have_ll = false, have_mc = false;
	for(int i = 0; i < targets_i; i++) {
		const struct targetspec *s = &targets[i].spec;
		if(s->mask[0] == 0xff && s->mask[1] == 0xff) {
			have_ll |= s->addr[0] == 0xfe && s->addr[1] >= 0x80 && s->addr[1] <= 0xbf;
		}
		if(s->mask[0] == 0xff) {
			have_mc |= s->addr[0] == 0xff;
		}
	}
	if(have_ll) {
		log_warning("Some of your targets are link-local IPv6 addresses. "
			"Scanning them will not work.");
	}
	if(have_mc) {
		log_warning("Some of your targets are multicast IPv6 addresses. "
			"Scanning them will not work.");
	}

	return 0;
}

static void shuffle(void *_buf, unsigned int stride, int n)
{
	char *buf = _buf;
	char *tmp = calloc(1, stride);
	for(int i = n-1; i > 0; i--) {
		int j = rand() % (i+1);
		// swap element i and j
		memcpy(tmp, &buf[stride * i], stride);
		memcpy(&buf[stride * i], &buf[stride * j], stride);
		memcpy(&buf[stride * j], tmp, stride);
	}
	free(tmp);
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

			trim_space(buf);
			if(buf[0] == '#' || buf[0] == '\0')
				continue; // skip comments and empty lines

			if(parse_ipv6(buf, &cache[cache_size*16]) < 0) {
				log_error("Failed to parse target IP \"%s\".", buf);
				break;
			}
			cache_size++;
		}
		return;
	}

	int unfinished_max = targets_i;
	while(1) {
		const int iter_max = unfinished_max;
		// update unfinished_max along the way, for the next iteration
		unfinished_max = 0;
		for(int i = 0; i < iter_max; i++) {
			if(targets[i].done)
				continue;
			unfinished_max = i + 1;
			if(targets[i].delayed_start > 0) {
				targets[i].delayed_start--;
				continue;
			}

			next_addr(&targets[i], &cache[cache_size*16]);
			cache_size++;
			if(cache_size == TARGET_RANDOMIZE_SIZE)
				goto out;
		}
		if(unfinished_max == 0)
			goto out;
	}
out:
	return;
}

static inline uint64_t read_be64(const void *ptr)
{
	uint64_t x;
	memcpy(&x, ptr, 8);
	return be64toh(x);
}

static inline void put_be64(void *ptr, const uint64_t v)
{
	uint64_t x = htobe64(v);
	memcpy(ptr, &x, 8);
}

static void next_addr(struct targetstate *t, uint8_t *dst)
{
	/* assemble current address in dst */
	for(int i = 0; i < 16; i++)
		dst[i] = t->spec.addr[i] | t->cur[i];

	/* increase address by one */
	// Conceptually what we want to do here is discontigous addition with one
	// e.g. 0b0001 mask 0b0110 + 1 = 0b1000
	// A neat trick for that is to OR the mask and then add normally.
	// Afterwards we need to remove the mask bits again, so the `addr | cur`
	// above remains correct.

	// Note: I tested __uint128_t for this too. GCCs code is extremely slow;
	// clang is fine, but it's still slower than this 64-bit implementation.
	// Note 2: reading the bytes as LE - or in any other order - would not
	// make the results incorrect, just "randomize" them a little.
	// However we want to keep the natural order.

	uint64_t m0 = read_be64(t->spec.mask), m1 = read_be64(t->spec.mask + 8);
	uint64_t c0 = read_be64(t->cur),       c1 = read_be64(t->cur + 8);

	uint64_t s1 = m1 | c1;
	if(s1 != UINT64_MAX) {
		// bottom half increases
		c1 = (s1 + 1) & ~m1;
	} else {
		c1 = 0;
		uint64_t s0 = m0 | c0;
		if(s0 != UINT64_MAX) {
			// bottom half overflows, increase top half
			c0 = (s0 + 1) & ~m0;
		} else {
			// both overflow
			t->done = 1;
		}
	}

	put_be64(t->cur,     c0);
	put_be64(t->cur + 8, c1);
}

static int count_mask_bits(const struct targetstate *t)
{
	enum {
		M_SZ = sizeof(t->spec.mask),
		ULL_SZ = sizeof(unsigned long long),
	};
	int b = 0;
#if __has_builtin(__builtin_popcountll)
	static_assert(M_SZ % ULL_SZ == 0, "");
	for (int off = 0; off < M_SZ; off += ULL_SZ) {
		unsigned long long x;
		memcpy(&x, &t->spec.mask[off], ULL_SZ);
		b += __builtin_popcountll(x);
	}
#else
	for (int off = 0; off < M_SZ; off++) {
		uint8_t x = t->spec.mask[off];
		for (; x; x >>= 1)
			b += x & 1;
	}
#endif
	return b;
}

static void count_total(const struct targetstate *t, uint64_t *total, bool *overflowed)
{
	if (t->bits <= 64) { // larger than /64
		*overflowed = true;
		return;
	}
	uint64_t one = TARGET_ADDR_COUNT(t);
#if __has_builtin(__builtin_add_overflow)
	if (__builtin_add_overflow(one, *total, total))
		*overflowed = true;
#else
	tmp = *total;
	*total += one;
	if (*total < tmp)
		*overflowed = true;
#endif

	// FIXME: should have a built-in selftest instead of relying the CI to run
	// past these asserts
#ifndef NDEBUG
	{
		uint64_t tmp1 = 0, tmp2 = 0;
		progress_single(t, &tmp1, &tmp2);
		assert(tmp1 == one);
	}
#endif
}

static void progress_single(const struct targetstate *t, uint64_t *total, uint64_t *done)
{
	// shortcuts
	if(t->bits == 128) {
		(*total)++;
		*done += t->done ? 1 : 0;
		return;
	} else if(t->done) {
		uint64_t one = TARGET_ADDR_COUNT(t);
		*total += one;
		*done += one;
		return;
	}

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
	*done += _done;
}
