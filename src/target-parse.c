#define _GNU_SOURCE // strchrnul()
#include <string.h>
#include <endian.h>

#include "target.h"
#include "util.h"

#define SPLIT_BITPOS(bitpos, off, mask) \
	do { /* assumes uint8_t array */ \
		*(off) = (bitpos) >> 3; \
		*(mask) = 1 << (7 - ((bitpos) & 7)); \
	} while(0)

static int parse_wcnibble(const char *str, struct targetspec *dst);

int target_parse(const char *str, struct targetspec *dst)
{
	if(strchr(str, 'x')) // wildcard nibble notation
		return parse_wcnibble(str, dst);

	char addr[40], *mask;
	mask = strchr(str, '/');
	if(!mask) { // assume /128 if no mask given
		if(parse_ipv6(str, dst->addr) < 0)
			return -1;
		memset(dst->mask, 0xff, 16);
		return 0;
	}
	if(mask - str > sizeof(addr) - 1)
		return -1;
	strncpy_term(addr, str, mask - str);
	mask++;

	if(parse_ipv6(addr, dst->addr) < 0)
		return -1;

	if(strchr(mask, '-')) { // subnet range notation
		char first[3], *second;
		second = strchr(mask, '-');
		if(!second || second - mask > sizeof(first) - 1)
			return -1;
		strncpy_term(first, mask, second - mask);
		second++;

		int begin, end;
		begin = strtol_simple(first, 10);
		end = strtol_simple(second, 10);
		if(begin > 128 || begin < 0 || end > 128 || end < 0)
			return -1;
		if(begin >= end)
			return -1;

		memset(dst->mask, 0xff, 16);
		// unset each bit individually because it's easier
		for(int i = begin; i < end; i++) {
			int off, bit;
			SPLIT_BITPOS(i, &off, &bit);
			dst->mask[off] &= ~bit;
		}
	} else { // classic subnet notation
		int masklen = strtol_simple(mask, 10);
		if(masklen > 128 || masklen < 0)
			return -1;

		memset(dst->mask, 0, 16);
		// set each bit individually because it's easier
		for(int i = 0; i < masklen; i++) {
			int off, bit;
			SPLIT_BITPOS(i, &off, &bit);
			dst->mask[off] |= bit;
		}
	}

	for(int i = 0; i < 16; i++)
		dst->addr[i] &= dst->mask[i];

	return 0;
}

static int parse_wcnibble(const char *str, struct targetspec *dst)
{
	memset(dst->addr, 0, 16);
	memset(dst->mask, 0xff, 16);
	int given = strchr_count(str, ':') + 1;
	if(given < 3 || given > 8) // '::' is 3 elements
		return -1;

	const char *p = str;
	int i = 0;
	while(1) {
		char cur[5], *next = strchrnul(p, ':');
		if(next - p > sizeof(cur) - 1)
			return -1;
		strncpy_term(cur, p, next - p);

		if((i == 0 || i == 7) && strlen(cur) == 0)
			strncpy(cur, "0", 3); // zero compression can't be used on first or last element
		if(strlen(cur) == 0) {
			// zero compression: an empty field fills up the missing zeroes
			i += 8 - given;
			goto next;
		}

		for(int j = 0; j < strlen(cur); j++) {
			if(cur[j] != 'x')
				continue;
			// if there's a wildcard nibble here unset bits in netmask and replace with 0
			int bitpos = i*16 + (j + (4 - strlen(cur)))*4;
			for(int k = bitpos; k < bitpos+4; k++) {
				int off, bit;
				SPLIT_BITPOS(k, &off, &bit);
				dst->mask[off] &= ~bit;
			}
			cur[j] = '0';
		}

		int val = strtol_simple(cur, 16);
		if(val == -1)
			return -1;
		uint16_t val_fixed = htobe16(val & 0xffff);
		memcpy(&dst->addr[i*2], &val_fixed, 2);

		next:
		if(*next == '\0')
			break;
		p = next + 1;
		i++;
	}

	return 0;
}
