#define _DEFAULT_SOURCE // htobe16()
#define _GNU_SOURCE // strchrnul()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h> // isdigit()
#include <endian.h>

#include "util.h"

void ipv6_string(char *dst, const uint8_t *addr)
{
	int pos = 0;
	int zc_state = 0; // 0 = pre-use, 1 = during, 2 = after ("dumb" impl. of zero compression)
	for(int i = 0; i < 8; i++) {
		uint16_t cur = addr[i*2] << 8 | addr[i*2 + 1];

		if(cur == 0 && zc_state == 0 && i != 7 && i != 0) {
			zc_state = 1;
			pos += snprintf(&dst[pos], 2, ":");
		} else if(cur != 0 && zc_state == 1) {
			zc_state = 2;
		}

		if(zc_state == 1)
			continue;
		if(cur == 0 && (i == 0 || i == 7)) // zeroe elements (first or last) maybe omitted
			goto seperator;
		pos += snprintf(&dst[pos], 5, "%x", cur);
		seperator:
		if(i != 7)
			pos += snprintf(&dst[pos], 2, ":");
	}
}

int parse_mac(const char *str, uint8_t *dst)
{
	const char *p = str;
	for(int i = 0; i < 6; i++) {
		char cur[3];
		int j = 0;
		while(*p && *p != ':' && *p != '-' && j < 2)
			cur[j++] = *(p++);
		cur[j] = '\0';
		j = strtol_simple(cur, 16);
		if(j == -1)
			return -1;
		dst[i] = j & 0xff;
		if(!*p && i != 5)
			return -1;
		p++;
	}
	return 0;
}

int parse_ipv6(const char *str, uint8_t *dst)
{
	memset(dst, 0, 16);
	int given = strchr_count(str, ':') + 1;
	if(given < 3 || given > 8) // '::' is 3 elements
		return -1;

	const char *p = str;
	int i = 0;
	while(i < 8) {
		char cur[5], *next = strchrnul(p, ':');
		if(next - p > sizeof(cur) - 1)
			return -1;
		strncpy_term(cur, p, next - p);

		if((i == 0 || i == 7) && strlen(cur) == 0)
			strncpy(cur, "0", 2); // zero compression can't be used on first or last element
		if(strlen(cur) == 0) {
			// zero compression: an empty field fills up the missing zeroes
			i += 8 - given;
			goto next;
		}

		int val = strtol_simple(cur, 16);
		if(val == -1)
			return -1;
		uint16_t val_fixed = htobe16(val & 0xffff);
		memcpy(&dst[i*2], &val_fixed, 2);

		next:
		if(*next == '\0')
			break;
		p = next + 1;
		i++;
	}

	return (i == 7) ? 0 : -1;
}

void init_ports(struct ports *p)
{
	for(int i = 0; i < PORTS_MAX_RANGES; i++) {
		// init each range as invalid
		p->r[i].begin = 1;
		p->r[i].end = 0;
	}
}

bool validate_ports(const struct ports *p)
{
	return p->r[0].end >= p->r[0].begin;
}

int parse_ports(const char *str, struct ports *dst)
{
	init_ports(dst);
	if(strcmp(str, "-") == 0) { // all of them
		dst->r[0].begin = 1;
		dst->r[0].end = 65535;
		return 0;
	}

	const char *p = str;
	int i = 0;
	while(1) {
		char cur[6];
		int j = 0;

		while(*p && isdigit(*p) && j < 5)
			cur[j++] = *(p++);
		cur[j] = '\0';
		j = strtol_simple(cur, 10);
		if(j == -1)
			return -1;
		dst->r[i].begin = dst->r[i].end = j & 0xffff;

		switch(*(p++)) {
			case ',':
				goto next;
			case '-':
				break;
			case '\0':
				return 0;
			default:
				return -1;
		}

		j = 0;
		while(*p && isdigit(*p) && j < 5)
			cur[j++] = *(p++);
		cur[j] = '\0';
		j = strtol_simple(cur, 10);
		if(j == -1)
			return -1;
		dst->r[i].end = j & 0xffff;
		if(dst->r[i].begin > dst->r[i].end)
			return -1;

		switch(*(p++)) {
			case ',':
				break; // goto next
			case '\0':
				return 0;
			default:
				return -1;
		}
		next:
		i++;
		if(i >= PORTS_MAX_RANGES)
			return -1;
	}
}

void ports_iter_begin(const struct ports *p, struct ports_iter *it)
{
	it->__p = p;
	it->__ri = -1;
}

int ports_iter_next(struct ports_iter *it)
{
	if(it->__ri == -1)
		goto next_range;
	it->val++;
	if(it->val > it->__p->r[it->__ri].end)
		goto next_range;
	return 1;
	next_range:
	it->__ri++;
	if(it->__ri >= PORTS_MAX_RANGES ||
		it->__p->r[it->__ri].begin > it->__p->r[it->__ri].end) // check if next range is valid
		return 0;
	it->val = it->__p->r[it->__ri].begin;
	return 1;
}

int strtol_suffix(const char *str)
{
	char *endptr;
	int value = strtol(str, &endptr, 10);
	if(endptr == str || strlen(endptr) > 1)
		return -1;
	if(*endptr == '\0')
		value *= 1;
	else if(*endptr == 'k')
		value *= 1000;
	else
		return -1;
	return value;
}

int strtol_simple(const char *str, int base)
{
	char *endptr;
	int value = strtol(str, &endptr, base);
	if(endptr == str || *endptr != '\0')
		return -1;
	return value;
}

int strchr_count(const char *str, int c)
{
	const char *p = str;
	int ret = 0;
	while(*p)
		ret += *(p++) == c;
	return ret;
}
