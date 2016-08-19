#define _DEFAULT_SOURCE // htobe16()
#define _GNU_SOURCE // strchrnul()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

#include "util.h"

void ipv6_string(char *dst, const uint8_t *addr)
{
	// TODO: make use of zero compression
	int pos = 0;
	for(int i = 0; i < 8; i++) {
		pos += snprintf(&dst[pos], 5, "%x", addr[i*2] << 8 | addr[i*2 + 1]);
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

	return 0;
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
