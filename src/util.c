#define _DEFAULT_SOURCE // htobe16
#define _GNU_SOURCE // strchrnul, pthread_setname_np
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h> // isdigit()
#include "os-endian.h"
#include <assert.h>
#include <pthread.h>

#include "util.h"

// Port ranges
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
	if(p)
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

// Various utilities
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

static void zc_find_range(const uint8_t *addr, int *first, int *last);

void ipv6_string(char *dst, const uint8_t *addr)
{
	int pos = 0,
		zc_first, zc_last;
	zc_find_range(addr, &zc_first, &zc_last);

	for(int i = 0; i < 8; i++) {
		uint16_t cur = addr[i*2] << 8 | addr[i*2 + 1];

		if(i == zc_first) {
			if(i == 0)
				pos += snprintf(&dst[pos], 3, "::");
			else
				pos += snprintf(&dst[pos], 2, ":");
			continue;
		} else if(i > zc_first && i <= zc_last) {
			continue;
		}

		pos += snprintf(&dst[pos], 5, "%x", cur);
		if(i != 7)
			pos += snprintf(&dst[pos], 2, ":");
	}
}

static void zc_find_range(const uint8_t *addr, int *first, int *last)
{
	int max_length = 0,
		cur_length = 0;
	*first = *last = -1;
	for(int i = 0; i < 8; i++) {
		uint16_t cur = addr[i*2] << 8 | addr[i*2 + 1];

		if(cur == 0) {
			cur_length++;
			continue;
		}
		// cur >= max to prefer compressing later zero sequences
		if(cur_length > 0 && cur_length >= max_length) {
			*first = i - cur_length;
			*last = i - 1;
			max_length = cur_length;
			cur_length = 0;
		}
	}
	if(cur_length > 0 && cur_length >= max_length) {
		*first = 8 - cur_length;
		*last = 8 - 1;
	}
}

void mac_string(char *dst, const uint8_t *addr)
{
	snprintf(dst, MAC_STRING_MAX, "%02X:%02X:%02X:%02X:%02X:%02X",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
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

static int _parse_ipv6(const char *str, uint8_t *dst)
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

		// FIXME: this will accept invalid addrs like :12::34:
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

int parse_ipv6(const char *str, uint8_t *dst)
{
	int given = strchr_count(str, ':') + 1;

	// special handling for ::1:2:3:4:5:6:7 and 1:2:3:4:5:6:7::
	// this is some seriously retarded shit, WHO CAME UP WITH THIS??
	if(given == 9) {
		char buf[40];
		strncpy(buf, str, sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = '\0';
		if(!strncmp(str, "::", 2))
			buf[0] = '0';
		else if(!strncmp(str + strlen(str) - 2, "::", 2))
			buf[strlen(str) - 1] = '0';
		return _parse_ipv6(buf, dst);
	}

	return _parse_ipv6(str, dst);
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

int realloc_if_needed(void **array, unsigned int elemsize, unsigned int used, unsigned int *total)
{
	if(used < *total)
		return 0;
	unsigned int new_total = *total * 3 / 2;
	if (new_total < used)
		new_total = used;
	void *new_array = realloc(*array, new_total * elemsize);
	if(new_array == NULL)
		return -1;
	*array = new_array;
	*total = new_total;
	return 0;
}

void trim_string(char *buf, const char *trimchars)
{
	// front
	int i = 0;
	while(buf[i] && strchr(trimchars, buf[i]))
		i++;
	if(i > 0)
		memmove(buf, &buf[i], strlen(buf) + 1 - i);

	// back
	char *ptr = buf + strlen(buf) - 1;
	while(ptr > buf && strchr(trimchars, *ptr))
		ptr--;
	*(ptr + 1) = '\0';
}

void set_thread_name(const char *name)
{
#ifdef __linux__
	pthread_setname_np(pthread_self(), name);
#else
	(void) name;
#endif
}

// UDP/TCP checksumming
void chksum(uint32_t *tmp, const uint16_t *p, int n)
{
	assert(((intptr_t) p) % sizeof(uint16_t) == 0); // align
	assert(n % 2 == 0);
	uint32_t sum = *tmp;
	while(n > 0) {
		sum += *p++;
		n -= 2;
	}
	*tmp = sum;
}

uint16_t chksum_final(uint32_t sum, const uint16_t *p, int n)
{
	assert(((intptr_t) p) % sizeof(uint16_t) == 0);
	while(n > 1) {
		sum += *p++;
		n -= 2;
	}
	if(n == 1)
		sum += *((uint8_t*) p);

	sum = (sum>>16) + (sum & 0xffff);
	sum = sum + (sum>>16);

	return ~sum;
}

// Output buffering
int obuf_write(struct obuf *b, const void *data, unsigned int datasize)
{
	if(b->offset + datasize > b->size)
		return -1;
	memcpy(&b->buffer[b->offset], data, datasize);
	b->offset += datasize;
	return 0;
}

int obuf_writestr(struct obuf *b, const char *data)
{
	return obuf_write(b, data, strlen(data));
}

void obuf_flush(struct obuf *b, FILE *f)
{
	fwrite(b->buffer, b->offset, 1, f);
	b->offset = 0;
}

void obuf_copy(const struct obuf *b, char *dest, unsigned int *len)
{
	memcpy(dest, b->buffer, b->offset);
	*len = b->offset;
}
