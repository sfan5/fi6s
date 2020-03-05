#ifndef _UTIL_H
#define _UTIL_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

// Port ranges
#define PORTS_MAX_RANGES 32
struct ports {
	struct { uint16_t begin, end; } r[PORTS_MAX_RANGES];
};
struct ports_iter {
	const struct ports *__p;
	int __ri;
	uint16_t val;
};

void init_ports(struct ports *p); // initialized as "invalid"
bool validate_ports(const struct ports *p); // just checks whether the struct contains anything
int parse_ports(const char *str, struct ports *dst); // parses list of ports into ports struct
void ports_iter_begin(const struct ports *p, struct ports_iter *it); // begins iterating on a list of ports, only does reset if p == NULL
int ports_iter_next(struct ports_iter *it); // gets next port value, has to be called initially; returns 0 if there's no more ports 1 otherwise

// Various utilities
#define IPV6_STRING_MAX 40

void ipv6_string(char *dst, const uint8_t *addr); // writes null-terminated string representing the IPv6 address into buffer
int parse_mac(const char *str, uint8_t *dst); // parses MAC address string and writes raw bytes into buffer
int parse_ipv6(const char *str, uint8_t *dst); // parses IPv6 address string and writes raw bytes into buffer
int strtol_suffix(const char *str); // parses number and permits k suffix that multiplies by 1000
int strtol_simple(const char *str, int base); // parses number
int strchr_count(const char *str, int c); // counts occurrences of c
int realloc_if_needed(void **array, unsigned int elemsize,
		unsigned int used, unsigned int *total); // reallocarray() wrapper for convenience
void trim_string(char *buf, const char *trimchars); // trims any amount of specified chars from left and right
void set_thread_name(const char *name); // sets name of calling thread

#define strncpy_term(dst, src, n) /* like strncpy but forces null-termination, CALLER NEEDS TO ENSURE THAT NULL BYTE FITS! */ \
	do { \
		strncpy(dst, src, n); \
		dst[n] = '\0'; \
	} while(0)

// UDP/TCP checksumming
#define CHKSUM_INITIAL 0x0000
void chksum(uint32_t *tmp, const uint16_t *p, int n);
uint16_t chksum_final(uint32_t tmp, const uint16_t *p, int n);

// Output buffering
struct obuf {
	char *buffer;
	unsigned int offset, size;
};

int obuf_write(struct obuf *b, const void *data, unsigned int datasize);
int obuf_writestr(struct obuf *b, const char *data);
void obuf_flush(struct obuf *b, FILE *f); // does not(!) flush the file

#define DECLARE_OBUF_STACK(name, bufsize) \
	char name ## _backing [bufsize]; \
	struct obuf name = { .buffer = name ## _backing, .offset = 0, .size = bufsize };

#endif // _UTIL_H
