// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

// Extremely simple logging wrappers
#define log_raw(fmt, ...) (fprintf(stderr, fmt "\n", ##__VA_ARGS__))
#define log_error(fmt, ...) log_raw("Error: " fmt, ##__VA_ARGS__)
#define log_warning(fmt, ...) log_raw("Warning: " fmt, ##__VA_ARGS__)
#ifdef NDEBUG
#define log_debug(fmt, ...) ((void)0)
#else
#define log_debug log_raw
#endif

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
void ports_iter_begin(const struct ports *p, struct ports_iter *it); // begins iterating on a list of ports; pass p == NULL to only reset
int ports_iter_next(struct ports_iter *it); // gets next port value, has to be called initially; returns 0 if there's no more ports 1 otherwise

// Various utilities
#define IPV6_STRING_MAX 40
#define MAC_STRING_MAX 18

#ifndef __has_builtin
#define __has_builtin(x) (0)
#endif

void ipv6_string(char *dst, const uint8_t *addr); // writes null-terminated string representing the IPv6 address into buffer
void mac_string(char *dst, const uint8_t *addr); // writes null-terminated string representing the MAC address into buffer
int parse_mac(const char *str, uint8_t *dst); // parses MAC address string and writes raw bytes into buffer
int parse_ipv6(const char *str, uint8_t *dst); // parses IPv6 address string and writes raw bytes into buffer
int strtol_suffix(const char *str); // parses number and permits k suffix that multiplies by 1000
int strtol_simple(const char *str, int base); // parses number
int strchr_count(const char *str, int c); // counts occurrences of c
int realloc_if_needed(void **array, unsigned int elemsize,
		unsigned int used, unsigned int *total); // reallocarray() wrapper for convenience
void trim_space(char *buf); // trim whitespace from string buffer
void set_thread_name(const char *name); // sets name of calling thread
uint64_t rand64(void); // number with at least 60 bits of randomness
uint64_t monotonic_ms(void); // monotonic clock (ms)

// UDP/TCP checksumming
#define CHKSUM_INITIAL 0x0000
uint32_t chksum(uint32_t sum, const void *p, unsigned int n);
uint16_t chksum_final(uint32_t tmp, const void *p, unsigned int n);

// Output buffering
struct obuf {
	char *buffer;
	unsigned int offset, size;
};

int obuf_write(struct obuf *b, const void *data, unsigned int datasize);
int obuf_writestr(struct obuf *b, const char *data);
void obuf_flush(struct obuf *b, FILE *f); // does not(!) flush the file
void obuf_copy(const struct obuf *b, char *dest, unsigned int *len); // caller needs to ensure data fits

#define DECLARE_OBUF_STACK(name, bufsize) \
	char name ## _backing [bufsize]; \
	struct obuf name = { .buffer = name ## _backing, .offset = 0, .size = bufsize };
