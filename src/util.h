#ifndef _UTIL_H
#define _UTIL_H

#include <stdint.h>

#define IPV6_STRING_MAX 40

void ipv6_string(char *dst, const uint8_t *addr); // writes null-terminated string representing the IPv6 address into buffer
int strtol_suffix(const char *str); // permits k suffix that multiplies by 1000, returns -1 on error
int strtol_simple(const char *str, int base); // returns -1 on error
int strchr_count(const char *str, int c); // counts occurrences of c

#define strncpy_term(dst, src, n) /* like strncpy but forces null-termination, CALLER NEEDS TO ENSURE THAT NULL BYTE FITS! */ \
	do { \
		strncpy(dst, src, n); \
		dst[n] = '\0'; \
	} while(0)

#endif // _UTIL_H
