#ifndef _UTIL_H
#define _UTIL_H

int strtol_suffix(const char *str); // permits k suffix that multiplies by 1000, returns -1 on error
int strtol_simple(const char *str, int base); // returns -1 on error
int strchr_count(const char *str, int c); // counts occurrences of c

#define strncpy_term(dst, src, n) /* like strncpy but forces null-termination, CALLER NEEDS TO ENSURE THAT NULL BYTE FITS! */ \
	do { \
		strncpy(dst, src, n); \
		dst[n] = '\0'; \
	} while(0)
		

#endif // _UTIL_H
