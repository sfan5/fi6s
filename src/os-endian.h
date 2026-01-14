// make sure htobe16 et al are available
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#if defined(__FreeBSD__)
#include <sys/endian.h>
#else
#include <endian.h>
#endif
