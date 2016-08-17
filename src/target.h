#ifndef _TARGET_H
#define _TARGET_H

#include <stdint.h>

struct targetspec {
	uint8_t addr[16];
	uint8_t mask[16];
};

int target_parse(const char *str, struct targetspec *dst);

#endif // _TARGET_H
