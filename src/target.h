#ifndef _TARGET_H
#define _TARGET_H

#include <stdint.h>

struct targetspec {
	uint8_t addr[16];
	uint8_t mask[16];
};

int target_parse(const char *str, struct targetspec *dst);

#define MAX_TARGETS 512
#define RANDOMIZE_SIZE 8192

void target_gen_init(void);
void target_gen_set_randomized(int v);
float target_gen_progress(void);
void target_gen_fini(void);
int target_gen_add(const struct targetspec *s);
int target_gen_next(uint8_t *dst);

#endif // _TARGET_H
