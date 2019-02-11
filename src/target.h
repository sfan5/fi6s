#ifndef _TARGET_H
#define _TARGET_H

#include <stdio.h>
#include <stdint.h>

struct targetspec {
	uint8_t addr[16];
	uint8_t mask[16];
};

int target_parse(const char *str, struct targetspec *dst);

#define TARGET_RANDOMIZE_SIZE 8192
#define TARGET_EVEN_SPREAD 1 // not sure why you would disable this, but you can

int target_gen_init(void);
void target_gen_set_randomized(int v);
void target_gen_set_streaming(FILE *f);
void target_gen_fini(void);

int target_gen_add(const struct targetspec *s);
int target_gen_finish_add(void);
void target_gen_print_summary(int max_rate, int nports);

int target_gen_next(uint8_t *dst);
float target_gen_progress(void);

#endif // _TARGET_H
