#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "binary.h"

static inline void write_align(FILE *f, uint64_t written)
{
	static const char bytes[RECORD_ALIGN] = { 0 };
	int have = written % RECORD_ALIGN;
	if(have > 0)
		fwrite(bytes, RECORD_ALIGN - have, 1, f);
}

void binary_write_header(FILE *f)
{
	struct file_header h;
	h.magic = FILE_MAGIC;
	h.version = 1;

	fwrite(&h, sizeof(h), 1, f);
	write_align(f, sizeof(h));
}

void binary_write_record(FILE *f, const struct rec_header *h)
{
#ifndef NDEBUG
	if(h->size != sizeof(*h))
		fprintf(stderr, "Incorrectly sized record!\n");
#endif
	fwrite(h, sizeof(*h), 1, f);
	write_align(f, h->size);
}

void binary_write_record_with_data(FILE *f, const struct rec_header *h, const void *data)
{
#ifndef NDEBUG
	if(h->size < sizeof(*h))
		fprintf(stderr, "Incorrectly sized record!\n");
#endif
	fwrite(h, sizeof(*h), 1, f);
	fwrite(data, h->size - sizeof(*h), 1, f);
	write_align(f, h->size);
}
