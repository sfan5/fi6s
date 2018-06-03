#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "binary.h"
#include "util.h"

static inline void write_align(struct obuf *o, uint64_t written)
{
	static const char bytes[RECORD_ALIGN] = { 0 };
	int have = written % RECORD_ALIGN;
	if(have > 0)
		obuf_write(o, bytes, RECORD_ALIGN - have);
}

void binary_write_header(struct obuf *o)
{
	struct file_header h;
	h.magic = FILE_MAGIC;
	h.version = 1;

	obuf_write(o, &h, sizeof(h));
	write_align(o, sizeof(h));
}

void binary_write_record(struct obuf *o, const struct rec_header *h)
{
#ifndef NDEBUG
	if(h->size != sizeof(*h))
		fprintf(stderr, "Incorrectly sized record!\n");
#endif
	obuf_write(o, h, sizeof(*h));
	write_align(o, h->size);
}

void binary_write_record_with_data(struct obuf *o, const struct rec_header *h, const void *data)
{
#ifndef NDEBUG
	if(h->size < sizeof(*h))
		fprintf(stderr, "Incorrectly sized record!\n");
#endif
	obuf_write(o, h, sizeof(*h));
	obuf_write(o, data, h->size - sizeof(*h));
	write_align(o, h->size);
}
