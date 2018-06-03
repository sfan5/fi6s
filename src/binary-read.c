#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h> // htonl

#include "binary.h"

static inline void skip_align(FILE *f, uint32_t read)
{
	char junk[RECORD_ALIGN];
	int have = read % RECORD_ALIGN;
	if(have > 0)
		fread(junk, RECORD_ALIGN - have, 1, f);
}

int binary_read_header(struct reader *r, FILE *f)
{
	struct file_header h;

	fread(&h, sizeof(h), 1, f);
	skip_align(f, sizeof(h));

	if(h.magic != FILE_MAGIC) {
		if(h.magic == htonl(FILE_MAGIC))
			fprintf(stderr, "This file was created on a system of differing endianness, reading it is not (yet) supported.\n");
		return -1;
	}
	if(h.version != 1) {
		fprintf(stderr, "Unsupported file version.\n");
		return -1;
	}

	r->file = f;
	r->version = h.version;
	r->record_size = 0;
	return 0;
}

int binary_read_record(struct reader *r, struct rec_header *h)
{
	fread(h, sizeof(*h), 1, r->file);
	if(feof(r->file))
		return -2;
	skip_align(r->file, sizeof(*h));

	r->record_size = h->size;
	if(h->size < sizeof(*h))
		return -1;
	else if(h->size == sizeof(*h)) // no data follows
		skip_align(r->file, h->size);
	return 0;
}

int binary_read_record_data(struct reader *r, void *data)
{
#ifndef NDEBUG
	if(r->record_size == 0) {
		fprintf(stderr, "Reading record data not allowed now!\n");
		return -1;
	} else if(r->record_size == sizeof(struct rec_header)) {
		fprintf(stderr, "Trying to read record data despite no data attached!\n");
		return -1;
	}
#endif

	fread(data, r->record_size - sizeof(struct rec_header), 1, r->file);
	skip_align(r->file, r->record_size);
	r->record_size = 0;
	return 0;
}
