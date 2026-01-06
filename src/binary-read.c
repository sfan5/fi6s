// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "binary.h"
#include "util.h"

static inline void skip_align(FILE *f, uint32_t read)
{
	char junk[RECORD_ALIGN];
	int have = read % RECORD_ALIGN;
	if(have > 0)
		(void)fread(junk, RECORD_ALIGN - have, 1, f);
}

static uint32_t bswap(uint32_t n)
{
	return ( (n & 0xff) << 24 ) |
		( ((n >> 8) & 0xff) << 16 ) |
		( ((n >> 16) & 0xff) << 8 ) |
		( ((n >> 24) & 0xff) );
}

int binary_read_header(struct reader *r, FILE *f)
{
	struct file_header h;

	memset(&h, 0, sizeof(h));
	(void)fread(&h, sizeof(h), 1, f);
	skip_align(f, sizeof(h));

	if(h.magic != FILE_MAGIC) {
		log_error("File header not found or incorrect.");
		if(h.magic == bswap(FILE_MAGIC))
			log_raw("This file was created on a system of differing endianness, reading it is not (yet) supported.");
		return -1;
	}
	if(h.version != 1) {
		log_error("Unsupported file version.");
		return -1;
	}

	r->file = f;
	r->version = h.version;
	r->record_size = 0;
	return 0;
}

int binary_read_record(struct reader *r, struct rec_header *h)
{
	int ret = fread(h, 1, sizeof(*h), r->file);
	if(ret < sizeof(*h))
		return ret == 0 ? -2 : -1;

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
		log_raw("%s: reading record data not allowed now!", __func__);
		return -1;
	} else if(r->record_size == sizeof(struct rec_header)) {
		log_raw("%s: trying to read record data despite no data attached!", __func__);
		return -1;
	}
#endif

	uint32_t datasize = r->record_size - sizeof(struct rec_header);
	if(fread(data, datasize, 1, r->file) != 1)
		return -1;
	skip_align(r->file, r->record_size);
	r->record_size = 0;
	return 0;
}
