#ifndef _BANNER_H
#define _BANNER_H

#include <stdint.h>
#include <stdio.h>

struct rec_header;

void binary_write_header(FILE *f);
void binary_write_record(FILE *f, const struct rec_header *h);
void binary_write_record_with_data(FILE *f, const struct rec_header *h, const void *data);

/** INTERNAL **/

#define FILE_MAGIC 0x4e414373
#define RECORD_ALIGN 8

struct file_header {
	uint32_t magic;
	uint16_t version;
} __attribute__(( packed, aligned(RECORD_ALIGN) ));

struct rec_header {
	uint64_t timestamp;
	uint32_t size; // incl. header
	uint16_t port;
	uint8_t ttl; // ignored for banner records
	uint8_t proto_status; // (proto << 4) | status; status is ignored for banner records
	uint8_t addr[16];
	// banner data follows here
} __attribute__(( packed, aligned(RECORD_ALIGN) ));

#endif // _BANNER_H
