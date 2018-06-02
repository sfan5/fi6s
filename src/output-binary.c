#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "output.h"

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

static inline void write_align(FILE *f, uint64_t written)
{
	static const char bytes[RECORD_ALIGN] = { 0 };
	int have = written % RECORD_ALIGN;
	if(have > 0)
		fwrite(bytes, RECORD_ALIGN - have, 1, f);
}


static void begin(FILE *f)
{
	setvbuf(f, NULL, _IOFBF, 65535);

	struct file_header h;
	h.magic = FILE_MAGIC;
	h.version = 1;

	fwrite(&h, sizeof(h), 1, f);
	write_align(f, sizeof(h));
	fflush(f);
}

static void status(FILE *f, uint64_t ts, const uint8_t *addr, int proto, uint16_t port, uint8_t ttl, int status)
{
	struct rec_header h;
	h.timestamp = ts;
	h.size = sizeof(struct rec_header);
	h.port = port;
	h.ttl = ttl;
	h.proto_status = (proto << 4) | status;
	memcpy(h.addr, addr, 16);

	fwrite(&h, sizeof(h), 1, f);
	write_align(f, h.size);
	fflush(f);
}

static void banner(FILE *f, uint64_t ts, const uint8_t *addr, int proto, uint16_t port, const char *banner, uint32_t bannerlen)
{
	struct rec_header h;
	h.timestamp = ts;
	h.size = sizeof(struct rec_header) + bannerlen;
	h.port = port;
	h.ttl = 0;
	h.proto_status = (proto << 4);
	memcpy(h.addr, addr, 16);

	fwrite(&h, sizeof(h), 1, f);
	fwrite(banner, bannerlen, 1, f);
	write_align(f, h.size);
	fflush(f);
}

static void end(FILE *f)
{
	(void) f;
}

const struct outputdef output_binary = {
	.begin = &begin,
	.output_status = &status,
	.output_banner = &banner,
	.end = &end,
	.postprocess = 0,
};
