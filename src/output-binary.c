#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "output.h"
#include "binary.h"

static void begin(FILE *f)
{
	setvbuf(f, NULL, _IOFBF, 65535);

	binary_write_header(f);
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

	binary_write_record(f, &h);
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

	binary_write_record_with_data(f, &h, banner);
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
