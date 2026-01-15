// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "output.h"
#include "binary.h"
#include "util.h"

static void begin(FILE *f)
{
	DECLARE_OBUF_STACK(buf, 256);

	binary_write_header(&buf);

	obuf_flush(&buf, f);
	fflush(f);
}

static void status(FILE *f, uint64_t ts, const uint8_t *addr, int proto, uint16_t port, uint8_t ttl, int status)
{
	DECLARE_OBUF_STACK(buf, 256);

	struct rec_header h;
	h.timestamp = ts;
	h.size = sizeof(struct rec_header);
	h.port = port;
	h.ttl = ttl;
	h.proto_status = (proto << 4) | status;
	memcpy(h.addr, addr, 16);

	binary_write_record(&buf, &h);
	obuf_flush(&buf, f);
}

static void banner(FILE *f, uint64_t ts, const uint8_t *addr, int proto, uint16_t port, const char *banner, uint32_t bannerlen)
{
	struct obuf buf = output_get_scratch_buf();

	struct rec_header h;
	h.timestamp = ts;
	h.size = sizeof(struct rec_header) + bannerlen;
	h.port = port;
	h.ttl = 0;
	h.proto_status = (proto << 4);
	memcpy(h.addr, addr, 16);

	binary_write_record_with_data(&buf, &h, banner);
	obuf_flush(&buf, f);
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
	.raw = 1,
};
