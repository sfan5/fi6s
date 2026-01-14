// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

#include "output.h"
#include "util.h"
#include "banner.h"

enum {
	OUTPUT_BUFFER = 256 + BANNER_MAX_LENGTH * (2+2),
};

static inline bool my_isprint(unsigned char c)
{
	return c >= 32 && c <= 126;
}

static void begin(FILE *f)
{
	fprintf(f, "#fi6s\n");
}

static void status(FILE *f, uint64_t ts, const uint8_t *addr, int proto, uint16_t port, uint8_t ttl, int status)
{
	// <status> tcp <port> <ip> <ts>
	char addrstr[IPV6_STRING_MAX];

	(void) ttl;
	ipv6_string(addrstr, addr);
	fprintf(f, "%s %s %u %s %" PRIu64 "\n",
		proto == OUTPUT_PROTO_TCP ? "tcp" : (proto == OUTPUT_PROTO_UDP ? "udp" : "icmp"),
		status == OUTPUT_STATUS_OPEN ? "open" : (status == OUTPUT_STATUS_CLOSED ? "closed" : "up"),
		port, addrstr, ts
	);
}

static void escaped(struct obuf *out, const unsigned char* buf, uint32_t len)
{
	char tmp[10];
	for(uint32_t i = 0; i < len; i++) {
		unsigned char c = buf[i];
		if(!my_isprint(c)) {
			snprintf(tmp, sizeof(tmp), "\\x%02x", (int)c);
			obuf_write(out, tmp, 4);
		} else {
			obuf_write(out, &c, 1);
		}
	}
}

static void banner(FILE *f, uint64_t ts, const uint8_t *addr, int proto, uint16_t port, const char *banner, uint32_t bannerlen)
{
	// banner tcp <port> <ip> <ts> <proto> <banner>
	DECLARE_OBUF_STACK(out, OUTPUT_BUFFER);

	char addrstr[IPV6_STRING_MAX], buffer[256];
	const char *svc;

	ipv6_string(addrstr, addr);
	svc = banner_service_type(banner_outproto2ip_type(proto), port);
	snprintf(buffer, sizeof(buffer), "banner %s %u %s %" PRIu64 " %s ",
		proto == OUTPUT_PROTO_TCP ? "tcp" : "udp",
		port, addrstr, ts,
		svc ? svc : "?"
	);
	obuf_writestr(&out, buffer);

	escaped(&out, (unsigned char*)banner, bannerlen);

	obuf_writestr(&out, "\n");

	obuf_flush(&out, f);
}

static void end(FILE *f)
{
	fprintf(f, "# end\n");
}

const struct outputdef output_list = {
	.begin = &begin,
	.output_status = &status,
	.output_banner = &banner,
	.end = &end,
	.raw = 0,
};
