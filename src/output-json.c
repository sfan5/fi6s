// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include "output.h"
#include "util.h"
#include "banner.h"

enum {
	MAX_NEEDED_BYTES = 256 + BANNER_MAX_LENGTH * (2+4),
};

static inline bool json_printable(unsigned char c)
{
	switch(c) {
		// avoid HTML stuff for portability
		case '<': case '>': case '&':
		// messes with the string
		case '\\': case '"':
			return false;
		default:
			return c >= 32 && c <= 126;
	}
}

static void begin(FILE *f)
{
	fprintf(f, "[\n");
}

static void status(FILE *f, uint64_t ts, const uint8_t *addr, int proto, uint16_t port, uint8_t ttl, int status)
{
	// {ip: "<ip>", timestamp: <ts>, ports: [{port: <port>, proto: "<tcp/udp>", status: "<status>", ttl: <ttl>}]},
	char addrstr[IPV6_STRING_MAX];

	ipv6_string(addrstr, addr);
	fprintf(f, "{\"ip\": \"%s\", \"timestamp\": %" PRIu64 ", \"ports\": [{\"port\": %u, \"proto\": \"%s\", \"status\": \"%s\", \"ttl\": %u}]},\n",
		addrstr, ts, port,
		proto == OUTPUT_PROTO_TCP ? "tcp" : (proto == OUTPUT_PROTO_UDP ? "udp" : "icmp"),
		status == OUTPUT_STATUS_OPEN ? "open" : (status == OUTPUT_STATUS_CLOSED ? "closed" : "up"),
		ttl
	);
}

static void json_escape(struct obuf *out, const unsigned char* buf, uint32_t len)
{
	char tmp[10];
	for(uint32_t i = 0; i < len; i++) {
		unsigned char c = buf[i];
		// Note: this just encodes the byte as an unicode codepoint with the same value
		if(!json_printable(c)) {
			snprintf(tmp, sizeof(tmp), "\\u%04x", (int)c);
			obuf_write(out, tmp, 6);
		} else {
			obuf_write(out, &c, 1);
		}
	}
}

static void banner(FILE *f, uint64_t ts, const uint8_t *addr, int proto, uint16_t port, const char *banner, uint32_t bannerlen)
{
	// {"ip": "<ip>", "timestamp": <ts>, "ports": [{"port": <port>, "proto": "<tcp/udp>", "service": {"name": "http", "banner": "......"}}]},
	struct obuf out = output_get_scratch_buf();
	static_assert(OUTPUT_SCRATCH_BUFFER_SIZE >= MAX_NEEDED_BYTES, "");

	char addrstr[IPV6_STRING_MAX], buffer[512];

	ipv6_string(addrstr, addr);
	snprintf(buffer, sizeof(buffer), "{\"ip\": \"%s\", \"timestamp\": %" PRIu64 ", \"ports\": [{\"port\": %u, \"proto\": \"%s\", \"service\": {\"name\": ",
		addrstr, ts, port, proto == OUTPUT_PROTO_TCP ? "tcp" : "udp"
	);
	obuf_writestr(&out, buffer);

	const char *temp = banner_service_type(banner_outproto2ip_type(proto), port);
	if(temp) {
		obuf_writestr(&out, "\"");
		obuf_writestr(&out, temp);
		obuf_writestr(&out, "\"");
	} else {
		obuf_writestr(&out, "null");
	}

	obuf_writestr(&out, ", \"banner\": \"");

	json_escape(&out, (unsigned char*) banner, bannerlen);

	obuf_writestr(&out, "\"}}]},\n");

	obuf_flush(&out, f);
}

static void end(FILE *f)
{
	fprintf(f, "{\"finished\": 1}]\n");
}

const struct outputdef output_json = {
	.begin = &begin,
	.output_status = &status,
	.output_banner = &banner,
	.end = &end,
	.raw = 0,
};
