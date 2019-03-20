#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include "output.h"
#include "util.h"
#include "banner.h"

#define OUTPUT_BUFFER (512 + BANNER_MAX_LENGTH * (2+4))

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
	for(uint32_t i = 0; i < len; i++) {
		int c = buf[i];
		if(!isprint(c) || strchr("<>&\\\"\'", c) != NULL) {
			char tmp[7];
			snprintf(tmp, sizeof(tmp), "\\u00%02x", c);
			obuf_writestr(out, tmp);
		} else {
			obuf_write(out, &buf[i], 1);
		}
	}
}

static void banner(FILE *f, uint64_t ts, const uint8_t *addr, int proto, uint16_t port, const char *banner, uint32_t bannerlen)
{
	// {"ip": "<ip>", "timestamp": <ts>, "ports": [{"port": <port>, "proto": "<tcp/udp>", "service": {"name": "http", "banner": "......"}}]},
	DECLARE_OBUF_STACK(out, OUTPUT_BUFFER);

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
	.postprocess = 1,
};
