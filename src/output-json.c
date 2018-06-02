#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include "output.h"
#include "util.h"
#include "banner.h"

static void begin(FILE *f)
{
	setvbuf(f, NULL, _IOLBF, 16384);
	fprintf(f, "[\n");
}

static void output_status(FILE *f, uint64_t ts, const uint8_t *addr, int proto, uint16_t port, uint8_t ttl, int status)
{
	// {ip: "<ip>", timestamp: <ts>, ports: [{port: <port>, proto: "<tcp/udp>", status: "<status>", ttl: <ttl>}]},
	char addrstr[IPV6_STRING_MAX];

	ipv6_string(addrstr, addr);
	fprintf(f, "{\"ip\": \"%s\", \"timestamp\": %" PRIu64 ", \"ports\": [{\"port\": %u, \"proto\": \"%s\", \"status\": \"%s\", \"ttl\": %u}]},\n",
		addrstr, ts, port,
		proto == OUTPUT_PROTO_TCP ? "tcp" : "udp",
		status == OUTPUT_STATUS_OPEN ? "open" : "closed", ttl
	);
}

static void json_escape(char *out, unsigned int outsize, const unsigned char* buf, uint32_t len)
{
	for(uint32_t i = 0; i < len; i++) {
		int c = buf[i];
		char tmp[7] = {0};
		if(!isprint(c) || strchr("<>&\\\"\'", c) != NULL)
			snprintf(tmp, sizeof(tmp), "\\u00%02x", c);
		else
			*tmp = c;
		my_strlcat(out, tmp, outsize);
	}
}

static void output_banner(FILE *f, uint64_t ts, const uint8_t *addr, int proto, uint16_t port, const char *banner, uint32_t bannerlen)
{
	// {"ip": "<ip>", "timestamp": <ts>, "ports": [{"port": <port>, "proto": "<tcp/udp>", "service": {"name": "http", "banner": "......"}}]},
	char addrstr[IPV6_STRING_MAX], svc[128], buffer[BANNER_MAX_LENGTH * (4+2)];
	const char *temp;

	// use buffer so we can fprintf everything at once
	*buffer = '\0';
	json_escape(buffer, sizeof(buffer), (unsigned char*) banner, bannerlen);

	ipv6_string(addrstr, addr);
	temp = banner_service_type(banner_outproto2ip_type(proto), port);
	if(temp)
		snprintf(svc, sizeof(svc), "\"%s\"", temp);
	else
		strncpy(svc, "null", sizeof(svc));
	fprintf(f, "{\"ip\": \"%s\", \"timestamp\": %" PRIu64 ", \"ports\": [{\"port\": %u, \"proto\": \"%s\", \"service\": {\"name\": %s, \"banner\": \"%s\"}}]},\n",
		addrstr, ts, port,
		proto == OUTPUT_PROTO_TCP ? "tcp" : "udp",
		svc, buffer
	);
}

static void end(FILE *f)
{
	fprintf(f, "{\"finished\": 1}]\n");
}

const struct outputdef output_json = {
	&begin,
	&output_status,
	&output_banner,
	&end,
};
