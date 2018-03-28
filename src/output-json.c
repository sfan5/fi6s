#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include "output.h"
#include "util.h"

static void begin(FILE *f)
{
	fprintf(f, "[\n");
}

static void output_status(FILE *f, uint64_t ts, const uint8_t *addr, uint16_t port, uint8_t ttl, int status)
{
	// {ip: "<ip>", timestamp: <ts>, ports: [{port: <port>, proto: "tcp", status: "<status>", ttl: <ttl>}]},
	char addrstr[IPV6_STRING_MAX];

	ipv6_string(addrstr, addr);
	fprintf(f, "{\"ip\": \"%s\", \"timestamp\": %" PRIu64 ", \"ports\": [{\"port\": %u, \"proto\": \"tcp\", \"status\": \"%s\", \"ttl\": %u}]},\n",
		addrstr, ts, port,
		status == OUTPUT_STATUS_OPEN ? "open" : "closed", ttl
	);
}

static void json_escape(char *out, unsigned int outsize, const char* buf, unsigned int len)
{
	for(unsigned int i = 0; i < len; i++) {
		int c = buf[i];
		char tmp[7] = {0};
		if(!isprint(c) || strchr("<>&\\\"\'", c) != NULL)
			snprintf(tmp, sizeof(tmp), "\\u00%02x", c);
		else
			*tmp = c;
		my_strlcat(out, tmp, outsize);
	}
}

static void output_banner(FILE *f, uint64_t ts, const uint8_t *addr, uint16_t port, const char *banner, unsigned int bannerlen)
{
	// {"ip": "<ip>", "timestamp": <ts>, "ports": [{"port": <port>, "proto": "tcp", "service": {"name": "http", "banner": "......"}}]},
	char addrstr[IPV6_STRING_MAX], buffer[16384];

	// buffer output here
	*buffer = '\0';
	json_escape(buffer, sizeof(buffer), banner, bannerlen);

	ipv6_string(addrstr, addr);
	fprintf(f, "{\"ip\": \"%s\", \"timestamp\": %" PRIu64 ", \"ports\": [{\"port\": %u, \"proto\": \"tcp\", \"service\": {\"name\": null, \"banner\": \"%s\"}}]},\n",
		addrstr, ts, port, buffer
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
