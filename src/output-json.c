#include <inttypes.h>

#include "output.h"
#include "util.h"

static void begin(FILE *f)
{
	(void) f;
}

static void output_status(FILE *f, uint64_t ts, const uint8_t *addr, uint16_t port, uint8_t ttl, int status)
{
	// {ip: "<ip>", timestamp: <ts>, ports: [{port: <port>, proto: "tcp", status: "<status>", ttl: <ttl>}]},
	char addrstr[IPV6_STRING_MAX];

	ipv6_string(addrstr, addr);
	fprintf(f, "{ip: \"%s\", timestamp: %" PRIu64 ", ports: [{port: %u, proto: \"tcp\", status: \"%s\", ttl: %u}]},\n",
		addrstr, ts, port,
		status == OUTPUT_STATUS_OPEN ? "open" : "closed", ttl
	);
}

static void end(FILE *f)
{
	fprintf(f, "{finished: 1}\n");
}

const struct outputdef output_json = {
	&begin,
	&output_status,
	&end,
};
