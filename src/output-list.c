#include <inttypes.h>

#include "output.h"
#include "util.h"

static void begin(FILE *f)
{
	fprintf(f, "#fi6s\n");
}

static void output_status(FILE *f, uint64_t ts, const uint8_t *addr, uint16_t port, uint8_t ttl, int status)
{
	// <status> tcp <port> <ip> <ts>
	char addrstr[IPV6_STRING_MAX];

	(void) ttl;
	ipv6_string(addrstr, addr);
	fprintf(f, "%s tcp %u %s %" PRIu64 "\n",
		status == OUTPUT_STATUS_OPEN ? "open" : "closed",
		port, addrstr, ts
	);
}

static void end(FILE *f)
{
	fprintf(f, "# end\n");
}

const struct outputdef output_list = {
	&begin,
	&output_status,
	&end,
};
