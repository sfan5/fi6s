#include <inttypes.h>
#include <ctype.h>
#include <string.h>

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

static void escaped(FILE *f, const char* buf, unsigned int len)
{
	for(unsigned int i = 0; i < len; i++) {
		int c = buf[i];
		if(c == '\0' || c > 127 || !isprint(c) || strchr("\r\n\"\\", c) != NULL)
			fprintf(f, "\\x%02x", c);
		else
			putc(c, f);
	}
}

static void output_banner(FILE *f, uint64_t ts, const uint8_t *addr, uint16_t port, const char *banner, unsigned int bannerlen)
{
	// banner tcp <port> <ip> <ts> <proto> <banner>
	char addrstr[IPV6_STRING_MAX];

	ipv6_string(addrstr, addr);
	fprintf(f, "banner tcp %u %s %" PRIu64 " ? ", port, addrstr, ts);
	escaped(f, banner, bannerlen);
	fprintf(f, "\n");
}

static void end(FILE *f)
{
	fprintf(f, "# end\n");
}

const struct outputdef output_list = {
	&begin,
	&output_status,
	&output_banner,
	&end,
};
