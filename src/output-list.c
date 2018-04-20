#include <inttypes.h>
#include <ctype.h>
#include <string.h>

#include "output.h"
#include "util.h"
#include "banner.h"

static void begin(FILE *f)
{
	fprintf(f, "#fi6s\n");
}

static void output_status(FILE *f, uint64_t ts, const uint8_t *addr, int proto, uint16_t port, uint8_t ttl, int status)
{
	// <status> tcp <port> <ip> <ts>
	char addrstr[IPV6_STRING_MAX];

	(void) ttl;
	ipv6_string(addrstr, addr);
	fprintf(f, "%s %s %u %s %" PRIu64 "\n",
		status == OUTPUT_STATUS_OPEN ? "open" : "closed",
		proto == OUTPUT_PROTO_TCP ? "tcp" : "udp",
		port, addrstr, ts
	);
}

static void escaped(char *out, unsigned int outsize, const unsigned char* buf, unsigned int len)
{
	for(unsigned int i = 0; i < len; i++) {
		int c = buf[i];
		char tmp[5] = {0};
		if(c > 127 || !isprint(c))
			snprintf(tmp, sizeof(tmp), "\\x%02x", c);
		else
			*tmp = c;
		my_strlcat(out, tmp, outsize);
	}
}

static void output_banner(FILE *f, uint64_t ts, const uint8_t *addr, int proto, uint16_t port, const char *banner, unsigned int bannerlen)
{
	// banner tcp <port> <ip> <ts> <proto> <banner>
	char addrstr[IPV6_STRING_MAX], buffer[BANNER_MAX_LENGTH * (2+2)];
	const char *svc;

	// output_banner() is called from a diff. thread, need to buffer output here
	*buffer = '\0';
	escaped(buffer, sizeof(buffer), (unsigned char*)banner, bannerlen);

	ipv6_string(addrstr, addr);
	svc = banner_service_type(banner_outproto2ip_type(proto), port);
	fprintf(f, "banner %s %u %s %" PRIu64 " %s %s\n",
		proto == OUTPUT_PROTO_TCP ? "tcp" : "udp",
		port, addrstr, ts,
		svc ? svc : "?", buffer
	);
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
