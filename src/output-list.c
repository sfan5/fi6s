#include <inttypes.h>
#include <ctype.h>
#include <string.h>

#include "output.h"
#include "util.h"
#include "banner.h"

#define OUTPUT_BUFFER 16384

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
		status == OUTPUT_STATUS_OPEN ? "open" : "closed",
		proto == OUTPUT_PROTO_TCP ? "tcp" : "udp",
		port, addrstr, ts
	);
}

static void escaped(struct obuf *out, const unsigned char* buf, uint32_t len)
{
	for(uint32_t i = 0; i < len; i++) {
		int c = buf[i];
		if(c > 127 || !isprint(c)) {
			char tmp[5];
			snprintf(tmp, sizeof(tmp), "\\x%02x", c);
			obuf_writestr(out, tmp);
		} else {
			obuf_write(out, &buf[i], 1);
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
	.postprocess = 1,
};
