#include "output.h"

static void begin(FILE *f)
{
	// TODO
}

static void output_status(FILE *f, uint64_t ts, const uint8_t *addr, uint16_t port, uint8_t ttl, int status)
{
	// TODO
}

static void output_banner(FILE *f, uint64_t ts, const uint8_t *addr, uint16_t port, const char *banner, unsigned int bannerlen)
{
	// TODO
}

static void end(FILE *f)
{
	// TODO
}

const struct outputdef output_binary = {
	&begin,
	&output_status,
	&output_banner,
	&end,
};
