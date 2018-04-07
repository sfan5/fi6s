#define _GNU_SOURCE
#include <string.h>

#include "banner.h"
#include "rawsock.h"
#include "output.h"

static const char *typemap_low[1024] = {
	[21] = "ftp",
	[22] = "ssh",
	[23] = "telnet",
	[53] = "domain",
	[80] = "http",
};

const char *banner_service_type(uint8_t ip_type, int port)
{
	(void) ip_type;
	if(port < 1024)
		return typemap_low[port];
	switch(port) {
		case 8080:
			return typemap_low[80];
		default:
			return NULL;
	}
}

uint8_t banner_outproto2ip_type(int output_proto)
{
	return output_proto == OUTPUT_PROTO_TCP ? IP_TYPE_TCP : IP_TYPE_UDP;
}

/****/

static const char *get_query_tcp(int port, unsigned int *len);
static const char *get_query_udp(int port, unsigned int *len);

const char *banner_get_query(uint8_t ip_type, int port, unsigned int *len)
{
	static const char dns[] =
		"\x00\x1e" // Length field (TCP only)
		"\x12\x34" // Transaction ID
		"\x01\x00" // QUERY opcode, RD=1
		"\x00\x01\x00\x00\x00\x00\x00\x00" // 1 query
		"\x07" "version" "\x04" "bind" "\x00\x00\x10\x00\x03" // version.bind.  CH  TXT
	;

	switch(port) {
		case 53: {
			int skip = ip_type == IP_TYPE_UDP ? 2 : 0;
			*len = sizeof(dns) - skip - 1; // mind the null byte!
			return &dns[skip];
		}
	}

	if(ip_type == IP_TYPE_TCP)
		return get_query_tcp(port, len);
	else
		return get_query_udp(port, len);
}

static const char *get_query_tcp(int port, unsigned int *len)
{
	static const char ftp[] =
		"HELP\r\n"
		"FEAT\r\n"
	;
	static const char http[] =
		"GET / HTTP/1.0\r\n"
		"Accept: */*\r\n"
		"User-Agent: fi6s/0.1 (+https://github.com/sfan5/fi6s)\r\n"
		"\r\n"
	;

	switch(port) {
		case 21:
			*len = strlen(ftp);
			return ftp;
		case 22:
		case 23:
			*len = 0;
			return "";
		case 80:
		case 8080:
			*len = strlen(http);
			return http;
		default:
			return NULL;
	}
}

static const char *get_query_udp(int port, unsigned int *len)
{
	(void) port; (void) len;
	return NULL;
}

/****/

void postprocess_tcp(int port, char *banner, unsigned int *len);
void postprocess_udp(int port, char *banner, unsigned int *len);

void banner_postprocess(uint8_t ip_type, int port, char *banner, unsigned int *len)
{
	switch(port) {

#define BREAK_ERR_IF(expr) \
	if(expr) { *len = 0; break; }
#define SKIP_LABELS() \
	while(off < *len) { \
		if((banner[off] & 0xc0) == 0xc0) /* message compression */ \
			{ off += 2; break; } \
		else if(banner[off] > 0) /* ordinary label */ \
			{ off += 1 + banner[off]; } \
		else /* terminating zero-length label */ \
			{ off += 1; break; } \
	}
		case 53: {
			int off = ip_type == IP_TYPE_UDP ? 0 : 2; // skip length field if required
			BREAK_ERR_IF(off + 12 > *len)
			uint16_t flags = (banner[off+2] << 8) | banner[off+3];
			uint8_t rcode = (flags & 0xf);
			if((flags & 0x8000) != 0x8000 || rcode != 0x0) {
				if(rcode == 4)
					strncpy(banner, "-NOTIMPL-", 12);
				else if(rcode == 5)
					strncpy(banner, "-REFUSED-", 12);
				else
					strncpy(banner, "-SERVFAIL-", 12);
				*len = strlen(banner);
				break;
			}

			uint16_t qdcount = (banner[off+4] << 8) | banner[off+5];
			uint16_t ancount = (banner[off+6] << 8) | banner[off+7];
			BREAK_ERR_IF(qdcount != 1 || ancount < 1)
			off += 12;
			// skip query
			SKIP_LABELS()
			off += 4;
			BREAK_ERR_IF(off > *len)

			// parse answer record
			SKIP_LABELS()
			BREAK_ERR_IF(off + 10 > *len)
			uint16_t rr_type = (banner[off] << 8) | banner[off+1];
			uint16_t rr_rdlength = (banner[off+8] << 8) | banner[off+9];
			BREAK_ERR_IF(rr_type != 0x0010 /* TXT */)
			BREAK_ERR_IF(rr_rdlength < 2)
			off += 10;
			BREAK_ERR_IF(off + rr_rdlength > *len)

			// return just the TXT record contents
			memmove(banner, &banner[off+1], rr_rdlength - 1);
			*len = rr_rdlength - 1;
			break;
		}
#undef BREAK_ERR_IF
#undef SKIP_LABELS

	}

	if(ip_type == IP_TYPE_TCP)
		postprocess_tcp(port, banner, len);
	else
		postprocess_udp(port, banner, len);
}

void postprocess_tcp(int port, char *banner, unsigned int *len)
{
	switch(port) {
		case 22: {
			// cut off after identification string or first NUL
			char *end;
			end = (char*) memmem(banner, *len, "\r\n", 2);
			if(!end)
				end = (char*) memchr(banner, 0, *len);
			if(end)
				*len = end - banner;
			break;
		}

		case 80:
		case 8080: {
			// cut off after headers
			char *end = (char*) memmem(banner, *len, "\r\n\r\n", 4);
			if(!end)
				end = (char*) memmem(banner, *len, "\n\n", 2);
			if(end)
				*len = end - banner;
			break;
		}

		default:
			break; // do nothing
	}
}

void postprocess_udp(int port, char *banner, unsigned int *len)
{
	(void) port; (void) banner; (void) len;
	// do nothing
}
