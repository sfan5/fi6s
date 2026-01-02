#define _GNU_SOURCE
#include <string.h>
#include <assert.h>

#include "banner.h"
#include "rawsock.h"
#include "output.h"
#include "util.h"

struct m_entry {
	const char *name;
	uint16_t port[4];
	unsigned tcp:1, udp:1;
};

// Contains all service types with associated ports that have either
// - a banner query or
// - code to decode a response
static const struct m_entry typelist[] = {
	{ "ftp",      { 21 }, 1, 0 },
	{ "ssh",      { 22 }, 1, 0 },
	{ "telnet",   { 23 }, 1, 0 },
	{ "domain",   { 53 }, 1, 1 },
	{ "http",     { 80, 8080 }, 1, 0 },
	{ "snmp",     { 161 }, 0, 1 },
	{ "tls",      { 443 }, 1, 0 },
	{ "ike",      { 500, 4500 }, 0, 1 },
	{ "rtsp",     { 554 }, 1, 0 },
	{ "pptp",     { 1723 }, 1, 0 },
	{ "mysql",    { 3306 }, 1, 0 },
	{ "sip",      { 5060 }, 0, 1 },
	{ "mdns",     { 5353 }, 0, 1 },
	{ NULL, }
};

#define CASE(port, name) case (port): return (name);
#define CASE2(port1, port2, name) case (port1): case (port2): return (name);

const char *banner_service_type(uint8_t ip_type, int port)
{
	(void) ip_type;
	// Same data as typelist[] but inlined for practicality
	switch(port) {
		CASE(21, "ftp")
		CASE(22, "ssh")
		CASE(23, "telnet")
		CASE(53, "domain")
		CASE2(80, 8080, "http")
		CASE(161, "snmp")
		CASE(443, "tls")
		CASE2(500, 4500, "ike")
		CASE(554, "rtsp")
		CASE(1723, "pptp")
		CASE(3306, "mysql")
		CASE(5060, "sip")
		CASE(5353, "mdns")
		default:
			return NULL;
	}
}

#undef CASE
#undef CASE2

void banner_print_service_types()
{
	printf("TCP ports:\n");
	for(const struct m_entry *c = typelist; c->name != NULL; c++) {
		if(!c->tcp)
			continue;
		printf("    %d", c->port[0]);
		for(int i = 1; i < 4 && c->port[i] != 0; i++)
			printf(",%d", c->port[i]);
		printf(" %s\n", c->name);

		assert(!strcmp(c->name, banner_service_type(IP_TYPE_TCP, c->port[0])));
	}
	printf("\n");

	printf("UDP ports:\n");
	for(const struct m_entry *c = typelist; c->name != NULL; c++) {
		if(!c->udp)
			continue;
		printf("    %d", c->port[0]);
		for(int i = 1; i < 4 && c->port[i] != 0; i++)
			printf(",%d", c->port[i]);
		unsigned int len = 0;
		banner_get_query(IP_TYPE_UDP, c->port[0], &len);
		printf(" %s (%d bytes payload)\n", c->name, len);

		assert(!strcmp(c->name, banner_service_type(IP_TYPE_UDP, c->port[0])));
	}
	printf("\n");

	printf("Collecting banners on TCP ports is possible regardless of whether the service is listed here.\n");
	printf("However support may be required to get a response from the service"
		" and/or decode it as human-readable output.\n");
	printf("UDP services typically only answer to well-formed queries, so"
		" scanning a port not listed here will be unsuccessful.\n");
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
			*len = sizeof(dns) - skip - 1;
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
	static const char pptp[] =
		"\x00\x9c" // length
		"\x00\x01" // control message
		"\x1a\x2b\x3c\x4d" // cookie
		"\x00\x01\x00\x00" // Start-Control-Connection-Request
		"\x01\x00\x00\x00" // version 1, revision 0
		"\x00\x00\x00\x03\x00\x00\x00\x02" // capabilities
		"\x00\x00\x00\x01"

		// hostname
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

		// vendor string
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	;
	// (see util/make-banner-query.py for details)
	static const char tls[] =
		"\x16\x03\x01\x00\x6c\x01\x00\x00\x68\x03\x03\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
		"\xaa\x55\xaa\x55\xaa\x55\xaa\x00\x00\x18\xc0\x2b"
		"\xc0\x2c\xc0\x09\xc0\x0a\xc0\x2f\xc0\x30\xc0\x13"
		"\xc0\x14\x00\x9e\x00\x9f\x00\x33\x00\x39\x01\x00"
		"\x00\x27\xff\x01\x00\x01\x00\x00\x0a\x00\x06\x00"
		"\x04\x00\x19\x00\x17\x00\x0b\x00\x02\x01\x00\x00"
		"\x0d\x00\x0a\x00\x08\x04\x01\x02\x01\x04\x03\x06"
		"\x03\x00\x17\x00\x00"
	;
	static const char rtsp[] =
		"OPTIONS rtsp://0.0.0.0:554/ RTSP/1.0\r\n"
		"CSeq: 1\r\n"
		"User-Agent: fi6s/0.1\r\n"
		"\r\n"
	;


	switch(port) {
		case 21:
			*len = sizeof(ftp) - 1;
			return ftp;
		case 80:
		case 8080:
			*len = sizeof(http) - 1;
			return http;
		case 443:
			*len = sizeof(tls) - 1;
			return tls;
		case 554:
			*len = sizeof(rtsp) - 1;
			return rtsp;
		case 1723:
			*len = sizeof(pptp) - 1;
			return pptp;
		default:
			*len = 0; // send nothing
			return "";
	}
}

static const char *get_query_udp(int port, unsigned int *len)
{
	static const char ike[] =
		"\x00\x00\x00\x00" // prefix (4500 only)
		"\x11\x22\x33\x44\x55\x66\x77\x88" // SA Initiator's SPI
		"\x00\x00\x00\x00\x00\x00\x00\x00" // SA Responder's SPI (empty)
		"\x21" // Next payload: 33
		"\x20\x22\x08" // IKE 2.0, IKE_SA_INIT, Flags: I
		"\x00\x00\x00\x00" // Message ID
		"\x00\x00\x01\x68" // Length: 24 + 48 + 264 + 20 = 360

		// Security Association (33)
		"\x22\x00\x00\x30" // next payload: 34, length: 48
		"\x00\x00\x00\x2c" // no next proposal, length: 44
		"\x01\x01\x00" // proposal no. 1, protocol: IKE
		"\x04" // 4 transforms
		"\x03\x00\x00\x0c\x01\x00\x00\x0c" // ENCR_AES_CBC
		"\x80\x0e\x00\x80" // Key Length: 128 bits
		"\x03\x00\x00\x08\x02\x00\x00\x02" // PRF_HMAC_SHA1
		"\x03\x00\x00\x08\x03\x00\x00\x02" // AUTH_HMAC_SHA1_96
		"\x00\x00\x00\x08\x04\x00\x00\x0e" // D-H: 2048 MODP Group

		// Key Exchange (34)
		"\x28\x00\x01\x08" // next payload: 40, length: 264
		"\x00\x0e\x00\x00" // D-H group num (see above)
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"

		// Nonce (40)
		"\x00\x00\x00\x14" // no next payload, length: 20
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
	;
	static const char snmp[] =
		"\x30\x29"
		"\x02\x01\x00" // version-1
		"\x04\x06" "public" // community string
		"\xa0\x1c" // get-request
		"\x02\x04\x11\x22\x33\x44" // request-id
		"\x02\x01\x00"
		"\x02\x01\x00"
		"\x30\x0e" // variable-bindings
		"\x30\x0c"
		"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00" // 1.3.6.1.2.1.1.1 = sysDescr
		"\x05\x00" // NULL
	;
	static const char sip[] =
		"OPTIONS sip:nm SIP/2.0\r\n"
		"Via: SIP/2.0/UDP nm;branch=z9hG4bK0;rport\r\n"
		"Max-Forwards: 70\r\n"
		"From: <sip:nm@nm>;tag=0000\r\n"
		"To: <sip:nm2@nm2>\r\n"
		"Call-ID: 1\r\n"
		"CSeq: 1 OPTIONS\r\n"
		"Accept: application/sdp\r\n"
		"Content-Length: 0\r\n"
		"\r\n"
	;
	static const char mdns[] =
		"\x12\x34" // Transaction ID
		"\x01\x00" // QUERY opcode, RD=1
		"\x00\x01\x00\x00\x00\x00\x00\x00" // 1 query
		"\x09" "_services" "\x07" "_dns-sd" "\x04" "_udp" "\x05" "local" "\x00"
		"\x00\x0c\x00\x01" // _services._dns-sd._udp.local.  IN  PTR
	;


	switch(port) {
		case 161:
			*len = sizeof(snmp) - 1;
			return snmp;
		case 500:
		case 4500: {
			int skip = port == 4500 ? 0 : 4;
			*len = sizeof(ike) - skip - 1;
			return &ike[skip];
		}
		case 5060:
			*len = sizeof(sip) - 1;
			return sip;
		case 5353:
			*len = sizeof(mdns) - 1;
			return mdns;
		default:
			return NULL;
	}
}

/****/

void postprocess_tcp(int port, uchar *banner, unsigned int *len);
void postprocess_udp(int port, uchar *banner, unsigned int *len);

// protocols:
static int dns_process(int off, uchar *banner, unsigned int *len);
static int mdns_process(uchar *banner, unsigned int *len);
static int ikev2_process(int off, uchar *banner, unsigned int *len);
static int snmp_process(uchar *banner, unsigned int *len);
static int pptp_process(uchar *banner, unsigned int *len);
static int mysql_process(uchar *banner, unsigned int *len);

void banner_postprocess(uint8_t ip_type, int port, char *_banner, unsigned int *len)
{
	uchar *banner = (uchar*) _banner;
	switch(port) {
		case 53: {
			int r = dns_process(ip_type == IP_TYPE_UDP ? 0 : 2, banner, len);
			if(r == -1)
				*len = 0;
			break;
		}
	}

	if(ip_type == IP_TYPE_TCP)
		postprocess_tcp(port, banner, len);
	else
		postprocess_udp(port, banner, len);
}

void postprocess_tcp(int port, uchar *banner, unsigned int *len)
{
	switch(port) {
		case 22: {
			// cut off after identification string or first NUL
			uchar *end;
			end = (uchar*) memmem(banner, *len, "\r\n", 2);
			if(!end)
				end = (uchar*) memchr(banner, 0, *len);
			if(end)
				*len = end - banner;
			break;
		}

		case 80:
		case 554:
		case 8080: {
			// cut off after headers
			uchar *end = (uchar*) memmem(banner, *len, "\r\n\r\n", 4);
			if(!end)
				end = (uchar*) memmem(banner, *len, "\n\n", 2);
			if(end)
				*len = end - banner;
			break;
		}

		case 1723: {
			int r = pptp_process(banner, len);
			if(r == -1)
				*len = 0;
			break;
		}

		case 3306: {
			int r = mysql_process(banner, len);
			if(r == -1)
				*len = 0;
			break;
		}

		default:
			break; // do nothing
	}
}

void postprocess_udp(int port, uchar *banner, unsigned int *len)
{
	switch(port) {
		case 161: {
			int r = snmp_process(banner, len);
			if(r == -1)
				*len = 0;
			break;
		}

		case 500:
		case 4500: {
			int r = ikev2_process(port == 4500 ? 4 : 0, banner, len);
			if(r == -1)
				*len = 0;
			break;
		}

		case 5353: {
			int r = mdns_process(banner, len);
			if(r == -1)
				*len = 0;
			break;
		}

		default:
			break; // do nothing
	}
}

/** DNS and mDNS **/
// https://tools.ietf.org/html/rfc1035

#define MDNS_TEXT_BUFFER_SIZE 512 // must be <= BANNER_MAX_LENGTH
#define ERR_IF(expr) \
	if(expr) { return -1; }
static int dns_skip_labels(int *_off, const uchar *banner, unsigned int len)
{
	int off = *_off;
	while(off < len) {
		uchar c = banner[off];
		if((c & 0xc0) == 0xc0) { /* message compression */
			off += 2;
			break;
		} else if(c > 0) { /* ordinary label */
			ERR_IF(c >= 64) // too long
			off += 1 + c;
		} else { /* terminating zero-length label */
			off += 1;
			break;
		}
	}
	*_off = off;
	return 0;
}

static int dns_copy_labels(int off, const uchar *banner, unsigned int len, struct obuf *to)
{
	while(off < len) {
		uchar c = banner[off];
		if((c & 0xc0) == 0xc0) { /* message compression */
			ERR_IF(off + 2 > len)
			uint16_t loc = (c & 0x3f) << 8 | banner[off+1];
			ERR_IF(loc >= off) // only jump backwards, this is what makes the recursion safe
			off = loc;
		} else if(c > 0) { /* ordinary label */
			ERR_IF(c >= 64) // too long
			ERR_IF(off + 1 + c > len)
			obuf_write(to, &banner[off + 1], c);
			obuf_writestr(to, ".");
			off += 1 + c;
		} else { /* terminating zero-length label */
			break;
		}
	}
	return 0;
}

static int dns_process_header(int *_off, uchar *banner, unsigned int *len)
{
	int off = *_off;
	int r;

	ERR_IF(off + 12 > *len)
	uint16_t flags = (banner[off+2] << 8) | banner[off+3];
	uint8_t rcode = (flags & 0xf);
	if((flags & 0x8000) != 0x8000 || rcode != 0x0) {
		const char *msg;
		if(rcode == 4)
			msg = "-NOTIMPL-";
		else if(rcode == 5)
			msg = "-REFUSED-";
		else
			msg = "-SERVFAIL-";
		*len = strlen(msg);
		memcpy(banner, msg, *len);
		return 1;
	}

	uint16_t qdcount = (banner[off+4] << 8) | banner[off+5];
	uint16_t ancount = (banner[off+6] << 8) | banner[off+7];
	ERR_IF(qdcount != 1 || ancount < 1)
	off += 12;

	// skip query
	r = dns_skip_labels(&off, banner, *len);
	ERR_IF(r == -1)
	off += 4;
	ERR_IF(off > *len)

	*_off = off;
	return 0;
}

static int dns_process(int off, uchar *banner, unsigned int *len)
{
	int r;

	r = dns_process_header(&off, banner, len);
	if(r == 1)
		return 0;
	ERR_IF(r == -1)

	// parse answer record
	r = dns_skip_labels(&off, banner, *len);
	ERR_IF(r == -1)
	ERR_IF(off + 10 > *len)
	uint16_t rr_type = (banner[off] << 8) | banner[off+1];
	uint16_t rr_rdlength = (banner[off+8] << 8) | banner[off+9];
	ERR_IF(rr_type != 0x0010 /* TXT */)
	ERR_IF(rr_rdlength < 2)
	off += 10;
	ERR_IF(off + rr_rdlength > *len)

	// return just the TXT record contents
	memmove(banner, &banner[off+1], rr_rdlength - 1);
	*len = rr_rdlength - 1;
	return 0;
}

static int mdns_process(uchar *banner, unsigned int *len)
{
	int off = 0;
	int r;
	DECLARE_OBUF_STACK(extra, MDNS_TEXT_BUFFER_SIZE) // temporary buffer to hold our output

	r = dns_process_header(&off, banner, len);
	if(r == 1)
		return 0;
	ERR_IF(r == -1)

	while(off < *len) {
		// parse answer record
		r = dns_skip_labels(&off, banner, *len);
		ERR_IF(r == -1)
		ERR_IF(off + 10 > *len)
		uint16_t rr_type = (banner[off] << 8) | banner[off+1];
		uint16_t rr_rdlength = (banner[off+8] << 8) | banner[off+9];
		ERR_IF(rr_type != 0x000c /* PTR */)
		ERR_IF(rr_rdlength < 1)
		off += 10;

		// copy the domain pointed by record
		ERR_IF(off + rr_rdlength > *len)
		int endoff = off + rr_rdlength;
		r = dns_copy_labels(off, banner, endoff, &extra);
		ERR_IF(r == -1)
		obuf_writestr(&extra, "\n");
		off = endoff;
	}

	obuf_copy(&extra, (char*) banner, len);
	return 0;
}
#undef ERR_IF

/** IKEv2 **/
// https://tools.ietf.org/html/rfc7296#section-3.1
// https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml

#define IKEV2_TEXT_BUFFER_SIZE 1024 // must be <= BANNER_MAX_LENGTH
#define ERR_IF(expr) \
	if(expr) { return -1; }
#define WRITEF(...) { \
		int _off = strlen(extra), _space = IKEV2_TEXT_BUFFER_SIZE - _off; \
		if (_space > 0) \
			snprintf(&extra[_off], _space, __VA_ARGS__); \
	}
#define WRITEHEX(buf, max) \
	for(int _i = 0; _i < max; _i++) \
		WRITEF("%02x", (int) (buf)[_i])
static int ikev2_process_header(uchar *header, char *extra)
{
	ERR_IF((header[17] & 0xf0) != 0x20) // version != 2.x
	ERR_IF((header[19] & 0x28) != 0x20) // flags & (I | R) != R

	WRITEF("Responder SPI: ")
	WRITEHEX(&header[8], 8)
	WRITEF("\n")

	WRITEF("Version: 2.%d\n", header[17] & 0x0f)

	return 0;
}

static int ikev2_process_payload(uint8_t type, uchar *buffer, unsigned int len, char *extra)
{
	switch(type) {
		case 33: // Security Association
		case 34: // Key Exchange
			break;

		case 38: { // Certificate Request
			ERR_IF(1 > len)
			uint8_t cert_type = buffer[0];
			if(cert_type != 4) // X.509 Certificate - Signature
				break;
			ERR_IF(1 + 20 > len)
			WRITEF("Certificate Request: X.509 ")
			WRITEHEX(&buffer[1], 20)
			if(len > 1 + 20)
				WRITEF(" ...")
			WRITEF("\n")
			break;
		}
		case 40: // Nonce
			ERR_IF(len == 0)
			WRITEF("Nonce: %d octets\n", len)
			break;
		case 41: { // Notify
			ERR_IF(4 > len)
			uint16_t message_type = buffer[2] << 8 | buffer[3];
			WRITEF("Notify %s: ", message_type < 16384 ? "Error" : "Status")
			if(message_type == 7)
				WRITEF("INVALID_SYNTAX")
			else if(message_type == 14)
				WRITEF("NO_PROPOSAL_CHOSEN")
			else if(message_type == 24)
				WRITEF("AUTHENTICATION_FAILED")
			else if(message_type == 16388)
				WRITEF("NAT_DETECTION_SOURCE_IP")
			else if(message_type == 16389)
				WRITEF("NAT_DETECTION_DESTINATION_IP")
			else if(message_type == 16390)
				WRITEF("COOKIE %d octets", len - 4)
			else if(message_type == 16404)
				WRITEF("MULTIPLE_AUTH_SUPPORTED")
			else if(message_type == 16418)
				WRITEF("CHILDLESS_IKEV2_SUPPORTED")
			else if(message_type == 16430)
				WRITEF("IKEV2_FRAGMENTATION_SUPPORTED")
			else
				WRITEF("unknown (%d)", message_type)
			WRITEF("\n")
			break;
		}
		case 43: { // Vendor ID
			WRITEF("Vendor ID: ")
			WRITEHEX(buffer, len)
			WRITEF("\n")
			break;
		}

		default:
			WRITEF("Unknown Payload (%d)\n", type)
			break;
	}
	return 0;
}

static int ikev2_process(int off, uchar *banner, unsigned int *len)
{
	char extra[IKEV2_TEXT_BUFFER_SIZE]; // temporary buffer to hold our output
	*extra = '\0';

	int r;
	ERR_IF(off + 28 > *len)
	r = ikev2_process_header(&banner[off], extra);
	ERR_IF(r == -1)

	uint8_t next_payload = banner[off+16];
	off += 28;
	do {
		ERR_IF(off + 4 > *len)
		uint16_t payload_length = banner[off+2] << 8 | banner[off+3];
		ERR_IF(payload_length < 4)
		ERR_IF(off + payload_length > *len)

		r = ikev2_process_payload(next_payload, &banner[off+4], payload_length - 4, extra);
		ERR_IF(r == -1)

		next_payload = banner[off];
		off += payload_length;
	} while(next_payload != 0);

	int final_len = strlen(extra);
	memcpy(banner, extra, final_len);
	*len = final_len;
	return 0;
}
#undef ERR_IF
#undef WRITEF
#undef WRITEHEX

/** SNMP **/

#define ERR_IF(expr) \
	if(expr) { return -1; }
static int snmp_decode_length(int *_off, uchar *banner, unsigned int len, uint16_t *decoded)
{
	int off = *_off;

	ERR_IF(off + 1 > len)
	uint8_t first = banner[off];
	off++;
	ERR_IF(first == 0x80 || first == 0xff) // not allowed: indefinite form / reserved

	if(!(first & 0x80)) {
		// short form
		*_off = off;
		*decoded = first;
		return 0;
	}
	// long form
	first &= ~0x80;
	ERR_IF(first > 2) // wouldn't fit into a single packet
	ERR_IF(off + first > len)
	uint16_t value;
	if(first == 2)
		value = banner[off] << 8 | banner[off+1];
	else // == 1
		value = banner[off];
	off += first;

	*_off = off;
	*decoded = value;
	return 0;
}

static int snmp_check_opaque(int *_off, uchar *banner, unsigned int len, uint8_t type, int skip)
{
	int off = *_off;
	int r;

	ERR_IF(off + 1 > len)
	ERR_IF(banner[off] != type)
	off++;

	uint16_t dlen;
	r = snmp_decode_length(&off, banner, len, &dlen);
	ERR_IF(r == -1)
	ERR_IF(off + dlen > len)
	if(skip)
		off += dlen;

	*_off = off;
	return 0;
}

static int snmp_decode_integer(int *_off, uchar *banner, unsigned int len, uint32_t *decoded)
{
	int off = *_off;
	int r;

	ERR_IF(off + 1 > len)
	ERR_IF(banner[off] != 0x02) // INTEGER
	off++;

	uint16_t dlen;
	r = snmp_decode_length(&off, banner, len, &dlen);
	ERR_IF(r == -1)
	ERR_IF(off + dlen > len)

	switch(dlen) {
		case 1:
			*decoded = banner[off];
			break;
		case 2:
			*decoded = banner[off] << 8 | banner[off+1];
			break;
		case 4:
			*decoded = banner[off] << 24 | banner[off+1] << 16 | banner[off+2] << 8 | banner[off+3];
			break;
		default:
			return -1;
	}

	off += dlen;
	*_off = off;
	return 0;
}

static int snmp_decode_string(int *_off, uchar *banner, unsigned int len, uint32_t *slen)
{
	int off = *_off;
	int r;

	ERR_IF(off + 1 > len)
	ERR_IF(banner[off] != 0x04) // OCTET STRING
	off++;

	uint16_t dlen;
	r = snmp_decode_length(&off, banner, len, &dlen);
	ERR_IF(r == -1)
	ERR_IF(off + dlen > len) // check-only

	*_off = off;
	*slen = dlen;
	return 0;
}

static int snmp_process(uchar *banner, unsigned int *len)
{
	int off, r;

	off = 0;
	r = snmp_check_opaque(&off, banner, *len, 0x30, 0); // ??
	ERR_IF(r == -1)

	uint32_t val;
	r = snmp_decode_integer(&off, banner, *len, &val); // version
	ERR_IF(r == -1)
	ERR_IF(val != 0)

	r = snmp_decode_string(&off, banner, *len, &val); // community string
	ERR_IF(r == -1)
	off += val;

	r = snmp_check_opaque(&off, banner, *len, 0xa2, 0); // get-response
	ERR_IF(r == -1)

	r = snmp_decode_integer(&off, banner, *len, &val); // request-id
	ERR_IF(r == -1)

	r = snmp_decode_integer(&off, banner, *len, &val); // error-status
	ERR_IF(r == -1)
	if(val != 0) {
		snprintf((char*) banner, *len, "-error %d-", val);
		*len = strlen((char*) banner);
		return 0;
	}

	r = snmp_decode_integer(&off, banner, *len, &val); // error-index
	ERR_IF(r == -1)

	for(int i = 0; i < 2; i++) {
		r = snmp_check_opaque(&off, banner, *len, 0x30, 0); // ??
		ERR_IF(r == -1)
	}

	r = snmp_check_opaque(&off, banner, *len, 0x06, 1); // OID
	ERR_IF(r == -1)

	r = snmp_decode_string(&off, banner, *len, &val); // value associated with OID
	ERR_IF(r == -1)

	// return just that string
	memmove(banner, &banner[off], val);
	*len = val;
	return 0;
}
#undef ERR_IF

/** PPTP **/

#define ERR_IF(expr) \
	if(expr) { return -1; }
static int pptp_process(uchar *banner, unsigned int *len)
{
	int off = 0;

	ERR_IF(off + 156 > *len)
	uint16_t msgtype = banner[off+2] << 8 | banner[off+3];
	ERR_IF(msgtype != 1) // control message
	static const uchar cookie[] = { 0x1a, 0x2b, 0x3c, 0x4d };
	ERR_IF(memcmp(cookie, &banner[off+4], 4) != 0)

	uint16_t firmware;
	char hostname[64+1], vendor[64+1];
	firmware = banner[off+26] << 8 | banner[off+27];
	memcpy(hostname, &banner[off+28], 64);
	hostname[64] = '\0';
	memcpy(vendor, &banner[off+92], 64);
	vendor[64] = '\0';

	snprintf((char*) banner, BANNER_MAX_LENGTH,
		"Firmware: %d\nHostname: %s\nVendor: %s", firmware, hostname, vendor);
	*len = strlen((char*) banner);
	return 0;
}
#undef ERR_IF

/** MySQL **/

#define ERR_IF(expr) \
	if(expr) { return -1; }
static int mysql_process(uchar *banner, unsigned int *len)
{
	int off = 0;

	ERR_IF(off + 5 > *len)
	uint8_t protocol = banner[off+4];
	off += 5;

	if(protocol == 0xff) {
		ERR_IF(off + 2 > *len)
		off += 2; // skip error code
	} else {
		ERR_IF(protocol != 10)
	}

	// version string / error message
	int i = 0;
	while(off+i < *len && banner[off+i] != 0)
		i++;

	memmove(banner, &banner[off], i);
	*len = i;
	return 0;
}
#undef ERR_IF
