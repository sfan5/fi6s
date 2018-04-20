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
	[500] = "ike",
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
	static const char ike[] =
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

	switch(port) {
		case 500:
			*len = sizeof(ike) - 1; // mind the null byte!
			return ike;
		default:
			return NULL;
	}
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

#define IKEV2_TEXT_BUFFER_SIZE 1024 // must be <= BANNER_MAX_LENGTH
#define BREAK_ERR_IF(expr) \
	if(expr) { return -1; }
#define WRITEF(...) { \
		int _off = strlen(extra), _space = IKEV2_TEXT_BUFFER_SIZE - _off; \
		if (_space > 0) \
			snprintf(&extra[_off], _space, __VA_ARGS__); \
	}
#define WRITEHEX(buf, max) \
	for(int _i = 0; _i < max; _i++) \
		WRITEF("%02x", (int) ((unsigned char*) buf)[_i])
static int ikev2_process_header(char *header, char *extra)
{
	BREAK_ERR_IF((header[17] & 0xf0) != 0x20) // version != 2.x
	BREAK_ERR_IF((header[19] & 0x28) != 0x20) // flags & (I | R) != R

	WRITEF("Responder SPI: ")
	WRITEHEX(&header[8], 8)
	WRITEF("\n")

	WRITEF("Version: 2.%d\n", header[17] & 0x0f)

	return 0;
}
static int ikev2_process_payload(uint8_t type, char *buffer, unsigned int len, char *extra)
{
	switch(type) {
		case 33: // Security Association
		case 34: // Key Exchange
			break;

		case 38: { // Certificate Request
			BREAK_ERR_IF(1 > len)
			uint8_t cert_type = buffer[0];
			if(cert_type != 4) // X.509 Certificate - Signature
				break;
			BREAK_ERR_IF(1 + 20 > len)
			WRITEF("Certificate Request: X.509 ")
			WRITEHEX(&buffer[1], 20)
			WRITEF("\n")
			break;
		}
		case 40: // Nonce
			BREAK_ERR_IF(len == 0)
			WRITEF("Nonce: %d octets\n", len)
			break;
		case 41: { // Notify
			BREAK_ERR_IF(4 > len)
			uint16_t message_type = buffer[2] << 8 | buffer[3];
			WRITEF("Notify %s: ", message_type < 16384 ? "Error" : "Status")
			if(message_type == 7)
				WRITEF("INVALID_SYNTAX")
			else if(message_type == 14)
				WRITEF("NO_PROPOSAL_CHOSEN")
			else if(message_type == 16388)
				WRITEF("NAT_DETECTION_SOURCE_IP")
			else if(message_type == 16389)
				WRITEF("NAT_DETECTION_SOURCE_IP")
			else if(message_type == 16390)
				WRITEF("COOKIE %d octets", len - 4)
			else if(message_type == 16404)
				WRITEF("MULTIPLE_AUTH_SUPPORTED")
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
#undef BREAK_ERR_IF
#undef WRITEF
#undef WRITEHEX

void postprocess_udp(int port, char *banner, unsigned int *len)
{
	switch(port) {

#define BREAK_ERR_IF(expr) \
	if(expr) { *len = 0; break; }
		case 500: {
			char extra[IKEV2_TEXT_BUFFER_SIZE]; // TODO: this sucks
			*extra = '\0';

			int off = 0, r;
			BREAK_ERR_IF(off + 28 > *len)
			r = ikev2_process_header(&banner[off], extra);
			BREAK_ERR_IF(r == -1)

			uint8_t next_payload = banner[off+16];
			off += 28;
			do {
				BREAK_ERR_IF(off + 4 > *len)
				uint16_t payload_length = banner[off+2] << 8 | banner[off+3];
				BREAK_ERR_IF(payload_length < 4)
				BREAK_ERR_IF(off + payload_length > *len)

				r = ikev2_process_payload(next_payload, &banner[off+4], payload_length - 4, extra);
				BREAK_ERR_IF(r == -1)

				next_payload = banner[off];
				off += payload_length;
			} while(next_payload != 0);
			if(*len == 0)
				break; // came here from BREAK_ERR_IF in above do-while

			int final_len = strlen(extra);
			memcpy(banner, extra, final_len);
			*len = final_len;
			break;
		}
#undef BREAK_ERR_IF


		default:
			break; // do nothing
	}
}
