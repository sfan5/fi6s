#ifndef _RAWSOCK_H
#define _RAWSOCK_H

#include <stdint.h>
#include <netinet/in.h>

#define ETH_TYPE_IPV6 0x86dd
#define IP_TYPE_TCP 0x06
#define IP_TYPE_UDP 0x11
#define IP_TYPE_ICMPV6 0x3a

enum {
	RAWSOCK_FILTER_IPTYPE  = (1 << 0),
	RAWSOCK_FILTER_DSTADDR = (1 << 1),
	RAWSOCK_FILTER_DSTPORT = (1 << 2),
};

#define FRAME_ETH_SIZE 14
struct frame_eth {
	uint8_t dest[6]; // Destination address
	uint8_t src[6]; // Source address
	uint16_t type; // Type of next header (usually IP)
} __attribute__((packed));

#define FRAME_IP_SIZE 40
struct frame_ip {
	uint8_t
		traffic1:4, // Traffic class
		ver:4; // Version (== 6)
	uint8_t
		flow1:4, // Flow label
		traffic2:4;
	uint16_t flow2;
	uint16_t len; // Payload length
	uint8_t next; // Type of next header (TCP or UDP)
	uint8_t ttl; // Hop limit
	uint8_t src[16]; // Source Address
	uint8_t dest[16]; // Destination Address
} __attribute__((packed));

// pseudo IPv6 header utilized in checksumming
#define PSEUDO_HEADER_SIZE 40
struct pseudo_header {
	uint8_t src[16];
	uint8_t dest[16];
	uint32_t len;
	uint8_t zero[3];
	uint8_t ipproto;
} __attribute__((packed));

typedef void (*rawsock_callback)(uint64_t /* timestamp */, int /* length */, const uint8_t* /* packet */);

int rawsock_open(const char *dev, int buffersize);
int rawsock_has_ethernet_headers(void);
int rawsock_setfilter(int flags, uint8_t iptype, const uint8_t *dstaddr, uint16_t dstport);
// For testing only, normally you use rawsock_loop.
int rawsock_sniff(uint64_t *ts, int *length, const uint8_t **pkt);
int rawsock_loop(rawsock_callback func);
void rawsock_breakloop(void);
int rawsock_send(const uint8_t *pkt, int size);
void rawsock_close(void);

void rawsock_eth_settings(const uint8_t *src, const uint8_t *dst);
void rawsock_eth_prepare(struct frame_eth *f, int type);
void rawsock_eth_decode(const struct frame_eth *f, int *type);

void rawsock_ip_settings(const uint8_t *src, int ttl);
void rawsock_ip_prepare(struct frame_ip *f, int type);
void rawsock_ip_modify(struct frame_ip *f, int length, const uint8_t *dst);
void rawsock_ip_decode(const struct frame_ip *f, int *type, int *length, int *ttl, const uint8_t **src, const uint8_t **dst);

int rawsock_getdev(char **dev);
int rawsock_getmac(const char *dev, uint8_t *mac); // MAC of the adapter/intf
int rawsock_getgw(const char *dev, uint8_t *mac); // MAC of the default router/gateway
int rawsock_getsrcip(const struct sockaddr_in6 *dest, const char *interface, uint8_t *ip);

#endif // _RAWSOCK_H
