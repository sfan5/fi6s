// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#pragma once
#include <stdint.h>
#include <netinet/in.h>

#define ETH_TYPE_IPV6 0x86dd
#define IP_TYPE_TCP 0x06
#define IP_TYPE_UDP 0x11
#define IP_TYPE_ICMPV6 0x3a

enum {
	// filter L4 protocol
	// special case: IP_TYPE_ICMPV6 will allow only 'Echo Reply'
	RAWSOCK_FILTER_IPTYPE  = (1 << 0),
	// filter by destination IP
	RAWSOCK_FILTER_DSTADDR = (1 << 1),
	// filter by destination port
	RAWSOCK_FILTER_DSTPORT = (1 << 2),
	// also include any related ICMP errors (filters apply to paylod likewise)
	RAWSOCK_FILTER_RELATED_ICMP = (1 << 3),
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
	uint8_t next; // Type of next header (TCP, UDP, ...)
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
int rawsock_setfilter(int flags, uint8_t iptype, const uint8_t *dstaddr, int dstport);
// For testing only, normally you use rawsock_loop.
int rawsock_sniff(uint64_t *ts, int *length, const uint8_t **pkt);
int rawsock_loop(rawsock_callback func);
void rawsock_breakloop(void);
int rawsock_send(const uint8_t *pkt, unsigned int size);
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
// advice: 0=quiet, 1=default route, 2=specific IP
int rawsock_getsrcip(const struct sockaddr_in6 *dest, const char *interface, uint8_t *ip, int advice);
/// @return 1 if IP is local to this host, 0 if not, -1 if error
int rawsock_islocal(const uint8_t *ip);
/**
 * Reserve a local port on the specified IP for the rest of the program lifetime.
 * The effect should be that the kernel ignores any packets to this tuple.
 * @param addr IPv6 address
 * @param type protocol (IP_TYPE)
 * @param port port number or 0 to let the kernel choose
 * @return reserved port number or -1 if error or -2 if unsupported
*/
int rawsock_reserve_port(const uint8_t *addr, int type, int port);
