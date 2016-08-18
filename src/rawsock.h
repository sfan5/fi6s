#ifndef _RAWSOCK_H
#define _RAWSOCK_H

#include <stdint.h>

#define FRAME_ETH_SIZE 14
#define FRAME_IP_SIZE 40

#define ETH_TYPE_IPV6 0xdd86
#define IP_TYPE_TCP 0x06
#define IP_TYPE_UDP 0x11

struct frame_eth {
	uint8_t dest[6]; // Destination address
	uint8_t src[6]; // Source address
	uint16_t type; // Type of next header (usually IP)
} __attribute__((packed));

struct frame_ip {
	uint32_t
		ver:4, // Version (== 0x06)
		traffic:8, // Traffic class
		flow:20; // Flow label
	uint16_t len; // Payload length
	uint8_t next; // Type of next header (TCP or UDP)
	uint8_t ttl; // Hop limit
	uint8_t src[16]; // Source Address
	uint8_t dest[16]; // Destination Address
} __attribute__((packed));

int rawsock_open(const char *dev);
int rawsock_send(const char *pkt, int size);
void rawsock_close(void);

void rawsock_eth_settings(const uint8_t *src, const uint8_t *dst);
void rawsock_eth_prepare(struct frame_eth *f, int type);

void rawsock_ip_settings(const uint8_t *src, int ttl);
void rawsock_ip_prepare(struct frame_ip *f, int type);
void rawsock_ip_modify(struct frame_ip *f, int length, const uint8_t *dst);

#endif // _RAWSOCK_H
