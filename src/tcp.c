#define _DEFAULT_SOURCE // htobe{16,32}()
#include <string.h>
#include <endian.h>
#include <assert.h>

#include "tcp.h"
#include "rawsock.h"

#define PSEUDO_HEADER_SIZE 40
#define CHKSUM_INITAL 0x0000

// pseudo IPv6 header utilized in checksumming
struct pseudo_header {
	uint8_t src[16];
	uint8_t dest[16];
	uint32_t len;
	uint8_t zero[3];
	uint8_t ipproto;
} __attribute__((packed));

static inline void chksum(uint32_t *tmp, const uint16_t *p, int n);
static uint16_t chksum_final(uint32_t sum, const uint16_t *p, int n);
static inline void reset_flags(struct tcp_header *pkt);

void tcp_prepare(struct tcp_header *pkt)
{
	pkt->seqnum = htobe32(1);
	pkt->acknum = htobe32(0);
	pkt->offset = TCP_HEADER_SIZE >> 2;
	pkt->reserved1 = 0;
	pkt->reserved2 = 0;
	pkt->winsz = htobe16(1024);
	pkt->urgptr = 0;
}

void tcp_modify(struct tcp_header *pkt, int srcport, int dstport)
{
	pkt->srcport = htobe16(srcport & 0xffff);
	pkt->dstport = htobe16(dstport & 0xffff);
}

void tcp_synpkt(struct tcp_header *pkt)
{
	reset_flags(pkt);
	pkt->f_syn = 1;
}

void tcp_checksum(const struct frame_ip *ipf, struct tcp_header *pkt)
{
	const _Alignas(uint16_t) struct pseudo_header ph = {
		.len = htobe32(TCP_HEADER_SIZE),
		.zero = {0},
		.ipproto = 0x06, // IPPROTO_TCP
	};
	uint32_t csum = CHKSUM_INITAL;

	chksum(&csum, (uint16_t*) ipf->src, 16); // ph->src
	chksum(&csum, (uint16_t*) ipf->dest, 16); // ph->dest
	chksum(&csum, (uint16_t*) &ph.len, 8); // rest of ph
	pkt->csum = 0;
	pkt->csum = chksum_final(csum, (uint16_t*) pkt, TCP_HEADER_SIZE); // packet contents
}

void tcp_decode(const struct tcp_header *pkt, int *srcport, int *dstport)
{
	if(srcport)
		*srcport = be16toh(pkt->srcport);
	if(dstport)
		*dstport = be16toh(pkt->dstport);
}

static inline void reset_flags(struct tcp_header *pkt)
{
	pkt->f_fin = 0;
	pkt->f_syn = 0;
	pkt->f_rst = 0;
	pkt->f_psh = 0;
	pkt->f_ack = 0;
	pkt->f_urg = 0;
}

static inline void chksum(uint32_t *tmp, const uint16_t *p, int n)
{
	assert(n % 2 == 0);
	while(n > 0) {
		*tmp += *p++;
		n -= 2;
	}
}

static uint16_t chksum_final(uint32_t sum, const uint16_t *p, int n)
{
	while(n > 1) {
		sum += *p++;
		n -= 2;
	}
	if(n == 1)
		sum += *((uint8_t*) p);

	sum = (sum>>16) + (sum & 0xffff);
	sum = sum + (sum>>16);

	return ~sum;
}
