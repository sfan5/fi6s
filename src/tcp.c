#define _DEFAULT_SOURCE // htobe{16,32}()
#include <string.h>
#include <endian.h>

#include "tcp.h"
#include "rawsock.h"

#define PSEUDO_HEADER_SIZE 40

// pseudo IPv6 header utilized in checksumming
struct pseudo_header {
	uint8_t src[16];
	uint8_t dest[16];
	uint32_t len;
	uint8_t zero[3];
	uint8_t ipproto;
} __attribute__((packed));

static uint16_t chksum(const uint16_t *p, int n);
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
	// TODO: avoid copying stuff
	uint8_t _Alignas(uint16_t) tmp[PSEUDO_HEADER_SIZE + TCP_HEADER_SIZE];
	struct pseudo_header *ph = (struct pseudo_header*) tmp;

	pkt->csum = 0;
	memcpy(&tmp[PSEUDO_HEADER_SIZE], pkt, TCP_HEADER_SIZE);
	memcpy(ph->src, ipf->src, 16);
	memcpy(ph->dest, ipf->dest, 16);
	ph->len = htobe32(TCP_HEADER_SIZE);
	memset(ph->zero, 0, 3);
	ph->ipproto = 0x06; // IPPROTO_TCP

	pkt->csum = chksum((uint16_t*) tmp, sizeof(tmp));
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

static uint16_t chksum(const uint16_t *p, int n)
{
	register uint32_t sum;

	sum = 0;
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
