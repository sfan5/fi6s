#define _DEFAULT_SOURCE // htobe16, htobe32
#include <string.h>
#include <endian.h>

#include "tcp.h"
#include "util.h"
#include "rawsock.h"

static inline void reset_flags(struct tcp_header *pkt);

void tcp_prepare(struct tcp_header *pkt)
{
	pkt->seqnum = 0;
	pkt->acknum = 0;
	pkt->offset = TCP_HEADER_SIZE >> 2;
	pkt->reserved1 = 0;
	pkt->reserved2 = 0;
	pkt->winsz = htobe16(4096);
	pkt->urgptr = 0;
}

void tcp_modify(struct tcp_header *pkt, int srcport, int dstport)
{
	pkt->srcport = htobe16(srcport & 0xffff);
	pkt->dstport = htobe16(dstport & 0xffff);
}

void tcp_make_syn(struct tcp_header *pkt, uint32_t seqnum)
{
	reset_flags(pkt);
	pkt->f_syn = 1;
	pkt->seqnum = htobe32(seqnum);
}

void tcp_make_rst(struct tcp_header *pkt, uint32_t seqnum)
{
	reset_flags(pkt);
	pkt->f_rst = 1;
	pkt->seqnum = htobe32(seqnum);
}

void tcp_make_ack(struct tcp_header *pkt, uint32_t seqnum, uint32_t acknum)
{
	reset_flags(pkt);
	pkt->f_ack = 1;
	pkt->seqnum = htobe32(seqnum);
	pkt->acknum = htobe32(acknum);
}

void tcp_checksum(const struct frame_ip *ipf, struct tcp_header *pkt, uint16_t dlen)
{
	_Alignas(uint16_t) struct pseudo_header ph = {
		.len = htobe32(TCP_HEADER_SIZE + dlen),
		.zero = {0},
		.ipproto = 0x06, // IPPROTO_TCP
	};
	uint32_t csum = CHKSUM_INITIAL;

	chksum(&csum, (uint16_t*) ipf->src, 16); // ph->src
	chksum(&csum, (uint16_t*) ipf->dest, 16); // ph->dest
	chksum(&csum, (uint16_t*) &ph.len, 8); // rest of ph
	pkt->csum = 0;
	pkt->csum = chksum_final(csum, (uint16_t*) pkt, TCP_HEADER_SIZE + dlen); // packet contents + data
}

void tcp_decode_header(const struct tcp_header *pkt, unsigned int *data_offset)
{
	unsigned int hdrlen = pkt->offset << 2;
	if(hdrlen < TCP_HEADER_SIZE)
		hdrlen = TCP_HEADER_SIZE;
	*data_offset = hdrlen;
}

void tcp_decode(const struct tcp_header *pkt, int *srcport, int *dstport)
{
	if(srcport)
		*srcport = be16toh(pkt->srcport);
	if(dstport)
		*dstport = be16toh(pkt->dstport);
}

void tcp_decode2(const struct tcp_header *pkt, uint32_t *seqnum, uint32_t *acknum)
{
	if(seqnum)
		*seqnum = be32toh(pkt->seqnum);
	if(acknum)
		*acknum = be32toh(pkt->acknum);
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
