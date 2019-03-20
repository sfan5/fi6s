#define _DEFAULT_SOURCE // htobe16, htobe32
#include <string.h>
#include <endian.h>

#include "icmp.h"
#include "util.h"
#include "rawsock.h"

void icmp_checksum(const struct frame_ip *ipf, struct icmp_header *pkt, uint16_t dlen)
{
	_Alignas(uint16_t) struct pseudo_header ph = {
		.len = htobe32(ICMP_HEADER_SIZE + dlen),
		.zero = {0},
		.ipproto = 0x3a, // IPPROTO_ICMPV6
	};
	uint32_t csum = CHKSUM_INITIAL;

	chksum(&csum, (uint16_t*) ipf->src, 16); // ph->src
	chksum(&csum, (uint16_t*) ipf->dest, 16); // ph->dest
	chksum(&csum, (uint16_t*) &ph.len, 8); // rest of ph
	pkt->csum = 0;
	pkt->csum = chksum_final(csum, (uint16_t*) pkt, ICMP_HEADER_SIZE + dlen); // packet contents + data
}
