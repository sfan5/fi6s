// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#define _DEFAULT_SOURCE // htobe16, htobe32
#include <string.h>
#include <assert.h>
#include "os-endian.h"

#include "udp.h"
#include "util.h"
#include "rawsock.h"

void udp_modify(struct udp_header *pkt, int srcport, int dstport)
{
	pkt->srcport = htobe16(srcport & 0xffff);
	pkt->dstport = htobe16(dstport & 0xffff);
}

void udp_modify2(struct udp_header *pkt, uint16_t dlen)
{
	pkt->len = htobe16(UDP_HEADER_SIZE + dlen);
}

void udp_checksum(const struct frame_ip *ipf, struct udp_header *pkt, uint16_t dlen)
{
	_Alignas(uint16_t) struct pseudo_header ph = {
		.len = htobe32(UDP_HEADER_SIZE + dlen),
		.zero = {0},
		.ipproto = 0x11, // IPPROTO_UDP
	};

	static_assert(sizeof(ph) == PSEUDO_HEADER_SIZE, "incorrect PSEUDO_HEADER_SIZE");
	static_assert(sizeof(*pkt) == UDP_HEADER_SIZE,  "incorrect UDP_HEADER_SIZE");

	uint32_t csum = CHKSUM_INITIAL;
	csum = chksum(csum, ipf->src, 16); // ph->src
	csum = chksum(csum, ipf->dest, 16); // ph->dest
	csum = chksum(csum, &ph.len, 8); // rest of ph
	pkt->csum = 0;
	pkt->csum = chksum_final(csum, pkt, UDP_HEADER_SIZE + dlen); // packet contents + data
}

void udp_decode(const struct udp_header *pkt, int *srcport, int *dstport)
{
	if(srcport)
		*srcport = be16toh(pkt->srcport);
	if(dstport)
		*dstport = be16toh(pkt->dstport);
}

