// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#define _DEFAULT_SOURCE // htobe16, htobe32
#include <string.h>
#include <assert.h>
#include "os-endian.h"

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

	static_assert(sizeof(ph) == PSEUDO_HEADER_SIZE, "incorrect PSEUDO_HEADER_SIZE");
	static_assert(sizeof(*pkt) == ICMP_HEADER_SIZE, "incorrect ICMP_HEADER_SIZE");

	uint32_t csum = CHKSUM_INITIAL;
	csum = chksum(csum, ipf->src, 16); // ph->src
	csum = chksum(csum, ipf->dest, 16); // ph->dest
	csum = chksum(csum, &ph.len, 8); // rest of ph
	pkt->csum = 0;
	pkt->csum = chksum_final(csum, pkt, ICMP_HEADER_SIZE + dlen); // packet contents + data
}
