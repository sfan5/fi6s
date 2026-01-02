// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#pragma once
#include <stdint.h>

#define UDP_HEADER_SIZE 8

struct udp_header {
	uint16_t srcport; // Source port
	uint16_t dstport; // Destination port
	uint16_t len; // Packet length
	uint16_t csum; // Checksum
} __attribute__((packed));
struct frame_ip;

void udp_modify(struct udp_header *pkt, int srcport, int dstport);
void udp_modify2(struct udp_header *pkt, uint16_t dlen);
void udp_checksum(const struct frame_ip *ipf, struct udp_header *pkt, uint16_t dlen);

void udp_decode(const struct udp_header *pkt, int *srcport, int *dstport);
