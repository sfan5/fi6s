// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#pragma once
#include <stdint.h>

#define ICMP_HEADER_SIZE 8

struct icmp_header {
	uint8_t type; // Type
	uint8_t code; // Code
	uint16_t csum; // Checksum
	union {
		uint8_t body8[4];
		uint16_t body16[2];
		uint32_t body32;
	}; // Message Body
} __attribute__((packed));
struct frame_ip;

void icmp_checksum(const struct frame_ip *ipf, struct icmp_header *pkt, uint16_t dlen);
