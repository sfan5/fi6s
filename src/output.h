// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

enum {
	OUTPUT_STATUS_OPEN = 0,
	OUTPUT_STATUS_CLOSED,
	OUTPUT_STATUS_UP,
};

enum {
	OUTPUT_PROTO_TCP = 0,
	OUTPUT_PROTO_UDP,
	OUTPUT_PROTO_ICMP,
};

struct outputdef {
	void (*begin)(FILE *);
	void (*output_status)(FILE *, uint64_t /*ts*/, const uint8_t * /*addr*/, int /*proto*/, uint16_t /*port*/, uint8_t /*ttl*/, int /*status*/);
	void (*output_banner)(FILE *, uint64_t /*ts*/, const uint8_t * /*addr*/, int /*proto*/, uint16_t /*port*/, const char * /*banner*/, uint32_t /*bannerlen*/);
	void (*end)(FILE *);
	bool raw;
};

extern const struct outputdef output_list;
extern const struct outputdef output_json;
extern const struct outputdef output_binary;

/* INTERNAL */

#define OUTPUT_SCRATCH_BUFFER_SIZE 32000
struct obuf;

// Returns a thread-local scratch buffer
struct obuf output_get_scratch_buf(void);
