// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "scan.h"
#include "util.h"
#include "output.h"
#include "binary.h"
#include "banner.h" // banner_postprocess
#include "rawsock.h" // IP_TYPE_{TCP,UDP}

static int show_closed, banners;
//
static FILE *outfile;
static struct outputdef outdef;

#define RECORD_MAX_DATA 64000 // must be >= BANNER_MAX_LENGTH

void scan_reader_set_general(int _show_closed, int _banners)
{
	show_closed = _show_closed;
	banners = _banners;
}

void scan_reader_set_output(FILE *_outfile, const struct outputdef *_outdef)
{
	outfile = _outfile;
	memcpy(&outdef, _outdef, sizeof(struct outputdef));
}

int scan_reader_main(FILE *infile)
{
	struct reader r;
	if(binary_read_header(&r, infile) < 0)
		return -1;

	char *databuf = calloc(1, RECORD_MAX_DATA);
	if(!databuf)
		return -1;

	bool any = false, b_only = true, c_only = true;

	outdef.begin(outfile);
	while(1) {
		struct rec_header h;
		int ret = binary_read_record(&r, &h);
		if(ret == -2)
			break;
		if(ret == -1) {
			log_error("Encountered invalid record header.");
			return -1;
		}
		any = true;

		int proto = h.proto_status >> 4, status = h.proto_status & 0xf;

		int has_data = h.size > sizeof(h);
		if(has_data) {
			uint32_t data_length = h.size - sizeof(h);
			if(data_length > RECORD_MAX_DATA) {
				log_error("Record has too much data (%" PRIu32 " > %d)", data_length, RECORD_MAX_DATA);
				return -1;
			}

			ret = binary_read_record_data(&r, databuf);
			if(ret == -1) {
				log_error("Record data truncated.");
				return -1;
			}

			if(!banners)
				continue;
			c_only = false;
			if(!outdef.raw) {
				uint8_t ip_type = proto == OUTPUT_PROTO_TCP ? IP_TYPE_TCP : IP_TYPE_UDP;
				banner_postprocess(ip_type, h.port, databuf, &data_length);
			}
			outdef.output_banner(outfile, h.timestamp, h.addr, proto, h.port, databuf, data_length);
		} else {
			bool show = outdef.raw || show_closed || status != OUTPUT_STATUS_CLOSED;
			b_only = false;
			c_only &= !show;
			if(show)
				outdef.output_status(outfile, h.timestamp, h.addr, proto, h.port, h.ttl, status);
		}
	}
	outdef.end(outfile);

	if(!any)
		log_raw("Note: the scan file was empty.");
	else if(!banners && b_only) // relevant for UDP
		log_raw("Note: the scan file wasn't empty, but all records were filtered. Try with --banners.");
	else if(c_only) // relevant for TCP
		log_raw("Note: the scan file wasn't empty, but all records were filtered. Try with --show-closed.");

	free(databuf);
	return 0;
}
