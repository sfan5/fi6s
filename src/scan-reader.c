#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "scan.h"
#include "output.h"
#include "binary.h"
#include "banner.h" // banner_postprocess
#include "rawsock.h" // IP_TYPE_{TCP,UDP}

static int show_closed, banners;
//
static FILE *outfile;
static struct outputdef outdef;

#define RECORD_MAX_DATA 65535 // must be >= BANNER_MAX_LENGTH

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
	if(binary_read_header(&r, infile) < 0) {
		fprintf(stderr, "Could not identify scan file header.\n");
		return -1;
	}

	outdef.begin(outfile);
	while(1) {
		struct rec_header h;
		int ret = binary_read_record(&r, &h);
		if(ret == -2)
			break;
		if(ret == -1) {
			fprintf(stderr, "Encountered invalid record header.\n");
			return -1;
		}

		int proto = h.proto_status >> 4, status = h.proto_status & 0xf;

		int has_data = h.size > sizeof(h);
		if(has_data) {
			uint32_t data_length = h.size - sizeof(h);
			if(data_length > RECORD_MAX_DATA) {
				fprintf(stderr, "Record has too much data (%" PRIu32 " > %d)\n", data_length, RECORD_MAX_DATA);
				return -1;
			}

			char data[RECORD_MAX_DATA];
			ret = binary_read_record_data(&r, data);
			if(ret == -1)
				return -1;

			if(!banners)
				continue;
			if(!outdef.raw) {
				uint8_t ip_type = proto == OUTPUT_PROTO_TCP ? IP_TYPE_TCP : IP_TYPE_UDP;
				banner_postprocess(ip_type, h.port, data, &data_length);
			}
			outdef.output_banner(outfile, h.timestamp, h.addr, proto, h.port, data, data_length);
		} else {
			if(outdef.raw || show_closed || status != OUTPUT_STATUS_CLOSED)
				outdef.output_status(outfile, h.timestamp, h.addr, proto, h.port, h.ttl, status);
		}
	}
	outdef.end(outfile);
	return 0;
}
