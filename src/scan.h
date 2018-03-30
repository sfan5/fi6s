#ifndef _SCAN_H
#define _SCAN_H

#include <stdio.h>
#include <stdint.h>

struct outputdef;
struct ports;

#define STATS_INTERVAL   1000 // ms
#define FINISH_WAIT_TIME 5    // s
#define BANNER_TIMEOUT   2500 // ms
#define FIRST_SEQNUM 0xf0000000

void scan_settings(
	const uint8_t *source_addr, int source_port,
	const struct ports *ports, int max_rate,
	int show_closed, int banners,
	FILE *outfile, const struct outputdef *outdef);
int scan_main(const char *interface, int quiet);

int scan_responder_init(FILE *outfile, const struct outputdef *outdef, uint16_t source_port);
void scan_responder_process(uint64_t ts, int len, const uint8_t *rpacket);
void scan_responder_finish();

#endif // _SCAN_H
