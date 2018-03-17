#ifndef _SCAN_H
#define _SCAN_H

#include <stdio.h>
#include <stdint.h>

#include "output.h"
struct ports;

#define STATS_INTERVAL 1000 // ms
#define FINISH_WAIT_TIME 5 // s

void scan_settings(
	const uint8_t *source_addr, int source_port,
	const struct ports *ports, int max_rate,
	int show_closed, int banners,
	FILE *outfile, const struct outputdef *outdef);
int scan_main(const char *interface, int quiet);

#endif // _SCAN_H
