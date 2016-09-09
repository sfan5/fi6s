#ifndef _SCAN_H
#define _SCAN_H

#include <stdint.h>

struct ports;

void scan_settings(const uint8_t *source_addr, int source_port, const struct ports *ports);
int scan_main(const char *interface, int quiet);

#endif // _SCAN_H
