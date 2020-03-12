#ifndef _BANNER_H
#define _BANNER_H

#include <stdint.h>

#define BANNER_QUERY_MAX_LENGTH 1024
#define BANNER_MAX_LENGTH 4096

typedef unsigned char uchar;

void banner_print_service_types();
const char *banner_service_type(uint8_t ip_type, int port);
const char *banner_get_query(uint8_t ip_type, int port, unsigned int *len);
// The buffer passed into this must be writable and hold at least BANNER_MAX_LENGTH bytes
void banner_postprocess(uint8_t ip_type, int port, char *data, unsigned int *len);

uint8_t banner_outproto2ip_type(int output_proto); // helper used by output modules

#endif // _BANNER_H
