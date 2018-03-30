#ifndef _BANNER_H
#define _BANNER_H

#include <stdint.h>

#define BANNER_QUERY_MAX_LENGTH 1024
#define BANNER_MAX_LENGTH 4096

const char *banner_service_type(int port);
const char *banner_get_query(int port, unsigned int *len);
void banner_postprocess(int port, char *data, unsigned int *len);

#endif // _BANNER_H
