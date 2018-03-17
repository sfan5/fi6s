#ifndef _BANNER_H
#define _BANNER_H

#include <stdint.h>

#define BANNER_QUERY_MAX_LENGTH 256
const char *banner_get_query(int port, unsigned int *len);
void banner_postprocess(int port, char *data, unsigned int *len);

#endif // _BANNER_H
