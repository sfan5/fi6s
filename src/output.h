#ifndef _OUTPUT_H
#define _OUTPUT_H

#include <stdio.h>
#include <stdint.h>

enum {
	OUTPUT_STATUS_OPEN = 0,
	OUTPUT_STATUS_CLOSED,
};

struct outputdef {
	void (*begin)(FILE *);
	void (*output_status)(FILE *, uint64_t /*ts*/, const uint8_t * /*addr*/, uint16_t /*port*/, uint8_t /* ttl */, int /*status*/);
	void (*end)(FILE *);
};

const struct outputdef output_list;
const struct outputdef output_json;
const struct outputdef output_binary;

#endif // _OUTPUT_H
