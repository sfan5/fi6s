#define _GNU_SOURCE
#include <string.h>

#include "banner.h"

const char *banner_get_query(int port, unsigned int *len)
{
	static const char http[] =
		"GET / HTTP/1.0\r\n"
		"Accept: */*\r\n"
		"User-Agent: TEST\r\n"
		"\r\n"
	;

	switch(port) {
		case 22:
			*len = 0;
			return "";
		case 80:
			*len = strlen(http);
			return http;
		default:
			return NULL;
	}
}

void banner_postprocess(int port, char *banner, unsigned int *len)
{
	switch(port) {
		case 22: {
			// cut off after identification string or first NUL
			char *end;
			end = (char*) memmem(banner, *len, "\r\n", 2);
			if(!end)
				end = (char*) memchr(banner, 0, *len);
			if(end)
				*len = end - banner;
			break;
		}
		case 80: {
			// cut off after headers
			char *end = (char*) memmem(banner, *len, "\r\n\r\n", 4);
			if(!end)
				end = (char*) memmem(banner, *len, "\n\n", 2);
			if(end)
				*len = end - banner;
			break;
		}
	}
}
