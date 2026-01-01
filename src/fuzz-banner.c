#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "banner.h"
#include "rawsock.h"

#ifndef __AFL_FUZZ_TESTCASE_LEN
	#define OUTSIDE_AFL
	static ssize_t fuzz_len;
	#define __AFL_FUZZ_TESTCASE_LEN fuzz_len
	static unsigned char fuzz_buf[1024000];
	#define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
	#define __AFL_FUZZ_INIT() void sync(void)
	#define __AFL_LOOP(x) ((fuzz_len = read(fuzz_fd, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
#endif

__AFL_FUZZ_INIT();

int main(int argc, char *argv[])
{
	char tmp[BANNER_MAX_LENGTH] = {0};
	uint8_t ip_type;
	int port;

	if(argc < 3)
		return 1;
	if(!strcmp(argv[1], "tcp"))
		ip_type = IP_TYPE_TCP;
	else if(!strcmp(argv[1], "udp"))
		ip_type = IP_TYPE_UDP;
	else
		return 1;
	port = atoi(argv[2]);
	if(port < 1 || port > 65535)
		return 1;

#ifdef OUTSIDE_AFL
	if(argc < 4) {
		const char *m = "missing input file\n";
		write(2, m, strlen(m));
		return 1;
	}
	int fuzz_fd = open(argv[3], O_RDONLY);
#endif

#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT();
#endif

	unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
	while(__AFL_LOOP(10000)) {
		int len = __AFL_FUZZ_TESTCASE_LEN;
		if(len < 1)
			continue;

		memcpy(tmp, buf, len);

		unsigned int outlen = len;
		banner_postprocess(ip_type, port, tmp, &outlen);
	}
	return 0;
}
