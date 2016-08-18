#include <stdio.h>
typedef unsigned char u_char; // pcap.h breaks if you don't define these
typedef unsigned short u_short;
typedef unsigned int u_int;
#include <pcap.h>

#include "rawsock.h"

static pcap_t *handle;

int rawsock_open(const char *dev)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if(!dev) {
		dev = pcap_lookupdev(errbuf);
		if(!dev) {
			fprintf(stderr, "Couldn't determine default interface: %s\n", errbuf);
			return -1;
		}
		printf("Using default interface '%s'\n", dev);
	}
	handle = pcap_open_live(dev, 65535, 0, 1000, errbuf);
	if(!handle) {
		fprintf(stderr, "Couldn't open pcap handle: %s\n", errbuf);
		return -1;
	}

	return 0;
}

void rawsock_close(void)
{
	pcap_close(handle);
}
