#include <stdio.h>
// pcap.h breaks if you don't define these:
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
#include <pcap.h>

#include "rawsock.h"

int rawsock_getdev(char **dev)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	*dev = pcap_lookupdev(errbuf);
	if(!*dev)
		fprintf(stderr, "Couldn't determine default interface: %s\n", errbuf);
	return *dev ? 0 : -1;
}

int rawsock_getgw(const char *dev, uint8_t *mac)
{

}
