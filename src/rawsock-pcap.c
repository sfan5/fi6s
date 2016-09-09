#include <stdio.h>
#include <stdint.h>
#include <string.h>
// pcap.h breaks if you don't define these:
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
#include <pcap.h>

#include "rawsock.h"
#include "util.h"

static pcap_t *handle;

static void callback_fwd(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int rawsock_open(const char *dev, int buffersize)
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
	handle = pcap_open_live(dev, buffersize, 0, 1000, errbuf);
	if(!handle) {
		fprintf(stderr, "Couldn't open pcap handle: %s\n", errbuf);
		return -1;
	}
	if(pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Selected interface does not provide Ethernet headers.\n");
		goto err;
	}
	pcap_setdirection(handle, PCAP_D_IN);

	return 0;
	err:
	pcap_close(handle);
	return -1;
}

#define snprintf_append(buffer, format, ...) do { \
		int __sl = strlen(buffer); \
		snprintf(&(buffer)[__sl], sizeof(buffer) - __sl - 1, format, __VA_ARGS__); \
	} while(0)

int rawsock_setfilter(int flags, uint8_t iptype, const uint8_t *dstaddr, uint16_t dstport)
{
	char fstr[128];
	struct bpf_program fp;

	strncpy(fstr, "ip6", sizeof(fstr));
	if(flags & RAWSOCK_FILTER_IPTYPE) {
		if(iptype != IP_TYPE_TCP && iptype != IP_TYPE_UDP)
			return -1;
		snprintf_append(fstr, " and %s", (iptype == IP_TYPE_TCP)?"tcp":"udp");
	}
	if(flags & RAWSOCK_FILTER_DSTADDR) {
		char tmp[IPV6_STRING_MAX];
		ipv6_string(tmp, dstaddr);
		snprintf_append(fstr, " and dst %s", tmp);
	}
	if(flags & RAWSOCK_FILTER_DSTPORT) {
		snprintf_append(fstr, " and dst port %d", dstport);
	}

	if(pcap_compile(handle, &fp, fstr, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Failed to compile filter expression: %s\n", pcap_geterr(handle));
		return -1;
	}
	if(pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Faile to install filter: %s\n", pcap_geterr(handle));
		return -1;
	}

	return 0;
}

int rawsock_sniff(uint64_t *ts, int *length, const uint8_t **pkt)
{
	struct pcap_pkthdr *hdr;
	int r;
	r = pcap_next_ex(handle, &hdr, pkt);
	if(r < 0)
		return -1;
	else if(r == 0)
		return 0;
	if(hdr->caplen < hdr->len)
		return -1;
	*ts = hdr->ts.tv_sec;
	*length = hdr->caplen;
	return 1;
}

int rawsock_loop(rawsock_callback func)
{
	int r = pcap_loop(handle, -1, callback_fwd, (u_char*) func);
	if(r == -2)
		r = 0;
	return r;
}

void rawsock_breakloop(void)
{
	pcap_breakloop(handle);
}

int rawsock_send(const uint8_t *pkt, int size)
{
	int r = pcap_sendpacket(handle, pkt, size);
#ifndef NDEBUG
	if(r == -1)
		pcap_perror(handle, "");
#endif
	return r;
}

void rawsock_close(void)
{
	pcap_close(handle);
}

static void callback_fwd(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	if(hdr->caplen < hdr->len)
		return;
	((rawsock_callback) user)(hdr->ts.tv_sec, hdr->caplen, pkt);
}
