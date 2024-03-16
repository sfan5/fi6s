#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>

#include "rawsock.h"
#include "util.h"

static pcap_t *handle;
static pcap_dumper_t *dumper;
static int linktype;
static bool want_break;

static void callback_fwd(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int rawsock_open(const char *dev, int buffersize)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if(!strncmp(dev, "dump:", 5)) {
		// we'll dump sent packets to a file and use a dead handle for capturing
		handle = pcap_open_dead(DLT_EN10MB, buffersize);
		if(!strcmp(dev + 5, "-"))
			dumper = pcap_dump_fopen(handle, stdout);
		else
			dumper = pcap_dump_open(handle, dev + 5);
		if(!dumper) {
			fprintf(stderr, "Couldn't open pcap dumper: %s\n",
				handle ? pcap_geterr(handle) : "?");
		}
	} else {
		handle = pcap_open_live(dev, buffersize, 0, 150, errbuf);
	}
	if(!handle) {
		fprintf(stderr, "Couldn't open pcap handle: %s\n", errbuf);
		return -1;
	}
	linktype = pcap_datalink(handle);
	if(linktype != DLT_EN10MB && linktype != DLT_RAW) {
		fprintf(stderr, "Selected interface does not provide Ethernet or IP headers.\n");
		goto err;
	}
	pcap_setdirection(handle, PCAP_D_IN);

	return 0;
	err:
	rawsock_close();
	return -1;
}

int rawsock_has_ethernet_headers(void)
{
	return linktype == DLT_EN10MB;
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
		char *tmp;
		if(iptype == IP_TYPE_TCP)
			tmp = "tcp";
		else if(iptype == IP_TYPE_UDP)
			tmp = "udp";
		else if(iptype == IP_TYPE_ICMPV6)
			tmp = "icmp6";
		else
			return -1;
		snprintf_append(fstr, " and %s", tmp);
	}
	if(flags & RAWSOCK_FILTER_DSTADDR) {
		char tmp[IPV6_STRING_MAX];
		ipv6_string(tmp, dstaddr);
		snprintf_append(fstr, " and dst %s", tmp);
	}
	if(flags & RAWSOCK_FILTER_DSTPORT) {
		snprintf_append(fstr, " and dst port %d", dstport);
	}

	//printf("pcap filter: %s\n", fstr);
	if(pcap_compile(handle, &fp, fstr, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Failed to compile filter expression: %s\n", pcap_geterr(handle));
		return -1;
	}
	// can't set filter on dead handle
	if(!dumper) {
		int r = pcap_setfilter(handle, &fp);
		pcap_freecode(&fp);
		if(r != 0) {
			fprintf(stderr, "Failed to install filter: %s\n", pcap_geterr(handle));
			return -1;
		}
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
	if(hdr->caplen < hdr->len) // truncated packet
		return -1;
	*ts = hdr->ts.tv_sec;
	*length = hdr->caplen;
	return 1;
}

int rawsock_loop(rawsock_callback func)
{
	want_break = false;

	// pretend to loop if dead handle (dump mode)
	if(dumper) {
		do
			usleep(150*1000);
		while(!want_break);
		return 0;
	}

	int r = pcap_loop(handle, -1, callback_fwd, (u_char*) func);
	if(r == PCAP_ERROR_BREAK)
		r = 0;
	if(r != 0)
		pcap_perror(handle, "pcap_loop");
	return r;
}

void rawsock_breakloop(void)
{
	want_break = true;
	// calling pcap_breakloop on a dead handle should be a a no-op, but
	// actually segfaults on libpcap 1.10.1 or older.
	if(!dumper) {
		pcap_breakloop(handle);
	}
}

int rawsock_send(const uint8_t *pkt, int size)
{
	if(!rawsock_has_ethernet_headers()) {
#ifndef NDEBUG
		if (size <= FRAME_ETH_SIZE)
			return -1;
#endif
		pkt = &pkt[FRAME_ETH_SIZE];
		size -= FRAME_ETH_SIZE;
	}

	if(dumper) {
		struct pcap_pkthdr h = {0};
		h.caplen = size;
		h.len = size;
		pcap_dump((u_char*) dumper, &h, pkt);
		return 0;
	}

	int r = pcap_sendpacket(handle, pkt, size);
#ifndef NDEBUG
	if(r == -1)
		pcap_perror(handle, "");
#endif
	return r;
}

void rawsock_close(void)
{
	if(dumper)
		pcap_dump_close(dumper);
	if(handle)
		pcap_close(handle);
}

static void callback_fwd(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt)
{
	if(hdr->caplen < hdr->len) // truncated
		return;
	((rawsock_callback) user)(hdr->ts.tv_sec, hdr->caplen, pkt);
}
