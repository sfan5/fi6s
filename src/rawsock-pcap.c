// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <stdatomic.h>
#include <pcap.h>

#include "rawsock.h"
#include "util.h"

static pcap_t *handle;
static pcap_dumper_t *dumper;
static int linktype;
static atomic_bool want_break;

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
			log_raw("Couldn't open pcap dumper: %s",
				handle ? pcap_geterr(handle) : "?");
		}
	} else {
		handle = pcap_open_live(dev, buffersize, 0, 150, errbuf);
	}
	if(!handle) {
		log_raw("Couldn't open pcap handle: %s", errbuf);
		return -1;
	}
	linktype = pcap_datalink(handle);
	if(linktype != DLT_EN10MB && linktype != DLT_RAW) {
		log_error("Interface does not provide Ethernet or IP headers.");
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

#define snprintf_append(buffer, fmt, ...) do { \
		unsigned int buffer_l = strlen(buffer); \
		if(buffer_l < sizeof(buffer)) \
			snprintf(&(buffer)[buffer_l], sizeof(buffer) - buffer_l, fmt, __VA_ARGS__); \
	} while(0)

int rawsock_setfilter(int flags, uint8_t iptype, const uint8_t *dstaddr, int dstport)
{
	char fstr[128];
	struct bpf_program fp;

	// reference: <https://www.tcpdump.org/manpages/pcap-filter.7.html>

	const char *proto = NULL;
	if(flags & RAWSOCK_FILTER_IPTYPE) {
		if(iptype == IP_TYPE_TCP)
			proto = "tcp";
		else if(iptype == IP_TYPE_UDP)
			proto = "udp";
		else if(iptype == IP_TYPE_ICMPV6)
			proto = "icmp6";
		else
			assert(false);
	}

	// As of 1.10.6 libpcap does not always seem to optimize checking the L3
	// protocol so that adding 'and dst port xxxx' to an expression that already
	// implies udp will result in an extra comparison against the protocol byte.
	// Using 'udp dst port xxxx' avoid this.
	if(proto && (flags & RAWSOCK_FILTER_DSTPORT))
		flags &= ~RAWSOCK_FILTER_IPTYPE;

	strncpy(fstr, "ip6", sizeof(fstr));
	if(flags & RAWSOCK_FILTER_IPTYPE) {
		snprintf_append(fstr, " and %s", proto);
	}
	// Also libpacp doesn't reorder the conditions so check the port first,
	// which is much more likely to produce an early-exit case.
	if(flags & RAWSOCK_FILTER_DSTPORT) {
		assert(dstport > 0);
		if(proto)
			snprintf_append(fstr, " and %s dst port %d", proto, dstport);
		else
			snprintf_append(fstr, " and dst port %d", dstport);
	}
	if(flags & RAWSOCK_FILTER_DSTADDR) {
		char tmp[IPV6_STRING_MAX];
		assert(dstaddr);
		ipv6_string(tmp, dstaddr);
		snprintf_append(fstr, " and dst %s", tmp);
	}

	if(pcap_compile(handle, &fp, fstr, 1, PCAP_NETMASK_UNKNOWN) == -1) {
		pcap_perror(handle, "pcap_compile");
		log_raw("Filter expression was \"%s\"", fstr);
		return -1;
	}
	log_debug("filter: \"%s\" (%d insns)", fstr, fp.bf_len);

	// can't set filter on dead handle
	if(!dumper) {
		int r = pcap_setfilter(handle, &fp);
		pcap_freecode(&fp);
		if(r != 0) {
			pcap_perror(handle, "pcap_setfilter");
			return -1;
		}
	} else {
		pcap_freecode(&fp);
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
	assert(func);
	atomic_store(&want_break, false);

	// pretend to loop if dead handle (dump mode)
	if(dumper) {
		do
			usleep(150*1000);
		while(!atomic_load(&want_break));
		return 0;
	}

	int r = pcap_loop(handle, -1, callback_fwd, (u_char*) (intptr_t) func);
	if(r == PCAP_ERROR_BREAK)
		r = 0;
	if(r != 0)
		pcap_perror(handle, "pcap_loop");
	return r;
}

void rawsock_breakloop(void)
{
	atomic_store(&want_break, true);
	// calling pcap_breakloop on a dead handle should be a a no-op, but
	// actually segfaults on libpcap 1.10.1 or older.
	if(!dumper) {
		pcap_breakloop(handle);
	}
}

int rawsock_send(const uint8_t *pkt, unsigned int size)
{
	if(!rawsock_has_ethernet_headers()) {
#ifndef NDEBUG
		if (size <= FRAME_ETH_SIZE) {
			log_raw("%s: underflow!", __func__);
			return -1;
		}
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
	((rawsock_callback) (intptr_t) user)(hdr->ts.tv_sec, hdr->caplen, pkt);
}
