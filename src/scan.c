// fi6s
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2016 sfan5 <sfan5@live.de>

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h> // rand()
#include <stdbool.h>
#include <string.h>
#include <unistd.h> // usleep()
#include <limits.h>
#include <assert.h>
#include <stdatomic.h>
#include <pthread.h>

#include "scan.h"
#include "output.h"
#include "target.h"
#include "util.h"
#include "rawsock.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "banner.h"

enum {
	SEND_FINISHED 	  = (1 << 0),
	ERROR_SEND_THREAD = (1 << 1),
	ERROR_RECV_THREAD = (1 << 2),
};

static uint8_t source_addr[16];
static int source_port;
//
static struct ports ports;
static unsigned int max_rate;
static int show_closed, banners;
static uint8_t ip_type;
//
static FILE *outfile;
static struct outputdef outdef;

static uint32_t scan_randomness;
static atomic_uint pkts_sent, pkts_recv;
static atomic_uchar status_bits;

static inline int source_port_rand(void);
static void *send_thread_tcp(void *unused);
static void *send_thread_udp(void *unused);
static void *send_thread_icmp(void *unused);

static void *recv_thread(void *unused);
static void recv_handler(uint64_t ts, int len, const uint8_t *packet);
static void recv_handler_tcp(uint64_t ts, int len, const uint8_t *packet, const uint8_t *csrcaddr);
static void recv_handler_udp(uint64_t ts, int len, const uint8_t *packet, const uint8_t *csrcaddr);
static void recv_handler_icmp(uint64_t ts, int len, const uint8_t *packet, const uint8_t *csrcaddr);

#if ATOMIC_INT_LOCK_FREE != 2
#warning Non lock-free atomic types will severely affect performance.
#endif

#define RATE_CONTROL() do { \
	if(atomic_fetch_add(&pkts_sent, 1) >= max_rate) { \
		do usleep(1000); while(atomic_load(&pkts_sent) != 0); \
	} \
	} while(0)

/****/

void scan_set_general(const struct ports *_ports, int _max_rate, int _show_closed, int _banners)
{
	memcpy(&ports, _ports, sizeof(struct ports));
	max_rate = _max_rate < 0 ? UINT_MAX : _max_rate - 1;
	show_closed = _show_closed;
	banners = _banners;
}

void scan_set_network(const uint8_t *_source_addr, int _source_port, uint8_t _ip_type)
{
	memcpy(source_addr, _source_addr, 16);
	source_port = _source_port;
	ip_type = _ip_type;
}

void scan_set_output(FILE *_outfile, const struct outputdef *_outdef)
{
	outfile = _outfile;
	assert(_outdef);
	memcpy(&outdef, _outdef, sizeof(struct outputdef));
}

int scan_main(const char *interface, int quiet)
{
	if(rawsock_open(interface, 65535) < 0)
		return -1;
	scan_randomness = rand64();
	atomic_store(&pkts_sent, 0);
	atomic_store(&pkts_recv, 0);
	atomic_store(&status_bits, 0);
	if(banners && ip_type == IP_TYPE_TCP) {
		if(scan_responder_init(outfile, &outdef, source_port, scan_randomness) < 0)
			goto err;
	}
	if(!banners && ip_type == IP_TYPE_UDP)
		log_warning("UDP scans don't make sense without banners enabled.");
	if(banners && ip_type == IP_TYPE_ICMPV6)
		log_warning("Enabling banners is a no-op for ICMP scans.");

	// Set capture filters
	int fflags = RAWSOCK_FILTER_IPTYPE | RAWSOCK_FILTER_DSTADDR;
	if(source_port != -1 && ip_type != IP_TYPE_ICMPV6)
		fflags |= RAWSOCK_FILTER_DSTPORT;
	if(rawsock_setfilter(fflags, ip_type, source_addr, source_port) < 0)
		goto err;

	// Write output file header
	outdef.begin(outfile);

	// Start threads
	pthread_t tr, ts;
	if(pthread_create(&tr, NULL, recv_thread, NULL) < 0)
		goto err;
	pthread_detach(tr);
	do {
		int r;
		if(ip_type == IP_TYPE_TCP)
			r = pthread_create(&ts, NULL, send_thread_tcp, NULL);
		else if(ip_type == IP_TYPE_UDP)
			r = pthread_create(&ts, NULL, send_thread_udp, NULL);
		else // IP_TYPE_ICMPV6
			r = pthread_create(&ts, NULL, send_thread_icmp, NULL);
		if(r < 0)
			goto err;
	} while(0);
	pthread_detach(ts);

	// Stats & progress watching
	unsigned char cur_status = 0;
	while(1) {
		unsigned int cur_sent, cur_recv;
		// (used for rate control)
		cur_sent = atomic_exchange(&pkts_sent, 0);
		cur_recv = atomic_exchange(&pkts_recv, 0);
		if(!quiet) {
			float progress = target_gen_progress();
			unsigned int tcp_sent = 0;
			char tmp[10] = {'?', '?', '?', 0};
			if(progress >= 0.0f)
				snprintf(tmp, sizeof(tmp), "%3d", (int) (progress*100));
			if(banners && ip_type == IP_TYPE_TCP) {
				scan_responder_stats(&tcp_sent);
				fprintf(stderr, "snt:%5u rcv:%5u tcp:%5u p:%s%% \r", cur_sent, cur_recv, tcp_sent, tmp);
			} else {
				fprintf(stderr, "snt:%5u rcv:%5u p:%s%% \r", cur_sent, cur_recv, tmp);
			}
		}
		cur_status = atomic_load(&status_bits);
		if(cur_status)
			break;

		usleep(STATS_INTERVAL * 1000);
	}
	cur_status &= ~SEND_FINISHED; // leave only error bits

	// Wait for the last packets to arrive
	fputs("\n", stderr);
	if(!cur_status) {
		static_assert(FINISH_WAIT_TIME * 1000 > BANNER_TIMEOUT, "");
		fprintf(stderr, "Waiting %d more seconds...\n", FINISH_WAIT_TIME);
		usleep(FINISH_WAIT_TIME * 1000 * 1000);
	} else {
		fprintf(stderr, "Errors were encountered.\n");
		// FIXME: missing a way to abort the scan thread
	}
	rawsock_breakloop();
	if(banners && ip_type == IP_TYPE_TCP)
		scan_responder_finish();
	if(!quiet && !cur_status) {
		unsigned int cur_recv = atomic_exchange(&pkts_recv, 0);
		unsigned int tcp_sent = 0;
		if(banners && ip_type == IP_TYPE_TCP) {
			scan_responder_stats(&tcp_sent);
			fprintf(stderr, "rcv:%5u tcp:%5u\n", cur_recv, tcp_sent);
		} else {
			fprintf(stderr, "rcv:%5u\n", cur_recv);
		}
	}

	// Write output file footer
	outdef.end(outfile);

	int r = 0;
ret:
	rawsock_close();
	return r;
err:
	r = 1;
	goto ret;
}

static bool calc_bps(char *dst, unsigned int dstsize, uint64_t m1, uint64_t m2)
{
	uint64_t bps;
#if __has_builtin(__builtin_mul_overflow)
	if(__builtin_mul_overflow(m1, m2, &bps))
		return false;
#else
	bps = m1 * m2;
	if(bps < m1 || bps < m2)
		return false;
#endif
	uint32_t mbit = bps >> 17; // == bps * 8 / 1024 / 1024
	if(mbit > 1024) {
		snprintf(dst, dstsize, "%.1f Gbit/s", mbit / 1024.0f);
	} else {
		snprintf(dst, dstsize, "%d Mbit/s", (int)mbit);
	}
	return true;
}

void scan_print_summary(const struct ports *ports, int max_rate, int banners, uint8_t ip_type)
{
	unsigned int payload_min = 9999, payload_max = 0;
	if(ip_type == IP_TYPE_TCP) {
		payload_min = payload_max = TCP_HEADER_SIZE;
	} else if(ip_type == IP_TYPE_UDP && !banners) {
		payload_min = payload_max = UDP_HEADER_SIZE;
	} else if(ip_type == IP_TYPE_UDP) {
		// Need to know actual ports to know payload size
		if(!validate_ports(ports))
			return;
		struct ports_iter it;
		ports_iter_begin(ports, &it);
		while(ports_iter_next(&it) == 1) {
			unsigned int len = 0;
			banner_get_query(IP_TYPE_UDP, it.val, &len);
			len += UDP_HEADER_SIZE;
			if(len < payload_min)
				payload_min = len;
			if(len > payload_max)
				payload_max = len;
		}
	} else if(ip_type == IP_TYPE_ICMPV6) {
		payload_min = payload_max = ICMP_HEADER_SIZE;
	}
	payload_min += FRAME_ETH_SIZE + FRAME_IP_SIZE;
	payload_max += FRAME_ETH_SIZE + FRAME_IP_SIZE;

	if(payload_min == payload_max) {
		printf("Scanning will send packets with %u octets (incl. Ethernet and IP headers).\n",
			payload_min);
	} else {
		printf("Scanning will send packets with %u to %u octets (incl. Ethernet and IP headers).\n",
			payload_min, payload_max);
	}

	if(max_rate == -1)
		return;

	char buf[20] = {0}, buf2[20] = {0};
	calc_bps(buf, sizeof(buf), payload_min, max_rate);
	if(payload_min == payload_max) {
		printf("The scan is expected to use %s of bandwidth.\n", buf);
	} else {
		calc_bps(buf2, sizeof(buf2), payload_max, max_rate);
		printf("The scan is expected to use %s to %s of bandwidth.\n", buf, buf2);
	}
}

/****/

static void *send_thread_tcp(void *unused)
{
	uint8_t _Alignas(uint32_t) packet[FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE];
	uint8_t dstaddr[16];
	struct ports_iter it;

	(void) unused;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	set_thread_name("send");

	rawsock_eth_prepare(ETH_FRAME(packet), ETH_TYPE_IPV6);
	rawsock_ip_prepare(IP_FRAME(packet), IP_TYPE_TCP);
	if(target_gen_next(dstaddr) < 0)
		goto err;
	rawsock_ip_modify(IP_FRAME(packet), TCP_HEADER_SIZE, dstaddr);
	tcp_prepare(TCP_HEADER(packet));
	tcp_make_syn(TCP_HEADER(packet), tcp_first_seqnum(scan_randomness));
	ports_iter_begin(&ports, &it);

	while(1) {
		// Next port number (or target if ports exhausted)
		if(ports_iter_next(&it) == 0) {
			if(target_gen_next(dstaddr) < 0)
				break; // no more targets
			rawsock_ip_modify(IP_FRAME(packet), TCP_HEADER_SIZE, dstaddr);
			ports_iter_begin(NULL, &it);
			continue;
		}

		tcp_modify(TCP_HEADER(packet), source_port==-1?source_port_rand():source_port, it.val);
		tcp_checksum(IP_FRAME(packet), TCP_HEADER(packet), 0);
		rawsock_send(packet, sizeof(packet));

		RATE_CONTROL();
	}

	atomic_fetch_or(&status_bits, SEND_FINISHED);
	return NULL;
err:
	atomic_fetch_or(&status_bits, ERROR_SEND_THREAD);
	return NULL;
}

static void *send_thread_udp(void *unused)
{
	uint8_t _Alignas(uint32_t) packet[FRAME_ETH_SIZE + FRAME_IP_SIZE + UDP_HEADER_SIZE + BANNER_QUERY_MAX_LENGTH];
	uint8_t dstaddr[16];
	struct ports_iter it;

	(void) unused;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	set_thread_name("send");

	rawsock_eth_prepare(ETH_FRAME(packet), ETH_TYPE_IPV6);
	rawsock_ip_prepare(IP_FRAME(packet), IP_TYPE_UDP);
	if(target_gen_next(dstaddr) < 0)
		goto err;
	if(!banners) {
		rawsock_ip_modify(IP_FRAME(packet), UDP_HEADER_SIZE, dstaddr);
		udp_modify2(UDP_HEADER(packet), 0); // we send empty packets
	}
	ports_iter_begin(&ports, &it);

	while(1) {
		// Next port number (or target if ports exhausted)
		if(ports_iter_next(&it) == 0) {
			if(target_gen_next(dstaddr) < 0)
				break; // no more targets
			if(!banners)
				rawsock_ip_modify(IP_FRAME(packet), UDP_HEADER_SIZE, dstaddr);
			ports_iter_begin(NULL, &it);
			continue;
		}

		uint16_t dstport = it.val;
		udp_modify(UDP_HEADER(packet), source_port==-1?source_port_rand():source_port, dstport);
		unsigned int dlen = 0;
		if(banners) {
			const char *payload = banner_get_query(IP_TYPE_UDP, dstport, &dlen);
			if(payload && dlen > 0)
				memcpy(UDP_DATA(packet), payload, dlen);
			rawsock_ip_modify(IP_FRAME(packet), UDP_HEADER_SIZE + dlen, dstaddr);
			udp_modify2(UDP_HEADER(packet), dlen);
		}

		udp_checksum(IP_FRAME(packet), UDP_HEADER(packet), dlen);
		rawsock_send(packet, FRAME_ETH_SIZE + FRAME_IP_SIZE + UDP_HEADER_SIZE + dlen);

		RATE_CONTROL();
	}

	atomic_fetch_or(&status_bits, SEND_FINISHED);
	return NULL;
err:
	atomic_fetch_or(&status_bits, ERROR_SEND_THREAD);
	return NULL;
}

static void *send_thread_icmp(void *unused)
{
	uint8_t _Alignas(uint32_t) packet[FRAME_ETH_SIZE + FRAME_IP_SIZE + ICMP_HEADER_SIZE];
	uint8_t dstaddr[16];

	(void) unused;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	set_thread_name("send");

	rawsock_eth_prepare(ETH_FRAME(packet), ETH_TYPE_IPV6);
	rawsock_ip_prepare(IP_FRAME(packet), IP_TYPE_ICMPV6);
	if(target_gen_next(dstaddr) < 0)
		goto err;
	rawsock_ip_modify(IP_FRAME(packet), ICMP_HEADER_SIZE, dstaddr);
	ICMP_HEADER(packet)->type = 128; // Echo Request
	ICMP_HEADER(packet)->code = 0;
	ICMP_HEADER(packet)->body32 = scan_randomness;

	while(1) {
		icmp_checksum(IP_FRAME(packet), ICMP_HEADER(packet), 0);
		rawsock_send(packet, sizeof(packet));

		RATE_CONTROL();

		// Next target
		if(target_gen_next(dstaddr) < 0)
			break;
		rawsock_ip_modify(IP_FRAME(packet), ICMP_HEADER_SIZE, dstaddr);
	}

	atomic_fetch_or(&status_bits, SEND_FINISHED);
	return NULL;
err:
	atomic_fetch_or(&status_bits, ERROR_SEND_THREAD);
	return NULL;
}

/****/

static void *recv_thread(void *unused)
{
	(void) unused;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	set_thread_name("recv");

	int r = rawsock_loop(recv_handler);
	if(r < 0)
		atomic_fetch_or(&status_bits, ERROR_RECV_THREAD);
	return NULL;
}

static void recv_handler(uint64_t ts, int len, const uint8_t *packet)
{
	int v;
	const uint8_t *csrcaddr;

	atomic_fetch_add(&pkts_recv, 1);

	// decode
	if(rawsock_has_ethernet_headers()) {
		if(len < FRAME_ETH_SIZE)
			goto perr;
		rawsock_eth_decode(ETH_FRAME(packet), &v);
	} else {
		v = ETH_TYPE_IPV6;
		packet -= FRAME_ETH_SIZE; // FIXME: convenient but horrible hack
		len += FRAME_ETH_SIZE;
	}
	if(v != ETH_TYPE_IPV6 || len < FRAME_ETH_SIZE + FRAME_IP_SIZE)
		goto perr;
	rawsock_ip_decode(IP_FRAME(packet), &v, NULL, NULL, &csrcaddr, NULL);
	if(v != ip_type) // is this the ip type we expect?
		goto perr;

	// handle
	if(ip_type == IP_TYPE_TCP)
		recv_handler_tcp(ts, len, packet, csrcaddr);
	else if(ip_type == IP_TYPE_UDP)
		recv_handler_udp(ts, len, packet, csrcaddr);
	else // IP_TYPE_ICMPV6
		recv_handler_icmp(ts, len, packet, csrcaddr);

	return;
	perr: ;
#ifndef NDEBUG
	log_raw("%s: errored packet of length %d", __func__, len);
#endif
}

static void recv_handler_tcp(uint64_t ts, int len, const uint8_t *packet, const uint8_t *csrcaddr)
{
	if(len < FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE)
		goto perr;

	// Output stuff
	if(TCP_HEADER(packet)->f_ack && (TCP_HEADER(packet)->f_syn || TCP_HEADER(packet)->f_rst)) {
		int v, v2;
		tcp_decode(TCP_HEADER(packet), &v, NULL);
		rawsock_ip_decode(IP_FRAME(packet), NULL, NULL, &v2, NULL, NULL);
		int st = TCP_HEADER(packet)->f_syn ? OUTPUT_STATUS_OPEN : OUTPUT_STATUS_CLOSED;
		if(outdef.raw || show_closed || TCP_HEADER(packet)->f_syn)
			outdef.output_status(outfile, ts, csrcaddr, OUTPUT_PROTO_TCP, v, v2, st);
	}
	// Pass packet to responder
	if(banners)
		scan_responder_process(ts, len, packet);

	return;
	perr: ;
#ifndef NDEBUG
	log_raw("%s: errored packet of length %d", __func__, len);
#endif
}

static void recv_handler_udp(uint64_t ts, int len, const uint8_t *packet, const uint8_t *csrcaddr)
{
	if(len < FRAME_ETH_SIZE + FRAME_IP_SIZE + UDP_HEADER_SIZE)
		goto perr;

	int v;
	udp_decode(UDP_HEADER(packet), &v, NULL);
	if(!banners) {
		// We got an answer, that's already noteworthy enough
		int v2;
		rawsock_ip_decode(IP_FRAME(packet), NULL, NULL, &v2, NULL, NULL);
		outdef.output_status(outfile, ts, csrcaddr, OUTPUT_PROTO_UDP, v, v2, OUTPUT_STATUS_OPEN);
		return;
	}

	uint32_t plen = len - (FRAME_ETH_SIZE + FRAME_IP_SIZE + UDP_HEADER_SIZE);
	if(plen == 0)
		return;
	else if(plen > BANNER_MAX_LENGTH)
		plen = BANNER_MAX_LENGTH;
	char temp[BANNER_MAX_LENGTH];
	memcpy(temp, UDP_DATA(packet), plen);
	if(!outdef.raw)
		banner_postprocess(IP_TYPE_UDP, v, temp, &plen);
	outdef.output_banner(outfile, ts, csrcaddr, OUTPUT_PROTO_UDP, v, temp, plen);

	return;
	perr: ;
#ifndef NDEBUG
	log_raw("%s: errored packet of length %d", __func__, len);
#endif
}

static void recv_handler_icmp(uint64_t ts, int len, const uint8_t *packet, const uint8_t *csrcaddr)
{
	const int minlen = FRAME_ETH_SIZE + FRAME_IP_SIZE + ICMP_HEADER_SIZE;
	if(len < minlen)
		goto perr;
	else if(len != minlen)
		return;

	if(ICMP_HEADER(packet)->type != 129) // Echo Reply
		return;
	if(ICMP_HEADER(packet)->body32 != scan_randomness)
		return;

	int v2;
	rawsock_ip_decode(IP_FRAME(packet), NULL, NULL, &v2, NULL, NULL);
	outdef.output_status(outfile, ts, csrcaddr, OUTPUT_PROTO_ICMP, 0, v2, OUTPUT_STATUS_UP);

	return;
	perr: ;
#ifndef NDEBUG
	log_raw("%s: errored packet of length %d", __func__, len);
#endif
}

/****/

static inline int source_port_rand(void)
{
	int v;
	v = rand() & 0xffff; // random 16-bit number
	if(v < 16384)
		v = 16384;
	return v;
}
