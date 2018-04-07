#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h> // rand()
#include <stdbool.h>
#include <string.h>
#include <unistd.h> // usleep()
#include <limits.h>
#include <stdatomic.h>
#include <pthread.h>

#include "scan.h"
#include "output.h"
#include "target.h"
#include "util.h"
#include "rawsock.h"
#include "tcp.h"
#include "udp.h"
#include "banner.h"

static uint8_t source_addr[16];
static int source_port;
//
static struct ports ports;
static int max_rate, show_closed, banners, udp;
//
static FILE *outfile;
static struct outputdef outdef;

static atomic_uint pkts_sent, pkts_recv;
static bool send_finished;

static inline int source_port_rand(void);
static void *send_thread(void *unused);
static void *send_thread_udp(void *unused);
static void *recv_thread(void *unused);
static void recv_handler(uint64_t ts, int len, const uint8_t *packet);

#if ATOMIC_INT_LOCK_FREE != 2
#warning Non lock-free atomic types will severely affect performance.
#endif

void scan_set_general(const struct ports *_ports, int _max_rate, int _show_closed, int _banners)
{
	memcpy(&ports, _ports, sizeof(struct ports));
	max_rate = _max_rate == -1 ? INT_MAX : _max_rate - 1;
	show_closed = _show_closed;
	banners = _banners;
}

void scan_set_network(const uint8_t *_source_addr, int _source_port, int _ip_type)
{
	memcpy(source_addr, _source_addr, 16);
	source_port = _source_port;
	udp = _ip_type == IP_TYPE_UDP;
}

void scan_set_output(FILE *_outfile, const struct outputdef *_outdef)
{
	outfile = _outfile;
	memcpy(&outdef, _outdef, sizeof(struct outputdef));
}

int scan_main(const char *interface, int quiet)
{
	if(rawsock_open(interface, 65536) < 0)
		return -1;
	setvbuf(outfile, NULL, _IOLBF, 16384);
	atomic_store(&pkts_sent, 0);
	atomic_store(&pkts_recv, 0);
	send_finished = false;
	if(banners) {
		if(scan_responder_init(outfile, &outdef, source_port) < 0)
			goto err;
		if(!udp) {
			// pick some high enough number if rate isn't limited
			int count = max_rate == INT_MAX ? 65536 : (max_rate * BANNER_TIMEOUT / 1000);
			if(tcp_state_init(count) < 0)
				goto err;
		}
	}
	if(!banners && udp && !quiet)
		fprintf(stderr, "Warning: UDP scans don't really make sense without banners.\n");

	// Set capture filters
	int fflags = RAWSOCK_FILTER_IPTYPE | RAWSOCK_FILTER_DSTADDR;
	if(source_port != -1)
		fflags |= RAWSOCK_FILTER_DSTPORT;
	if(rawsock_setfilter(fflags, udp ? IP_TYPE_UDP : IP_TYPE_TCP, source_addr, source_port) < 0)
		goto err;

	// Write output file header
	outdef.begin(outfile);

	// Start threads
	pthread_t tr, ts;
	if(pthread_create(&tr, NULL, recv_thread, NULL) < 0)
		goto err;
	pthread_detach(tr);
	if(pthread_create(&ts, NULL, udp ? send_thread_udp : send_thread, NULL) < 0)
		goto err;
	pthread_detach(ts);

	// Stats & progress watching
	while(1) {
		unsigned int cur_sent, cur_recv;
		cur_sent = atomic_exchange(&pkts_sent, 0);
		cur_recv = atomic_exchange(&pkts_recv, 0);
		float progress = target_gen_progress();
		if(!quiet)
			fprintf(stderr, "snt:%4u rcv:%4u p:%3d%%\r", cur_sent, cur_recv, (int) (progress*100));
		if(send_finished)
			break;

		usleep(STATS_INTERVAL * 1000);
	}

	// Wait for the last packets to arrive
	fprintf(stderr, "\nWaiting %d more seconds...\n", FINISH_WAIT_TIME);
	usleep(FINISH_WAIT_TIME * 1000 * 1000);
	rawsock_breakloop();
	if(banners)
		scan_responder_finish();
	if(!quiet)
		fprintf(stderr, "rcv:%4u\n", atomic_exchange(&pkts_recv, 0));

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

static void *send_thread(void *unused)
{
	uint8_t _Alignas(long int) packet[FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE];
	uint8_t dstaddr[16];
	struct ports_iter it;

	(void) unused;
	rawsock_eth_prepare(ETH_FRAME(packet), ETH_TYPE_IPV6);
	rawsock_ip_prepare(IP_FRAME(packet), IP_TYPE_TCP);
	if(target_gen_next(dstaddr) < 0)
		return NULL;
	rawsock_ip_modify(IP_FRAME(packet), TCP_HEADER_SIZE, dstaddr);
	tcp_prepare(TCP_HEADER(packet));
	tcp_make_syn(TCP_HEADER(packet), FIRST_SEQNUM);
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

		// Rate control
		if(atomic_fetch_add(&pkts_sent, 1) >= max_rate) {
			// FIXME: this doesn't seem like a good idea
			do
				usleep(1000);
			while(atomic_load(&pkts_sent) != 0);
		}
	}

	send_finished = true;
	return NULL;
}

static void *send_thread_udp(void *unused)
{
	uint8_t _Alignas(long int) packet[FRAME_ETH_SIZE + FRAME_IP_SIZE + UDP_HEADER_SIZE + BANNER_QUERY_MAX_LENGTH];
	uint8_t dstaddr[16];
	struct ports_iter it;

	(void) unused;
	rawsock_eth_prepare(ETH_FRAME(packet), ETH_TYPE_IPV6);
	rawsock_ip_prepare(IP_FRAME(packet), IP_TYPE_UDP);
	if(target_gen_next(dstaddr) < 0)
		return NULL;
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

		// Rate control
		if(atomic_fetch_add(&pkts_sent, 1) >= max_rate) {
			// FIXME: this doesn't seem like a good idea
			do
				usleep(1000);
			while(atomic_load(&pkts_sent) != 0);
		}
	}

	send_finished = true;
	return NULL;
}

static void *recv_thread(void *unused)
{
	(void) unused;
	if(rawsock_loop(recv_handler) < 0)
		fprintf(stderr, "An error occurred in packet capture\n");
	return NULL;
}

static void recv_handler(uint64_t ts, int len, const uint8_t *packet)
{
	int v;
	const uint8_t *csrcaddr;

	atomic_fetch_add(&pkts_recv, 1);
	//printf("<< @%lu -- %d bytes\n", ts, len);

	// Decode
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
	if(!udp) {
		if(v != IP_TYPE_TCP || len < FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE)
			goto perr;
	} else {
		if(v != IP_TYPE_UDP || len < FRAME_ETH_SIZE + FRAME_IP_SIZE + UDP_HEADER_SIZE)
			goto perr;
	}

	// Output stuff
	int v2;
	if(!udp) {
		if(TCP_HEADER(packet)->f_ack && (TCP_HEADER(packet)->f_syn || TCP_HEADER(packet)->f_rst)) {
			tcp_decode(TCP_HEADER(packet), &v, NULL);
			rawsock_ip_decode(IP_FRAME(packet), NULL, NULL, &v2, NULL, NULL);
			if(show_closed || (!show_closed && TCP_HEADER(packet)->f_syn))
				outdef.output_status(outfile, ts, csrcaddr, OUTPUT_PROTO_TCP, v, v2, TCP_HEADER(packet)->f_syn?OUTPUT_STATUS_OPEN:OUTPUT_STATUS_CLOSED);
		}
		// Pass packet to responder
		if(banners)
			scan_responder_process(ts, len, packet);
	} else {
		tcp_decode(TCP_HEADER(packet), &v, NULL);
		rawsock_ip_decode(IP_FRAME(packet), NULL, NULL, &v2, NULL, NULL);
		if(banners) {
			unsigned int plen = len - (FRAME_ETH_SIZE + FRAME_IP_SIZE + UDP_HEADER_SIZE);
			if(plen > 0) {
				char temp[plen];
				memcpy(temp, UDP_DATA(packet), plen);
				banner_postprocess(IP_TYPE_UDP, v, temp, &plen);
				outdef.output_banner(outfile, ts, csrcaddr, OUTPUT_PROTO_UDP, v, temp, plen);
			}
		} else {
			// We got an answer, that's already noteworthy enough
			outdef.output_status(outfile, ts, csrcaddr, OUTPUT_PROTO_UDP, v, v2, OUTPUT_STATUS_OPEN);
		}
	}

	return;
	perr: ;
#ifndef NDEBUG
	fprintf(stderr, "Failed to decode packet of length %d\n", len);
#endif
}

static inline int source_port_rand(void)
{
	int v;
	v = rand() & 0xffff; // random 16-bit number
	v |= 4096; // ensure that 1) it's not zero 2) it's >= 4096
	return v;
}
