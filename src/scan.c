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
#include "target.h"
#include "util.h"
#include "rawsock.h"
#include "tcp.h"
#include "banner.h"

static uint8_t source_addr[16];
static int source_port;
static struct ports ports;
static int max_rate, show_closed, banners;
static FILE *outfile;
static struct outputdef outdef;

static atomic_uint pkts_sent, pkts_recv;
static bool send_finished;

#define FIRST_SEQNUM 0xf0000000
static inline int source_port_rand(void);
static void *send_thread(void *unused);
static void *recv_thread(void *unused);
static void recv_handler(uint64_t ts, int len, const uint8_t *packet);

static struct {
	uint8_t _Alignas(long int) buffer[FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE + BANNER_QUERY_MAX_LENGTH];
} responder;
static void responder_init();
static void responder_process(uint64_t ts, int len, const uint8_t *rpacket);

#define ETH_FRAME(buf) ( (struct frame_eth*) &(buf)[0] )
#define IP_FRAME(buf) ( (struct frame_ip*) &(buf)[FRAME_ETH_SIZE] )
#define TCP_HEADER(buf) ( (struct tcp_header*) &(buf)[FRAME_ETH_SIZE + FRAME_IP_SIZE] )
#define DATA(buf) ( (uint8_t*) &(buf)[FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE] )

#if ATOMIC_INT_LOCK_FREE != 2
#warning Non lock-free atomic types will severely affect performance.
#endif

void scan_settings(const uint8_t *_source_addr, int _source_port, const struct ports *_ports, int _max_rate, int _show_closed, int _banners, FILE *_outfile, const struct outputdef *_outdef)
{
	memcpy(source_addr, _source_addr, 16);
	source_port = _source_port;
	memcpy(&ports, _ports, sizeof(struct ports));
	max_rate = _max_rate == -1 ? INT_MAX : _max_rate - 1;
	show_closed = _show_closed;
	banners = _banners;
	outfile = _outfile;
	memcpy(&outdef, _outdef, sizeof(struct outputdef));
}

int scan_main(const char *interface, int quiet)
{
	if(rawsock_open(interface, 65536) < 0)
		return -1;
	setvbuf(outfile, NULL, _IOLBF, 512);
	atomic_store(&pkts_sent, 0);
	atomic_store(&pkts_recv, 0);
	send_finished = false;
	if(banners)
		responder_init();

	// Set capture filters
	int fflags = RAWSOCK_FILTER_IPTYPE | RAWSOCK_FILTER_DSTADDR;
	if(source_port != -1)
		fflags |= RAWSOCK_FILTER_DSTPORT;
	if(rawsock_setfilter(fflags, IP_TYPE_TCP, source_addr, source_port) < 0)
		goto err;

	// Write output file header
	outdef.begin(outfile);

	// Start threads
	pthread_t tr, ts;
	if(pthread_create(&tr, NULL, recv_thread, NULL) < 0)
		goto err;
	pthread_detach(tr);
	if(pthread_create(&ts, NULL, send_thread, NULL) < 0)
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
		tcp_checksum_nodata(IP_FRAME(packet), TCP_HEADER(packet));
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
	if(len < FRAME_ETH_SIZE)
		goto perr;
	rawsock_eth_decode(ETH_FRAME(packet), &v);
	if(v != ETH_TYPE_IPV6 || len < FRAME_ETH_SIZE + FRAME_IP_SIZE)
		goto perr;
	rawsock_ip_decode(IP_FRAME(packet), &v, NULL, NULL, &csrcaddr, NULL);
	if(v != IP_TYPE_TCP || len < FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE)
		goto perr;

	// Output stuff
	if(TCP_HEADER(packet)->f_ack && (TCP_HEADER(packet)->f_syn || TCP_HEADER(packet)->f_rst)) {
		int v2;
		tcp_decode(TCP_HEADER(packet), &v, NULL);
		rawsock_ip_decode(IP_FRAME(packet), NULL, NULL, &v2, NULL, NULL);
		if(show_closed || (!show_closed && TCP_HEADER(packet)->f_syn))
			outdef.output_status(outfile, ts, csrcaddr, v, v2, TCP_HEADER(packet)->f_syn?OUTPUT_STATUS_OPEN:OUTPUT_STATUS_CLOSED);
	}
	// Pass packet to responder
	if(banners)
		responder_process(ts, len, packet);

	return;
	perr:
#ifndef NDEBUG
	fprintf(stderr, "Failed to decode packet of length %d\n", len);
#endif
	;
}

static void responder_init()
{
	uint8_t *spacket = responder.buffer;

	rawsock_eth_prepare(ETH_FRAME(spacket), ETH_TYPE_IPV6);
	rawsock_ip_prepare(IP_FRAME(spacket), IP_TYPE_TCP);
	tcp_prepare(TCP_HEADER(spacket));
}

static void responder_process(uint64_t ts, int len, const uint8_t *rpacket)
{
	uint8_t *spacket = responder.buffer;
	const uint8_t *rsrcaddr;
	int rport;
	uint32_t rseqnum, acknum;

	rawsock_ip_decode(IP_FRAME(rpacket), NULL, NULL, NULL, &rsrcaddr, NULL);
	tcp_decode(TCP_HEADER(rpacket), &rport, NULL);

	if(TCP_HEADER(rpacket)->f_psh) {
		// we got a banner!
		tcp_decode2(TCP_HEADER(rpacket), &rseqnum, &acknum);
		unsigned int plen = len - (FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE);
		banner_postprocess(rport, (char*) DATA(rpacket), &plen);
		outdef.output_banner(outfile, ts, rsrcaddr, rport, (char*) DATA(rpacket), plen);

		// terminate connection
		rseqnum += plen;
		goto send_ack_rst;
	} else if(TCP_HEADER(rpacket)->f_ack) {
		tcp_decode2(TCP_HEADER(rpacket), &rseqnum, &acknum);
		//printf("< seqnum = %08x acked -> %08x\n", rseqnum, acknum);

		if(TCP_HEADER(rpacket)->f_syn) {
			if(acknum != FIRST_SEQNUM + 1)
				return;
			rseqnum += 1; // syn-ack increases seqnum by one

			unsigned int plen;
			const char *payload = banner_get_query(rport, &plen);
			if(payload) {
				// send ack(+psh) with banner query
				rawsock_ip_modify(IP_FRAME(spacket), TCP_HEADER_SIZE + plen, rsrcaddr);
				tcp_make_ack(TCP_HEADER(spacket), FIRST_SEQNUM + 1, rseqnum);
				TCP_HEADER(spacket)->f_psh = (plen > 0);
				//printf("> ack%s seq=%08x ack=%08x\n", TCP_HEADER(spacket)->f_psh?"+psh":"", FIRST_SEQNUM + 1, rseqnum);
				tcp_modify(TCP_HEADER(spacket), source_port, rport);
				memcpy(DATA(spacket), payload, plen);
				tcp_checksum(IP_FRAME(spacket), TCP_HEADER(spacket), plen);

				rawsock_send(spacket, FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE + plen);
			} else {
				// terminate connection
				goto send_ack_rst;
			}
		}
	}
	return;

	send_ack_rst:
	rawsock_ip_modify(IP_FRAME(spacket), TCP_HEADER_SIZE, rsrcaddr);
	tcp_make_ack(TCP_HEADER(spacket), acknum, rseqnum);
	TCP_HEADER(spacket)->f_rst = 1;
	//printf("> ack+rst seq=%08x ack=%08x\n", acknum, rseqnum);
	tcp_modify(TCP_HEADER(spacket), source_port, rport);
	tcp_checksum_nodata(IP_FRAME(spacket), TCP_HEADER(spacket));

	rawsock_send(spacket, FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE);
}

static inline int source_port_rand(void)
{
	int v;
	v = rand() & 0xffff; // random 16-bit number
	v |= 4096; // ensure that 1) it's not zero 2) it's >= 4096
	return v;
}
