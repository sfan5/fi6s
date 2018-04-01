#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h> // usleep()
#include <pthread.h>

#include "scan.h"
#include "rawsock.h"
#include "tcp.h"
#include "output.h"
#include "banner.h"

static struct {
	/* TODO: better sharing of these vars with scan.c */
	FILE *outfile;
	const struct outputdef *outdef;
	uint16_t source_port;

	uint8_t _Alignas(long int) buffer[FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE + BANNER_QUERY_MAX_LENGTH];

	pthread_t tcp_thread;
	bool tcp_thread_exit;
} responder;

static void *tcp_thread(void *unused);

#define ETH_FRAME(buf) ( (struct frame_eth*) &(buf)[0] )
#define IP_FRAME(buf) ( (struct frame_ip*) &(buf)[FRAME_ETH_SIZE] )
#define TCP_HEADER(buf) ( (struct tcp_header*) &(buf)[FRAME_ETH_SIZE + FRAME_IP_SIZE] )
#define DATA(buf, data_offset) ( (uint8_t*) &(buf)[FRAME_ETH_SIZE + FRAME_IP_SIZE + data_offset] )

int scan_responder_init(FILE *outfile, const struct outputdef *outdef, uint16_t source_port)
{
	uint8_t *spacket = responder.buffer;

	rawsock_eth_prepare(ETH_FRAME(spacket), ETH_TYPE_IPV6);
	rawsock_ip_prepare(IP_FRAME(spacket), IP_TYPE_TCP);
	tcp_prepare(TCP_HEADER(spacket));

	responder.outfile = outfile;
	responder.outdef = outdef;
	responder.source_port = source_port;

	responder.tcp_thread_exit = 0;
	if(pthread_create(&responder.tcp_thread, NULL, tcp_thread, NULL) < 0)
		return -1;

	return 0;
}

#if 0
#define tcp_debug(...) fprintf(stderr, __VA_ARGS__)
#else
#define tcp_debug(...) do {} while(0)
#endif

void scan_responder_process(uint64_t ts, int len, const uint8_t *rpacket)
{
	uint8_t *spacket = responder.buffer;
	const uint8_t *rsrcaddr;
	int rport;
	uint32_t rseqnum, acknum;

	rawsock_ip_decode(IP_FRAME(rpacket), NULL, NULL, NULL, &rsrcaddr, NULL);
	tcp_decode(TCP_HEADER(rpacket), &rport, NULL);

	unsigned int data_offset;
	tcp_decode_header(TCP_HEADER(rpacket), &data_offset);
	if(!TCP_HEADER(rpacket)->f_rst && !TCP_HEADER(rpacket)->f_syn &&
		len > FRAME_ETH_SIZE + FRAME_IP_SIZE + data_offset) {
		tcp_decode2(TCP_HEADER(rpacket), &rseqnum, &acknum);
		unsigned int plen = len - (FRAME_ETH_SIZE + FRAME_IP_SIZE + data_offset);

		// push data into session buffer
		tcp_debug("< seqnum = %08x got data\n", rseqnum);
		int ok = tcp_state_find_and_push(rsrcaddr, rport, DATA(rpacket, data_offset), plen, rseqnum);

		if(!TCP_HEADER(rpacket)->f_ack)
			return; // FIXME: we should keep track of our own seqnums
		if(ok) {
			// send ack(+fin)
			rawsock_ip_modify(IP_FRAME(spacket), TCP_HEADER_SIZE, rsrcaddr);
			tcp_make_ack(TCP_HEADER(spacket), acknum, rseqnum + plen);
			TCP_HEADER(spacket)->f_fin = TCP_HEADER(rpacket)->f_fin;
			tcp_modify(TCP_HEADER(spacket), responder.source_port, rport);

			tcp_debug("> ack%s seq=%08x ack=%08x\n",
				TCP_HEADER(spacket)->f_fin?"+fin":"", acknum, rseqnum);
		} else {
			// send rst
			rawsock_ip_modify(IP_FRAME(spacket), TCP_HEADER_SIZE, rsrcaddr);
			tcp_make_rst(TCP_HEADER(spacket), acknum);
			tcp_modify(TCP_HEADER(spacket),responder.source_port, rport);

			tcp_debug("> rst seq=%08x\n", rseqnum);
		}
		tcp_checksum_nodata(IP_FRAME(spacket), TCP_HEADER(spacket));
		rawsock_send(spacket, FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE);
	} else if(TCP_HEADER(rpacket)->f_ack) {
		tcp_decode2(TCP_HEADER(rpacket), &rseqnum, &acknum);

		tcp_debug("< seqnum = %08x acked: %08x\n", rseqnum, acknum);
		if(!TCP_HEADER(rpacket)->f_syn)
			return;

		if(acknum != FIRST_SEQNUM + 1)
			return;
		rseqnum += 1; // syn-ack increases seqnum by one

		unsigned int plen;
		const char *payload = banner_get_query(rport, &plen);
		if(!payload) {
			// we don't actually want to grab a banner, send an RST
			rawsock_ip_modify(IP_FRAME(spacket), TCP_HEADER_SIZE, rsrcaddr);
			tcp_make_ack(TCP_HEADER(spacket), acknum, rseqnum);
			TCP_HEADER(spacket)->f_rst = 1;
			tcp_modify(TCP_HEADER(spacket), responder.source_port, rport);

			tcp_checksum_nodata(IP_FRAME(spacket), TCP_HEADER(spacket));
			rawsock_send(spacket, FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE);
			tcp_debug("> ack+rst seq=%08x ack=%08x\n", acknum, rseqnum);
			return;
		}

		// send ack(+psh) with banner query
		rawsock_ip_modify(IP_FRAME(spacket), TCP_HEADER_SIZE + plen, rsrcaddr);
		tcp_make_ack(TCP_HEADER(spacket), FIRST_SEQNUM + 1, rseqnum);
		TCP_HEADER(spacket)->f_psh = (plen > 0);
		tcp_modify(TCP_HEADER(spacket), responder.source_port, rport);
		memcpy(DATA(spacket, TCP_HEADER_SIZE), payload, plen);

		tcp_checksum(IP_FRAME(spacket), TCP_HEADER(spacket), plen);
		rawsock_send(spacket, FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE + plen);
		tcp_debug("> ack%s seq=%08x ack=%08x\n",
			TCP_HEADER(spacket)->f_psh?"+psh":"", FIRST_SEQNUM + 1, rseqnum);

		// register as new tcp session
		tcp_state_create(rsrcaddr, rport, ts, rseqnum - 1);
	}
}

static void *tcp_thread(void *unused)
{
	(void) unused;
	do {
		// TODO: handle case of thread being behind schedule
		usleep(BANNER_TIMEOUT * 1000 / 2);

		tcp_state_id id;
		while(tcp_state_next_expired(BANNER_TIMEOUT, &id)) {
			unsigned int len;
			void *buf = tcp_state_get_buffer(id, &len);
			uint64_t ts = tcp_state_get_timestamp(id);
			uint16_t srcport;
			const uint8_t *srcaddr = tcp_state_get_remote(id, &srcport);

			if (len > 0) {
				// output banner to file
				banner_postprocess(srcport, buf, &len);
				responder.outdef->output_banner(responder.outfile, ts, srcaddr, srcport, buf, len);
			}

			// destroy tcp session
			tcp_state_destroy(id);

			// TODO: terminate connection if needed(?)
		}
	} while(!responder.tcp_thread_exit);
	return NULL;
}

void scan_responder_finish()
{
	responder.tcp_thread_exit = 1;
	pthread_join(responder.tcp_thread, NULL);
}
