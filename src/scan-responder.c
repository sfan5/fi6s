#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h> // usleep()
#include <stdatomic.h>
#include <pthread.h>

#include "scan.h"
#include "rawsock.h"
#include "tcp.h"
#include "output.h"
#include "banner.h"
#include "util.h"

static struct {
	/* TODO: better sharing of these vars with scan.c */
	FILE *outfile;
	const struct outputdef *outdef;
	uint16_t source_port;

	uint8_t _Alignas(uint32_t) buffer[FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE + BANNER_QUERY_MAX_LENGTH];

	pthread_t tcp_thread;
	atomic_bool tcp_thread_exit;
} responder;

static void *tcp_thread(void *unused);

int scan_responder_init(FILE *outfile, const struct outputdef *outdef, uint16_t source_port)
{
	uint8_t *spacket = responder.buffer;

	rawsock_eth_prepare(ETH_FRAME(spacket), ETH_TYPE_IPV6);
	rawsock_ip_prepare(IP_FRAME(spacket), IP_TYPE_TCP);
	tcp_prepare(TCP_HEADER(spacket));

	responder.outfile = outfile;
	responder.outdef = outdef;
	responder.source_port = source_port;

	if(tcp_state_init() < 0)
		return -1;

	atomic_store(&responder.tcp_thread_exit, false);
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
	tcp_state_ptr p;

	rawsock_ip_decode(IP_FRAME(rpacket), NULL, NULL, NULL, &rsrcaddr, NULL);
	tcp_decode(TCP_HEADER(rpacket), &rport, NULL);

	unsigned int data_offset;
	tcp_decode_header(TCP_HEADER(rpacket), &data_offset);
	// ordinary packet with data
	if(!TCP_HEADER(rpacket)->f_rst && !TCP_HEADER(rpacket)->f_syn &&
		len > FRAME_ETH_SIZE + FRAME_IP_SIZE + data_offset) {
		tcp_decode2(TCP_HEADER(rpacket), &rseqnum, NULL);
		unsigned int plen = len - (FRAME_ETH_SIZE + FRAME_IP_SIZE + data_offset);

		tcp_debug("< seqnum = %08x got data\n", rseqnum);
		if(!tcp_state_find(rsrcaddr, rport, &p))
			goto send_rst;

		// push data into session buffer
		tcp_state_push(&p, TCP_DATA(rpacket, data_offset), plen, rseqnum);

		const int x = TCP_HEADER(rpacket)->f_fin ? 1 : 0; // TODO: read RFC to find out what's up with this
		uint32_t lseqnum = tcp_state_add_seqnum(&p, x);
		if(x)
			tcp_state_set_fin(&p);

		tcp_state_unlock(&p);

		// send ack(+fin)
		rawsock_ip_modify(IP_FRAME(spacket), TCP_HEADER_SIZE, rsrcaddr);
		tcp_make_ack(TCP_HEADER(spacket), lseqnum, rseqnum + plen + x);
		TCP_HEADER(spacket)->f_fin = TCP_HEADER(rpacket)->f_fin;
		tcp_modify(TCP_HEADER(spacket), responder.source_port, rport);

		tcp_debug("> ack%s seq=%08x ack=%08x\n",
			TCP_HEADER(spacket)->f_fin?"+fin":"", lseqnum, rseqnum + plen + x);
		tcp_checksum(IP_FRAME(spacket), TCP_HEADER(spacket), 0);
		rawsock_send(spacket, FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE);
	// FIN packet (no data)
	} else if(TCP_HEADER(rpacket)->f_fin) {
		tcp_decode2(TCP_HEADER(rpacket), &rseqnum, NULL);

		tcp_debug("< seqnum = %08x finish\n", rseqnum);
		if(!tcp_state_find(rsrcaddr, rport, &p))
			goto send_rst;

		const int x = 1; // TODO: read RFC to find out what's up with this
		uint32_t lseqnum = tcp_state_add_seqnum(&p, x);
		tcp_state_set_fin(&p);

		tcp_state_unlock(&p);

		// send ack+fin
		rawsock_ip_modify(IP_FRAME(spacket), TCP_HEADER_SIZE, rsrcaddr);
		tcp_make_ack(TCP_HEADER(spacket), lseqnum, rseqnum + x);
		TCP_HEADER(spacket)->f_fin = 1;
		tcp_modify(TCP_HEADER(spacket), responder.source_port, rport);

		tcp_debug("> ack+fin seq=%08x ack=%08x\n",
			lseqnum, rseqnum + x);
		tcp_checksum(IP_FRAME(spacket), TCP_HEADER(spacket), 0);
		rawsock_send(spacket, FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE);
	// ACK packet (no data)
	} else if(TCP_HEADER(rpacket)->f_ack) {
		tcp_decode2(TCP_HEADER(rpacket), &rseqnum, &acknum);

		tcp_debug("< seqnum = %08x acked: %08x\n", rseqnum, acknum);
		if(!TCP_HEADER(rpacket)->f_syn)
			return;

		uint32_t lseqnum = FIRST_SEQNUM + 1; // expected acknum for the initial answer
		if(acknum != lseqnum)
			return;
		rseqnum += 1; // syn-ack increases seqnum by one

		unsigned int plen;
		const char *payload = banner_get_query(IP_TYPE_TCP, rport, &plen);
		if(!payload) {
			// we don't actually want to grab a banner, send an RST
			rawsock_ip_modify(IP_FRAME(spacket), TCP_HEADER_SIZE, rsrcaddr);
			tcp_make_ack(TCP_HEADER(spacket), lseqnum, rseqnum);
			TCP_HEADER(spacket)->f_rst = 1;
			tcp_modify(TCP_HEADER(spacket), responder.source_port, rport);

			tcp_checksum(IP_FRAME(spacket), TCP_HEADER(spacket), 0);
			rawsock_send(spacket, FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE);
			tcp_debug("> ack+rst seq=%08x ack=%08x\n", lseqnum, rseqnum);
			return;
		}

		// send ack(+psh) with banner query
		rawsock_ip_modify(IP_FRAME(spacket), TCP_HEADER_SIZE + plen, rsrcaddr);
		tcp_make_ack(TCP_HEADER(spacket), lseqnum, rseqnum);
		TCP_HEADER(spacket)->f_psh = (plen > 0);
		tcp_modify(TCP_HEADER(spacket), responder.source_port, rport);
		memcpy(TCP_DATA(spacket, TCP_HEADER_SIZE), payload, plen);

		tcp_checksum(IP_FRAME(spacket), TCP_HEADER(spacket), plen);
		rawsock_send(spacket, FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE + plen);
		tcp_debug("> ack%s seq=%08x ack=%08x\n",
			TCP_HEADER(spacket)->f_psh?"+psh":"", lseqnum, rseqnum);

		// register as new tcp session
		lseqnum += plen;
		tcp_state_create(rsrcaddr, rport, ts, lseqnum, rseqnum - 1);
	}

	return;
	send_rst:
	if(TCP_HEADER(rpacket)->f_ack) {
		tcp_decode2(TCP_HEADER(rpacket), &rseqnum, &acknum);
		uint32_t lseqnum = acknum;

		// send rst
		rawsock_ip_modify(IP_FRAME(spacket), TCP_HEADER_SIZE, rsrcaddr);
		tcp_make_ack(TCP_HEADER(spacket), lseqnum, rseqnum);
		TCP_HEADER(spacket)->f_rst = 1;
		tcp_modify(TCP_HEADER(spacket), responder.source_port, rport);

		tcp_checksum(IP_FRAME(spacket), TCP_HEADER(spacket), 0);
		rawsock_send(spacket, FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE);
		tcp_debug("> ack+rst seq=%08x ack=%08x\n", lseqnum, rseqnum);
	} else {
		tcp_debug("want to send rst but can't..."); // because we don't know our local seqnum
	}
}

static void *tcp_thread(void *unused)
{
	(void) unused;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	set_thread_name("tcp");

	const int packet_sz = FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE;
	uint8_t _Alignas(uint32_t) packet[packet_sz];
	// Copy the prepared structure from the "global" packet buffer
	memcpy(packet, responder.buffer, packet_sz);

	do {
		usleep(BANNER_TIMEOUT * 1000 / 2);

		tcp_state_ptr p;
		while(tcp_state_next_expired(BANNER_TIMEOUT, &p)) {
			uint32_t len;
			void *buf = tcp_state_get_buffer(&p, &len);
			uint64_t ts;
			int have_fin;
			tcp_state_get_misc(&p, &ts, &have_fin);
			uint16_t srcport;
			const uint8_t *srcaddr = tcp_state_get_remote(&p, &srcport);

			if(len > 0) {
				// output banner to file
				if(!responder.outdef->raw)
					banner_postprocess(IP_TYPE_TCP, srcport, buf, &len);
				responder.outdef->output_banner(responder.outfile, ts, srcaddr, OUTPUT_PROTO_TCP, srcport, buf, len);
			}

			// terminate connection if needed
			if(!have_fin) {
				uint32_t lseqnum = tcp_state_add_seqnum(&p, 0);

				// send rst
				rawsock_ip_modify(IP_FRAME(packet), TCP_HEADER_SIZE, srcaddr);
				tcp_make_rst(TCP_HEADER(packet), lseqnum);
				tcp_modify(TCP_HEADER(packet), responder.source_port, srcport);

				tcp_checksum(IP_FRAME(packet), TCP_HEADER(packet), 0);
				rawsock_send(packet, packet_sz);
				tcp_debug("> rst seq=%08x\n", lseqnum);
			}

			// destroy tcp session
			tcp_state_delete(&p);
		}
	} while(!atomic_load(&responder.tcp_thread_exit));
	return NULL;
}

void scan_responder_finish()
{
	atomic_store(&responder.tcp_thread_exit, true);
	pthread_join(responder.tcp_thread, NULL);
}
