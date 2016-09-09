#include <stdio.h>
#include <stdlib.h> // rand()
#include <string.h>

#include "scan.h"
#include "target.h"
#include "util.h"
#include "rawsock.h"
#include "tcp.h"

static uint8_t source_addr[16];
static int source_port;
static struct ports ports;

#define ETH_FRAME(buf) ( (struct frame_eth*) &(buf)[0] )
#define IP_FRAME(buf) ( (struct frame_ip*) &(buf)[FRAME_ETH_SIZE] )
#define TCP_HEADER(buf) ( (struct tcp_header*) &(buf)[FRAME_ETH_SIZE + FRAME_IP_SIZE] )

void scan_settings(const uint8_t *_source_addr, int _source_port, const struct ports *_ports)
{
	memcpy(source_addr, _source_addr, 16);
	source_port = _source_port;
	memcpy(&ports, _ports, sizeof(struct ports));
}

static inline int source_port_rand(void)
{
	int v;
	v = rand() & 0xffff; // random 16-bit number
	v |= 4096; // ensure that 1) it's not zero 2) it's >= 4096
	return v;
}

int scan_main(const char *interface)
{
	if(rawsock_open(interface, 2048) < 0)
		return 1;
	int ret;


	// Set filters
	int fflags = RAWSOCK_FILTER_IPTYPE | RAWSOCK_FILTER_DSTADDR;
	if(source_port != -1)
		fflags |= RAWSOCK_FILTER_DSTPORT;
	if(rawsock_setfilter(fflags, IP_TYPE_TCP, source_addr, source_port) < 0)
		goto err;


	uint8_t _Alignas(long int) packet[FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE];
	uint8_t dstaddr[16];
	struct ports_iter it;
	rawsock_eth_prepare(ETH_FRAME(packet), ETH_TYPE_IPV6);
	rawsock_ip_prepare(IP_FRAME(packet), IP_TYPE_TCP);
	if(target_gen_next(dstaddr) < 0)
		goto err;
	rawsock_ip_modify(IP_FRAME(packet), TCP_HEADER_SIZE, dstaddr);
	ports_iter_begin(&ports, &it);

	uint64_t ts;
	int clen;
	const uint8_t *cpacket;

	int v;
	const uint8_t *csrcaddr;

	while(1) {
		// Send TCP packet
		if(ports_iter_next(&it) == 0) {
			if(target_gen_next(dstaddr) < 0)
				break; // no more targets
			rawsock_ip_modify(IP_FRAME(packet), TCP_HEADER_SIZE, dstaddr);
			ports_iter_begin(NULL, &it);
		}
		make_a_syn_pkt_pls(TCP_HEADER(packet), it.val, source_port==-1?source_port_rand():source_port);
		checksum_pkt_pls(IP_FRAME(packet), TCP_HEADER(packet));
		rawsock_send(packet, sizeof(packet));

		// Sniff response packet
		do {
			ret = rawsock_sniff(&ts, &clen, &cpacket);
			if(ret < 0)
				goto err;
		} while(ret == 0);
		printf("got %d byte packet @%lu\n", clen, ts);

		// Decode response packet
		if(clen < FRAME_ETH_SIZE)
			goto perr;
		rawsock_eth_decode(ETH_FRAME(cpacket), &v);
		if(v != ETH_TYPE_IPV6 || clen < FRAME_ETH_SIZE + FRAME_IP_SIZE)
			goto perr;
		rawsock_ip_decode(IP_FRAME(cpacket), &v, NULL, &csrcaddr, NULL);
		if(v != IP_TYPE_TCP || clen < FRAME_ETH_SIZE + FRAME_IP_SIZE + TCP_HEADER_SIZE)
			goto perr;
		if(TCP_HEADER(cpacket)->f_ack && (TCP_HEADER(cpacket)->f_syn || TCP_HEADER(cpacket)->f_rst)) {
			decode_pkt_pls(TCP_HEADER(cpacket), &v, NULL);
			char tmp[IPV6_STRING_MAX];
			ipv6_string(tmp, csrcaddr);
			printf("%s port %d %s\n", tmp, v, TCP_HEADER(cpacket)->f_syn?"open":"closed");
		}

		continue;
		perr:
		printf("Failed to parse sniffed packet\n");
	}


	ret = 0;
	goto ret;
	err:
	ret = 1;
	ret:
	rawsock_close();
	return ret;
}
