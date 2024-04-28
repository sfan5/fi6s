#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "scan.h"
#include "rawsock.h"
#include "tcp.h"
#include "output.h"
#include "banner.h"
#include "util.h"

/*
 * <https://lwn.net/Articles/495304/>
 * <https://github.com/avagin/tcp-repair/blob/master/tcp-constructor.c>
 * sudo ip6tables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST SYN,ACK -m tcp --dport 1235 -j DROP
 */

static struct {
	/* TODO: better sharing of these vars with scan.c */
	FILE *outfile;
	const struct outputdef *outdef;
	uint16_t source_port;
	int epoll_fd;

	pthread_t tcp_thread;
	atomic_bool tcp_thread_exit;
} responder;

static void *tcp_thread(void *unused);

int scan_responder_init(FILE *outfile, const struct outputdef *outdef, uint16_t source_port)
{
	responder.outfile = outfile;
	responder.outdef = outdef;
	responder.source_port = source_port;

	responder.epoll_fd = epoll_create(1);
	if(responder.epoll_fd == -1)
		return -1;

	atomic_store(&responder.tcp_thread_exit, false);
	if(pthread_create(&responder.tcp_thread, NULL, tcp_thread, NULL) < 0)
		return -1;

	return 0;
}

#if 1
#define tcp_debug(...) fprintf(stderr, __VA_ARGS__)
#else
#define tcp_debug(...) do {} while(0)
#endif

#define my_perror(s) do { perror(s); return; } while(0)

void scan_responder_process(uint64_t ts, int len, const uint8_t *rpacket)
{
	const uint8_t *rsrcaddr;
	int rport;
	uint32_t rseqnum, acknum;

	rawsock_ip_decode(IP_FRAME(rpacket), NULL, NULL, NULL, &rsrcaddr, NULL);
	tcp_decode(TCP_HEADER(rpacket), &rport, NULL);

	if(!TCP_HEADER(rpacket)->f_ack || !TCP_HEADER(rpacket)->f_syn)
		return;

	tcp_decode2(TCP_HEADER(rpacket), &rseqnum, &acknum);

	tcp_debug("< seqnum = %08x syn-ack %08x\n", rseqnum, acknum);

	uint32_t lseqnum = FIRST_SEQNUM + 1; // expected acknum for the initial answer
	if(acknum != lseqnum)
		return;
	rseqnum += 1; // syn-ack increases seqnum by one

	int sock = socket(AF_INET6, SOCK_STREAM, 0);
	if (sock == -1) my_perror("socket");

	int opt = 1;
	if (setsockopt(sock, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt)) == -1)
		my_perror("setsockopt(TCP_REPAIR)");

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
		my_perror("setsockopt(SO_REUSEADDR)");

	// sending side (us)
	opt = TCP_SEND_QUEUE;
	if (setsockopt(sock, SOL_TCP, TCP_REPAIR_QUEUE, &opt, sizeof(opt)) == -1)
		my_perror("setsockopt(TCP_REPAIR_QUEUE)");

	if (setsockopt(sock, SOL_TCP, TCP_QUEUE_SEQ, &lseqnum, sizeof(lseqnum)) == -1)
		my_perror("setsockopt(TCP_QUEUE_SEQ)");

	// receiving side (remote)
	opt = TCP_RECV_QUEUE;
	if (setsockopt(sock, SOL_TCP, TCP_REPAIR_QUEUE, &opt, sizeof(opt)) == -1)
		my_perror("setsockopt(TCP_REPAIR_QUEUE)");

	if (setsockopt(sock, SOL_TCP, TCP_QUEUE_SEQ, &rseqnum, sizeof(rseqnum)) == -1)
		my_perror("setsockopt(TCP_QUEUE_SEQ)");

	// source address
	struct sockaddr_in6 addr = {0};
	{
		addr.sin6_family = AF_INET6;
		struct frame_ip tmp;
		rawsock_ip_prepare(&tmp, 0);
		memcpy(addr.sin6_addr.s6_addr, tmp.src, 16);
		addr.sin6_port = be16toh(responder.source_port);
		if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1)
			my_perror("bind");
	}

	// destination address
	{
		addr.sin6_family = AF_INET6;
		memcpy(addr.sin6_addr.s6_addr, rsrcaddr, 16);
		addr.sin6_port = be16toh(rport);
		if (connect(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1)
			my_perror("connect");
	}

	// options
	struct tcp_repair_opt opts[] = {
		{ .opt_code = TCPOPT_MAXSEG, .opt_val = 1220 }, // minimum MSS (RFC9293)
		{ .opt_code = TCPOPT_WINDOW, .opt_val = 0 }, // wscale not negotiated
	};
	if (setsockopt(sock, SOL_TCP, TCP_REPAIR_OPTIONS, &opts, sizeof(opts)) == -1)
		my_perror("setsockopt(TCP_REPAIR_OPTIONS)");

	// put everything into motion
	opt = 0;
	if (setsockopt(sock, SOL_TCP, TCP_REPAIR, &opt, sizeof(opt)) == -1)
		my_perror("setsockopt(TCP_REPAIR)");

	tcp_debug("repaired into fd=%d\n", sock);

	unsigned int plen;
	const char *payload = banner_get_query(IP_TYPE_TCP, rport, &plen);
	if(!payload) {
		close(sock);
		return;
	}

	send(sock, payload, plen, 0);

	struct epoll_event ev = {
		.events = EPOLLIN,
		.data.fd = sock,
	};
	if(epoll_ctl(responder.epoll_fd, EPOLL_CTL_ADD, sock, &ev) == -1) {
		perror("epoll_ctl");
		close(sock);
	}
}

static void *tcp_thread(void *unused)
{
	(void) unused;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	set_thread_name("tcp");

	do {
		struct epoll_event ev;
		int r = epoll_wait(responder.epoll_fd, &ev, 1, 1000);
		if(r <= 0)
			continue;

		if(ev.events & EPOLLIN) {
			char buf[123];
			int r = recv(ev.data.fd, buf, sizeof(buf), 0);
			if(r > 0) {
				fwrite(buf, r, 1, stdout);
			}
		}

	} while(!atomic_load(&responder.tcp_thread_exit));
	return NULL;
}

void scan_responder_finish()
{
	atomic_store(&responder.tcp_thread_exit, true);
	pthread_join(responder.tcp_thread, NULL);
}
