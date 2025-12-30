#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <pcap.h>
#include <sys/socket.h>

#ifdef __linux__
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <linux/filter.h>
#endif

#include "rawsock.h"
#include "util.h"

#ifdef __linux__
#define NL_READ_BUFFER_SIZE (64*1024*1024) // 64 KiB

static int netlink_read(int sock, unsigned int seq, char *buf, unsigned int bufsz);
static int mac_for_neighbor(int sock, char *buf, const uint8_t* ip, uint8_t *mac);
#endif

int rawsock_getdev(char **out_dev)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs, *d;

	if(pcap_findalldevs(&alldevs, errbuf) != 0) {
		log_raw("pcap_findalldevs: %s", errbuf);
		return -1;
	}

	// Pick the first device that has a suitable-looking IPv6 address
	*out_dev = NULL;
	for(d = alldevs; d; d = d->next) {
		if(d->flags & PCAP_IF_LOOPBACK)
			continue;
		if(!(d->flags & PCAP_IF_UP))
			continue;
		for(pcap_addr_t *a = d->addresses; a; a = a->next) {
			if(a->addr->sa_family != AF_INET6)
				continue;
			struct sockaddr_in6 *inaddr = (struct sockaddr_in6*) a->addr;
			// Exclude link-local fe80::
			if(inaddr->sin6_addr.s6_addr[0] == 0xfe &&
				inaddr->sin6_addr.s6_addr[1] == 0x80)
				continue;
			*out_dev = strdup(d->name);
			goto found;
		}
	}

found:
	pcap_freealldevs(alldevs);
	return 0;
}

int rawsock_getgw(const char *dev, uint8_t *mac)
{
#ifdef __linux__
	int sock;
	char *buf;
	struct nlmsghdr *msg;

	buf = calloc(1, NL_READ_BUFFER_SIZE);
	if(!buf) {
		return -1;
	}

	sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if(sock == -1) {
		perror("socket");
		free(buf);
		return -1;
	}

	// Ask for all routes
	memset(buf, 0, NL_READ_BUFFER_SIZE);
	msg = (struct nlmsghdr*) buf;
	msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	msg->nlmsg_type = RTM_GETROUTE;
	msg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	msg->nlmsg_seq = 1;
	if(send(sock, msg, msg->nlmsg_len, 0) == -1) {
		perror("send");
		close(sock);
		free(buf);
		return -1;
	}

	int len = netlink_read(sock, 1, buf, NL_READ_BUFFER_SIZE);
	if(len == -1) {
		close(sock);
		free(buf);
		return -1;
	}
	// Process each answer msg
	uint8_t gateway_ip[16];
	int success = 0;
	for(; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len)) {
		if(msg->nlmsg_type != RTM_NEWROUTE)
			continue;
		struct rtmsg *rtm = (struct rtmsg*) NLMSG_DATA(msg);
		if(rtm->rtm_family != AF_INET6 || rtm->rtm_table != RT_TABLE_MAIN)
			continue;

		struct rtattr *rta;
		unsigned int rtlen;

		// First, check if this is the right interface
		char ifname[IF_NAMESIZE] = {0};
		rta = (struct rtattr*) RTM_RTA(rtm);
		rtlen = RTM_PAYLOAD(msg);
		for(; RTA_OK(rta, rtlen); rta = RTA_NEXT(rta, rtlen)) {
			if(rta->rta_type == RTA_OIF)
				if_indextoname(*(int*) RTA_DATA(rta), ifname);
		}
		if(strcmp(ifname, dev) != 0)
			continue;

		// Find the gateway
		rta = (struct rtattr*) RTM_RTA(rtm);
		rtlen = RTM_PAYLOAD(msg);
		for(; RTA_OK(rta, rtlen); rta = RTA_NEXT(rta, rtlen)) {
			if(rta->rta_type != RTA_GATEWAY)
				continue;

			uint8_t *addr = (uint8_t*) RTA_DATA(rta);
			memcpy(gateway_ip, addr, 16);
			success |= 1;

			// read MAC from link-local addr
			if(addr[0] == 0xfe && addr[1] == 0x80 &&
				addr[11] == 0xff && addr[12] == 0xfe)
			{
				memcpy(mac, &addr[8], 3);
				memcpy(&mac[3], &addr[13], 3);
				*mac ^= 0x02; // IPv6 modified EUI
				success |= 2;
			}
		}
	}

	if(success == 1) {
		// we have seen a gateway, but couldn't read its mac
		success = mac_for_neighbor(sock, buf, gateway_ip, mac) == 0;
		if(!success) {
			char buf2[IPV6_STRING_MAX];
			ipv6_string(buf2, gateway_ip);
			log_raw("Couldn't determine the MAC address of your gateway, "
				"which appears to be %s.", buf2);
		}
	}

	close(sock);
	free(buf);
	return success ? 0 : -1;
#else
	(void) dev, (void) mac;
	return -1;
#endif
}

#ifdef __linux__
static int mac_for_neighbor(int sock, char *buf, const uint8_t* ip, uint8_t *mac)
{
	struct nlmsghdr *msg;

	// Ask for all neighbors
	memset(buf, 0, NL_READ_BUFFER_SIZE);
	msg = (struct nlmsghdr*) buf;
	msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	msg->nlmsg_type = RTM_GETNEIGH;
	msg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	msg->nlmsg_seq = 10;
	if(send(sock, msg, msg->nlmsg_len, 0) == -1) {
		perror("send");
		return -1;
	}

	int len = netlink_read(sock, 10, buf, NL_READ_BUFFER_SIZE);
	if(len == -1)
		return -1;
	// Process each answer msg
	for(; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len)) {
		if(msg->nlmsg_type != RTM_NEWNEIGH)
			continue;
		struct ndmsg *ndm = (struct ndmsg*) NLMSG_DATA(msg);
		if(ndm->ndm_family != AF_INET6)
			continue;
		if(ndm->ndm_state != NUD_REACHABLE && ndm->ndm_state != NUD_STALE &&
			ndm->ndm_state != NUD_DELAY && ndm->ndm_state != NUD_PERMANENT)
			continue;

		struct rtattr *rta;
		unsigned int rtlen;

		// First check that this is the right addr
		bool success = false;
		rta = (struct rtattr*) RTM_RTA(ndm);
		rtlen = RTM_PAYLOAD(msg);
		for(; RTA_OK(rta, rtlen); rta = RTA_NEXT(rta, rtlen)) {
			if(rta->rta_type == NDA_DST)
				success = memcmp(ip, RTA_DATA(rta), 16) == 0;
		}
		if(!success)
			continue;

		// Find the MAC address
		rta = (struct rtattr*) RTM_RTA(ndm);
		rtlen = RTM_PAYLOAD(msg);
		for(; RTA_OK(rta, rtlen); rta = RTA_NEXT(rta, rtlen)) {
			if(rta->rta_type != NDA_LLADDR)
				continue;
			memcpy(mac, RTA_DATA(rta), 6);
			return 0;
		}
	}

	return -1;
}
#endif

int rawsock_getmac(const char *dev, uint8_t *mac)
{
#ifdef __linux__
	FILE *f;
	char buf[64];

	snprintf(buf, sizeof(buf), "/sys/class/net/%s/address", dev);
	f = fopen(buf, "r");
	if(!f)
		return -1;

	int rd = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	return rd > 0 ? parse_mac(buf, mac) : -1;
#else
	(void) dev, (void) mac;
	return -1;
#endif
}

int rawsock_getsrcip(const struct sockaddr_in6 *dest, const char *interface, uint8_t *ip, int advice)
{
	int sock, ret = 0;
	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if(sock == -1) {
		ret = -1;
		goto afnosupport;
	}

#ifdef __linux__
	// Attempt to bind the socket to the interface we are actually going to use (may fail)
	if(interface)
		setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface) + 1);
#else
	(void) interface;
#endif

	if(connect(sock, (struct sockaddr*) dest, sizeof(struct sockaddr_in6)) == -1) {
		log_debug("%s: errno=%d", __func__, errno);
		if(errno == EAFNOSUPPORT) {
			ret = -1;
			goto afnosupport;
		}
		if(errno == ENETUNREACH) {
			if(advice == 1) {
				log_warning("Your machine does not seem to have any IPv6 "
					"connectivity (no default route?)");
			} else if(advice == 2) {
				char buf[IPV6_STRING_MAX];
				ipv6_string(buf, dest->sin6_addr.s6_addr);
				log_warning("Your machine might not have working IPv6 "
					"connectivity (to %s)", buf);
			}
		}
		close(sock);
		return -1;
	}

	struct sockaddr_in6 tmp;
	socklen_t tmplen = sizeof(tmp);
	if(getsockname(sock, (struct sockaddr*) &tmp, &tmplen) == -1)
		ret = -1;
	else
		memcpy(ip, tmp.sin6_addr.s6_addr, 16);

	if(0) {
afnosupport:
		if(advice > 0)
			log_warning("Your machine does not seem to have working IPv6");
	}
	close(sock);
	return ret;
}

int rawsock_islocal(const uint8_t *ip)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs, *d;

	if(pcap_findalldevs(&alldevs, errbuf) != 0) {
		log_debug("pcap_findalldevs: %s", errbuf);
		return -1;
	}

	int ret = 0;
	for(d = alldevs; d; d = d->next) {
		if(!(d->flags & PCAP_IF_UP))
			continue;
		for(pcap_addr_t *a = d->addresses; a; a = a->next) {
			if(a->addr->sa_family != AF_INET6)
				continue;
			struct sockaddr_in6 *inaddr = (struct sockaddr_in6*) a->addr;
			if(!memcmp(inaddr->sin6_addr.s6_addr, ip, 16)) {
				ret = 1;
				goto found;
			}
		}
	}

found:
	pcap_freealldevs(alldevs);
	return ret;
}

int rawsock_reserve_port(const uint8_t *addr, int type, int port)
{
#ifdef __linux__
	// create a normal server socket but use a filter to drop all packets
	if(type != IP_TYPE_TCP && type != IP_TYPE_UDP)
		return -1;
	int sock = socket(AF_INET6, type == IP_TYPE_TCP ? SOCK_STREAM : SOCK_DGRAM, 0);
	if(sock == -1) {
		perror("socket");
		return -1;
	}

	struct sock_filter f[] = {
		{ 0x06, 0, 0, 0 }, // ret #0
	};
	struct sock_fprog prog = {
		.len = sizeof(f) / sizeof(*f),
		.filter = f
	};
	if(setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) == -1) {
		perror("setsockopt(SO_ATTACH_FILTER)");
		close(sock);
		return -1;
	}

	struct sockaddr_in6 tmp = {0};
	tmp.sin6_family = AF_INET6;
	memcpy(tmp.sin6_addr.s6_addr, addr, 16);
	assert(port >= 0);
	tmp.sin6_port = htons(port & 0xffff);
	if(bind(sock, (struct sockaddr*) &tmp, sizeof(tmp)) == -1) {
		perror("bind");
		close(sock);
		return -1;
	}

	if(type == IP_TYPE_TCP && listen(sock, 1) == -1) {
		perror("listen");
		close(sock);
		return -1;
	}

	socklen_t tmplen = sizeof(tmp);
	if(getsockname(sock, (struct sockaddr*) &tmp, &tmplen) == -1) {
		perror("getsockname");
		close(sock);
		return -1;
	}

	// everything went well. the socket needs to stay open so we leak it here.
	assert(tmp.sin6_port != 0);
	return ntohs(tmp.sin6_port);
#else
	return -2;
#endif
}

#ifdef __linux__
// have I mentioned that netlink has a horrible interface?
static int netlink_read(int sock, unsigned int seq, char *buf, unsigned int bufsz)
{
	unsigned int head = 0; // first unread nlmsg
	unsigned int tail = 0; // end of buffer
	bool done = false;

	while(!done) {
		// get more bytes
		int rlen = recv(sock, buf + tail, bufsz - tail, 0);
		if(rlen == -1) {
			perror("recv");
			return -1;
		}
		tail += rlen;
		if(tail >= bufsz) {
			log_warning("insufficient buffer to read from netlink");
			return -1;
		}

		// try parsing them
		struct nlmsghdr *msg = (struct nlmsghdr*) (buf + head);
		unsigned int mlen = tail - head;
		for(; NLMSG_OK(msg, mlen); msg = NLMSG_NEXT(msg, mlen)) {
			if(msg->nlmsg_seq != seq) {
				log_debug("ignoring unrelated netlink message");
				msg->nlmsg_type = NLMSG_NOOP; // mark ignored
				continue;
			} else if(msg->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr*) NLMSG_DATA(msg);
				log_error("netlink reports error %d", err->error);
				return -1;
			} else if(!(msg->nlmsg_flags & NLM_F_MULTI) || msg->nlmsg_type == NLMSG_DONE) {
				done = true;
				break;
			}
		}
		head = tail - mlen;
	}

	return head;
}
#endif
