#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
// pcap.h breaks if you don't define these:
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
#include <pcap.h>
#include <sys/socket.h>

#ifdef __linux__
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#endif

#include "rawsock.h"
#include "util.h"

#ifdef __linux__
#define NL_READ_BUFFER_SIZE (64*1024*1024) // 64 KiB

static int netlink_read(int sock, char *buf, int bufsz);
static int mac_for_neighbor(int sock, char *buf, const uint8_t* ip, uint8_t *mac);
#endif

int rawsock_getdev(char **dev)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	*dev = pcap_lookupdev(errbuf);
	if(!*dev)
		fprintf(stderr, "Couldn't determine default interface: %s\n", errbuf);
	return *dev ? 0 : -1;
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
	msg->nlmsg_seq = 0;
	msg->nlmsg_pid = getpid();
	if(send(sock, msg, msg->nlmsg_len, 0) == -1) {
		perror("send");
		close(sock);
		free(buf);
		return -1;
	}

	int len = netlink_read(sock, buf, NL_READ_BUFFER_SIZE);
	if(len == -1)
		return -1;
	// Process each answer msg
	uint8_t gateway_ip[16];
	int success = 0;
	for(; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len)) {
		struct rtmsg *rtm = (struct rtmsg*) NLMSG_DATA(msg);
		if(rtm->rtm_family != AF_INET6 || rtm->rtm_table != RT_TABLE_MAIN)
			continue;

		struct rtattr *rta;
		int rtlen;

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

		// Process each attribute
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
			fprintf(stderr, "Couldn't determine the MAC address of your gateway, "
				"which appears to be %s.\n", buf2);
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
	msg->nlmsg_seq = 0;
	msg->nlmsg_pid = getpid();
	if(send(sock, msg, msg->nlmsg_len, 0) == -1) {
		perror("send");
		return -1;
	}

	int len = netlink_read(sock, buf, NL_READ_BUFFER_SIZE);
	if(len == -1)
		return -1;
	// Process each answer msg
	for(; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len)) {
		struct ndmsg *ndm = (struct ndmsg*) NLMSG_DATA(msg);
		if(ndm->ndm_family != AF_INET6)
			continue;
		if(ndm->ndm_state != NUD_REACHABLE && ndm->ndm_state != NUD_STALE &&
			ndm->ndm_state != NUD_DELAY && ndm->ndm_state != NUD_PERMANENT)
			continue;

		struct rtattr *rta = (struct rtattr*) RTM_RTA(ndm);
		int rtlen = RTM_PAYLOAD(msg);

		// Process each attribute
		uint8_t temp_mac[6];
		int success = 0;
		for(; RTA_OK(rta, rtlen); rta = RTA_NEXT(rta, rtlen)) {
			// check if we have the right addr
			if(rta->rta_type == NDA_DST)
				success = memcmp(ip, RTA_DATA(rta), 16) == 0;

			if(rta->rta_type != NDA_LLADDR)
				continue;
			memcpy(temp_mac, RTA_DATA(rta), 6);
		}

		if(success) {
			memcpy(mac, temp_mac, 6);
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

int rawsock_getsrcip(const struct sockaddr_in6 *dest, uint8_t *ip)
{
	int sock;
	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if(sock == -1)
		return -1;
	if(connect(sock, (struct sockaddr*) dest, sizeof(struct sockaddr_in6)) == -1) {
		if(errno == ENETUNREACH || errno == EAFNOSUPPORT)
			fprintf(stderr, "Warning: Your machine does not seem to have any IPv6 connectivity\n");
		close(sock);
		return -1;
	}

	struct sockaddr_in6 tmp;
	socklen_t tmplen = sizeof(struct sockaddr_in6);
	int ret = 0;
	if(getsockname(sock, (struct sockaddr*) &tmp, &tmplen) == -1)
		ret = -1;
	else
		memcpy(ip, tmp.sin6_addr.s6_addr, 16);

	close(sock);
	return ret;
}

#ifdef __linux__
static int netlink_read(int sock, char *buf, int bufsz)
{
	struct nlmsghdr *msg;
	int have = 0;

	// have I mentioned that netlink has a horrible interface?
	while(1) {
		int len = recv(sock, buf, bufsz - have, 0);
		if(len == -1) {
			perror("recv");
			return -1;
		}
		if(len + have >= bufsz) {
			fprintf(stderr, "insufficient buffer to read from netlink\n");
			return -1;
		}

		msg = (struct nlmsghdr*) buf;
		if(!NLMSG_OK(msg, len))
			return -1;

		if(msg->nlmsg_seq != 0 || msg->nlmsg_pid != getpid())
			continue; // not the one we want
		if(msg->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr*) NLMSG_DATA(msg);
			fprintf(stderr, "netlink reports error %d\n", err->error);
			return -1;
		}

		if(msg->nlmsg_type == NLMSG_DONE)
			break;
		// advance in buffer
		buf = &buf[len];
		have += len;
	}

	return have;
}
#endif
