#include <stdio.h>
#include <string.h>
#include <unistd.h>
// pcap.h breaks if you don't define these:
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
#include <pcap.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "rawsock.h"
#include "util.h"

static int netlink_read(int sock, char *buf, int bufsz);

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
	int sock;
	char buf[8192];
	struct nlmsghdr *msg;

	sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if(sock == -1) {
		perror("socket");
		return -1;
	}

	// Ask for all routes
	memset(buf, 0, sizeof(buf));
	msg = (struct nlmsghdr*) buf;
	msg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	msg->nlmsg_type = RTM_GETROUTE;
	msg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	msg->nlmsg_seq = 0;
	msg->nlmsg_pid = getpid();
	if(send(sock, msg, msg->nlmsg_len, 0) == -1) {
		perror("send");
		close(sock);
		return -1;
	}

	int len = netlink_read(sock, buf, sizeof(buf));
	if(len == -1)
		return -1;
	// Process each answer msg
	char ifname[IF_NAMESIZE] = {0};
	int success = 0;
	for(; NLMSG_OK(msg, len); msg = NLMSG_NEXT(msg, len)) {
		struct rtmsg *rtm = (struct rtmsg*) NLMSG_DATA(msg);
		if(rtm->rtm_family != AF_INET6 || rtm->rtm_table != RT_TABLE_MAIN)
			continue;

		struct rtattr *rta = (struct rtattr*) RTM_RTA(rtm);
		int rtlen = RTM_PAYLOAD(msg);
		// Process each attribute
		for(; RTA_OK(rta, rtlen); rta = RTA_NEXT(rta, rtlen)) {
			// Check that we have the right interface
			if(rta->rta_type == RTA_OIF)
				if_indextoname(*(int*) RTA_DATA(rta), ifname);
			if(strcmp(ifname, dev) != 0)
				continue;

			if(rta->rta_type != RTA_GATEWAY)
				continue;
			uint8_t *addr = (uint8_t*) RTA_DATA(rta);
			// link-local addr (MAC-based)
			if(addr[0] == 0xfe && addr[1] == 0x80 &&
				addr[11] == 0xff && addr[12] == 0xfe)
			{
				memcpy(mac, &addr[8], 3);
				memcpy(&mac[3], &addr[13], 3);
				*mac ^= 0x02; // ???
				success = 1;
				continue; // a "break" might cause us to miss an RTA_OIF leading to incorrect data
			}

			char buf2[IPV6_STRING_MAX];
			ipv6_string(buf2, addr);
			fprintf(stderr, "Couldn't auto-detect gateway mac as its "
				"address (%s) is not a link-local one.\n", buf2);
		}
	}

	close(sock);
	return success ? 0 : -1;
}

int rawsock_getmac(const char *dev, uint8_t *mac)
{
	FILE *f;
	char buf[64];

	snprintf(buf, sizeof(buf), "/sys/class/net/%s/address", dev);
	f = fopen(buf, "r");
	if(!f)
		return -1;

	int rd = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	return rd > 0 ? parse_mac(buf, mac) : -1;
}

int rawsock_getsrcip(const struct sockaddr_in6 *dest, uint8_t *ip)
{
	int sock;
	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if(sock == -1)
		return -1;
	if(connect(sock, (struct sockaddr*) dest, sizeof(struct sockaddr_in6)) == -1) {
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

static int netlink_read(int sock, char *buf, int bufsz)
{
	struct nlmsghdr *msg;
	int have = 0;

	// Have I mentioned that netlink has a horrible interface?
	while(1) {
		int len = recv(sock, buf, bufsz - have, 0);
		if(len == -1) {
			perror("recv");
			return -1;
		}

		msg = (struct nlmsghdr*) buf;
		if(!NLMSG_OK(msg, len))
			return -1;

		if(msg->nlmsg_seq != 0 || msg->nlmsg_pid != getpid())
			continue; // msg not for us
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
