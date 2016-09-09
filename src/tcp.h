#ifndef _TCP_H
#define _TCP_H

#include <stdint.h>

#define TCP_HEADER_SIZE 20

struct tcp_header {
	uint16_t srcport; // Source port
	uint16_t dstport; // Destination port
	uint32_t seqnum; // Sequence number
	uint32_t acknum; // Acknowledgment number
	uint8_t
		reserved1:4, // Reserved (includes 1 unimporatant flag)
		offset:4; // Data offset
	uint8_t
		f_fin:1, // Finish flag
		f_syn:1, // SYN flag
		f_rst:1, // Reset flag
		f_psh:1, // Push flag
		f_ack:1, // ACK flag
		f_urg:1, // Urgent flag
		reserved2:2; // Reserved (unimportant flags)
	uint16_t winsz; // Window size
	uint16_t csum; // Checksum
	uint16_t urgptr; // Urgent pointer
} __attribute__((packed));
struct frame_ip;

void tcp_prepare(struct tcp_header *pkt);
void tcp_modify(struct tcp_header *pkt, int srcport, int dstport);
void tcp_synpkt(struct tcp_header *pkt);
void tcp_checksum(const struct frame_ip *ipf, struct tcp_header *pkt);

void tcp_decode(const struct tcp_header *pkt, int *srcport, int *dstport);

#endif // _TCP_H
