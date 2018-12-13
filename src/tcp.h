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
typedef struct {
	void *c;
	uint16_t i;
} tcp_state_ptr;
struct frame_ip;

void tcp_prepare(struct tcp_header *pkt);
void tcp_modify(struct tcp_header *pkt, int srcport, int dstport);
void tcp_make_syn(struct tcp_header *pkt, uint32_t seqnum);
void tcp_make_rst(struct tcp_header *pkt, uint32_t seqnum);
void tcp_make_ack(struct tcp_header *pkt, uint32_t seqnum, uint32_t acknum);
void tcp_checksum(const struct frame_ip *ipf, struct tcp_header *pkt, uint16_t dlen);

void tcp_decode_header(const struct tcp_header *pkt, unsigned int *data_offset);
void tcp_decode(const struct tcp_header *pkt, int *srcport, int *dstport);
void tcp_decode2(const struct tcp_header *pkt, uint32_t *seqnum, uint32_t *acknum);


int tcp_state_init(void);
void tcp_state_create(const uint8_t *srcaddr, uint16_t srcport,
	uint64_t ts, uint32_t next_lseqnum, uint32_t first_rseqnum);

// both will leave state locked for caller to unlock (or delete)
int tcp_state_find(const uint8_t *srcaddr, uint16_t srcport, tcp_state_ptr *out_p);
int tcp_state_next_expired(int timeout_ms, tcp_state_ptr *out_p);

void tcp_state_push(tcp_state_ptr *p, void *data, uint32_t length, uint32_t seqnum);
void tcp_state_add_seqnum(tcp_state_ptr *p, uint32_t *old, uint32_t add);
void tcp_state_set_fin(tcp_state_ptr *p);

void *tcp_state_get_buffer(tcp_state_ptr *p, uint32_t *length); // writable!
void tcp_state_get_misc(tcp_state_ptr *p, uint64_t *timestamp, int *fin);
const uint8_t *tcp_state_get_remote(tcp_state_ptr *p, uint16_t *port);

void tcp_state_delete(tcp_state_ptr *p);
void tcp_state_unlock(tcp_state_ptr *p);

#endif // _TCP_H
