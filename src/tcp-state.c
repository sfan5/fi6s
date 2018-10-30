#define _POSIX_C_SOURCE 199309L // CLOCK_MONOTONIC
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "tcp.h"
#include "banner.h"

#define TCP_BUFFER_LEN BANNER_MAX_LENGTH
#define TCP_STATES_PER_CHUNK 256

#define TCP_PTR_CHUNK(ptr) ((struct tcp_states_chunk*) (ptr)->c)
#define TCP_PTR_STATE(ptr) TCP_PTR_CHUNK(ptr)->s[(ptr)->i]

struct tcp_state {
	// remote endpoint
	uint8_t srcaddr[16];
	uint16_t srcport; // == 0 indicates free entry

	// timestamps
	uint64_t creation_time; // monotonic, in ms
	uint64_t saved_timestamp;

	// local sequence numbers
	uint32_t next_lseqnum; // seqnum of next packet we would be sending

	// remote sequence numbers
	uint32_t first_rseqnum; // == <seqnum of syn-ack> + 1
	uint32_t max_rseqnum; // highest seen of (seqnum + payload len)

	// received data
	char buffer[TCP_BUFFER_LEN];
};

struct tcp_states_chunk {
	// Locked while any of the states inside this chunk may be read/written.
	// This happens on two threads:
	// - scan thread: _create, _push and _add_seqnum
	// - tcp thread: _next_expired, _destroy and the _get methods
	pthread_mutex_t lock;

	struct tcp_state s[TCP_STATES_PER_CHUNK];
	struct tcp_states_chunk *next;
};

static struct tcp_states_chunk *first;


static int create_chunk(struct tcp_states_chunk **dest);
static void internal_find_empty(tcp_state_ptr *out_p);
static int internal_find(const uint8_t *srcaddr, uint16_t srcport, tcp_state_ptr *out_p);
// !! caller is expected to hold chunk lock
static void internal_push(tcp_state_ptr *p, void *data, unsigned int length, uint32_t seqnum);
// !! end
static inline uint64_t monotonic_ms(void);

int tcp_state_init(void)
{
	return create_chunk(&first);
}

void tcp_state_create(const uint8_t *srcaddr, uint16_t srcport, uint64_t ts, uint32_t next_lseqnum, uint32_t first_rseqnum)
{
	tcp_state_ptr p;
	internal_find_empty(&p);

	struct tcp_state *s = &TCP_PTR_STATE(&p);
	memcpy(s->srcaddr, srcaddr, 16);
	s->srcport = srcport;
	s->creation_time = monotonic_ms();
	s->saved_timestamp = ts;
	s->next_lseqnum = next_lseqnum;
	s->first_rseqnum = first_rseqnum + 1;
	s->max_rseqnum = s->first_rseqnum;
#ifndef NDEBUG
	memset(s->buffer, 0, sizeof(s->buffer));
#endif

	tcp_state_unlock(&p);
}

int tcp_state_push(const uint8_t *srcaddr, uint16_t srcport,
	void *data, unsigned int length, uint32_t seqnum)
{
	tcp_state_ptr p;
	if(!internal_find(srcaddr, srcport, &p))
		return 0;

	internal_push(&p, data, length, seqnum);
	tcp_state_unlock(&p);

	return 1;
}

int tcp_state_add_seqnum(const uint8_t *srcaddr, uint16_t srcport,
	uint32_t *old, uint32_t add)
{
	tcp_state_ptr p;
	if(!internal_find(srcaddr, srcport, &p))
		return 0;

	struct tcp_state *s = &TCP_PTR_STATE(&p);
	*old = s->next_lseqnum;
	s->next_lseqnum += add;

	tcp_state_unlock(&p);
	return 1;
}


void *tcp_state_get_buffer(tcp_state_ptr *p, uint32_t *length)
{
	struct tcp_state *s = &TCP_PTR_STATE(p);
	*length = s->max_rseqnum - s->first_rseqnum;
	return s->buffer;
}

uint64_t tcp_state_get_timestamp(tcp_state_ptr *p)
{
	return TCP_PTR_STATE(p).saved_timestamp;
}

const uint8_t *tcp_state_get_remote(tcp_state_ptr *p, uint16_t *port)
{
	struct tcp_state *s = &TCP_PTR_STATE(p);
	*port = s->srcport;
	return s->srcaddr;
}


int tcp_state_next_expired(int timeout, tcp_state_ptr *out_p)
{
	struct tcp_states_chunk *cur = first;
	uint16_t i;
	const uint64_t lower = monotonic_ms() - timeout;

	pthread_mutex_lock(&cur->lock);
	do {
		for(i = 0; i < TCP_STATES_PER_CHUNK; i++) {
			if(cur->s[i].srcport == 0)
				continue;
			if(cur->s[i].creation_time <= lower)
				goto found;
		}

		if(!cur->next) {
			pthread_mutex_unlock(&cur->lock);
			return 0;
		}

		pthread_mutex_lock(&cur->next->lock);
		pthread_mutex_unlock(&cur->lock);
		cur = cur->next;
	} while(1);

found:
	out_p->c = cur;
	out_p->i = i;
	// cur->lock remains locked, to be unlocked by tcp_state_unlock
	return 1;
}

void tcp_state_delete(tcp_state_ptr *p)
{
	TCP_PTR_STATE(p).srcport = 0; // invalidate the entry
	tcp_state_unlock(p);
}

void tcp_state_unlock(tcp_state_ptr *p)
{
	pthread_mutex_unlock(&TCP_PTR_CHUNK(p)->lock);
#ifndef NDEBUG
	p->c = NULL;
#endif
}


static int create_chunk(struct tcp_states_chunk **dest)
{
	struct tcp_states_chunk *cur = calloc(1, sizeof(struct tcp_states_chunk));
	if(!cur)
		return -1;
	if(pthread_mutex_init(&cur->lock, NULL) < 0) {
		free(cur);
		return -1;
	}
	*dest = cur;
	return 0;
}

static void internal_find_empty(tcp_state_ptr *out_p)
{
	struct tcp_states_chunk *cur = first;
	uint16_t i;

	pthread_mutex_lock(&cur->lock);
	do {
		for(i = 0; i < TCP_STATES_PER_CHUNK; i++) {
			if(cur->s[i].srcport == 0)
				goto found;
		}

		if(!cur->next) {
			if(create_chunk(&cur->next) < 0) {
				fprintf(stderr, "ERROR: Ran out of memory for TCP sessions\n");
				abort();
			}
		}

		pthread_mutex_lock(&cur->next->lock);
		pthread_mutex_unlock(&cur->lock);
		cur = cur->next;
	} while(1);

found: ;
	out_p->c = cur;
	out_p->i = i;
	// cur->lock remains locked, to be unlocked by tcp_state_unlock
}

static int internal_find(const uint8_t *srcaddr, uint16_t srcport, tcp_state_ptr *out_p)
{
	struct tcp_states_chunk *cur = first;
	uint16_t i;

	pthread_mutex_lock(&cur->lock);
	do {
		for(i = 0; i < TCP_STATES_PER_CHUNK; i++) {
			if(cur->s[i].srcport == srcport && !memcmp(cur->s[i].srcaddr, srcaddr, 16))
				goto found;
		}

		if(!cur->next) {
			pthread_mutex_unlock(&cur->lock);
			return 0;
		}

		pthread_mutex_lock(&cur->next->lock);
		pthread_mutex_unlock(&cur->lock);
		cur = cur->next;
	} while(1);

found:
	out_p->c = cur;
	out_p->i = i;
	// cur->lock remains locked, to be unlocked by tcp_state_unlock
	return 1;
}

static void internal_push(tcp_state_ptr *p, void *data, unsigned int length, uint32_t seqnum)
{
	struct tcp_state *s = &TCP_PTR_STATE(p);
	if(seqnum < s->first_rseqnum) // pretend seqnum wraparound doesn't exist
		return;

	unsigned int offset = seqnum - s->first_rseqnum;
	if(offset > TCP_BUFFER_LEN)
		return;
	else if(offset + length > TCP_BUFFER_LEN)
		length = TCP_BUFFER_LEN - offset;
	memcpy(&s->buffer[offset], data, length);
	if(seqnum + length > s->max_rseqnum)
		s->max_rseqnum = seqnum + length;
}

static inline uint64_t monotonic_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000 + t.tv_sec / 1000000;
}
