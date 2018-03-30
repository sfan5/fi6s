#define _POSIX_C_SOURCE 199309L // CLOCK_MONOTONIC
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "tcp.h"
#include "banner.h"

#define TCP_BUFFER_LEN BANNER_MAX_LENGTH

struct tcp_state {
	uint8_t srcaddr[16];
	uint16_t srcport; // == 0 indicates free entry

	uint64_t creation_time, saved_timestamp;
	uint32_t first_seqnum; // == <seqnum of syn-ack> + 1
	uint32_t max_seqnum; // highest seen (seqnum + payload len)
	char buffer[TCP_BUFFER_LEN];
};

static pthread_mutex_t states_lock;
static struct tcp_state *states;
static tcp_state_id states_count;

// !!! Below methods don't do locking !!!
static int tcp_state_find(const uint8_t *srcaddr, uint16_t srcport, tcp_state_id *out_id);
static void tcp_state_push(tcp_state_id id, void *data, unsigned int length, uint32_t seqnum);

static inline uint64_t monotonic_ms(void);

int tcp_state_init(int count)
{
	if(count <= 0)
		return -1;
	if(pthread_mutex_init(&states_lock, NULL) < 0)
		return -1;
	states = calloc(count, sizeof(struct tcp_state));
	if(!states)
		return -1;
	states_count = count;
	return 0;
}

tcp_state_id tcp_state_create(const uint8_t *srcaddr, uint16_t srcport, uint64_t ts, uint32_t first_seqnum)
{
	tcp_state_id id;
	pthread_mutex_lock(&states_lock);
	for(id = 0; id < states_count; id++) {
		if(states[id].srcport == 0)
			goto ret;
	}
#ifndef NDEBUG
	fprintf(stderr, "Dropping TCP session due to overflow\n");
#endif
	id = 0;

	ret: ;
	struct tcp_state *s = &states[id];
	s->srcport = srcport; // "claim" this entry
	s->creation_time = monotonic_ms(); // and mark it as fresh
	pthread_mutex_unlock(&states_lock);
	// rest of initialization:
	memcpy(s->srcaddr, srcaddr, 16);
	s->saved_timestamp = ts;
	s->first_seqnum = first_seqnum + 1;
	s->max_seqnum = s->first_seqnum;
#ifndef NDEBUG
	memset(s->buffer, 0, sizeof(s->buffer));
#endif
	return id;
}

static int tcp_state_find(const uint8_t *srcaddr, uint16_t srcport, tcp_state_id *out_id)
{
	for(tcp_state_id id = 0; id < states_count; id++) {
		if(states[id].srcport == srcport && !memcmp(states[id].srcaddr, srcaddr, 16)) {
			*out_id = id;
			return 1;
		}
	}
	return 0;
}

static void tcp_state_push(tcp_state_id id, void *data, unsigned int length, uint32_t seqnum)
{
	struct tcp_state *s = &states[id];
	if(seqnum < s->first_seqnum) // pretend seqnum wraparound doesn't exist
		return;

	unsigned int offset = seqnum - s->first_seqnum;
	if(offset > TCP_BUFFER_LEN)
		return;
	else if(offset + length > TCP_BUFFER_LEN)
		length = TCP_BUFFER_LEN - offset;
	memcpy(&s->buffer[offset], data, length);
	if(seqnum + length > s->max_seqnum)
		s->max_seqnum = seqnum + length; 
}

int tcp_state_find_and_push(const uint8_t *srcaddr, uint16_t srcport,
	void *data, unsigned int length, uint32_t seqnum)
{
	tcp_state_id id;
	int r = 1;
	pthread_mutex_lock(&states_lock);
	if(!tcp_state_find(srcaddr, srcport, &id)) {
		r = 0;
		goto ret;
	}
	tcp_state_push(id, data, length, seqnum);

	ret:
	pthread_mutex_unlock(&states_lock);
	return r;
}


void *tcp_state_get_buffer(tcp_state_id id, unsigned int *length)
{
	// no locking because this method is read-only
	struct tcp_state *s = &states[id];
	*length = s->max_seqnum - s->first_seqnum;
	return s->buffer;
}

uint64_t tcp_state_get_timestamp(tcp_state_id id)
{
	// no locking because this method is read-only
	return states[id].saved_timestamp;
}

const uint8_t *tcp_state_get_remote(tcp_state_id id, uint16_t *port)
{
	// no locking because this method is read-only
	struct tcp_state *s = &states[id];
	*port = s->srcport;
	return s->srcaddr;
}


int tcp_state_next_expired(int timeout, tcp_state_id *out_id)
{
	// no locking because this method is read-only
	uint64_t lower = monotonic_ms() - timeout;
	for(tcp_state_id id = 0; id < states_count; id++) {
		if(states[id].srcport == 0)
			continue;
		if(states[id].creation_time <= lower) {
			*out_id = id;
			return 1;
		}
	}
	return 0;
}

void tcp_state_destroy(tcp_state_id id)
{
	pthread_mutex_lock(&states_lock);
	states[id].srcport = 0; // invalidate the entry
	pthread_mutex_unlock(&states_lock);
}


static inline uint64_t monotonic_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000 + t.tv_sec / 1000000;
}
