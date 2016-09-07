#define _DEFAULT_SOURCE // htobe16()
#include <string.h>
#include <endian.h>

#include "rawsock.h"

static uint8_t eth_src[6], eth_dst[6];

static uint8_t ip_src[16], ip_ttl;


void rawsock_eth_settings(const uint8_t *src, const uint8_t *dst)
{
	memcpy(eth_src, src, 6);
	memcpy(eth_dst, dst, 6);
}

void rawsock_eth_prepare(struct frame_eth *f, int type)
{
	memcpy(f->dest, eth_dst, 16);
	memcpy(f->src, eth_src, 16);
	f->type = htobe16(type & 0xffff);
}

void rawsock_eth_decode(const struct frame_eth *f, int *type)
{
	*type = be16toh(f->type);
}


void rawsock_ip_settings(const uint8_t *src, int ttl)
{
	memcpy(ip_src, src, 16);
	ip_ttl = ttl & 0xff;
}

void rawsock_ip_prepare(struct frame_ip *f, int type)
{
	f->ver = 6;
	f->traffic1 = 0;
	f->traffic2 = 0;
	f->flow1 = 0;
	f->flow2 = 0;
	f->next = type & 0xff;
	f->ttl = ip_ttl;
	memcpy(f->src, ip_src, 16);
}

void rawsock_ip_modify(struct frame_ip *f, int length, const uint8_t *dst)
{
	f->len = htobe16(length & 0xffff);
	memcpy(f->dest, dst, 16);
}

void rawsock_ip_decode(const struct frame_ip *f, int *type, int *length, const uint8_t **src, const uint8_t **dst)
{
	if(type)
		*type = f->next;
	if(length)
		*length = be16toh(f->len);
	if(src)
		*src = (const uint8_t*) &f->src;
	if(dst)
		*dst = (const uint8_t*) &f->dest;
}
