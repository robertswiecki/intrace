/*
 * author: Robert Swiecki <robert@swiecki.net>
 */

#ifndef _SENDER_H_
#define _SENDER_H_

/* For FreeBSD/Sorlaris */
#include <netinet/in_systm.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#define PAYL_SZ 1

struct tcppkt {
	struct ip iph;
	struct tcphdr tcph;
	uint8_t payload[PAYL_SZ];
} __attribute__ ((__packed__));

typedef struct tcppkt tcppkt_t;

extern int sender_init(intrace_t * intrace);
extern void *sender_thr(void *arg);

#endif
