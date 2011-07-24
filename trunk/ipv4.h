/*
 * author: Robert Swiecki <robert@swiecki.net>
 */

#ifndef _IPV4_H_
#define _IPV4_H_

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

typedef struct tcppkt4 tcppkt4_t;

struct tcppkt4 {
	struct ip iph;
	struct tcphdr tcph;
	uint8_t payload[MAX_PAYL_SZ];
} __attribute__ ((__packed__));

struct ip4pkt {
	struct ip iph;
	char dummy[1500];
} __attribute__ ((__packed__));
typedef struct ip4pkt ip4pkt_t;

struct icmp4bdy {
	struct icmphdr icmph;
	struct ip iph;
} __attribute__ ((__packed__));
typedef struct icmp4bdy icmp4bdy_t;

extern void ipv4_sendpkt(intrace_t * intrace, int seqSkew, int ackSkew);
extern void ipv4_tcp_sock_ready(intrace_t * intrace, struct msghdr *msg);
extern void ipv4_icmp_sock_ready(intrace_t * intrace, struct msghdr *msg);

#endif
