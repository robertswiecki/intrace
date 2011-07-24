/*
 * author: Robert Swiecki <robert@swiecki.net>
 */

#ifndef _IPV6_H_
#define _IPV6_H_

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

typedef struct tcppkt6 tcppkt6_t;

struct tcppkt6 {
	struct ip6_hdr iph;
	struct tcphdr tcph;
	uint8_t payload[MAX_PAYL_SZ];
} __attribute__ ((__packed__));

struct tcp6bdy {
	struct tcphdr tcph;
} __attribute__ ((__packed__));
typedef struct tcp6bdy tcp6bdy_t;

struct icmp6bdy {
	struct icmp6_hdr icmph;
	struct ip6_hdr iph;
} __attribute__ ((__packed__));
typedef struct icmp6bdy icmp6bdy_t;

extern void ipv6_sendpkt(intrace_t * intrace, int seqSkew, int ackSkew);
extern void ipv6_tcp_sock_ready(intrace_t * intrace, struct msghdr *msg);
extern void ipv6_icmp_sock_ready(intrace_t * intrace, struct msghdr *msg);

#endif
