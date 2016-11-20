/*
 *
 * intrace
 *
 * author: R. Swiecki <robert@swiecki.net>
 */

#ifndef _INTRACE_H_
#define _INTRACE_H_

#include <config.h>

#include <sys/param.h>
#include <sys/types.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

enum fMode {
	ANY = 0,
	IPV4 = 1,
	IPV6 = 2
};

typedef struct {
	pthread_mutex_t mutex;

	char *hostname;
	uint16_t port;
	size_t paylSz;

	struct in_addr rip;
	struct in_addr lip;
	struct in6_addr rip6;
	struct in6_addr lip6;
	uint16_t rport;
	uint16_t lport;
	uint32_t seq;
	uint32_t ack;

	enum fMode familyMode;
	bool isIPv6;
	int maxhop;
	int cnt;
	int if_index;

	struct {
		int rcvSocketTCP;
		int rcvSocketICMP;

		struct in_addr ip_trace[MAX_HOPS + 1];
		struct in_addr icmp_trace[MAX_HOPS + 1];
		struct in6_addr ip_trace6[MAX_HOPS + 1];
		struct in6_addr icmp_trace6[MAX_HOPS + 1];
		int16_t proto[MAX_HOPS + 1];
	} listener;

	struct {
		int sndSocket;
	} sender;
} intrace_t;

#define _IT_AF(i) (i->isIPv6 ? AF_INET6 : AF_INET)
#define _IT_IPPROTO(i) (i->isIPv6 ? IPPROTO_IPV6 : IPPROTO_IP)
#define _IT_PKTINFO(i) (i->isIPv6 ? IPV6_RECVPKTINFO : IP_PKTINFO)
#define _IT_ICMPPROTO(i) (i->isIPv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP)
#define _IT_LIP(i) (i->isIPv6 ? (void*)i->lip6.s6_addr : (void*)&i->lip.s_addr)
#define _IT_RIP(i) (i->isIPv6 ? (void*)i->rip6.s6_addr : (void*)&i->rip.s_addr)
#define _IT_TRACE_IP(i, d) (i->isIPv6 ? (void*)i->listener.ip_trace6[d].s6_addr : (void*)&i->listener.ip_trace[d].s_addr)
#define _IT_TRACE_ICMP(i, d) (i->isIPv6 ? (void*)i->listener.icmp_trace6[d].s6_addr : (void*)&i->listener.icmp_trace[d].s_addr)
#define _IT_IPSTR(i) (i->isIPv6 ? "IPv6" : "IPv4" )
#define _IT_IPCMP(i, f, s) (!memcmp(f, s, i->isIPv6 ? 16 : 4))
#define _IT_ISANY(i, a) (!memcmp(a, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", i->isIPv6 ? 16 : 4))

#include <errors.h>
#include <debug.h>
#include <threads.h>
#include <sender.h>
#include <listener.h>
#include <display.h>
#include <ipv4.h>
#include <ipv6.h>

#endif
