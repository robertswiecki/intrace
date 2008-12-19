/*
 * intrace
 *
 * Listener
 *
 * author: Robert Swiecki <robert@swiecki,net>
 */

#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <errno.h>
#include <stdio.h>

#include <intrace.h>

static void listener_tcp(intrace_t * intrace, pkt_t * pkt, uint32_t pktlen)
{
	struct tcphdr *tcph = (struct tcphdr *)((uint8_t*)&pkt->iph + ((uint32_t) pkt->iph.ip_hl * 4));

	while (pthread_mutex_lock(&intrace->mutex)) ;

	if (intrace->port && ntohs(tcph->th_dport) != intrace->port &&
			ntohs(tcph->th_sport) != intrace->port) {
/* That's bad ;) */
	} else if ((tcph->th_flags & TH_ACK) &&
	    ((intrace->ack + PAYL_SZ) == ntohl(tcph->th_ack)) &&
	    (intrace->rip.s_addr == pkt->iph.ip_src.s_addr) && intrace->cnt && intrace->cnt < MAX_HOPS) {

		int hop = intrace->cnt - 1;
		memcpy(&intrace->listener.trace[hop].s_addr, &pkt->iph.ip_src, sizeof(pkt->iph.ip_src));
		intrace->listener.proto[hop] = IPPROTO_TCP;
		intrace->maxhop = hop;

		intrace->cnt = MAX_HOPS;
	} else if ((tcph->th_flags & TH_RST) && intrace->cnt &&
		   (intrace->rip.s_addr == pkt->iph.ip_src.s_addr) &&
		   (intrace->lip.s_addr == pkt->iph.ip_dst.s_addr) &&
		   (intrace->lport == ntohs(tcph->th_dport)) &&
		   (intrace->rport == ntohs(tcph->th_sport)) && intrace->cnt && intrace->cnt < MAX_HOPS) {

		int hop = intrace->cnt - 1;
		memcpy(&intrace->listener.trace[hop].s_addr, &pkt->iph.ip_src, sizeof(pkt->iph.ip_src));
		intrace->listener.proto[hop] = -1;
		intrace->maxhop = hop;

		intrace->cnt = MAX_HOPS;
	} else if (intrace->rip.s_addr == pkt->iph.ip_src.s_addr) {

		memcpy(&intrace->lip, &pkt->iph.ip_dst, sizeof(pkt->iph.ip_dst));
		intrace->rport = ntohs(tcph->th_sport);
		intrace->lport = ntohs(tcph->th_dport);
		if (ntohl(tcph->th_seq))
			intrace->seq = ntohl(tcph->th_seq);
		if (ntohl(tcph->th_ack))
			intrace->ack = ntohl(tcph->th_ack);
	}

	while (pthread_mutex_unlock(&intrace->mutex)) ;
}

static inline int listener_checkIcmp(intrace_t * intrace, pkt_t * pkt, uint32_t pktlen)
{
	icmpbdy_t *pkticmp = (icmpbdy_t *)((uint8_t*)&pkt->iph + ((uint32_t)pkt->iph.ip_hl * 4));

	if (((uint8_t*)pkticmp - (uint8_t*)pkt + sizeof(struct icmphdr) + sizeof(struct ip)) > pktlen)
		return errPkt;

	/* F..n linux ;) */
#ifdef __linux__
	if (pkticmp->icmph.type != ICMP_TIMXCEED)
		return errPkt;
#else
	if (pkticmp->icmph.icmp_type != ICMP_TIMXCEED)
		return errPkt;
#endif

	if (pkticmp->iph.ip_src.s_addr != intrace->lip.s_addr)
		return errPkt;

	if (pkticmp->iph.ip_dst.s_addr != intrace->rip.s_addr)
		return errPkt;

	if (pkticmp->iph.ip_p != IPPROTO_TCP)
		return errPkt;

	int id = ntohs(pkticmp->iph.ip_id);
	if (id >= MAX_HOPS)
		return errPkt;

	return id;
}

static void listener_icmp(intrace_t * intrace, pkt_t * pkt, uint32_t pktlen)
{
	int id;

	while (pthread_mutex_lock(&intrace->mutex)) ;

	if (intrace->maxhop >= MAX_HOPS) {
		while (pthread_mutex_unlock(&intrace->mutex)) ;
		return;
	}

	if ((id = listener_checkIcmp(intrace, pkt, pktlen)) < 0) {
		while (pthread_mutex_unlock(&intrace->mutex)) ;
		return;
	}

	memcpy(&intrace->listener.trace[id].s_addr, &pkt->iph.ip_src, sizeof(pkt->iph.ip_src));
	intrace->listener.proto[id] = IPPROTO_ICMP;

	if (id > intrace->maxhop) ;
	intrace->maxhop = id;

	while (pthread_mutex_unlock(&intrace->mutex)) ;
}

static void listener_process(intrace_t * intrace)
{
	pkt_t pkt;
	size_t pktSize;
	fd_set fds;

	for (;;) {
		FD_ZERO(&fds);
		FD_SET(intrace->listener.rcvSocketTCP, &fds);
		FD_SET(intrace->listener.rcvSocketICMP, &fds);

		int maxFd =
		    (intrace->listener.rcvSocketTCP >
		     intrace->listener.rcvSocketICMP) ? intrace->listener.rcvSocketTCP : intrace->listener.
		    rcvSocketICMP;

		if (select(maxFd + 1, &fds, NULL, NULL, NULL) < 1)
			continue;

		if ((pktSize = recv(intrace->listener.rcvSocketTCP, &pkt, sizeof(pkt), MSG_TRUNC | MSG_DONTWAIT)) != -1)
			listener_tcp(intrace, &pkt, pktSize);

		if ((pktSize =
		     recv(intrace->listener.rcvSocketICMP, &pkt, sizeof(pkt), MSG_TRUNC | MSG_DONTWAIT)) != -1)
			listener_icmp(intrace, &pkt, pktSize);
	}
}

int listener_init(intrace_t * intrace)
{
	char errbuf[512];

	intrace->listener.rcvSocketTCP = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (intrace->listener.rcvSocketTCP < 0) {
		strerror_r(errno, errbuf, sizeof(errbuf) - 1);
		debug_printf(dlError, "listener: Cannot open raw TCP socket, '%s'\n", errbuf);
		return errSocket;
	}

	intrace->listener.rcvSocketICMP = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (intrace->listener.rcvSocketICMP < 0) {
		strerror_r(errno, errbuf, sizeof(errbuf) - 1);
		debug_printf(dlError, "listener: Cannot open raw ICMP socket, '%s'\n", errbuf);
		close(intrace->listener.rcvSocketTCP);
		return errSocket;
	}

	return errNone;
}

void *listener_thr(void *arg)
{
	listener_process((intrace_t *) arg);

	return NULL;
}
