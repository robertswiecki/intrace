/*
 * intrace
 *
 * ipv4 routines
 *
 * author: Robert Swiecki <robert@swiecki,net>
 *
 * ipv4_cksum_tcp author:
 *  Copyright (C) 2002 Sourcefire,Inc
 *  Marc Norton <mnorton@sourcefire.com>
 *  http://www.google.com/codesearch/p?hl=en&sa=N&cd=1&ct=rc#BAGwO4Atb2c/snort-1.9.1/src/checksum.h
 */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 */

#include "config.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>

#include "intrace.h"

static inline unsigned short ipv4_cksum_tcp(u_int16_t * h, u_int16_t * d, int dlen)
{
	unsigned int cksum;
	unsigned short answer = 0;

	cksum = h[0];
	cksum += h[1];
	cksum += h[2];
	cksum += h[3];
	cksum += h[4];
	cksum += h[5];

	cksum += d[0];
	cksum += d[1];
	cksum += d[2];
	cksum += d[3];
	cksum += d[4];
	cksum += d[5];
	cksum += d[6];
	cksum += d[7];
	cksum += d[8];
	cksum += d[9];

	dlen -= 20;
	d += 10;

	while (dlen >= 32) {
		cksum += d[0];
		cksum += d[1];
		cksum += d[2];
		cksum += d[3];
		cksum += d[4];
		cksum += d[5];
		cksum += d[6];
		cksum += d[7];
		cksum += d[8];
		cksum += d[9];
		cksum += d[10];
		cksum += d[11];
		cksum += d[12];
		cksum += d[13];
		cksum += d[14];
		cksum += d[15];
		d += 16;
		dlen -= 32;
	}

	while (dlen >= 8) {
		cksum += d[0];
		cksum += d[1];
		cksum += d[2];
		cksum += d[3];
		d += 4;
		dlen -= 8;
	}

	while (dlen > 1) {
		cksum += *d++;
		dlen -= 2;
	}

	if (dlen == 1) {
		*(unsigned char *)(&answer) = (*(unsigned char *)d);
		cksum += answer;
	}

	cksum = (cksum >> 16) + (cksum & 0x0000ffff);
	cksum += (cksum >> 16);

	return (unsigned short)(~cksum);
}

void ipv4_sendpkt(intrace_t * intrace, int seqSkew, int ackSkew)
{
	tcppkt4_t pkt;
	uint16_t pktSz = sizeof(pkt) - MAX_PAYL_SZ + intrace->paylSz;

	struct sockaddr_in raddr;
	struct {
		uint32_t saddr;
		uint32_t daddr;
		uint8_t zero;
		uint8_t protocol;
		uint16_t tcp_len;
	} __attribute__ ((__packed__)) pseudoh;

	raddr.sin_family = AF_INET;
	raddr.sin_port = htons(intrace->rport);
	memcpy(&raddr.sin_addr.s_addr, &intrace->rip.s_addr, sizeof(raddr.sin_addr.s_addr));

	bzero(&pkt, pktSz);

	pkt.iph.ip_v = 0x4;
	pkt.iph.ip_hl = sizeof(pkt.iph) / 4;
	pkt.iph.ip_len = htons(pktSz);
	pkt.iph.ip_id = htons(intrace->cnt);
	pkt.iph.ip_off = htons(IP_DF | (0 & IP_OFFMASK));
	pkt.iph.ip_ttl = intrace->cnt;
	pkt.iph.ip_p = IPPROTO_TCP;
	memcpy(&pkt.iph.ip_src, &intrace->lip.s_addr, sizeof(pkt.iph.ip_src));
	memcpy(&pkt.iph.ip_dst, &intrace->rip.s_addr, sizeof(pkt.iph.ip_dst));

	pkt.tcph.th_sport = htons(intrace->lport);
	pkt.tcph.th_dport = htons(intrace->rport);
	pkt.tcph.th_seq = htonl(intrace->ack + seqSkew);
	pkt.tcph.th_ack = htonl(intrace->seq + ackSkew);
	pkt.tcph.th_off = sizeof(pkt.tcph) / 4;
	pkt.tcph.th_flags = TH_ACK | TH_PUSH;
	pkt.tcph.th_win = htons(0xFFFF);
	pkt.tcph.th_urp = htons(0x0);

	memset(&pkt.payload, '\0', intrace->paylSz);

	uint16_t l4len = pktSz - sizeof(pkt.iph);
	pseudoh.saddr = pkt.iph.ip_src.s_addr;
	pseudoh.daddr = pkt.iph.ip_dst.s_addr;
	pseudoh.zero = 0x0;
	pseudoh.protocol = pkt.iph.ip_p;
	pseudoh.tcp_len = htons(l4len);

	pkt.tcph.th_sum = ipv4_cksum_tcp((u_int16_t *) & pseudoh, (u_int16_t *) & pkt.tcph, l4len);

	sendto(intrace->sender.sndSocket, &pkt, pktSz, MSG_NOSIGNAL, (struct sockaddr *)&raddr,
	       sizeof(struct sockaddr));
}

static inline int ipv4_checkTcp(intrace_t * intrace UNUSED, ip4pkt_t * pkt, uint32_t pktlen)
{
	if (pktlen < sizeof(struct ip))
		return errPkt;

	if (pktlen < ((pkt->iph.ip_hl * 4) + sizeof(struct tcphdr)))
		return errPkt;

	return errNone;
}

void ipv4_tcp_sock_ready(intrace_t * intrace, struct msghdr *msg)
{
	ip4pkt_t *pkt = msg->msg_iov->iov_base;
	uint32_t pktlen = msg->msg_iov->iov_len;

	if (ipv4_checkTcp(intrace, pkt, pktlen) < 0)
		return;

	while (pthread_mutex_lock(&intrace->mutex)) ;
	struct tcphdr *tcph =
	    (struct tcphdr *)((uint8_t *) & pkt->iph + ((uint32_t) pkt->iph.ip_hl * 4));

	if (intrace->port && ntohs(tcph->th_dport) != intrace->port
	    && ntohs(tcph->th_sport) != intrace->port) {
/* UNSAFE_ Fix length check */
	} else if ((tcph->th_flags & TH_ACK)
		   && (((intrace->ack + intrace->paylSz) == ntohl(tcph->th_ack))
		       || (intrace->ack + intrace->paylSz + 1) == ntohl(tcph->th_ack))
		   && (intrace->rip.s_addr == pkt->iph.ip_src.s_addr)
		   && intrace->cnt && intrace->cnt < MAX_HOPS) {

		int hop = intrace->cnt - 1;
		intrace->listener.proto[hop] = IPPROTO_TCP;
		memcpy(&intrace->listener.ip_trace[hop].s_addr, &pkt->iph.ip_src,
		       sizeof(pkt->iph.ip_src));
		intrace->maxhop = hop;
		intrace->cnt = MAX_HOPS;

	} else if ((tcph->th_flags & TH_RST) && intrace->cnt &&
		   (intrace->rip.s_addr == pkt->iph.ip_src.s_addr) &&
		   (intrace->lip.s_addr == pkt->iph.ip_dst.s_addr) &&
		   (intrace->lport == ntohs(tcph->th_dport)) &&
		   (intrace->rport == ntohs(tcph->th_sport)) && intrace->cnt
		   && intrace->cnt < MAX_HOPS) {

		int hop = intrace->cnt - 1;
		memcpy(&intrace->listener.ip_trace[hop].s_addr, &pkt->iph.ip_src,
		       sizeof(pkt->iph.ip_src));
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

static inline int ipv4_checkIcmp(intrace_t * intrace, ip4pkt_t * pkt, uint32_t pktlen)
{
	icmp4bdy_t *pkticmp =
	    (icmp4bdy_t *) ((uint8_t *) & pkt->iph + ((uint32_t) pkt->iph.ip_hl * 4));

	if (pktlen < sizeof(struct ip))
		return errPkt;

	if (pktlen < ((pkt->iph.ip_hl * 4) + sizeof(struct icmphdr) + sizeof(struct ip)))
		return errPkt;

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

void ipv4_icmp_sock_ready(intrace_t * intrace, struct msghdr *msg)
{
	ip4pkt_t *pkt = msg->msg_iov->iov_base;
	uint32_t pktlen = msg->msg_iov->iov_len;

	if (intrace->maxhop >= MAX_HOPS) {
		return;
	}

	int id;
	if ((id = ipv4_checkIcmp(intrace, pkt, pktlen)) < 0) {
		return;
	}

	while (pthread_mutex_lock(&intrace->mutex)) ;
	icmp4bdy_t *pkticmp =
	    (icmp4bdy_t *) ((uint8_t *) & pkt->iph + ((uint32_t) pkt->iph.ip_hl * 4));

	memcpy(&intrace->listener.ip_trace[id].s_addr, &pkt->iph.ip_src, sizeof(pkt->iph.ip_src));
	memcpy(&intrace->listener.icmp_trace[id].s_addr, &pkticmp->iph.ip_dst,
	       sizeof(pkticmp->iph.ip_dst));
	intrace->listener.proto[id] = IPPROTO_ICMP;

	if (id > intrace->maxhop)
		intrace->maxhop = id;

	while (pthread_mutex_unlock(&intrace->mutex)) ;
}
