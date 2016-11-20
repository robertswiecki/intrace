/*
 * intrace
 *
 * ipv6 routines
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

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include "intrace.h"

static uint16_t in_cksum(const uint16_t * addr, uint32_t len, uint32_t csum)
{
	int nleft = len;
	const u_short *w = addr;
	u_short answer;
	int sum = csum;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1)
		sum += htons(*(u_char *) w << 8);

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

static uint32_t nextproto6_cksum(const struct ip6_hdr *ip6, const uint16_t * data, uint32_t len,
				 uint32_t next_proto)
{
	union ip6_pseudo_hdr {
		struct {
			struct in6_addr ph_src;
			struct in6_addr ph_dst;
			u_int32_t ph_len;
			u_int8_t ph_zero[3];
			u_int8_t ph_nxt;
		} ph;
		u_int16_t pa[20];
	};
	size_t i;
	u_int32_t sum = 0;
	union ip6_pseudo_hdr phu;

	memset(&phu, 0, sizeof(phu));
	phu.ph.ph_src = ip6->ip6_src;
	phu.ph.ph_dst = ip6->ip6_dst;
	phu.ph.ph_len = htonl(len);
	phu.ph.ph_nxt = next_proto;

	for (i = 0; i < sizeof(phu.pa) / sizeof(phu.pa[0]); i++) {
		sum += phu.pa[i];
	}

	return in_cksum(data, len, sum);
}

void ipv6_sendpkt(intrace_t * intrace, int seqSkew, int ackSkew)
{
	tcppkt6_t pkt;
	uint16_t pktSz = sizeof(pkt) - MAX_PAYL_SZ + intrace->paylSz;

	struct sockaddr_in6 raddr;
	bzero(&raddr, sizeof(raddr));

	raddr.sin6_family = AF_INET6;
	memcpy(raddr.sin6_addr.s6_addr, intrace->rip6.s6_addr, sizeof(pkt.iph.ip6_dst.s6_addr));

	uint16_t l4len = pktSz - sizeof(pkt.iph);
	bzero(&pkt, pktSz);

#define IP6_VERSION 6
	pkt.iph.ip6_flow = htonl((IP6_VERSION << 28) | intrace->cnt);
	pkt.iph.ip6_plen = htons(l4len);
	pkt.iph.ip6_nxt = IPPROTO_TCP;
	pkt.iph.ip6_hlim = intrace->cnt;

	memcpy(pkt.iph.ip6_src.s6_addr, intrace->lip6.s6_addr, sizeof(pkt.iph.ip6_src.s6_addr));
	memcpy(pkt.iph.ip6_dst.s6_addr, intrace->rip6.s6_addr, sizeof(pkt.iph.ip6_dst.s6_addr));

	pkt.tcph.th_sport = htons(intrace->lport);
	pkt.tcph.th_dport = htons(intrace->rport);
	pkt.tcph.th_seq = htonl(intrace->ack + seqSkew);
	pkt.tcph.th_ack = htonl(intrace->seq + ackSkew);
	pkt.tcph.th_off = sizeof(pkt.tcph) / 4;
	pkt.tcph.th_flags = TH_ACK | TH_PUSH;
	pkt.tcph.th_win = htons(0xFFFF);
	pkt.tcph.th_urp = htons(0x0);

	memset(&pkt.payload, '\0', intrace->paylSz);

	pkt.tcph.th_sum = nextproto6_cksum(&pkt.iph, (uint16_t *) & pkt.tcph, l4len, IPPROTO_TCP);

	struct msghdr msgh;
	struct cmsghdr *cmsg;
	struct in6_pktinfo *pinfo;
	char cbuf[CMSG_SPACE(sizeof(*pinfo))];
	struct iovec iov;

	iov.iov_base = &pkt;
	iov.iov_len = sizeof(pkt);

	msgh.msg_name = &raddr;
	msgh.msg_namelen = sizeof(raddr);
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_flags = 0;
	memset(cbuf, 0, CMSG_SPACE(sizeof(*pinfo)));
	cmsg = (struct cmsghdr *)cbuf;
	pinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	pinfo->ipi6_ifindex = intrace->if_index;
	cmsg->cmsg_len = CMSG_LEN(sizeof(*pinfo));
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;
	msgh.msg_control = cmsg;
	msgh.msg_controllen = cmsg->cmsg_len;

	sendmsg(intrace->sender.sndSocket, &msgh, MSG_NOSIGNAL);
}

static bool ipv6_extract_srcdst(intrace_t * intrace, struct msghdr *msg, struct in6_addr *src,
				struct in6_addr *dst)
{
	struct sockaddr_in6 *sa = (struct sockaddr_in6 *)msg->msg_name;
	memcpy(src->s6_addr, sa->sin6_addr.s6_addr, sizeof(src->s6_addr));

	struct cmsghdr *cmsg;
	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == IPV6_PKTINFO)) {
			struct in6_pktinfo *pktInfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			memcpy(dst->s6_addr, pktInfo->ipi6_addr.s6_addr, sizeof(dst->s6_addr));
			intrace->if_index = pktInfo->ipi6_ifindex;
			return true;
		}
	}

	return false;
}

static inline int ipv6_checkTcp(intrace_t * intrace UNUSED, struct tcphdr *pkt UNUSED,
				uint32_t pktlen)
{
	if (pktlen < sizeof(struct tcphdr))
		return errPkt;

	return errNone;
}

void ipv6_tcp_sock_ready(intrace_t * intrace, struct msghdr *msg)
{
	struct in6_addr src, dst;
	struct tcphdr *tcph = (struct tcphdr *)msg->msg_iov->iov_base;
	uint32_t pktlen = msg->msg_iov->iov_len;

	if (ipv6_checkTcp(intrace, tcph, pktlen) < 0)
		return;

	if (!ipv6_extract_srcdst(intrace, msg, &src, &dst)) {
		debug_printf(dlError, "Cannot get IPv6 TCP packet's src/dst IP addresses\n");
		return;
	}

	while (pthread_mutex_lock(&intrace->mutex)) ;

	if (intrace->port && ntohs(tcph->th_dport) != intrace->port
	    && ntohs(tcph->th_sport) != intrace->port) {
/* UNSAFE_ Fix length check */
	} else if ((tcph->th_flags & TH_ACK)
		   && (((intrace->ack + intrace->paylSz) == ntohl(tcph->th_ack))
		       || (intrace->ack + intrace->paylSz + 1) == ntohl(tcph->th_ack))
		   && _IT_IPCMP(intrace, intrace->rip6.s6_addr, src.s6_addr)
		   && intrace->cnt && intrace->cnt < MAX_HOPS) {

		int hop = intrace->cnt - 1;
		intrace->listener.proto[hop] = IPPROTO_TCP;
		memcpy(intrace->listener.ip_trace6[hop].s6_addr,
		       src.s6_addr, sizeof(intrace->listener.ip_trace6[hop].s6_addr));
		intrace->maxhop = hop;
		intrace->cnt = MAX_HOPS;

	} else if ((tcph->th_flags & TH_RST) && intrace->cnt &&
		   _IT_IPCMP(intrace, intrace->rip6.s6_addr, src.s6_addr) &&
		   _IT_IPCMP(intrace, intrace->lip6.s6_addr, dst.s6_addr) &&
		   (intrace->lport == ntohs(tcph->th_dport)) &&
		   (intrace->rport == ntohs(tcph->th_sport)) && intrace->cnt
		   && intrace->cnt < MAX_HOPS) {

		int hop = intrace->cnt - 1;

		memcpy(intrace->listener.ip_trace6[hop].s6_addr, src.s6_addr, sizeof(src.s6_addr));

		intrace->listener.proto[hop] = -1;
		intrace->maxhop = hop;
		intrace->cnt = MAX_HOPS;

	} else if (_IT_IPCMP(intrace, intrace->rip6.s6_addr, src.s6_addr)) {

		memcpy(intrace->lip6.s6_addr, dst.s6_addr, sizeof(intrace->lip6.s6_addr));
		intrace->rport = ntohs(tcph->th_sport);
		intrace->lport = ntohs(tcph->th_dport);
		if (ntohl(tcph->th_seq))
			intrace->seq = ntohl(tcph->th_seq);
		if (ntohl(tcph->th_ack))
			intrace->ack = ntohl(tcph->th_ack);
	}
	while (pthread_mutex_unlock(&intrace->mutex)) ;
}

static inline int ipv6_checkIcmp(intrace_t * intrace, icmp6bdy_t * pkt, uint32_t pktlen)
{
	icmp6bdy_t *pkticmp = pkt;

	if (pktlen < (sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr)))
		return errPkt;

	if (pkticmp->icmph.icmp6_type != ICMP6_TIME_EXCEEDED)
		return errPkt;

	if (!_IT_IPCMP(intrace, pkticmp->iph.ip6_src.s6_addr, intrace->lip6.s6_addr))
		return errPkt;

	if (!_IT_IPCMP(intrace, pkticmp->iph.ip6_dst.s6_addr, intrace->rip6.s6_addr))
		return errPkt;

	int id = ntohl(pkticmp->iph.ip6_flow) & 0x000FFFFF;
	if (id >= MAX_HOPS)
		return errPkt;

	return id;
}

void ipv6_icmp_sock_ready(intrace_t * intrace, struct msghdr *msg)
{
	icmp6bdy_t *pkt = (icmp6bdy_t *) msg->msg_iov->iov_base;
	uint32_t pktlen = msg->msg_iov->iov_len;

	struct in6_addr src, dst;
	if (!ipv6_extract_srcdst(intrace, msg, &src, &dst)) {
		debug_printf(dlError, "Cannot get IPv6 ICMP packet's src/dst IP addresses\n");
		return;
	}

	int id;
	if ((id = ipv6_checkIcmp(intrace, pkt, pktlen)) < 0)
		return;

	while (pthread_mutex_lock(&intrace->mutex)) ;

	if (intrace->maxhop >= MAX_HOPS) {
		while (pthread_mutex_unlock(&intrace->mutex)) ;
		return;
	}

	memcpy(intrace->listener.ip_trace6[id].s6_addr, src.s6_addr, sizeof(src.s6_addr));
	memcpy(intrace->listener.icmp_trace6[id].s6_addr, pkt->iph.ip6_dst.s6_addr,
	       sizeof(pkt->iph.ip6_dst.s6_addr));
	intrace->listener.proto[id] = IPPROTO_ICMPV6;

	if (id > intrace->maxhop)
		intrace->maxhop = id;

	while (pthread_mutex_unlock(&intrace->mutex)) ;
}
