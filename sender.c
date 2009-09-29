/*
 * intrace
 *
 * Sender
 *
 * author: Robert Swiecki <robert@swiecki,net>
 *
 * sender_cksum_tcp author:
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

#include <config.h>

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
#include <sys/ioctl.h>

#include <intrace.h>

static inline unsigned short sender_cksum_tcp(u_int16_t * h, u_int16_t * d,
					      int dlen)
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

static void sender_sendpkt(intrace_t * intrace, int seqSkew, int ackSkew)
{
	tcppkt_t pkt;
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
	memcpy(&raddr.sin_addr.s_addr, &intrace->rip.s_addr,
	       sizeof(raddr.sin_addr.s_addr));

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

	pkt.tcph.th_sum =
	    sender_cksum_tcp((u_int16_t *) & pseudoh, (u_int16_t *) & pkt.tcph,
			     l4len);

	sendto(intrace->sender.sndSocket, &pkt, pktSz, MSG_NOSIGNAL,
	       (struct sockaddr *)&raddr, sizeof(struct sockaddr));
}

static void sender_process(intrace_t * intrace)
{
	for (;;) {
		while (pthread_mutex_lock(&intrace->mutex)) ;

		if ((intrace->cnt > 0) && (intrace->cnt < MAX_HOPS)) {

			sender_sendpkt(intrace, 0, 0);
			sender_sendpkt(intrace, -1, 0);
			sender_sendpkt(intrace, 0, 1);
			sender_sendpkt(intrace, -1, 1);

			intrace->cnt++;
		}

		while (pthread_mutex_unlock(&intrace->mutex)) ;
		usleep(500000);
	}
}

int sender_init(intrace_t * intrace)
{
	char errbuf[256];
	int tmp = 1;

	intrace->sender.sndSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (intrace->sender.sndSocket < 0) {
		strerror_r(errno, errbuf, sizeof(errbuf) - 1);
		debug_printf(dlError, "sender: Cannot open raw socket, %s\n",
			     errbuf);
		return errSocket;
	}

	if (setsockopt
	    (intrace->sender.sndSocket, IPPROTO_IP, IP_HDRINCL, (char *)&tmp,
	     sizeof(tmp))) {
		debug_printf(dlError, "sender: Cannot setsockopt on socket\n");
		close(intrace->sender.sndSocket);
		return errSocket;
	}

	return errNone;
}

void *sender_thr(void *arg)
{
	sender_process((intrace_t *) arg);

	return NULL;
}
