/*
 * intrace
 *
 * Sender
 *
 * author: Robert Swiecki <robert@swiecki,net>
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

/* The procedure was found on the Internet - unknown license status!!! */
static inline uint16_t sender_cksum(uint16_t * addr, size_t cnt, uint16_t * pseudo, size_t pseudosz)
{
	register uint32_t cksum = 0;

	while (cnt > 1) {
		cksum += *(addr++);
		cnt -= 2;
	}

	while (pseudosz > 1) {
		cksum += *(pseudo++);
		pseudosz -= 2;
	}

	if (cnt > 0)
		cksum += *(uint8_t *) addr;

	while (cksum >> 16)
		cksum = (cksum & 0xffff) + (cksum >> 16);

	return ~cksum & (uint32_t) 0xffff;
}

static void sender_sendpkt(intrace_t * intrace)
{
	tcppkt_t pkt;
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

	bzero(&pkt, sizeof(pkt));

	pkt.iph.ip_v = 0x4;
	pkt.iph.ip_hl = sizeof(pkt.iph) / 4;
	pkt.iph.ip_len = htons(sizeof(pkt));
	pkt.iph.ip_id = htons(intrace->cnt);
	pkt.iph.ip_off = htons(IP_DF | (0 & IP_OFFMASK));
	pkt.iph.ip_ttl = intrace->cnt;
	pkt.iph.ip_p = IPPROTO_TCP;
	memcpy(&pkt.iph.ip_src, &intrace->lip.s_addr, sizeof(pkt.iph.ip_src));
	memcpy(&pkt.iph.ip_dst, &intrace->rip.s_addr, sizeof(pkt.iph.ip_dst));

	pkt.tcph.th_sport = htons(intrace->lport);
	pkt.tcph.th_dport = htons(intrace->rport);
	pkt.tcph.th_seq = htonl(intrace->ack);
	pkt.tcph.th_ack = htonl(intrace->seq);
	pkt.tcph.th_off = sizeof(pkt.tcph) / 4;
	pkt.tcph.th_flags = TH_ACK;
	pkt.tcph.th_win = htons(0xFFFF);
	pkt.tcph.th_urp = htons(0x0);

	memset(&pkt.payload, '\0', sizeof(pkt.payload));

	uint16_t l4len = sizeof(pkt) - sizeof(pkt.iph);
	pseudoh.saddr = pkt.iph.ip_src.s_addr;
	pseudoh.daddr = pkt.iph.ip_dst.s_addr;
	pseudoh.zero = 0x0;
	pseudoh.protocol = pkt.iph.ip_p;
	pseudoh.tcp_len = htons(l4len);

	pkt.tcph.th_sum = sender_cksum((u_int16_t *) & pkt.tcph, l4len, (u_int16_t *) & pseudoh, sizeof(pseudoh));

	sendto(intrace->sender.sndSocket, &pkt, sizeof(pkt), MSG_NOSIGNAL,
	       (struct sockaddr *)&raddr, sizeof(struct sockaddr));
}

static void sender_process(intrace_t * intrace)
{
	for (;;) {
		while (pthread_mutex_lock(&intrace->mutex)) ;

		if ((intrace->cnt > 0) && (intrace->cnt < MAX_HOPS)) {

			sender_sendpkt(intrace);
			sender_sendpkt(intrace);
			sender_sendpkt(intrace);

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
		debug_printf(dlError, "sender: Cannot open raw socket, %s\n", errbuf);
		return errSocket;
	}

	if (setsockopt(intrace->sender.sndSocket, IPPROTO_IP, IP_HDRINCL, (char *)&tmp, sizeof(tmp))) {
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
