/*
 * intrace
 *
 * Display routines
 *
 * author: Robert Swiecki <robert@swiecki,net>
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>

#include "intrace.h"

static inline int display_selectInput(void)
{
#define INPUTFD 0
	int ret;

	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(INPUTFD, &fds);

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 0;

	ret = select(INPUTFD + 1, &fds, NULL, NULL, &tv);

	if (ret > 0)
		tcflush(INPUTFD, TCIFLUSH);	/* Flush input fd */

	return ret;
}

static inline void display_disableScroll(void)
{
	/* Disable console scrolling */
	printf("\033[?1049h");
}

static inline void display_clr(void)
{
	/* ANSI clear code */
	printf("\033[H\033[2J");
}

static inline void display_cursPos(unsigned int x, unsigned int y)
{
	/* Move cursor to pos x,y */
	printf("\033[%u;%uH", x, y);
}

int display_process(intrace_t * intrace)
{
	display_disableScroll();
	display_clr();

	for (;;) {
		display_cursPos(0, 0);

		/* Lock mutex */
		while (pthread_mutex_lock(&intrace->mutex)) ;

		char locAddr[INET6_ADDRSTRLEN], rmtAddr[INET6_ADDRSTRLEN];
		inet_ntop(_IT_AF(intrace), _IT_LIP(intrace), locAddr, sizeof(locAddr));
		inet_ntop(_IT_AF(intrace), _IT_RIP(intrace), rmtAddr, sizeof(rmtAddr));

		printf("=========================[ %s %s ]========================\n", INTRACE_NAME, INTRACE_VERSION);

		printf("Remote: %s/%d (%d)\n", rmtAddr, intrace->rport, intrace->port ? intrace->port : 0);
		printf("Local: %s/%d\n", locAddr, intrace->lport);
		printf("Payload Size: %zu bytes, Seq: 0x%08x, Ack: 0x%08x\n", intrace->paylSz,
		       intrace->seq, intrace->ack);

		if (intrace->cnt >= MAX_HOPS)
			intrace->cnt = 0;

		if (!intrace->seq)
			printf("%-75s", "Status: Sniffing for connection packets");
		else if (!intrace->cnt)
			printf("%-75s", "Status: Press ENTER");
		else
			printf("Status: Packets sent #%-50d", intrace->cnt - 1);

		printf("\n\n");
		if (intrace->isIPv6)
			printf("%3s  %-41s  %-41s  %s\n", "#", "[src addr]", "[icmp src addr]",
			       "[pkt type]");
		else
			printf("%3s  %-17s  %-17s  %s\n", "#", "[src addr]", "[icmp src addr]",
			       "[pkt type]");

		for (int i = 1; i <= intrace->maxhop; i++) {

			const char *pktType = "NO REPLY";

			if (intrace->listener.proto[i] == IPPROTO_TCP)
				pktType = "TCP";
			else if (intrace->listener.proto[i] == IPPROTO_ICMP
				 || intrace->listener.proto[i] == IPPROTO_ICMPV6) {

				if (!_IT_IPCMP(intrace, _IT_TRACE_IP(intrace, i), _IT_RIP(intrace)))
					pktType = "ICMP_TIMXCEED";
				else
					pktType = "ICMP_TIMXCEED NAT";

			} else if (intrace->listener.proto[i] == -1)
				pktType = "TCP_RST";

			char ipPktAddr[] = "  ---                                  ";
			if (!_IT_ISANY(intrace, _IT_TRACE_IP(intrace, i))) {
				inet_ntop(_IT_AF(intrace), _IT_TRACE_IP(intrace, i), ipPktAddr,
					  strlen(ipPktAddr));
			}

			char icmpPktAddr[] = "  ---                                  ";
			if (!_IT_ISANY(intrace, _IT_TRACE_ICMP(intrace, i))) {
				inet_ntop(_IT_AF(intrace), _IT_TRACE_ICMP(intrace, i), icmpPktAddr,
					  strlen(icmpPktAddr));
			}

			if (intrace->isIPv6)
				printf("%2d.  [%-39s]  [%-39s]  [%s]\n", i, ipPktAddr, icmpPktAddr,
				       pktType);
			else
				printf("%2d.  [%-15.15s]  [%-15.15s]  [%s]\n", i, ipPktAddr,
				       icmpPktAddr, pktType);
		}

		if (display_selectInput() > 0) {
			if (!intrace->cnt && intrace->seq) {
				intrace->cnt = 1;
				intrace->maxhop = 0;
				bzero(intrace->listener.ip_trace,
				      sizeof(intrace->listener.ip_trace));
				bzero(intrace->listener.ip_trace6,
				      sizeof(intrace->listener.ip_trace6));
				bzero(intrace->listener.icmp_trace,
				      sizeof(intrace->listener.icmp_trace));
				bzero(intrace->listener.icmp_trace6,
				      sizeof(intrace->listener.icmp_trace6));
				display_clr();
			}
		}

		/* UnLock mutex */
		while (pthread_mutex_unlock(&intrace->mutex)) ;
		usleep(200000);
	}

	return errNone;
}
