/*
 * intrace
 *
 * Display routines
 *
 * author: Robert Swiecki <robert@swiecki,net>
 */

#include <config.h>

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

#include <intrace.h>

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

		char *header = INTRACE_NAME " " INTRACE_VERSION " " INTRACE_AUTHORS "\n";
		printf("%s", header);

		/* Lock mutex */
		while (pthread_mutex_lock(&intrace->mutex)) ;

		printf("\nR: %s/%d ", inet_ntoa(intrace->rip), intrace->rport);
		intrace->port ? printf("(%d)", intrace->port) : printf("(ANY)");

		printf(" L: %s/%d\nSEQ: 0x%08x, ACK: 0x%08x\n",
		       inet_ntoa(intrace->lip), intrace->lport, intrace->seq, intrace->ack);

		if (intrace->cnt >= MAX_HOPS)
			intrace->cnt = 0;

		if (!intrace->seq)
			printf("%-75s", "Status: Sniffing for connection packets");
		else if (!intrace->cnt)
			printf("%-75s", "Status: Press ENTER");
		else
			printf("Status: Packets sent #%-50d", intrace->cnt - 1);

		printf("\n\n");

		for (int i = 1; i <= intrace->maxhop; i++) {

			const char *pktType = "[NO RESPONSE]";

			if (intrace->listener.proto[i] == IPPROTO_TCP)
				pktType = "[TCP REPLY]";
			else if (intrace->listener.proto[i] == IPPROTO_ICMP) {

				if (intrace->listener.trace[i].s_addr != intrace->rip.s_addr)
					pktType = "[ICMP TTL-EXCEEDED]";
				else
					pktType = "[ICMP TTL-EXCEEDED] [NAT?]";
				
			} else if (intrace->listener.proto[i] == -1)
				pktType = "[TCP RST]";

			const char *pktAddr = "***";
			if (intrace->listener.trace[i].s_addr)
				pktAddr = inet_ntoa(intrace->listener.trace[i]);

			printf("%3d.    %-18s %-57s\n", i, pktAddr, pktType);

		}

		if (display_selectInput() > 0) {
			if (!intrace->cnt && intrace->seq) {
				intrace->cnt = 1;
				intrace->maxhop = 0;
				bzero(intrace->listener.trace, sizeof(intrace->listener.trace));
				display_clr();
			}
		}

		/* UnLock mutex */
		while (pthread_mutex_unlock(&intrace->mutex)) ;
		usleep(200000);
	}

	return errNone;
}
