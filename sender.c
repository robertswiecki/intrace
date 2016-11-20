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
#include <sys/ioctl.h>

#include "intrace.h"

static void sender_process(intrace_t * intrace)
{
	for (;;) {
		while (pthread_mutex_lock(&intrace->mutex)) ;

		if ((intrace->cnt > 0) && (intrace->cnt < MAX_HOPS)) {

			if (intrace->isIPv6) {
				ipv6_sendpkt(intrace, -1, -1);
				ipv6_sendpkt(intrace, -1, 0);
				ipv6_sendpkt(intrace, 0, -1);
				ipv6_sendpkt(intrace, 0, 0);
			} else {
				ipv4_sendpkt(intrace, -1, -1);
				ipv4_sendpkt(intrace, -1, 0);
				ipv4_sendpkt(intrace, 0, -1);
				ipv4_sendpkt(intrace, 0, 0);
			}

			intrace->cnt++;
		}

		while (pthread_mutex_unlock(&intrace->mutex)) ;
		usleep(750000);
	}
}

int sender_init(intrace_t * intrace)
{
	int tmp = 1;

	intrace->sender.sndSocket = socket(_IT_AF(intrace), SOCK_RAW, IPPROTO_RAW);
	if (intrace->sender.sndSocket < 0) {
		debug_printf(dlError, "sender: Cannot open raw socket, %s\n", strerror(errno));
		return errSocket;
	}

	if (!intrace->isIPv6 && setsockopt
	    (intrace->sender.sndSocket, _IT_IPPROTO(intrace), IP_HDRINCL, (char *)&tmp,
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
