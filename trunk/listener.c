/*
 * intrace
 *
 * Listener
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

static void listener_tcp_sock_ready(intrace_t * intrace, int sock)
{
	if (intrace->isIPv6)
		ipv6_tcp_sock_ready(intrace, sock);
	else
		ipv4_tcp_sock_ready(intrace, sock);
}

static void listener_icmp_sock_ready(intrace_t * intrace, int sock)
{
	if (intrace->isIPv6)
		ipv6_icmp_sock_ready(intrace, sock);
	else
		ipv4_icmp_sock_ready(intrace, sock);
}

static void listener_process(intrace_t * intrace)
{
	for (;;) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(intrace->listener.rcvSocketTCP, &fds);
		FD_SET(intrace->listener.rcvSocketICMP, &fds);
		int maxFd = intrace->listener.rcvSocketTCP > intrace->listener.rcvSocketICMP ?
		    intrace->listener.rcvSocketTCP : intrace->listener.rcvSocketICMP;

		if (select(maxFd + 1, &fds, NULL, NULL, NULL) < 1)
			continue;

		if (FD_ISSET(intrace->listener.rcvSocketTCP, &fds))
			listener_tcp_sock_ready(intrace, intrace->listener.rcvSocketTCP);

		if (FD_ISSET(intrace->listener.rcvSocketICMP, &fds))
			listener_icmp_sock_ready(intrace, intrace->listener.rcvSocketICMP);
	}
}

int listener_init(intrace_t * intrace)
{
	char errbuf[512];

	intrace->listener.rcvSocketTCP = socket(_IT_AF(intrace), SOCK_RAW, IPPROTO_TCP);
	if (intrace->listener.rcvSocketTCP < 0) {
		strerror_r(errno, errbuf, sizeof(errbuf) - 1);
		debug_printf(dlError, "listener: Cannot open raw TCP socket, '%s'\n", errbuf);
		return errSocket;
	}

	intrace->listener.rcvSocketICMP = socket(_IT_AF(intrace), SOCK_RAW, _IT_ICMPPROTO(intrace));
	if (intrace->listener.rcvSocketTCP < 0) {
		strerror_r(errno, errbuf, sizeof(errbuf) - 1);
		debug_printf(dlError, "listener: Cannot open raw ICMPv6 socket, '%s'\n", errbuf);
		return errSocket;
	}

	int on = 1;
	if (intrace->isIPv6
	    && setsockopt(intrace->listener.rcvSocketTCP, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) == -1) {
		strerror_r(errno, errbuf, sizeof(errbuf) - 1);
		debug_printf(dlError, "listener: Cannot set IPV6_RECVPKTINFO, '%s'\n", errbuf);
		return errSocket;
	}

	return errNone;
}

void *listener_thr(void *arg)
{
	listener_process((intrace_t *) arg);

	return NULL;
}
