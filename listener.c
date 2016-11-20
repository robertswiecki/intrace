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

#include "config.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <errno.h>
#include <stdio.h>

#include "intrace.h"

static uint32_t listener_get_packet(intrace_t * intrace UNUSED, int sock, uint8_t * buf,
				    uint32_t buflen, struct msghdr *msg)
{
	bzero(msg, sizeof(struct msghdr));

	struct iovec iov;
	iov.iov_len = buflen;
	iov.iov_base = buf;

	char addrbuf[4096];
	char ansbuf[4096];
	msg->msg_name = addrbuf;
	msg->msg_namelen = sizeof(addrbuf);
	msg->msg_iov = &iov;
	msg->msg_iovlen = 1;
	msg->msg_control = ansbuf;
	msg->msg_controllen = sizeof(ansbuf);
	msg->msg_flags = 0;

	if (recvmsg(sock, msg, MSG_WAITALL) == -1) {
		return 0;
	}

	return msg->msg_controllen;
}

static void listener_tcp_sock_ready(intrace_t * intrace, int sock)
{
	struct msghdr msg;
	uint8_t buf[4096];
	if (listener_get_packet(intrace, sock, buf, sizeof(buf), &msg) == 0) {
		debug_printf(dlError, "Cannot get TCP packet\n");
		return;
	}

	if (intrace->isIPv6)
		ipv6_tcp_sock_ready(intrace, &msg);
	else
		ipv4_tcp_sock_ready(intrace, &msg);
}

static void listener_icmp_sock_ready(intrace_t * intrace, int sock)
{
	struct msghdr msg;
	uint8_t buf[4096];
	if (listener_get_packet(intrace, sock, buf, sizeof(buf), &msg) == 0) {
		debug_printf(dlError, "Cannot get ICMP packet\n");
		return;
	}

	if (intrace->isIPv6)
		ipv6_icmp_sock_ready(intrace, &msg);
	else
		ipv4_icmp_sock_ready(intrace, &msg);
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
	intrace->listener.rcvSocketTCP = socket(_IT_AF(intrace), SOCK_RAW, IPPROTO_TCP);
	if (intrace->listener.rcvSocketTCP < 0) {
		debug_printf(dlError, "listener: Cannot open raw TCP socket, '%s'\n",
			     strerror(errno));
		return errSocket;
	}

	intrace->listener.rcvSocketICMP = socket(_IT_AF(intrace), SOCK_RAW, _IT_ICMPPROTO(intrace));
	if (intrace->listener.rcvSocketTCP < 0) {
		debug_printf(dlError, "listener: Cannot open raw ICMPv6 socket, '%s'\n",
			     strerror(errno));
		return errSocket;
	}

	int on = 1;
	if (setsockopt
	    (intrace->listener.rcvSocketTCP, _IT_IPPROTO(intrace), _IT_PKTINFO(intrace), &on,
	     sizeof(on)) == -1) {
		debug_printf(dlError, "listener: Cannot set IPV6_RECVPKTINFO on TCP socket, '%s'\n",
			     strerror(errno));
		return errSocket;
	}
	if (setsockopt
	    (intrace->listener.rcvSocketICMP, _IT_IPPROTO(intrace), _IT_PKTINFO(intrace), &on,
	     sizeof(on)) == -1) {
		debug_printf(dlError,
			     "listener: Cannot set IPV6_RECVPKTINFO on ICMP socket, '%s'\n",
			     strerror(errno));
		return errSocket;
	}

	return errNone;
}

void *listener_thr(void *arg)
{
	listener_process((intrace_t *) arg);

	return NULL;
}
