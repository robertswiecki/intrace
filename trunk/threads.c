/*
 * intrace
 *
 * Threads
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

#include <pthread.h>
#include <netdb.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <intrace.h>

extern int h_errno;

static char *thread_err2asc(int err)
{
	switch (err) {
	case NETDB_INTERNAL:
		return strerror(errno);
		break;
	case NETDB_SUCCESS:
		return "No problem";
		break;
	case HOST_NOT_FOUND:
		return "Authoritative Answer. Host not found";
		break;
	case TRY_AGAIN:
		return "Non-Authoritative. Host not found, or SERVERFAIL";
		break;
	case NO_RECOVERY:
		return "Non recoverable errors, FORMERR, REFUSED, NOTIMP";
		break;
	case NO_DATA:
		return "No valid name, no data record of requested type";
		break;
	default:
		return "Strange, shouldn't happen";
		break;
	}

	return "?";
}

int threads_process(intrace_t * intrace)
{
	int err;
	pthread_attr_t attr;
	pthread_t t;
	struct hostent *he;

	if (pthread_mutex_init(&intrace->mutex, NULL) != 0) {
		debug_printf(dlFatal, "threads: Mutex initialization failed\n");
		return errMutex;
	}

	debug_printf(dlDebug, "Resolving '%s'\n", intrace->hostname);
	if (!(he = gethostbyname(intrace->hostname))) {
		debug_printf(dlFatal,
			     "threads: Cannot resolve IPv4 for '%s': '%s' (%d).\n",
			     intrace->hostname, thread_err2asc(h_errno),
			     h_errno);
		return errResolve;
	}

	if (he->h_length != IPVERSION) {
		debug_printf(dlFatal, "threads: not an IPv4 addr, len=%d\n",
			     he->h_length);
		return errResolve;
	}

	memcpy(&intrace->rip.s_addr, he->h_addr, sizeof(intrace->rip.s_addr));
	debug_printf(dlDebug, "IPv4 for '%s' resolved='%s'\n",
		     intrace->hostname, inet_ntoa(intrace->rip));

	if ((err = listener_init(intrace)) != errNone) {
		debug_printf(dlFatal,
			     "threads: Listener initialization failed, err=%d'\n",
			     err);
		return err;
	}

	if ((err = sender_init(intrace)) != errNone) {
		debug_printf(dlFatal,
			     "threads: Packet sender initialization failed, err=%d\n",
			     err);
		return err;
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&t, &attr, listener_thr, (void *)intrace) < 0) {
		debug_printf(dlFatal,
			     "threads: Cannot create listener thread\n");
		return errThread;
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&t, &attr, sender_thr, (void *)intrace) < 0) {
		debug_printf(dlFatal, "threads: Cannot create sender thread\n");
		return errThread;
	}

	display_process(intrace);
	return errNone;
}
