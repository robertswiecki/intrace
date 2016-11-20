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

#include "config.h"

#include <pthread.h>
#include <netdb.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include "intrace.h"

// For setuid case only
static int threads_dropPrivs(void)
{
	if (setuid(getuid()) == -1)
		return errPrivs;

	return errNone;
}

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

bool threads_resolveIP(intrace_t * intrace, const char *hostname)
{
	struct hostent he;
	struct hostent *hep;
	char workspace[4096];
	int err;

	if (intrace->familyMode == ANY || intrace->familyMode == IPV6) {
		gethostbyname2_r(hostname, AF_INET6, &he, workspace, sizeof(workspace), &hep, &err);
		if (hep != NULL) {
			memcpy(intrace->rip6.s6_addr, hep->h_addr, hep->h_length);
			intrace->isIPv6 = true;
			return true;
		}
	}
	if (intrace->familyMode == ANY || intrace->familyMode == IPV4) {
		gethostbyname2_r(hostname, AF_INET, &he, workspace, sizeof(workspace), &hep, &err);
		if (hep != NULL) {
			memcpy(&intrace->rip.s_addr, hep->h_addr, hep->h_length);
			intrace->isIPv6 = false;
			return true;
		}
	}

	debug_printf(dlError, "Couldn't resolve '%s': '%s'\n", intrace->hostname,
		     thread_err2asc(h_errno));
	return false;
}

int threads_process(intrace_t * intrace)
{
	int err;
	pthread_attr_t attr;
	pthread_t t;

	if (pthread_mutex_init(&intrace->mutex, NULL) != 0) {
		debug_printf(dlFatal, "threads: Mutex initialization failed\n");
		return errMutex;
	}

	debug_printf(dlDebug, "Resolving '%s'\n", intrace->hostname);
	if (!threads_resolveIP(intrace, intrace->hostname)) {
		debug_printf(dlFatal, "Resolving '%s' failed\n", intrace->hostname);
		return errResolve;
	}

	char haddr[INET6_ADDRSTRLEN];
	if (!inet_ntop(_IT_AF(intrace), _IT_RIP(intrace), haddr, sizeof(haddr))) {
		debug_printf(dlFatal, "Cannot convert IP addr to a text form\n");
		return errResolve;
	}

	debug_printf(dlDebug, "%s for '%s' resolved='%s'\n", _IT_IPSTR(intrace), intrace->hostname,
		     haddr);

	if ((err = listener_init(intrace)) != errNone) {
		debug_printf(dlFatal, "threads: Listener initialization failed, err=%d'\n", err);
		return err;
	}

	if ((err = sender_init(intrace)) != errNone) {
		debug_printf(dlFatal, "threads: Packet sender initialization failed, err=%d\n",
			     err);
		return err;
	}

	if ((err = threads_dropPrivs()) != errNone) {
		debug_printf(dlFatal, "threads: Couldn't drop privileges, err=%d\n", err);
		return err;
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&t, &attr, listener_thr, (void *)intrace) < 0) {
		debug_printf(dlFatal, "threads: Cannot create listener thread\n");
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
