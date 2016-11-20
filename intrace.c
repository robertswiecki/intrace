/*
 * intrace
 *
 * Main
 *
 * author: Robert Swiecki <robert@swiecki.net>
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <string.h>

#include "intrace.h"

extern char *optarg;

int main(int argc, char **argv)
{
	int c;
	int dl = dlInfo, err;
	intrace_t intrace;

	bzero(&intrace, sizeof(intrace_t));
	intrace.paylSz = 1;
	intrace.familyMode = ANY;

	printf(INTRACE_NAME ", version " INTRACE_VERSION " " INTRACE_AUTHORS "\n");

	for (;;) {
		c = getopt(argc, argv, "h:p:d:s:46");
		if (c < 0)
			break;

		switch (c) {
		case 'h':
			intrace.hostname = optarg;
			break;
		case 'p':
			intrace.port = atoi(optarg);
			break;
		case 'd':
			dl = atoi(optarg);
			break;
		case 's':
			intrace.paylSz = strtoul(optarg, NULL, 10);
			break;
		case '4':
			intrace.familyMode = IPV4;
			break;
		case '6':
			intrace.familyMode = IPV6;
			break;
		default:
			break;
		}
	}

	/* Initialize subsystems */
	if ((err = _debug_init(dl)) < 0) {
		fprintf(stderr, "Can't initialize debug, err=%d!\n", err);
		return err;
	}

	if (!intrace.hostname) {
		debug_printf(dlInfo,
			     "Usage: %s <-h hostname> [-p <port>] [-d <debuglevel>] [-s <payloadsize>] [-4] [-6]\n",
			     argv[0]);
		return errArg;
	}

	if (intrace.paylSz > MAX_PAYL_SZ) {
		debug_printf(dlWarn, "Payload size set to %d\n", MAX_PAYL_SZ);
		intrace.paylSz = MAX_PAYL_SZ;
	}

	return threads_process(&intrace);
}
