/*
 * intrace
 *
 * Main
 *
 * author: Robert Swiecki <robert@swiecki.net>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <string.h>

#include <intrace.h>

extern char *optarg;

int main(int argc, char **argv)
{
	char c;
	int dl = dlInfo, err;
	intrace_t intrace;

	bzero(&intrace, sizeof(intrace_t));

	printf(INTRACE_NAME ", version " INTRACE_VERSION " " INTRACE_AUTHORS"\n");

	for (;;) {
		c = getopt(argc, argv, "h:p:d:");
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
		default:
			break;
		}
	}

	/* Initialize subsystems */
	if ((err = _debug_init(dl, NULL)) < 0) {
		fprintf(stderr, "Can't initialize debug, err=%d!\n", err);
		return err;
	}

	if (!intrace.hostname) {
		debug_printf(dlInfo, "Usage: %s <-h hostname> [-p <port>] [-d <debuglevel>]\n", argv[0]);
		return errArg;
	}

	return threads_process(&intrace);
}
