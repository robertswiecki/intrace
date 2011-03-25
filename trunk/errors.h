/*
 * intrace
 *
 * Errors
 *
 * author: R. Swiecki <robert@swiecki.net>
 */

#ifndef _ERRORS_H_
#define _ERRORS_H_

/* Errors */
enum {
	errNone = 0, errMem = -1, errArg = -2,
	errMutex = -3, errThread = -4, errPrivs = -5,

	errPcapOpen = -20, errSocket = -21, errResolve = -22,
	errPcapBpf = -23, errPcapLink = -24, errPkt = -25
};

#endif
