/*
 *
 * intrace
 *
 * author: R. Swiecki <robert@swiecki.net>
 */

#ifndef _INTRACE_H_
#define _INTRACE_H_

#include <config.h>

#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct {
	pthread_mutex_t mutex;

	char *hostname;
	uint16_t port;
	unsigned int paylSz;

	struct in_addr rip;
	struct in_addr lip;
	uint16_t rport;
	uint16_t lport;
	uint32_t seq;
	uint32_t ack;

	int maxhop;
	int cnt;

	struct {
		int rcvSocketTCP;
		int rcvSocketICMP;
		struct in_addr trace[MAX_HOPS + 1];
		int16_t proto[MAX_HOPS + 1];
	} listener;

	struct {
		int sndSocket;
	} sender;

} intrace_t;

#include <errors.h>
#include <debug.h>
#include <threads.h>
#include <sender.h>
#include <listener.h>
#include <display.h>

#endif
