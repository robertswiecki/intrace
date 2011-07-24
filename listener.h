/*
 * author: R. Swiecki <robert@swiecki.net>
 */

#ifndef _LISTENER_H_
#define _LISTENER_H_

/* For FreeBSD/Sorlaris */
#include <netinet/in_systm.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

#define PCAP_ETHHDRSZ 14

extern int listener_init(intrace_t * intrace);
extern void *listener_thr(void *arg);

#endif
