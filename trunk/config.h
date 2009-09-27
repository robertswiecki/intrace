/*
 * intrace
 *
 * Configuration
 *
 * author: Robert Swiecki <robert@swiecki.net>
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#define INTRACE_NAME "InTrace"
#define INTRACE_VERSION "1.4.3"
#define INTRACE_AUTHORS "(C)2007-2009 Robert Swiecki <robert@swiecki.net>"

/* struct tcphdr incompabilities */
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#define MAX_HOPS 32

#endif
