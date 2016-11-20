/*
 * intrace
 *
 * Debug routines
 *
 * author: Pawel Pisarczyk <pawel@immos.com.pl>
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
#include <stdarg.h>
#include <pthread.h>
#include <ctype.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "intrace.h"

struct {
	pthread_mutex_t mutex;
	debug_level_t dl;
	FILE *f;
} debug;

/* Function prints debug string on given debug level */
int _debug_printf(debug_level_t dl, const char *file, const char *func, int line, const char *fmt,
		  ...)
{
	struct tm tm;
	char buf[4096], *p;
	struct timeval tv;
	struct timezone tz;

	struct {
		char *name;
		char *color;
	} dls[] = {
		{
		"<FATAL>", "\033[1;31m"}, {
		"<ERROR>", "\033[0;31m"}, {
		"<WARNING>", "\033[0;33m"}, {
		"<INFO>", "\033[0;32m"}, {
		"<DETAILS>", "\033[0m"}, {
		"<DEBUG>", "\033[0;37m"}
	};
	va_list args;

	va_start(args, fmt);
	if (dl <= debug.dl) {
		pthread_mutex_lock(&debug.mutex);

		if ((debug.f == stdout) || (debug.f == stderr))
			fprintf(debug.f, "%s", dls[dl].color);

		gettimeofday(&tv, &tz);
		localtime_r((const time_t *)&tv.tv_sec, &tm);

		if (dl >= dlDebug)
			snprintf(buf, sizeof(buf),
				 "%d/%02d/%02d %02d:%02d:%02d.%d %s (%s:%s %d) ",
				 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
				 tm.tm_hour, tm.tm_min, tm.tm_sec, (int)tv.tv_usec, dls[dl].name,
				 file, func, line);
		else
			snprintf(buf, sizeof(buf),
				 "%d/%02d/%02d %02d:%02d:%02d.%d %s ",
				 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
				 tm.tm_hour, tm.tm_min, tm.tm_sec, (int)tv.tv_usec, dls[dl].name);

		vsnprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), fmt, args);
		for (p = buf; *p; p++) {
			if (!isascii(*p))
				*p = '_';
		}

		fprintf(debug.f, "%s", buf);

		if ((debug.f == stdout) || (debug.f == stderr))
			fprintf(debug.f, "\033[0m");

		fflush(debug.f);
		pthread_mutex_unlock(&debug.mutex);
	}
	va_end(args);

	return 0;
}

/* Function initializes debug */
int _debug_init(debug_level_t dl)
{
	debug.dl = dl;
	debug.f = stdout;

	if (pthread_mutex_init(&debug.mutex, NULL) < 0)
		return errMutex;

	return 0;
}
