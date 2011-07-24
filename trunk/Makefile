#  Makefile for the project
#  Robert Swiecki <robert@swiecki.net>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307


CC = gcc
CFLAGS = -fPIC -O3 -g -ggdb -c -std=gnu99 -I. -pedantic \
		 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE \
		 -Wall -Werror -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wcast-align \
		 -Wreturn-type -Wpointer-arith -Wbad-function-cast

LD = gcc
LDFLAGS = -fPIC -lpthread

SRCS = debug.c intrace.c threads.c listener.c \
	   sender.c display.c ipv4.c ipv6.c

OBJS = $(SRCS:.c=.o)
BIN = intrace

all: $(BIN)

.c.o: %.c
	@(echo CC $<; $(CC) $(CFLAGS) $<)

$(BIN): $(OBJS)
	@(echo LD $@; $(CC) -o $(BIN) $(OBJS) $(LDFLAGS))

clean:
	@(echo CLEAN; rm -f core $(OBJS) $(BIN))

indent:
	@(echo INDENT; indent -linux -l120 -lc120 -ut -sob -c33 -cp33 *.c *.h; rm -f *~)
# DO NOT DELETE
