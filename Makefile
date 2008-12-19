#
# Makefile for intrace
# Robert Swiecki <robert@swiecki.net>
#


SRCDIR := $(shell pwd)
PLUGINS := plug-ins

#CC =  /usr/crosstool/v10/gcc-4.2.1-glibc-2.3.5-nptl/x86_64-unknown-linux-gnu/x86_64-unknown-linux-gnu/bin/gcc
CC = gcc
CFLAGS = -fPIC -O3 -g -ggdb -c -std=gnu99 -I. -pedantic \
		 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE \
		 -Wall -Werror -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized -Wcast-align \
		 -Wreturn-type -Wpointer-arith -Wbad-function-cast

MKDEP = gcc -MM
MKDEPFLAGS = $(CFLAGS)

AR = ar
ARFLAGS = -r

LD = gcc
LDFLAGS = -fPIC -lpthread

SRCS = debug.c intrace.c threads.c listener.c \
	   sender.c display.c

OBJS = $(SRCS:.c=.o)
BIN = intrace

all: $(BIN)

.c.o: %.c
	@(echo CC $<; $(CC) $(CFLAGS) $<)

$(BIN): $(OBJS)
	@(echo LD $@; $(CC) -o $(BIN) $(OBJS) $(LDFLAGS))

clean:
	@(echo CLEAN; rm -f core $(OBJS) $(BIN))
# DO NOT DELETE
