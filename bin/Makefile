##############################################################
# puf Makefile
#
# Author: Chris Pavlina
##############################################################
SHELL:=/bin/bash

# Variables used by the Makefile
CC = $(shell command -v colorgcc 2>&1 || echo gcc)

CFLAGS = -I${CURDIR}/../include -g -Og -Wall -Wextra -Werror -std=c99
LDFLAGS = -L.. -lpuf -lreadline

SOURCES = $(wildcard *.c)
OBJECTS = ${SOURCES:.c=.o}

.PHONY: all clean

all: puf pufctl

# Include calculated dependencies
-include ${OBJECTS:.o=.d}

# Custom rule that calculates dependencies
%.o: %.c
	${CC} -c  ${CFLAGS} $*.c -o $*.o
	${CC} -MM ${CFLAGS} $*.c -o $*.d

puf: puf.o base64.o optparse.o
	${CC} ${CFLAGS} $^ ${LDFLAGS} -o $@

pufctl: pufctl.o optparse.o
	${CC} ${CFLAGS} $^ ${LDFLAGS} -o $@

clean:
	rm -f ${OBJECTS}
	rm -f ${OBJECTS:.o=.d}
	rm -f pufctl puf
