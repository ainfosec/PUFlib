##############################################################
# pufctl Makefile
#
# Author: Chris Pavlina
##############################################################
SHELL:=/bin/bash

# Variables used by the Makefile
CC = $(shell command -v colorgcc 2>&1 || echo gcc)

CFLAGS = -I${CURDIR}/../include -g -Og -Wall -Wextra -std=c99
LDFLAGS = -L.. -lpuf -lreadline

OBJECTS = pufctl.o

.PHONY: all clean

all: pufctl

# Include calculated dependencies
-include ${OBJECTS:.o=.d}

# Custom rule that calculates dependencies
%.o: %.c
	${CC} -c  ${CFLAGS} $*.c -o $*.o
	${CC} -MM ${CFLAGS} $*.c -o $*.d

pufctl: ${OBJECTS}
	${CC} ${CFLAGS} $^ ${LDFLAGS} -o $@

clean:
	rm -f ${OBJECTS}
	rm -f ${OBJECTS:.o=.d}
	rm -f pufctl
