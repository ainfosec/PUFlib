# vim: set ft=make noexpandtab shiftwidth=8 softtabstop=0 :
##############################################################
# PUFlib Makefile include for modules
# Description: Provides common targets and definitions for modules
#
# Author: Chris Pavlina
# Date: 6/28/2016
##############################################################
SHELL:=/bin/bash

CFLAGS = ${PUFLIB_CFLAGS} -fvisibility=hidden ${MODCFLAGS}
LDFLAGS = ${PUFLIB_LDFLAGS} ${MODLDFLAGS}

OBJECTS = $(patsubst %.c,%.o,${SOURCES})

.PHONY: all clean

all: ${MODNAME}.mod.o

${MODNAME}.mod.o: ${OBJECTS}
	ld -r $^ -o $@
	for sym in $$(nm $@ | grep -e ' [DTt] ' | awk '{print $$3}'); do \
		objcopy $@ --redefine-sym $${sym}=${MODNAME}__$${sym}; \
	done
	objcopy $@ --globalize-symbol=${MODNAME}__MODULE_INFO

clean:
	rm -f ${OBJECTS}
	rm -f ${OBJECTS:.o=.d}
	rm -f ${MODNAME}.mod.o
