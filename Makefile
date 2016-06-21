##############################################################
# PUFlib Makefile
# Description: Compiles PUFlic
#
# Author: Jacob I. Torrey
# Author: Chris Pavlina
# Date: 6/21/2016
##############################################################
SHELL:=/bin/bash

# Variables used by the Makefile
CC = $(shell command -v colorgcc 2>&1 || echo gcc)

SONAME = libpuf.so
SO_MAJ = 1
SO_MIN = 0.1
SOFILE = ${SONAME}.${SO_MAJ}.${SO_MIN}

CFLAGS = -O2 -I. -g -Wall -fPIC
LDFLAGS = -shared -Wl,-soname,${SONAME}.${SO_MAJ}

MODULES = puflibtest

# Translate the list of modules to their respective subdirectories,
# source files, and object files
MODULE_DIRS = $(patsubst %,modules/%,${MODULES})
MODULE_SOURCES = $(foreach mod,${MODULE_DIRS},$(wildcard ${MODULE_DIRS}/*.c))
MODULE_OBJECTS = ${MODULE_SOURCES:.c=.o}

# List all the objects needed here
OBJECTS = puflib.o module_list.o ${MODULE_OBJECTS}

# Include calculated dependencies
-include ${OBJECTS:.o=.d}

# Custom rule that calculates dependencies
%.o: %.c
	${CC} -c  ${CFLAGS} $*.c -o $*.o
	${CC} -MM ${CFLAGS} $*.c -o $*.d

${SOFILE}: $(OBJECTS)
	${CC} ${LDFLAGS} $^ -o ${SOFILE}
	ln -fs ${SOFILE} ${SONAME}.${SO_MAJ}
	ln -fs ${SONAME}.${SO_MAJ} ${SONAME}

test: test.o ${SOFILE}
	${CC} ${CFLAGS} -Wl,-rpath,. -L. -lpuf -o test test.o

module_list.c:
	bash ./gen_module_list ${MODULES} > $@

clean:
	rm -f ${SONAME}.${SO_MAJ}.${SO_MIN} ${SONAME}.${SO_MAJ} ${SONAME}
	rm -f test
	rm -f ${OBJECTS}
	rm -f ${OBJECTS:.o=.d}
	rm -f module_list.c
