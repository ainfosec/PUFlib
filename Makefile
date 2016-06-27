##############################################################
# PUFlib Makefile
# Description: Compiles PUFlib
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

CFLAGS = -Iinclude -g -Wall -Wextra -fPIC
LDFLAGS = -shared -Wl,-soname,${SONAME}.${SO_MAJ}

MODULES := puflibtest
MODULES_SUPPORTED := $(shell bash ./scripts/test_module_support ${MODULES})

# Translate the list of modules to their respective subdirectories,
# source files, and object files
MODULE_DIRS = $(patsubst %,modules/%,${MODULES_SUPPORTED})
MODULE_SOURCES = $(foreach mod,${MODULE_DIRS},$(wildcard ${MODULE_DIRS}/*.c))
MODULE_OBJECTS = ${MODULE_SOURCES:.c=.o}

# List all the objects needed here
OBJECTS = src/puflib.o src/misc.o src/platform-posix.o module_list.o ${MODULE_OBJECTS}

.PHONY: all clean

all: ${SOFILE}

# Include calculated dependencies
-include ${OBJECTS:.o=.d}
-include $(patsubst %,modules/%/Makefile.inc,${MODULES_SUPPORTED})

# Custom rule that calculates dependencies
THIS_MODULE_NAME = $(patsubst modules/%/,%,$(dir $@))
%.o: %.c
	${CC} -c  ${CFLAGS} ${CFLAGS-${THIS_MODULE_NAME}} $*.c -o $*.o
	${CC} -MM ${CFLAGS} ${CFLAGS-${THIS_MODULE_NAME}} $*.c -o $*.d

${SOFILE}: ${OBJECTS}
	${CC} ${LDFLAGS} $^ -o ${SOFILE}
	ln -fs ${SOFILE} ${SONAME}.${SO_MAJ}
	ln -fs ${SONAME}.${SO_MAJ} ${SONAME}

test: test.o ${SOFILE}
	${CC} ${CFLAGS} -Wl,-rpath,. -L. -lpuf -o test test.o

module_list.c:
	bash ./scripts/gen_module_list ${MODULES_SUPPORTED} > $@

clean:
	rm -f ${SONAME}.${SO_MAJ}.${SO_MIN} ${SONAME}.${SO_MAJ} ${SONAME}
	rm -f test
	rm -f ${OBJECTS} test.o
	rm -f ${OBJECTS:.o=.d} test.d
	rm -f module_list.c
