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

CFLAGS = -I${CURDIR}/include -g -Og -Wall -Wextra -fPIC -std=c99
LDFLAGS = -shared -Wl,-soname,${SONAME}.${SO_MAJ}

MODULES := puflibtest
MODULES_SUPPORTED := $(shell bash ./scripts/test_module_support ${MODULES})
MODULE_DIRS = $(foreach mod,${MODULES_SUPPORTED},modules/${mod})
MODULE_PACKAGES = $(foreach mod,${MODULES_SUPPORTED},modules/${mod}/${mod}.mod.o)

define module_mf
	make -C modules/$(1) $(2) PUFLIB_MF=${CURDIR}/Makefile.inc MODNAME=$(1) \
			PUFLIB_CFLAGS="${CFLAGS}" PUFLIB_LDFLAGS="${LDFLAGS}"			\
			CC="${CC}"
endef

# List all the objects needed here
OBJECTS = puflib/puflib.o puflib/misc.o puflib/platform-posix.o module_list.o

.PHONY: all clean pufctl puf ${MODULE_DIRS}

all: ${SOFILE} pufctl puf

pufctl:
	${MAKE} -C bin pufctl

puf:
	${MAKE} -C bin puf

# Include calculated dependencies
-include ${OBJECTS:.o=.d}
-include $(patsubst %,modules/%/Makefile.inc,${MODULES_SUPPORTED})

# Custom rule that calculates dependencies
%.o: %.c
	${CC} -c  ${CFLAGS} $*.c -o $*.o
	${CC} -MM ${CFLAGS} $*.c -o $*.d

# Module package
# This links together all the .o files in a module and only exports the module
# info struct, ensuring no symbol collisions between modules.
THIS_MODULE_NAME = $(patsubst modules/%,%,$@)
${MODULE_DIRS}:
	$(call module_mf,${THIS_MODULE_NAME},all)

${SOFILE}: ${OBJECTS} ${MODULE_DIRS}
	${CC} ${LDFLAGS} ${OBJECTS} ${MODULE_PACKAGES} -o ${SOFILE}
	ln -fs ${SOFILE} ${SONAME}.${SO_MAJ}
	ln -fs ${SONAME}.${SO_MAJ} ${SONAME}

test: test.o ${SOFILE}
	${CC} ${CFLAGS} -Wl,-rpath,. -L. -o test test.o -lpuf -lreadline

module_list.c:
	bash ./scripts/gen_module_list ${MODULES_SUPPORTED} > $@

clean:
	rm -f ${SONAME}.${SO_MAJ}.${SO_MIN} ${SONAME}.${SO_MAJ} ${SONAME}
	rm -f test
	rm -f ${OBJECTS} test.o
	rm -f ${OBJECTS:.o=.d} test.d
	rm -f module_list.c
	for mod in ${MODULES}; do \
		$(call module_mf,$${mod},clean); \
	done
	make -C bin clean
