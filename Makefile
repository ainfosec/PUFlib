##############################################################
# PUFlib Makefile
# Description: Compiles PUFlib
#
# Author: Jacob I. Torrey
# Author: Chris Pavlina
# Date: 2016-08-09
##############################################################
SHELL:=/bin/bash

# Variables used by the Makefile
CC = $(shell command -v colorgcc 2>&1 || echo gcc)
INSTALL = install

DESTDIR ?=
PREFIX ?= /usr

SONAME = libpuf.so
SO_MAJ = 1
SO_MIN = 0.1
SOFILE = ${SONAME}.${SO_MAJ}.${SO_MIN}

CFLAGS = -I${CURDIR}/include -g -Og -Wall -Wextra -Werror -fPIC -std=c99
LDFLAGS = -shared -Wl,-soname,${SONAME}.${SO_MAJ}

MODULES := puflibtest sxc
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

.PHONY: all docs deb install clean distclean pufctl puf ${MODULE_DIRS}

all: ${SOFILE} pufctl puf

pufctl:
	${MAKE} -C bin pufctl

puf:
	${MAKE} -C bin puf

docs:
	doxygen doxyfile

install: ${SOFILE} pufctl puf
	${INSTALL} -m 0755 -d ${DESTDIR}/${PREFIX}/lib
	${INSTALL} -m 0755 -d ${DESTDIR}/${PREFIX}/bin
	${INSTALL} -m 0755 -d ${DESTDIR}/${PREFIX}/include
	${INSTALL} -m 0644 ${SOFILE} ${DESTDIR}/${PREFIX}/lib/${SOFILE}
	ln -fs ${SOFILE} ${DESTDIR}/${PREFIX}/lib/${SONAME}.${SO_MAJ}
	ln -fs ${SONAME}.${SO_MAJ} ${DESTDIR}/${PREFIX}/lib/${SONAME}
	${INSTALL} -m 0755 bin/puf ${DESTDIR}/${PREFIX}/bin/puf
	${INSTALL} -m 0755 bin/pufctl ${DESTDIR}/${PREFIX}/bin/pufctl
	${INSTALL} -m 0644 include/puflib.h ${DESTDIR}/${PREFIX}/include/puflib.h
	${INSTALL} -m 0644 include/puflib_internal.h ${DESTDIR}/${PREFIX}/include/puflib_internal.h
	${INSTALL} -m 0644 include/puflib_module.h ${DESTDIR}/${PREFIX}/include/puflib_module.h

deb: distclean
	tar -cz . -f ../puflib_1.0.orig.tar.gz
	dpkg-buildpackage -uc -us
	dpkg-buildpackage -Tclean

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

module_list.c:
	bash ./scripts/gen_module_list ${MODULES_SUPPORTED} > $@

distclean: clean
	rm -f ${SONAME}.${SO_MAJ}.${SO_MIN} ${SONAME}.${SO_MAJ} ${SONAME}
	rm -rf docs/html
	make -C bin distclean
	for mod in ${MODULES}; do \
		$(call module_mf,$${mod},distclean); \
	done

clean:
	rm -f ${OBJECTS}
	rm -f ${OBJECTS:.o=.d}
	rm -f module_list.c
	for mod in ${MODULES}; do \
		$(call module_mf,$${mod},clean); \
	done
	make -C bin clean
