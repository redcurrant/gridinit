lib_LTLIBRARIES = libgridinit-utils.la

libgridinit_utils_la_SOURCES = \
	uid.c \
	common.c \
	limits.c \
	command.c \
	children.c \
	gridinit-utils.h \
	gridinit-internals.h

include_HEADERS = gridinit-utils.h
libgridinit_utils_la_CFLAGS = -g -Wall -std=gnu99 -D_REENTRANT $(GLIB_CFLAGS) -D HAVE_EXTRA_DEBUG=1
libgridinit_utils_la_LDFLAGS = $(GLIB_LDFLAGS)
libgridinit_utils_la_LIBADD = -lglib-2.0 

