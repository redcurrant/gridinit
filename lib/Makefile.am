CFLAGS = -std=gnu99
CFLAGS+= -D_REENTRANT
CFLAGS+= -D_LARGEFILE64_SOURCE
CFLAGS+= -D_FILE_OFFSET_BITS=64
CFLAGS+= -O2
#CFLAGS+= -O0 -fno-inline -D HAVE_EXTRA_DEBUG=1
CFLAGS+= -g
CFLAGS+= -Wall -Wextra -Werror
CFLAGS+= -Wimplicit-function-declaration
#CFLAGS+= -Wold-style-definition
CFLAGS+= -Wredundant-decls
CFLAGS+= -Wsequence-point
CFLAGS+= -Wstrict-prototypes
CFLAGS+= -Wunused
CFLAGS+= -DG_ERRORCHECK_MUTEXES -DG_DISABLE_DEPRECATED=1 $(GLIB_CFLAGS)

lib_LTLIBRARIES = libgridinit-utils.la

include_HEADERS = gridinit-utils.h

libgridinit_utils_la_SOURCES = \
	uid.c \
	common.c \
	limits.c \
	command.c \
	children.c \
	gridinit-utils.h \
	gridinit-internals.h

libgridinit_utils_la_LDFLAGS = $(GLIB_LDFLAGS)
libgridinit_utils_la_LIBADD = -llog4c -lglib-2.0 

