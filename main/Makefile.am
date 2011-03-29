noinst_PROGRAMS = 
bin_PROGRAMS = gridinit gridinit_cmd gridinit_testcmd

CFLAGS = -std=gnu99
CFLAGS+= -D_REENTRANT
CFLAGS+= -D_LARGEFILE64_SOURCE
CFLAGS+= -D_FILE_OFFSET_BITS=64
CFLAGS+= -O2
#CFLAGS+= -O0 -fno-inline -DHAVE_EXTRA_DEBUG=1
CFLAGS+= -g
CFLAGS+= -Wall -Wextra -Werror
CFLAGS+= -Wimplicit-function-declaration
#CFLAGS+= -Wold-style-definition
CFLAGS+= -Wredundant-decls
CFLAGS+= -Wsequence-point
CFLAGS+= -Wstrict-prototypes
CFLAGS+= -Wunused
CFLAGS+= -DG_ERRORCHECK_MUTEXES -DG_DISABLE_DEPRECATED=1 $(GLIB_CFLAGS)
CFLAGS+= `pkg-config --cflags libevent`

CFLAGS+= -I. -I.. -I../lib -I@LIBEVENT_DIR@/include

LDFLAGS = -L@LIBEVENT_LIBDIR@
LDFLAGS+= `pkg-config --libs libevent`

gridinit_SOURCES = gridinit.c cnx.c alerting.c gridinit_alerts.h gridinit_internals.h
gridinit_LDADD = -llog4c $(GLIB_LIBS) ../lib/libgridinit-utils.la

gridinit_cmd_SOURCES = gridinit_cmd.c cnx.c gridinit_internals.h
gridinit_cmd_LDADD = -llog4c $(GLIB_LIBS)

gridinit_testcmd_SOURCES = test_cmd.c
gridinit_testcmd_LDADD = -llog4c $(GLIB_LIBS) ../lib/libgridinit-utils.la

