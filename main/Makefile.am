noinst_PROGRAMS = 
bin_PROGRAMS = gridinit gridinit_cmd

CFLAGS= -g -O2 -std=gnu99 -D_REENTRANT
CFLAGS+= -Wall -Wextra -Werror
CFLAGS+= $(GLIB_CFLAGS)
CFLAGS+= -I. -I.. -I../lib -I@LIBEVENT_DIR@/include
CFLAGS+= -DHAVE_EXTRA_DEBUG=1

LDFLAGS = -L@LIBEVENT_LIBDIR@

gridinit_SOURCES = gridinit.c cnx.c alerting.c gridinit_alerts.h gridinit_internals.h
gridinit_LDADD = -llog4c -levent $(GLIB_LIBS) ../lib/libgridinit-utils.la

gridinit_cmd_SOURCES = gridinit_cmd.c cnx.c gridinit_internals.h
gridinit_cmd_LDADD = -llog4c $(GLIB_LIBS)

