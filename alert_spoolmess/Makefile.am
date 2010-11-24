CFLAGS = -std=gnu99
CFLAGS+= -D_REENTRANT
CFLAGS+= -D_LARGEFILE64_SOURCE
CFLAGS+= -D_FILE_OFFSET_BITS=64
CFLAGS+= -O2
CFLAGS+= -g
CFLAGS+= -D HAVE_EXTRA_DEBUG=1
CFLAGS+= -Wall -Wextra -Werror
CFLAGS+= -Wimplicit-function-declaration
CFLAGS+= -Wold-style-definition
CFLAGS+= -Wredundant-decls
CFLAGS+= -Wsequence-point
CFLAGS+= -Wstrict-prototypes
CFLAGS+= -Wunused
CFLAGS+= -DG_ERRORCHECK_MUTEXES -DG_DISABLE_DEPRECATED=1 $(GLIB_CFLAGS)

plugindir=$(libdir)/gridinit

plugin_LTLIBRARIES = gridinit_alert_spoolmess.la

gridinit_alert_spoolmess_la_CFLAGS = $(CFLAGS) -I@METAUTILS_DIR@/include

gridinit_alert_spoolmess_la_LDFLAGS = -module -avoid-version $(GLIB_LDFLAGS) -L/usr/local/@LD_LIBDIR@

gridinit_alert_spoolmess_la_LIBADD = -llog4c ../lib/libgridinit-utils.la $(GLIB_LIBS) @LSYSMM@

gridinit_alert_spoolmess_la_SOURCES = module.c

