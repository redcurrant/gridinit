plugindir=$(libdir)/gridinit

plugin_LTLIBRARIES = gridinit_alert_spoolmess.la

gridinit_alert_spoolmess_la_CFLAGS = $(GLIB_CFLAGS)

gridinit_alert_spoolmess_la_LDFLAGS = -module -avoid-version $(GLIB_LDFLAGS) -L/usr/local/@LD_LIBDIR@

gridinit_alert_spoolmess_la_LIBADD = -llog4c ../lib/libgridinit-utils.la $(GLIB_LIBS) @LSYSMM@

gridinit_alert_spoolmess_la_SOURCES = module.c

