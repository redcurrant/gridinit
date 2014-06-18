#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef LOG_DOMAIN
# define LOG_DOMAIN "supervisor.uid"
#endif

#include "./gridinit-utils.h"
#include "./gridinit-internals.h"

#include <sys/types.h>
#include <unistd.h>

GError*
g_error_printf(const char *dom, int code, const char *fmt, ...)
{
	GError *e;
	gchar *str;
	va_list va;

	va_start(va, fmt);
	str = g_strdup_vprintf (fmt, va);
	va_end(va);

	e = g_error_new(g_quark_from_static_string(dom), code, str);
	g_free(str);
	return e;
}

