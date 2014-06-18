#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridinit.utils"
#endif

#include <glib.h>
#include "./gridinit_internals.h"

#define STR_SKIP_SPACES(s) do {\
	register gchar c;\
	for (; (c = *s) && g_ascii_isspace(c) ;++s);\
} while (0)

#define STR_TRIM_TRAILING_SPACES(s) do { \
	register gchar c, *end; \
	for (end = s; *end ;++end); \
	-- end; \
	for (; end > s && (c = *end) && g_ascii_isspace(c) ;--end) *end = '\0'; \
} while (0)

gboolean
gridinit_group_in_set(const gchar *group, const gchar *set)
{
	gchar **tokens, **token, *g;

	tokens = g_strsplit_set(set, ",:", -1);
	if (!tokens)
		return 0;
	for (token=tokens; (g = *token) ;token++) {
		STR_SKIP_SPACES(g);
		STR_TRIM_TRAILING_SPACES(g);
		if (!*g)
			continue;
		if (0 == g_ascii_strcasecmp(g, group)) {
			g_strfreev(tokens);
			return TRUE;
		}
	}
	g_strfreev(tokens);
	return FALSE;
}

