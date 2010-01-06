#ifndef  __GRID_SUPERVISOR_INTERNALS_H__
# define __GRID_SUPERVISOR_INTERNALS_H__
# include <glib.h>
# include <log4c.h>
# include <gridinit-utils.h>

# define JOURNAL(Prio,Format,...) log4c_category_log(log4c_category_get(LOG_DOMAIN), \
	Prio, "%u "Format, getpid(), ##__VA_ARGS__)

# define FATAL(Format,...)  JOURNAL(LOG4C_PRIORITY_FATAL,  Format, ##__VA_ARGS__)
# define ALERT(Format,...)  JOURNAL(LOG4C_PRIORITY_ALERT,  Format, ##__VA_ARGS__)
# define CRIT(Format,...)   JOURNAL(LOG4C_PRIORITY_CRIT,   Format, ##__VA_ARGS__)
# define ERROR(Format,...)  JOURNAL(LOG4C_PRIORITY_ERROR,  Format, ##__VA_ARGS__)
# define WARN(Format,...)   JOURNAL(LOG4C_PRIORITY_WARN,   Format, ##__VA_ARGS__)
# define NOTICE(Format,...) JOURNAL(LOG4C_PRIORITY_NOTICE, Format, ##__VA_ARGS__)
# define INFO(Format,...)   JOURNAL(LOG4C_PRIORITY_INFO,   Format, ##__VA_ARGS__)
# define DEBUG(Format,...)  JOURNAL(LOG4C_PRIORITY_DEBUG,  Format, ##__VA_ARGS__)
# define TRACE(Format,...)  JOURNAL(LOG4C_PRIORITY_TRACE,  Format, ##__VA_ARGS__)

GError* g_error_printf(const char *dom, int code, const char *fmt, ...);

#endif
