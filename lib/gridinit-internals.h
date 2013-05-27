/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef  __GRID_SUPERVISOR_INTERNALS_H__
# define __GRID_SUPERVISOR_INTERNALS_H__
# include <glib.h>
# include <log4c.h>

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
