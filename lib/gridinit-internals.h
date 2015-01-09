/*
gridinit-utils, a helper library for gridinit.
Copyright (C) 2013 AtoS Worldline, original work aside of Redcurrant
Copyright (C) 2015 OpenIO, modified for OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef  __GRID_SUPERVISOR_INTERNALS_H__
# define __GRID_SUPERVISOR_INTERNALS_H__
# include <glib.h>

#ifndef GRIDINIT_DOMAIN
# define GRIDINIT_DOMAIN "gridinit"
#endif

# define GRID_LOGLVL_TRACE  (32 << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_DEBUG  (16 << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_INFO   (8  << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_NOTICE (4  << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_WARN   (2  << G_LOG_LEVEL_USER_SHIFT)
# define GRID_LOGLVL_ERROR  (1  << G_LOG_LEVEL_USER_SHIFT)

# define FATAL(Format,...)  g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_ERROR,  Format, ##__VA_ARGS__)
# define ALERT(Format,...)  g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_ERROR,  Format, ##__VA_ARGS__)
# define CRIT(Format,...)   g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_ERROR,  Format, ##__VA_ARGS__)
# define ERROR(Format,...)  g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_ERROR,  Format, ##__VA_ARGS__)
# define WARN(Format,...)   g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_WARN,   Format, ##__VA_ARGS__)
# define NOTICE(Format,...) g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_NOTICE, Format, ##__VA_ARGS__)
# define INFO(Format,...)   g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_INFO,   Format, ##__VA_ARGS__)
# define DEBUG(Format,...)  g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_DEBUG,  Format, ##__VA_ARGS__)
# define TRACE(Format,...)  g_log(GRIDINIT_DOMAIN, GRID_LOGLVL_TRACE,  Format, ##__VA_ARGS__)

GError* g_error_printf(const char *dom, int code, const char *fmt, ...);

#endif
