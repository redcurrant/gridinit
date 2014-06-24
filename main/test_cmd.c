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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include "../lib/gridinit-utils.h"

static void
dump_limits(void)
{
	gint64 limit;

	g_print("\nLIMITS:\n");
	supervisor_limit_get(SUPERV_LIMIT_THREAD_STACK, &limit);
	g_print("\tSUPERV_LIMIT_THREAD_STACK = %"G_GINT64_FORMAT"\n", limit);

	supervisor_limit_get(SUPERV_LIMIT_MAX_FILES, &limit);
	g_print("\tSUPERV_LIMIT_MAX_FILES = %"G_GINT64_FORMAT"\n", limit);

	supervisor_limit_get(SUPERV_LIMIT_CORE_SIZE, &limit);
	g_print("\tSUPERV_LIMIT_CORE_SIZE = %"G_GINT64_FORMAT"\n", limit);
}

static void
dump_environment(void)
{
	gchar **env, **p_env;
	const gchar *value;

	g_print("\nENVIRONMENT:\n");
	if (!(env = g_listenv()))
		return;

	for (p_env=env ; *p_env ; p_env++) {
		value = g_getenv(*p_env);
		g_print("\t%s=%s\n", *p_env, value);
	}
	
	g_strfreev(env);
}

static void
dump_cwd(void)
{
	gchar *dir;

	dir = g_get_current_dir();
	g_print("Current directory: %s\n", dir);
	g_free(dir);
}

static void
my_sleep(gdouble sleep_time)
{
	GTimer *timer;

	g_print("\nSleeping %f seconds\n", sleep_time);

	timer = g_timer_new();
	while (g_timer_elapsed(timer, NULL) < sleep_time)
		sleep(1);

	g_print("Sleeped %f seconds\n", g_timer_elapsed(timer, NULL));
	g_timer_destroy(timer);
}

static void
reopen_output(const gchar *path)
{
	if (!freopen(path, "a", stderr))
		g_printerr("freopen(%s, \"a\", stderr) : %s\n", path, strerror(errno));
	if (!freopen(path, "a", stdout))
		g_printerr("freopen(%s, \"a\", stdout) : %s\n", path, strerror(errno));
}

int
main(int argc, char **args)
{
	gdouble sleep_time = 1.0;

	if (argc > 1) 
		reopen_output(args[1]);
	if (argc > 2)
		sleep_time = g_ascii_strtod(args[2], NULL);

	dump_cwd();
	dump_limits();
	dump_environment();
	my_sleep(sleep_time);
	
	return 0;
}

