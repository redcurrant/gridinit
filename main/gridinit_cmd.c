#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridinit_cmd"
#endif

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <strings.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#include <glib.h>

#include "./gridinit_internals.h"
#include "../lib/gridinit-internals.h"

#define EV_FLAG(F) ((F)|EV_PERSIST)

static gchar sock_path[1024];
static gchar line[65536];

static char *argv_status_normal[] = {
	"status",
	NULL
};

static char *argv_status_full[] = {
	"status",
	"-a",
	NULL
};

#define ARGCARGV_STATUS_NORMAL 1, argv_status_normal
#define ARGCARGV_STATUS_FULL   2, argv_status_full

struct child_info_s {
	char *key;
	char *cmd;
	gint pid;
	guint uid;
	guint gid;
	gboolean enabled;
	gboolean respawn;
	time_t last_start_attempt;
	time_t last_kill_attempt;
	guint counter_started;
	guint counter_died;
	struct {
		long core_size;
		long stack_size;
		long nb_files;
	} rlimits;
};

static gint
compare_child_info(gconstpointer p1, gconstpointer p2)
{
	const struct child_info_s *c1, *c2;
	c1 = p1;
	c2 = p2;
	return g_strcasecmp(c1->key, c2->key);
}

static size_t
get_longest_key(GList *all_jobs)
{
	size_t maxlen = 5;
	GList *l;
	for (l=all_jobs; l ;l=l->next) {
		struct child_info_s *ci = l->data;
		size_t len = strlen(ci->key);
		if (len > maxlen)
			maxlen = len;
	}
	return maxlen;
}

static GList*
read_services_list(FILE *in_stream)
{
	GList *all_jobs = NULL;

	while (!feof(in_stream) && !ferror(in_stream)) {
		if (NULL != fgets(line, sizeof(line), in_stream)) {
			int len = strlen(line);
			if (line[len-1] == '\n' || line[len-1]=='\r')
				line[--len] = '\0';
			gchar **tokens = g_strsplit(line, " ", 12);
			if (tokens) {
				if (g_strv_length(tokens) == 12) {
					struct child_info_s ci;
					ci.pid = atoi(tokens[0]);
					ci.enabled = atoi(tokens[1]) != 0;
					ci.counter_started = atoi(tokens[2]);
					ci.counter_died = atoi(tokens[3]);
					ci.last_start_attempt = atol(tokens[4]);
					ci.rlimits.core_size = atol(tokens[5]);
					ci.rlimits.stack_size = atol(tokens[6]);
					ci.rlimits.nb_files = atol(tokens[7]);
					ci.uid = atol(tokens[8]);
					ci.gid = atol(tokens[9]);
					ci.key = g_strdup(tokens[10]);
					ci.cmd = g_strdup(tokens[11]);
					all_jobs = g_list_prepend(all_jobs,
						g_memdup(&ci, sizeof(struct child_info_s)));
				}
				g_strfreev(tokens);
			}
		}
	}

	return g_list_sort(all_jobs, compare_child_info);
}

static void
dump_as_is(FILE *in_stream, void *udata)
{
	(void) udata;
	while (!feof(in_stream) && !ferror(in_stream)) {
		if (NULL != fgets(line, sizeof(line), in_stream)) {
			int len = strlen(line);
			if (line[len-1] == '\n' || line[len-1]=='\r')
				line[--len] = '\0';
			write(1, line, len);
			write(1, "\n", 1);
		}
	}
}

static void
dump_status(FILE *in_stream, void *udata)
{
	char fmt_title[256], fmt_line[256], fmt_title_full[256], fmt_line_full[256];
	size_t maxlen;
	gboolean flag_full;
	GList *all_jobs = NULL, *l;

	flag_full = *(gboolean*)udata;
	all_jobs = read_services_list(in_stream);

	maxlen = get_longest_key(all_jobs);
	g_snprintf(fmt_title, sizeof(fmt_title), "#%%%us %%6s %%5s %%6s %%5s %%19s %%s\n", maxlen-1);
	g_snprintf(fmt_line, sizeof(fmt_line),    "%%%us %%6s %%5d %%6d %%5d %%19s %%s\n", maxlen);
	g_snprintf(fmt_title_full, sizeof(fmt_title_full), "#%%%us %%6s %%5s %%6s %%5s %%5s %%5s %%5s %%19s %%s\n", maxlen-1);
	g_snprintf(fmt_line_full, sizeof(fmt_line_full),    "%%%us %%6s %%5d %%6d %%5d %%5ld %%5ld %%5ld %%19s %%s\n", maxlen);

	/* Dump the list */
	if (flag_full)
		fprintf(stdout, fmt_title_full, "KEY", "STATUS", "PID", "#START", "#DIED",
			"CSZ", "SSZ", "MFD", "SINCE", "CMD");
	else
		fprintf(stdout, fmt_title, "KEY", "STATUS", "PID", "#START", "#DIED",
			"SINCE", "CMD");

	for (l=all_jobs; l ;l=l->next) {
		char str_time[20] = "---------- --------";
		struct child_info_s *ci;
		
		ci = l->data;
		if (ci->pid >= 0)
			strftime(str_time, sizeof(str_time), "%Y-%m-%d %H:%M:%S",
				gmtime(&(ci->last_start_attempt)));
		if (flag_full)
			fprintf(stdout, fmt_line_full,
				ci->key, (ci->enabled ? "ON":"OFF"), ci->pid,
				ci->counter_started, ci->counter_died,
				ci->rlimits.core_size, ci->rlimits.stack_size, ci->rlimits.nb_files,
				str_time, ci->cmd);
		else
			fprintf(stdout, fmt_line,
				ci->key, (ci->enabled ? "ON":"OFF"), ci->pid,
				ci->counter_started, ci->counter_died,
				str_time, ci->cmd);
	}
	fflush(stdout);

	/* free anything */
	for (l=all_jobs; l ;l=l->next) {
		struct child_info_s *ci = l->data;
		g_free(ci->key);
		g_free(ci->cmd);
		g_free(ci);
		l->data = NULL;
	}
	
	g_list_free(all_jobs);
	all_jobs = NULL;
}

static FILE*
open_cnx(void)
{
	int req_fd = -1;
	FILE *req_stream = NULL;
	if (-1 == (req_fd = __open_unix_client(sock_path))) {
		g_printerr("Connection to UNIX socket [%s] failed : %s\n", sock_path, strerror(errno));
		return NULL;
	}

	if (NULL == (req_stream = fdopen(req_fd, "a+"))) {
		g_printerr("Connection to UNIX socket [%s] failed : %s\n", sock_path, strerror(errno));
		close(req_fd);
		return NULL;
	}

	return req_stream;
}

static void
send_commandf(void (*dumper)(FILE *, void *), void *udata, const char *fmt, ...)
{
	va_list va;
	FILE *req_stream;
	
	if (NULL != (req_stream = open_cnx())) {

		va_start(va, fmt);
		vfprintf(req_stream, fmt, va);
		va_end(va);

		fflush(req_stream);
		dumper(req_stream, udata);
		fclose(req_stream);
	}
}

static void
send_commandv(void (*dumper)(FILE *, void*), void *udata, int argc, char **args)
{
	int i;
	FILE *req_stream;
	
	if (NULL != (req_stream = open_cnx())) {
		for (i=0; i<argc ;i++) {
			fputs(args[i], req_stream);
			fputc(' ', req_stream);
		}
		fputc('\n', req_stream);

		fflush(req_stream);
		dumper(req_stream, udata);
		fclose(req_stream);
	}
}

static int
command_status(int argc, char **args)
{
	gboolean flag_all;
	
	flag_all = (argc >= 2) && 0 == g_ascii_strcasecmp(args[1], "-a");
	send_commandf(dump_status, &flag_all, "status\n");
	return 1;
}


static int
command_start(int argc, char **args)
{
	send_commandv(dump_as_is, NULL, argc, args);
	command_status(ARGCARGV_STATUS_NORMAL);
	return 1;
}


static int
command_stop(int argc, char **args)
{
	send_commandv(dump_as_is, NULL, argc, args);
	command_status(ARGCARGV_STATUS_NORMAL);
	return 1;
}


static int
command_reload(int argc, char **args)
{
	(void) argc;
	(void) args;
	send_commandf(dump_as_is, NULL, "reload\n");
	command_status(ARGCARGV_STATUS_FULL);
	return 1;
}


/* ------------------------------------------------------------------------- */

struct command_s {
	const gchar *name;
	int (*action) (int argc, char **args);
};

static struct command_s COMMANDS[] = {
	{ "start",   command_start  },
	{ "stop",    command_stop   },
	{ "status",  command_status },
	{ "reload",  command_reload },
	{ NULL, NULL }
};

int
main(int argc, char ** args)
{
	struct command_s *cmd;
	
	bzero(sock_path, sizeof(sock_path));
	g_strlcpy(sock_path, GRIDINIT_SOCK_PATH, sizeof(sock_path)-1);
	close(0);

	if (argc < 2) {
		command_status(0, NULL);
		return 0;
	}
	
	for (cmd=COMMANDS; cmd->name ;cmd++) {
		if (0 == g_ascii_strcasecmp(cmd->name, args[1])) {
			int rc = cmd->action(argc-1, args+1);
			close(1);
			close(2);
			return rc;
		}
	}

	command_status(ARGCARGV_STATUS_NORMAL);	
	close(1);
	close(2);
	return 1;
}

