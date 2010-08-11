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

#define MINI 0
#define MEDIUM 1

static gchar sock_path[1024];
static gchar line[65536];

#define BOOL(i) (i?1:0)

struct child_info_s {
	char *key;
	char *group;
	char *cmd;
	gint pid;
	guint uid;
	guint gid;
	gboolean enabled;
	gboolean respawn;
	gboolean broken;
	gboolean breakable;
	guint32 user_flags;
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

static const char *
get_child_status(struct child_info_s *ci)
{
	if (ci->broken)
		return "BROKEN";
	if (!ci->enabled)
		return "DISABLED";
	if (ci->pid <= 0)
		return "DOWN";
	return "UP";
}

static size_t
get_longest_group(GList *all_jobs)
{
	size_t maxlen = 5;
	GList *l;
	for (l=all_jobs; l ;l=l->next) {
		struct child_info_s *ci = l->data;
		size_t len = strlen(ci->group);
		if (len > maxlen)
			maxlen = len;
	}
	return maxlen;
}

static size_t
get_longest_key(GList *all_jobs)
{
	size_t maxlen = 4;
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
			gchar **tokens = g_strsplit(line, " ", 15);
			if (tokens) {
				if (g_strv_length(tokens) == 15) {
					struct child_info_s ci;
					ci.pid = atoi(tokens[0]);
					ci.enabled = BOOL(atoi(tokens[1]));
					ci.broken = BOOL(atoi(tokens[2]));
					ci.respawn = BOOL(atoi(tokens[3]));
					ci.counter_started = atoi(tokens[4]);
					ci.counter_died = atoi(tokens[5]);
					ci.last_start_attempt = atol(tokens[6]);
					ci.rlimits.core_size = atol(tokens[7]);
					ci.rlimits.stack_size = atol(tokens[8]);
					ci.rlimits.nb_files = atol(tokens[9]);
					ci.uid = atol(tokens[10]);
					ci.gid = atol(tokens[11]);
					ci.key = g_strdup(tokens[12]);
					ci.group = g_strdup(tokens[13]);
					ci.cmd = g_strdup(tokens[14]);
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
			if (write(1, line, len)!=len || write(1, "\n", 1)!=1) {
				g_error("stdout write error");
				return;
			}
		}
	}
}

static void
dump_status(FILE *in_stream, void *udata)
{
	char fmt_title[256], fmt_line[256];
	size_t maxkey, maxgroup;
	int how;
	GList *all_jobs = NULL, *l;

	how = *(int*)udata;
	all_jobs = read_services_list(in_stream);

	maxkey = get_longest_key(all_jobs);
	maxgroup = get_longest_group(all_jobs);

	/* write the title line */
	switch (how) {
	case MINI:
		g_snprintf(fmt_title, sizeof(fmt_title),
				"%%-%us %%8s %%6s %%s\n",
				(guint)maxkey);
		g_snprintf(fmt_line, sizeof(fmt_line),
				"%%-%us %%8s %%6d %%s\n",
				(guint)maxkey);
		fprintf(stdout, fmt_title, "KEY", "STATUS", "PID", "GROUP");
		break;
	case MEDIUM:
		g_snprintf(fmt_title, sizeof(fmt_title),
				"%%-%us %%8s %%5s %%6s %%5s %%19s %%%us %%s\n",
				(guint)maxkey, (guint)maxgroup);
		g_snprintf(fmt_line, sizeof(fmt_line),
				"%%-%us %%8s %%5d %%6d %%5d %%19s %%%us %%s\n",
				(guint)maxkey, (guint)maxgroup);
		fprintf(stdout, fmt_title, "KEY", "STATUS", "PID", "#START",
				"#DIED", "SINCE", "GROUP", "CMD");
		break;
	default:
		g_snprintf(fmt_title, sizeof(fmt_title),
				"%%-%us %%8s %%5s %%6s %%5s %%8s %%8s %%8s %%19s %%%us %%s\n",
				(guint)maxkey, (guint)maxgroup);
		g_snprintf(fmt_line, sizeof(fmt_line),
				"%%-%us %%8s %%5d %%6d %%5d %%8ld %%8ld %%8ld %%19s %%%us %%s\n",
				(guint)maxkey, (guint)maxgroup);

		fprintf(stdout, fmt_title, "KEY", "STATUS", "PID", "#START",
				"#DIED", "CSZ", "SSZ", "MFD", "SINCE", "GROUP", "CMD");
		break;
	}

	/* Dump the list */
	for (l=all_jobs; l ;l=l->next) {
		char str_time[20] = "---------- --------";
		struct child_info_s *ci;
		
		ci = l->data;
		if (ci->pid >= 0)
			strftime(str_time, sizeof(str_time), "%Y-%m-%d %H:%M:%S",
				gmtime(&(ci->last_start_attempt)));

		switch (how) {
		case MINI:
			fprintf(stdout, fmt_line, ci->key, get_child_status(ci), ci->pid, ci->group);
			break;
		case MEDIUM:
			fprintf(stdout, fmt_line,
				ci->key, get_child_status(ci), ci->pid,
				ci->counter_started, ci->counter_died,
				str_time, ci->group, ci->cmd);
			break;
		default:
			fprintf(stdout, fmt_line,
				ci->key, get_child_status(ci), ci->pid,
				ci->counter_started, ci->counter_died,
				ci->rlimits.core_size, ci->rlimits.stack_size, ci->rlimits.nb_files,
				str_time, ci->group, ci->cmd);
			break;
		}
	}
	fflush(stdout);

	/* free anything */
	for (l=all_jobs; l ;l=l->next) {
		struct child_info_s *ci = l->data;
		g_free(ci->key);
		g_free(ci->cmd);
		g_free(ci->group);
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
	gchar **real_args = NULL;
	int i, count_args, how;

	how = MINI; /*minimal output by default*/
	count_args = 1;
	real_args = calloc(count_args+1, sizeof(char*));
	real_args[0] = args[0];
	
	for (i=1; i<argc ;i++) {/* parse options until a '--' is met */
		char *arg = args[i];
		if (0 == g_ascii_strcasecmp(arg, "--full")) 
			how = MEDIUM + 1;
		else if (0 == g_ascii_strcasecmp(arg, "--medium")) 
			how = MEDIUM;
		else if (0 == g_ascii_strcasecmp(arg, "--minimal")) 
			how = MINI;
		else if (0 == g_ascii_strcasecmp(arg, "--"))
			break;
		else if (g_str_has_prefix(arg, "--"))
			g_error("Unexpected status option : [%s]", arg);
		else {	
			real_args[count_args++] = arg;
			real_args = realloc(realloc, count_args+1);
			real_args[count_args] = NULL;
		}
	}
	for (; i<argc ;i++) {/* everything after the '--' are arguments */
		real_args[count_args++] = args[i];
		real_args = realloc(realloc, count_args+1);
		real_args[count_args] = NULL;
	}
	
	send_commandv(dump_status, &how, count_args, real_args);
	free(real_args);
	return 1;
}


static int
command_start(int argc, char **args)
{
	send_commandv(dump_as_is, NULL, argc, args);
	return 1;
}


static int
command_stop(int argc, char **args)
{
	send_commandv(dump_as_is, NULL, argc, args);
	return 1;
}

static int
command_repair(int argc, char **args)
{
	send_commandv(dump_as_is, NULL, argc, args);
	return 1;
}

static int
command_reload(int argc, char **args)
{
	(void) argc;
	(void) args;
	send_commandf(dump_as_is, NULL, "reload\n");
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
	{ "repair",  command_repair },
	{ NULL, NULL }
};

static int
main_options(int argc, char **args)
{
	int opt;

	/* set pretty defaults */
	bzero(sock_path, sizeof(sock_path));
	g_strlcpy(sock_path, GRIDINIT_SOCK_PATH, sizeof(sock_path)-1);

	/*  */
	while ((opt = getopt(argc, args, "c:")) != -1) {
		switch (opt) {
			case 'c':
				bzero(sock_path, sizeof(sock_path));
				g_strlcpy(sock_path, optarg, sizeof(sock_path)-1);
				break;
		}
	}

	return optind;
}

int
main(int argc, char ** args)
{
	struct command_s *cmd;
	int opt_index;
	
	close(0);
	opt_index = main_options(argc, args);

	if (opt_index >= argc) {
		char *fake_args[] = {"status", NULL };
		command_status(1, fake_args);
		return 0;
	}
	
	for (cmd=COMMANDS; cmd->name ;cmd++) {
		if (0 == g_ascii_strcasecmp(cmd->name, args[opt_index])) {
			int rc = cmd->action(argc-opt_index, args+opt_index);
			close(1);
			close(2);
			return rc;
		}
	}

	close(1);
	close(2);
	return 1;
}

