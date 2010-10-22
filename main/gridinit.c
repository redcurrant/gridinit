#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridinit.main"
#endif

#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <math.h>
#include <signal.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <glob.h>

#include <log4c.h>
#include <event.h>
#include <glib.h>

#include <gridinit-utils.h>
#include "./gridinit_internals.h"
#include "./gridinit_alerts.h"
#include "../lib/gridinit-internals.h"

#ifdef HAVE_EXTRA_DEBUG
# define XDEBUG DEBUG
# define XTRACE TRACE
#else
# define XDEBUG(FMT,...)
# define XTRACE(FMT,...)
#endif

#define BOOL(i) (i?1:0)

struct server_sock_s {
	int family;
	int fd;
	char *url;
	struct event event;
	struct stat unix_stat_path;
	struct stat unix_stat_sock;
};

static GList *list_of_servers = NULL;
static GList *list_of_signals = NULL; /* list of libevent events */

static char sock_path[1024] = "";
static char pidfile_path[1024] = "";
static char default_working_directory[1024] = "";
static char *config_path = NULL;
static char *config_subdir = NULL;

static volatile int flag_quiet = 0;
static volatile int flag_daemon = 0;
static volatile int flag_running = ~0;
static volatile int flag_cfg_reload = 0;
static volatile int flag_check_socket = 0;

static volatile gint32 default_uid = -1;
static volatile gint32 default_gid = -1;

static gboolean _cfg_reload(gboolean services_only, GError **err);

static void servers_ensure(void);


#define USERFLAG_ONDIE_EXIT                                          0x00000001
#define USERFLAG_ALERT_PENDING                                       0x00000002

/* ------------------------------------------------------------------------- */

static struct event timer_event;

static void timer_event_arm(gboolean first);
static void timer_event_cb(int i, short s, void *p);

static void
timer_event_cb(int i, short s, void *p)
{
	(void)i;
	(void)s;
	(void)p;
	timer_event_arm(FALSE);
}

static void
timer_event_arm(gboolean first)
{
	struct timeval tv;
	if (first)
		evtimer_set(&timer_event, timer_event_cb, NULL);
	tv.tv_sec = tv.tv_usec = 1L;
	evtimer_add(&timer_event, &tv);
}

/* Process management helpers ---------------------------------------------- */

static void
alert_proc_died(void *udata, struct child_info_s *ci)
{
	(void) udata;

	/* if the user_flags on the process contain the on_die:exit flag,
	 * then we mark the gridinit to stop */
	if (ci->user_flags & USERFLAG_ONDIE_EXIT) {
		supervisor_children_enable(ci->key, FALSE);
		flag_running = FALSE;
	}

	supervisor_children_set_user_flags(ci->key, ci->user_flags|USERFLAG_ALERT_PENDING);
}

static void
alert_send_deferred(void *udata, struct child_info_s *ci)
{
	gchar buff[1024];

	(void) udata;

	if (!(ci->user_flags & USERFLAG_ALERT_PENDING))
		return;

	supervisor_children_set_user_flags(ci->key, ci->user_flags & (~USERFLAG_ALERT_PENDING));
	if (ci->broken) {
		g_snprintf(buff, sizeof(buff), "Process broken [%s] %s", ci->key, ci->cmd);
		gridinit_alerting_send(GRIDINIT_EVENT_BROKEN, buff);
	}
	else {
		g_snprintf(buff, sizeof(buff), "Process died [%s] %s", ci->key, ci->cmd);
		gridinit_alerting_send(GRIDINIT_EVENT_DIED, buff);
	}
}

static void
alert_proc_started(void *udata, struct child_info_s *ci)
{
	gchar buff[1024];

	(void) udata;
	g_snprintf(buff, sizeof(buff), "Process started pid=%d [%s] %s",
		ci->pid, ci->key, ci->cmd);
	gridinit_alerting_send(GRIDINIT_EVENT_STARTED, buff);
}

/* COMMANDS management ----------------------------------------------------- */

#define REPLY_STR_CONTANT(BuffEvent,Message) bufferevent_write((BuffEvent), (Message), sizeof(Message)-1)

static void
__reply_sprintf(struct bufferevent *bevent, const char *fmt, ...)
{
	gchar *str = NULL;
	va_list ap;
	
	va_start(ap, fmt);
	str = g_strdup_vprintf(fmt, ap);
	va_end(ap);

	if (str) {
		bufferevent_write(bevent, str, strlen(str));
		g_free(str);
	}
}

static int
command_check(struct bufferevent *bevent, int argc, char **argv)
{
	(void) argc;
	(void) argv;
	servers_ensure();
	REPLY_STR_CONTANT(bevent, "Done! (check the logs)\n");
	return 0;
}

static int
command_start(struct bufferevent *bevent, int argc, char **args)
{
	guint count = 0;
	void start_process(const char *proc_name) {

		DEBUG("Repairing and Starting [%s]", proc_name);

		supervisor_children_repair(proc_name);
		
		switch (supervisor_children_status(proc_name, TRUE)) {
		case -1:
			NOTICE("Cannot start [%s] : %s", proc_name, strerror(errno));
			__reply_sprintf(bevent, "notfound: %s\n", proc_name);
			return;
		case 0:
			count ++;
			NOTICE("Already started [%s] : %s", proc_name, strerror(errno));
			__reply_sprintf(bevent, "already: %s\n", proc_name);
			return;
		case 1:
			count ++;
			NOTICE("Started [%s] : %s", proc_name, strerror(errno));
			__reply_sprintf(bevent, "enabled: %s\n", proc_name);
			return;
		default:
			NOTICE("Cannot start [%s] : %s", proc_name, strerror(errno));
			__reply_sprintf(bevent, "error: %s (%s)\n", proc_name, strerror(errno));
			return;
		}
	}

	void child_starter(void *udata, struct child_info_s *ci) {
		char *group = udata;

		if (group && *group && g_ascii_strcasecmp(ci->group, group)) {
			DEBUG("start: Skipping [%s] with group [%s]", ci->key, ci->group);
			return;
		}
		start_process(ci->key);
	}

	if (argc <= 1) {
		supervisor_run_services(NULL, child_starter);
	}
	else {
		int i;
		for (i=1; i<argc ;i++) {
			char *what = args[i];
			if (*what == '@') {
				DEBUG("start: only group [%s]", what);
				supervisor_run_services(what+1, child_starter);
			}
			else {
				DEBUG("start: only service [%s]", what);
				start_process(what);
			}
		}
	}
	
	__reply_sprintf(bevent, "Done! (%u services matched)\n", count);
	return 0;
}

static int 
command_stop(struct bufferevent *bevent, int argc, char **args)
{
	guint count = 0;
	void stop_process(const char *proc_name) {
		INFO("Stopping process keyed [%s]", proc_name);
		switch (supervisor_children_status(proc_name, FALSE)) {
		case -1:
			__reply_sprintf(bevent, "notfound: %s\n", proc_name);
			return;
		case 0:
			count ++;
			__reply_sprintf(bevent, "already: %s\n", proc_name);
			return;
		case 1:
			count ++;
			__reply_sprintf(bevent, "stopped: %s\n", proc_name);
			return;
		default:
			__reply_sprintf(bevent, "error: %s (%s)\n", proc_name, strerror(errno));
			return;
		}
	}

	void child_stopper(void *udata, struct child_info_s *ci) {
		char *group = udata;

		if (group && *group && g_ascii_strcasecmp(ci->group, group))
			return;
		stop_process(ci->key);
	}

	if (argc <= 1) {
		supervisor_run_services(NULL, child_stopper);
	}
	else {
		int i;
		for (i=1; i<argc ;i++) {
			char *what = args[i];
			if (*what == '@')
				supervisor_run_services(what+1, child_stopper);
			else
				stop_process(what);
		}
	}

	__reply_sprintf(bevent, "Done! (%u services matched)\n", count);
	return 0;
}

static int
command_show(struct bufferevent *bevent, int argc, char **args)
{
	/* Callback used when running all the services or the services
	 * matching specific groups */
	void run_service(void *udata, struct child_info_s *ci) {
		gsize buff_size;
		gchar buff[2048];
		gchar *group = udata;
		
		/* if a group is set, skip the service if it doesn't match the group*/
		if (group && *group && g_ascii_strcasecmp(group, ci->group))
			return;

		buff_size = g_snprintf(buff, sizeof(buff),
				"%d "
				"%d %d %d "
				"%u %u "
				"%ld "
				"%ld %ld %ld "
				"%u %u "
				"%s %s %s\n",
			ci->pid,
			BOOL(ci->enabled), BOOL(ci->broken), BOOL(ci->respawn),
			ci->counter_started, ci->counter_died,
			ci->last_start_attempt,
			ci->rlimits.core_size, ci->rlimits.stack_size, ci->rlimits.nb_files,
			ci->uid, ci->gid,
			ci->key, ci->group, ci->cmd);

		TRACE("status line [%.*s]", buff_size-1, buff);
		bufferevent_write(bevent, buff, buff_size);
	}

	int i;

	if (argc <= 1) {
		supervisor_run_services(NULL, run_service);
		return 0;
	}

	for (i=1; i<argc ;i++) {
		char *what = args[i];

		if (*what == '@') /* Run the services for the group */
			supervisor_run_services(what+1, run_service);
		else { /* Specific service asked */
			int rc;
			struct child_info_s ci;

			bzero(&ci, sizeof(ci));
			rc = supervisor_children_get_info(what, &ci);
			if (rc == 0)
				run_service(NULL, &ci);
			else {
				if (errno == ENOENT)
					REPLY_STR_CONTANT(bevent, "Service not found\n");
				else
					REPLY_STR_CONTANT(bevent, "gridinit internal error\n");
			}
		}
	}
	REPLY_STR_CONTANT(bevent, "\n");
	return 0;
}

static int
command_repair(struct bufferevent *bevent, int argc, char **argv)
{
	int count;

	(void) argc;
	(void) argv;

	count = supervisor_children_repair_all();
	__reply_sprintf(bevent, "Repaired %d processes!\n\n", count);

	return 0;
}

static int
command_reload(struct bufferevent *bevent, int argc, char **argv)
{
	GError *error_local = NULL;
	guint count;
	
	(void) argc;
	(void) argv;

	count = supervisor_children_mark_obsolete();
	__reply_sprintf(bevent, "Marked %u obsolete services\n", count);

	if (!_cfg_reload(TRUE, &error_local)) {
		__reply_sprintf(bevent, "error: Failed to reload the configuration from [%s]\n", config_path);
		__reply_sprintf(bevent, "cause: %s\n", error_local ? error_local->message : "NULL");
	}
	else {
		count = supervisor_children_disable_obsolete();
		__reply_sprintf(bevent, "Services refreshed, %u disabled\n", count);
	}
	return 0;
}

static int
command_INVALID(struct bufferevent *bevent, int argc, char **argv)
{
	(void) argc;
	(void) argv;
	REPLY_STR_CONTANT(bevent, "400 BAD REQUEST\n");
	return 0;
}

static int
command_help(struct bufferevent *bevent, int argc, char **argv)
{
	(void) argc;
	(void) argv;
	REPLY_STR_CONTANT(bevent, "Commands:\n");
	REPLY_STR_CONTANT(bevent, "\t start ID [ID]...  : starts the process with the given ID\n");
	REPLY_STR_CONTANT(bevent, "\t stop ID [ID]...   : stops the process with the given ID\n");
	REPLY_STR_CONTANT(bevent, "\t status [ID]...    : stops the process with the given ID\n");
	REPLY_STR_CONTANT(bevent, "\t reload            : reloads the configuration and restores a UNIX socket if necessary\n");
	REPLY_STR_CONTANT(bevent, "\t repair            : \n");
	REPLY_STR_CONTANT(bevent, "\t check             : \n");
	REPLY_STR_CONTANT(bevent, "\n");
	return 0;
}

typedef int (*cmd_f)(struct bufferevent *bevent, int argc, char **argv);

struct cmd_mapping_s {
	const gchar *cmd_name;
	cmd_f cmd_callback;
};

static struct cmd_mapping_s COMMANDS [] = {
	{"status",  command_show },
	{"repair",  command_repair },
	{"start",   command_start },
	{"stop",    command_stop },
	{"reload",  command_reload },
	{"check",   command_check },
	{"help",    command_help },
	{NULL,      NULL}
};

static cmd_f
__resolve_command(const gchar *n)
{
	int i;
	for (i=0; ;i++) {
		struct cmd_mapping_s *cmd = COMMANDS + i;
		if (!cmd->cmd_name)
			return NULL;
		if (0 == g_ascii_strcasecmp(n, cmd->cmd_name))
			return cmd->cmd_callback;
	}
}


/* Libevent callbacks ------------------------------------------------------ */

static void
supervisor_signal_handler(int s, short flags, void *udata)
{
	(void) udata;
	(void) flags;

	switch (s) {
	case SIGUSR1: /* ignored */
		return;
	case SIGUSR2: 
		flag_check_socket = ~0;
		return;
	case SIGPIPE: /* ignored */
		return;
	case SIGINT:
	case SIGQUIT:
	case SIGKILL:
	case SIGTERM:
		flag_running = 0;
		return;
	case SIGCHLD:
		(void) supervisor_children_catharsis(NULL, alert_proc_died);
		return;
	case SIGALRM:
		return;
	}
}

static void
__bevent_error(struct bufferevent *p_bevent, short what, void *udata)
{
	int fd;

	(void) what;
	fd = GPOINTER_TO_SIZE(udata);

	if (fd >= 0) {
		int sock_err;
		socklen_t sock_err_len;

		sock_err_len = sizeof(sock_err);
		if (0 != getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &sock_err_len))
			DEBUG("Unexpected error fd=%d : getsockopt() error : %s", fd, strerror(errno));
		else
			DEBUG("Connection closed fd=%d : %s", fd, strerror(sock_err));
		shutdown(fd, SHUT_RDWR);
		close(fd);
	}
	else {
		WARN("BufferEvent %p : error detected, freeing and closing fd=%d", p_bevent, fd);
	}

	bufferevent_disable(p_bevent, EV_READ);
	bufferevent_disable(p_bevent, EV_WRITE);
	bufferevent_free(p_bevent);
}

static void
__event_command_in(struct bufferevent *p_bevent, void *udata)
{
	int rc = 0;
	/* raw command */
	size_t offset;
	char buff[1024];
	/* parsed command */
	int argc = 0;
	gchar **argv = NULL;

	(void) udata;
	offset = 0;
	memset(buff, 0x00, sizeof(buff));

	/* Read the command received until a new line is available or until
	 * the end of the input. Remember this server only uses UNIX sockets,
	 * and messages sent to these sockets are sent/received atomically. */

	while (offset < sizeof(buff)-1) {
		char c;
		size_t r;
		r = bufferevent_read(p_bevent, &c, 1);
		if (!r)
			break;
		if (!c || c=='\n' || c=='\r') {
			if (!offset)
				continue;
			else
				break;
		}
		buff[offset ++] = c;
	}
	
	if (!offset) { /* Empty buffer, read again */
		bufferevent_enable(p_bevent, EV_READ);
		bufferevent_disable(p_bevent, EV_WRITE);
		TRACE("fd=%d : empty command, reading again", GPOINTER_TO_INT(udata));
		return;
	}
	
	/* Something has been read, manage this as a command */
	if (!g_shell_parse_argv(buff, &argc, &argv, NULL)) {
		REPLY_STR_CONTANT(p_bevent, "400 Invalid request");
		rc = 0;
	}
	else {
		cmd_f cmd = __resolve_command(argv[0]);
		if (!cmd)
			rc = command_INVALID(p_bevent, argc, argv);
		else
			rc = (cmd)(p_bevent, argc, argv);
		g_strfreev(argv);
		argv = NULL;
	}

	/* Manage the command's return code */
	if (rc == 0) {
		bufferevent_disable(p_bevent, EV_READ);
		bufferevent_enable(p_bevent, EV_WRITE);
	}
	else {
		int fd = GPOINTER_TO_INT(udata);
		bufferevent_disable(p_bevent, EV_READ);
		bufferevent_disable(p_bevent, EV_WRITE);
		if (fd >= 0) {
			shutdown(fd, SHUT_RDWR);
			close(fd);
		}
		bufferevent_free(p_bevent);
	}
}

static void
__event_command_out(struct bufferevent *p_bevent, void *udata)
{
	int fd;
	
	fd = GPOINTER_TO_SIZE(udata);

	bufferevent_disable(p_bevent, EV_READ);
	bufferevent_disable(p_bevent, EV_WRITE);
	if (fd >= 0) {
		shutdown(fd, SHUT_RDWR);
		close(fd);
	}
	bufferevent_free(p_bevent);
	DEBUG("Connection closed by server fd=%d : no keepalive", fd);
}

static void
__event_accept(int fd, short flags, void *udata)
{
	struct linger ls = {1,0};
	socklen_t ss_len;
	struct sockaddr_storage ss;
	int fd_client;
	int i_opt, i_rc;
	struct event_base *libevents_handle;
	
	(void) flags;
	libevents_handle = udata;
	
	ss_len = sizeof(ss);
	fd_client = accept(fd, (struct sockaddr*)&ss, &ss_len);
	if (fd_client < 0) {
		ERROR("accept error on fd=%d : %s", fd, strerror(errno));
		return;
	}

	/*SO_LINGER*/
	ls.l_onoff = 1;
	ls.l_linger = 0;
	i_rc = setsockopt(fd_client, SOL_SOCKET, SO_LINGER, (void *) &ls, sizeof(ls));
	if (i_rc == -1)
		WARN("fd=%i Cannot set the linger behaviour (%s)", fd_client, strerror(errno));

	/*SO_REUSEADDR*/
	i_opt = 1;
	i_rc = setsockopt(fd_client, SOL_SOCKET, SO_REUSEADDR, (void*) &i_opt, sizeof(i_opt));
	if (i_rc == -1)
		WARN("fd=%i Cannot set the REUSEADDR flag (%s)", fd_client, strerror(errno));

	/*SO_KEEPALIVE*/
	i_opt = 1;
	i_rc = setsockopt(fd_client, SOL_SOCKET, SO_KEEPALIVE, (void*) &i_opt, sizeof(i_opt));
	if (i_rc == -1)
		WARN("fd=%i Cannot trigger the tcp keepalive behaviour (%s)", fd_client, strerror(errno));

	/* TCP-specific options */
	socklen_t opt_len = sizeof(i_opt);
	i_rc = getsockopt(fd_client, SOL_SOCKET, SO_TYPE, (void*)&i_opt, &opt_len);
	if (i_rc == -1)
		WARN("fd=%i Cannot check the socket type (%s)", fd_client, strerror(errno));
	else if (i_opt == SOCK_STREAM && ss.ss_family == AF_INET) {
		
		/* TCP_QUICKACK */
		i_opt = 1;
		i_rc = setsockopt(fd_client, IPPROTO_TCP, TCP_QUICKACK, (void*)&i_opt, sizeof(i_opt));
		if (i_rc == -1)
			WARN("fd=%i Cannot set TCP_QUICKACK mode on socket (%s)", fd_client, strerror(errno));
		
		/* TCP_NODELAY */
		i_opt = 1;
		i_rc = setsockopt(fd_client, IPPROTO_TCP, TCP_NODELAY, (void*)&i_opt, sizeof(i_opt));
		if (i_rc == -1)
			WARN("fd=%i Cannot set TCP_NODELAY mode on socket (%s)", fd_client, strerror(errno));
	}

	evutil_make_socket_closeonexec(fd_client);

	/* Now manage this connection */
	struct bufferevent *p_bevent =  NULL;
	p_bevent = bufferevent_new(fd_client, __event_command_in,
		__event_command_out, __bevent_error, GINT_TO_POINTER(fd_client));
	bufferevent_settimeout(p_bevent, 1000, 4000);
	bufferevent_enable(p_bevent, EV_READ);
	bufferevent_disable(p_bevent, EV_WRITE);
	bufferevent_base_set(libevents_handle, p_bevent);
	INFO("Connection accepted : accept(%d) = %d", fd, fd_client);
}


/* Server socket pool management ------------------------------------------- */

static int
servers_is_unix(struct server_sock_s *server)
{
	struct sockaddr_storage ss;
	socklen_t ss_len;

	bzero(&ss, sizeof(ss));
	ss_len = sizeof(ss);

	if (server->fd < 0)
		return FALSE;
		
	if (0 == getsockname(server->fd, (struct sockaddr*) &ss, &ss_len)) {
		if (ss.ss_family==AF_UNIX || ss.ss_family==AF_LOCAL) {
			return TRUE;
		}
	}

	errno = 0;
	return FALSE;
}

static int
servers_is_the_same(struct server_sock_s *server)
{
	struct stat stat_sock, stat_path;
	
	bzero(&stat_sock, sizeof(stat_sock));
	bzero(&stat_path, sizeof(stat_path));

	return ((0 == stat(server->url, &stat_path))
			&& (0 == fstat(server->fd, &stat_sock))
			&& (stat_path.st_ino == server->unix_stat_path.st_ino)
			&& (stat_sock.st_ino == server->unix_stat_sock.st_ino));
}

static void
servers_unmonitor_one(struct server_sock_s *server)
{
	if (server->fd < 0) {
		/* server socket already stopped */
		return ;
	}

	/* Stop the libevent management right now */	
	if (event_pending(&(server->event), EV_READ, NULL))
		event_del(&(server->event));

	/* If the current socket is a UNIX socket, remove the socket file
	 * on disk only if this file is exactly the same that the file
	 * this socket created. We must avoid deleting a socket file
	 * opened by another process */
	if (servers_is_unix(server) && servers_is_the_same(server))
		unlink(server->url);

	shutdown(server->fd, SHUT_RDWR);
	close(server->fd);
	server->fd = -1;
}

/* starts the server monitoring with the libevent.
 * The inner file descriptor must be a valid socket filedes */
static gboolean
servers_monitor_one(struct server_sock_s *server)
{
	struct sockaddr_storage ss;
	socklen_t ss_len;

	if (!server || server->fd < 0) {
		errno = EINVAL;
		return FALSE;
	}

	memset(&ss, 0x00, sizeof(ss));
	ss_len = sizeof(ss);
	if (-1 == getsockname(server->fd, (struct sockaddr*) &ss, &ss_len)) {
		if (!flag_quiet)
			g_printerr("Error with socket [%s]\n", server->url);
		return FALSE;
	}
	
	/* For unix sockets, remember the stat for further checks */
	if (ss.ss_family==AF_UNIX || ss.ss_family==AF_LOCAL) {
		if (0 != stat(((struct sockaddr_un*)&ss)->sun_path, &(server->unix_stat_path))) {
			if (!flag_quiet)
				g_printerr("Error with socket [%s]\n", server->url);
			return FALSE;
		}
		if (0 != fstat(server->fd, &(server->unix_stat_sock))) {
			if (!flag_quiet)
				g_printerr("Error with socket [%s]\n", server->url);
			return FALSE;
		}
	}

	event_set(&(server->event), server->fd, EV_READ|EV_PERSIST, __event_accept, NULL);
	event_add(&(server->event), NULL);
	errno = 0;
	if (!flag_quiet)
		g_printerr("Socket opened [%s]\n", server->url);
	return TRUE;
}

static int
servers_monitor_none(void)
{
	GList *l;

	TRACE("About to stop all the server sockets");
	for (l=list_of_servers; l ;l=l->next) {
		struct server_sock_s *s = l->data;
		servers_unmonitor_one(s);
	}

	errno = 0;
	return TRUE;
}

static int
servers_monitor_all(void)
{
	GList *l;
	
	TRACE("About to monitor all the server sockets");
	
	for (l=list_of_servers; l ;l=l->next) {
		struct server_sock_s *s = l->data;
		if (!servers_monitor_one(s))
			return FALSE;
	}

	errno = 0;
	return TRUE;
}

/**
 * Creates a server structure based on the file descriptor and
 * add it to the list
 */
static gboolean
servers_save_fd(int fd, const char *url)
{
	struct server_sock_s *server;

	if (fd < 0)
		return FALSE;

	/* should check if the socket is not already monitored */
	server = g_malloc0(sizeof(*server));
	server->fd = fd;
	server->url = g_strdup(url);

	list_of_servers = g_list_prepend(list_of_servers, server);
	return TRUE;
}

/**
 * Opens a UNIX server socket then manage a server based on it
 */
static int
servers_save_unix(const char *path)
{
	int sock;

	if (-1 == (sock = __open_unix_server(path)))
		goto label_error;

	if (!servers_save_fd(sock, path))
		goto label_error;

	errno = 0;
	return sock;

label_error:
	if (sock >= 0) {
		typeof(errno) errsav;
		errsav = errno;
		shutdown(sock, SHUT_RDWR);
		close(sock);
		errno = errsav;
	}
	return -1;
}

/** 
 * Stops the server socket then 
 */
static void
servers_clean(void)
{
	GList *l;

	/* stop */
	servers_monitor_none();

	/* clean */
	for (l=list_of_servers; l ; l=l->next) {
		struct server_sock_s *p_server = l->data;

		if (p_server->url)
			g_free(p_server->url);

		memset(p_server, 0x00, sizeof(*p_server));
		g_free(p_server);
		l->data = NULL;
	}

	g_list_free(list_of_servers);
	list_of_servers = NULL;
}

/** 
 * Reopens all the UNIX server sockets bond on paths that changed.
 */
static void
servers_ensure(void)
{
	GList *l;
	
	flag_check_socket = 0;
	TRACE("About to ensure the server sockets");

	for (l=list_of_servers; l ; l=l->next) {
		struct server_sock_s *p_server = l->data;

		NOTICE("Ensuring socket fd=%d bond to [%s]", p_server->fd, p_server->url);

		if (servers_is_unix(p_server) && !servers_is_the_same(p_server)) {

			/* close */
			servers_unmonitor_one(p_server);

			/* reopen */
			p_server->fd = __open_unix_server(p_server->url);
			if (p_server->fd < 0) {
				WARN("unix: failed to reopen a server bond to [%s] : %s",
						p_server->url, strerror(errno));
			}
			else if (!servers_monitor_one(p_server)) {
				WARN("unix: failed to monitor a server bond to [%s] : %s",
						p_server->url, strerror(errno));
				servers_unmonitor_one(p_server);
			}
		}
	}
}

/* Signals management ------------------------------------------------------ */

static void
signals_manage(int s)
{
	struct event *signal_event;
	signal_event = g_malloc0(sizeof(*signal_event));
	event_set(signal_event, s, EV_SIGNAL|EV_PERSIST, supervisor_signal_handler, NULL);
	event_add(signal_event, NULL);
	list_of_signals = g_list_prepend(list_of_signals, signal_event);
}

static void
signals_clean(void)
{
	GList *l;
	for (l=list_of_signals; l ;l=l->next) {
		struct event *signal_event = l->data;
		g_free(signal_event);
		l->data = NULL;
	}
	g_list_free(list_of_signals);
	list_of_signals = NULL;
}

/* Configuration ----------------------------------------------------------- */

static gboolean
_cfg_value_is_true(const gchar *val)
{
	return val && (
		   0==g_ascii_strcasecmp(val,"true")
		|| 0==g_ascii_strcasecmp(val,"yes")
		|| 0==g_ascii_strcasecmp(val,"enable")
		|| 0==g_ascii_strcasecmp(val,"enabled")
		|| 0==g_ascii_strcasecmp(val,"on"));
}

static GHashTable*
_cfg_extract_parameters (GKeyFile *kf, const char *s, const char *p, GError **err)
{
	gchar **all_keys=NULL, **current_key=NULL;
	gsize size=0;
	GHashTable *ht=NULL;

	ht = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	all_keys = g_key_file_get_keys (kf, s, &size, err);
	if (!all_keys)
		goto error;
	for (current_key=all_keys; current_key && *current_key ;current_key++) {
		if (g_str_has_prefix(*current_key, p)) {
			gchar *value = g_key_file_get_value (kf, s, *current_key, err);
			g_hash_table_insert (ht, g_strdup(*current_key + strlen(p)), value);
		}
	}

	g_strfreev(all_keys);
	return ht;
error:
	if (ht)
		g_hash_table_destroy(ht);
	if (all_keys)
		g_strfreev(all_keys);
	return NULL;
}

static gchar*
__get_and_enlist(GSList **gc, GKeyFile *kf, const gchar *section, const gchar *key)
{
	gchar *str;

	if (NULL != (str = g_key_file_get_string(kf, section, key, NULL)))
		*gc = g_slist_prepend(*gc, str);

	return str;
}

static void
my_free1(gpointer p1, gpointer p2)
{
	(void) p2;
	if (p1)
		g_free(p1);
}

static gboolean
_str_is_num(const gchar *s)
{
	for (; *s ; s++) {
		if (!g_ascii_isdigit(*s))
			return FALSE;
	}
	return TRUE;
}

/** XXX JFS Linux-specific code */
static gboolean
uid_exists(const gchar *str, gint32 *id)
{
	struct passwd pwd, *p_pwd;
	gchar buf[1024];

	if (_str_is_num(str)) {
		gint64 i64;

		i64 = g_ascii_strtoll(str, NULL, 10);
		*id = i64;
		return TRUE;
	}

	if (0 != getpwnam_r(str, &pwd, buf, sizeof(buf), &p_pwd))
		return FALSE;
		
	*id = pwd.pw_uid;
	return TRUE;
}

/** XXX JFS Linux-specific code */
static gboolean
gid_exists(const gchar *str, gint32 *id)
{
	struct group grp, *p_grp;
	gchar buf[1024];

	if (_str_is_num(str)) {
		gint64 i64;

		i64 = g_ascii_strtoll(str, NULL, 10);
		*id = i64;
		return TRUE;
	}

	if (0 != getgrnam_r(str, &grp, buf, sizeof(buf), &p_grp))
		return FALSE;
		
	*id = grp.gr_gid;
	return TRUE;
}

static gboolean
_cfg_service_load_env(GKeyFile *kf, const gchar *section, const gchar *str_key, GError **err)
{
	gboolean rc = FALSE;
	GHashTable *ht_env;
	GHashTableIter iter_env;
	gpointer k, v;
	
	ht_env = _cfg_extract_parameters(kf, section, "env.", err);
	if (!ht_env)
		return FALSE;	

	g_hash_table_iter_init(&iter_env, ht_env);
	while (g_hash_table_iter_next(&iter_env, &k, &v)) {
		if (0 != supervisor_children_setenv(str_key, (gchar*)k, (gchar*)v)) {
			WARN("[%s] saved environment [%s]=[%s] : %s",
				str_key, (gchar*)k, (gchar*)v, strerror(errno));
			goto exit;
		}
		DEBUG("[%s] saved environment variable [%s]=[%s]",
				str_key, (gchar*)k, (gchar*)v);
	}

	DEBUG("[%s] environment saved", str_key);
	rc = TRUE;
exit:
	g_hash_table_destroy(ht_env);
	return rc;
}

static gboolean
_cfg_section_service(GKeyFile *kf, const gchar *section, GError **err)
{
	GSList *gc = NULL;
	gboolean rc = FALSE, rc_enable;
	gchar *str_key;
	gchar *str_command, *str_enabled, *str_ondie, *str_uid, *str_gid,
		*str_limit_stack, *str_limit_core, *str_limit_fd, *str_wd,
		*str_group;

	str_key = strchr(section, '.');
	str_key ++;
	str_command = __get_and_enlist(&gc, kf, section, "command");
	str_enabled = __get_and_enlist(&gc, kf, section, "enabled");
	str_ondie = __get_and_enlist(&gc, kf, section, "on_die");
	str_uid = __get_and_enlist(&gc, kf, section, "uid");
	str_gid = __get_and_enlist(&gc, kf, section, "gid");
	str_group = __get_and_enlist(&gc, kf, section, "group");
	str_limit_fd = __get_and_enlist(&gc, kf, section, "limit.max_files");
	str_limit_core = __get_and_enlist(&gc, kf, section, "limit.core_size");
	str_limit_stack = __get_and_enlist(&gc, kf, section, "limit.stack_size");
	str_wd = __get_and_enlist(&gc, kf, section, CFG_KEY_PATH_WORKINGDIR);

	if (!supervisor_children_register(str_key, str_command, err))
		goto label_exit;

	if (*default_working_directory)
		supervisor_children_set_working_directory(str_key, default_working_directory);

	/* Enables or not */
	rc_enable = supervisor_children_enable(str_key, _cfg_value_is_true(str_enabled));
	if (0 > rc_enable) {
		*err = g_error_printf(LOG_DOMAIN, EINVAL, "Service [%s] cannot be marked [%s] : rc=%d",
		                        str_key, (_cfg_value_is_true(str_enabled)?"ENABLED":"DISABLED"),
					rc_enable);
		goto label_exit;
	}

	/* on_die management */
	if (str_ondie) {
		if (0 == g_ascii_strcasecmp(str_ondie, "cry")) {
			supervisor_children_set_respawn(str_key, FALSE);
		}
		else if (0 == g_ascii_strcasecmp(str_ondie, "exit")) {
			supervisor_children_set_user_flags(str_key, USERFLAG_ONDIE_EXIT);
			supervisor_children_set_respawn(str_key, FALSE);
		}
		else if (0 == g_ascii_strcasecmp(str_ondie, "respawn"))
			supervisor_children_set_respawn(str_key, TRUE);
		else {
			WARN("Service [%s] has an unexpected [%s] value (%s), set to 'respawn'",
				str_key, "on_die", str_ondie);
			supervisor_children_set_respawn(str_key, TRUE);
		}
	}

	/* By default set the current uid/gid */
	supervisor_children_set_ids(str_key, getuid(), getgid());

	/* Overwrite this by possibly configured default uid/gid  */
	if (default_uid>0 && default_gid>0)
		supervisor_children_set_ids(str_key, default_uid, default_gid);

	/* explicit user/group pair */
	if (str_uid && str_gid && *str_uid && *str_uid) {
		gint32 uid, gid;

		uid = gid = -1;
		if (!uid_exists(str_uid, &uid)) {
			/* Invalid user */
			*err = g_error_printf(LOG_DOMAIN, EINVAL, "Service [%s] cannot cannot receive UID [%s] : errno=%d %s",
		                        str_key, str_uid, errno, strerror(errno));
			goto label_exit;
		}
		if (!gid_exists(str_gid, &gid)) {
			/* Invalid group */
			*err = g_error_printf(LOG_DOMAIN, EINVAL, "Service [%s] cannot cannot receive GID [%s] : errno=%d %s",
		                        str_key, str_gid, errno, strerror(errno));
			goto label_exit;
		}
	
		supervisor_children_set_ids(str_key, uid, gid);
	}

	/* alternative limits */
	if (str_limit_stack) {
		gint64 i64 = g_ascii_strtoll(str_limit_stack, NULL, 10);
		supervisor_children_set_limit(str_key, SUPERV_LIMIT_THREAD_STACK, i64 * 1024);
	}
	if (str_limit_fd) {
		gint64 i64 = g_ascii_strtoll(str_limit_fd, NULL, 10);
		supervisor_children_set_limit(str_key, SUPERV_LIMIT_MAX_FILES, i64);
	}
	if (str_limit_core) {
		gint64 i64 = g_ascii_strtoll(str_limit_core, NULL, 10);
		supervisor_children_set_limit(str_key, SUPERV_LIMIT_CORE_SIZE, i64 * 1024 * 1024);
	}
	
	/* Explicit working directory */
	if (str_wd) {
		if (!g_file_test(str_wd, G_FILE_TEST_IS_DIR|G_FILE_TEST_IS_EXECUTABLE))
			WARN("Explicit working directory for [%s] does not exist yet [%s]",
				str_key, str_wd);
		supervisor_children_set_working_directory(str_key, str_wd);
	}

	/* Loads the environment */
	supervisor_children_clearenv(str_key);
	if (!_cfg_service_load_env(kf, section, str_key, err)) {
		ERROR("Failed to load environment for service [%s]", str_key);
		goto label_exit;
	}

	/* reset/set the process's group */
	supervisor_children_set_group(str_key, NULL);
	if (str_group)
		supervisor_children_set_group(str_key, str_group);
	
	rc = TRUE;

label_exit:
	if (gc) {
		g_slist_foreach(gc, my_free1, NULL);
		g_slist_free(gc);
	}
	return rc;
}

static gboolean
_cfg_section_alert(GKeyFile *kf, const gchar *section, GError **err)
{
	gchar cfg_plugin[1024], cfg_symbol[128];
	gchar **p_key, **keys;

	bzero(cfg_plugin, sizeof(cfg_plugin));
	bzero(cfg_symbol, sizeof(cfg_symbol));

	keys = g_key_file_get_keys(kf, section, NULL, err);
	if (!keys)
		return FALSE;

	for (p_key=keys; *p_key ;p_key++) {
		gchar *str;

		str = g_key_file_get_string(kf, section, *p_key, NULL);
		
		if (!g_ascii_strcasecmp(*p_key, "plugin")) {
			if (*cfg_plugin)
				ERROR("Alerting plugin already known : plugin=[%s]", cfg_plugin);
			else
				g_strlcpy(cfg_plugin, str, sizeof(cfg_plugin)-1);
		}
		else if (!g_ascii_strcasecmp(*p_key, "symbol")) {
			if (*cfg_symbol)
				ERROR("Alerting symbol already known : symbol=[%s]", cfg_symbol);
			else
				g_strlcpy(cfg_symbol, str, sizeof(cfg_symbol)-1);
		}

		g_free(str);
	}

	g_strfreev(keys);

	if (!*cfg_symbol || !*cfg_plugin) {
		ERROR("Missing configuration keys : both \"plugin\" and \"symbol\""
			" must be present in section [%s]", section);
		return FALSE;
	}
	else {
		GHashTable *ht_params;
		gboolean rc;
		ht_params = _cfg_extract_parameters(kf, section, "config.", err);
		rc = gridinit_alerting_configure(cfg_plugin, cfg_symbol, ht_params, err);
		g_hash_table_destroy(ht_params);
		if (!rc)
			return FALSE;
	}
	
	return TRUE;
}

static gboolean
_cfg_section_default(GKeyFile *kf, const gchar *section, GError **err)
{
	gchar buf_user[256]="", buf_group[256]="", buf_includes[1024]="";
	gint64 limit_thread_stack = 1024;
	gint64 limit_core_size = -1;
	gint64 limit_nb_files = 8192;
	gchar **p_key, **keys;

	keys = g_key_file_get_keys(kf, section, NULL, err);
	if (!keys)
		return FALSE;

	/* Load the system limit and the pidfile path */
	for (p_key=keys; *p_key ;p_key++) {
		gchar *str;

		str = g_key_file_get_string(kf, section, *p_key, NULL);

		if (!g_ascii_strcasecmp(*p_key, CFG_KEY_LIMIT_CORESIZE)) {
			limit_core_size = g_ascii_strtoll(str, NULL, 10);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_PATH_WORKINGDIR)) {
			if (!g_file_test(*p_key, G_FILE_TEST_IS_DIR|G_FILE_TEST_IS_EXECUTABLE))
				WARN("Default working directory does not exist yet [%s]", *p_key);
			bzero(default_working_directory, sizeof(default_working_directory));
			g_strlcpy(default_working_directory, str, sizeof(default_working_directory)-1);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_LIMIT_NBFILES)) {
			limit_nb_files = g_ascii_strtoll(str, NULL, 10);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_LIMIT_STACKSIZE)) {
			limit_thread_stack = g_ascii_strtoll(str, NULL, 10);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_PATH_PIDFILE)) {
			bzero(pidfile_path, sizeof(pidfile_path));
			g_strlcpy(pidfile_path, str, sizeof(pidfile_path)-1);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_LISTEN)) {
			if (str[0] == '/') {
				bzero(sock_path, sizeof(sock_path));
				g_strlcpy(sock_path, str, sizeof(sock_path)-1);
			}
			else {
				g_printerr("section=%s, key=listen : not a UNIX path, ignored! [%s]\n",
					section, str);
			}
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_USER)) {
			bzero(buf_user, sizeof(buf_user));
			g_strlcpy(buf_user, str, sizeof(buf_user)-1);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_GROUP)) {
			bzero(buf_group, sizeof(buf_group));
			g_strlcpy(buf_group, str, sizeof(buf_group)-1);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_INCLUDES)) {
			bzero(buf_includes, sizeof(buf_includes));
			g_strlcpy(buf_includes, str, sizeof(buf_includes)-1);
		}

		g_free(str);
	}
	g_strfreev(keys);

	/* Set the defautl limits for the services (apply them directly to the gridinit itself) */
	(void) supervisor_limit_set(SUPERV_LIMIT_CORE_SIZE, limit_core_size * 1024 * 1024);
	(void) supervisor_limit_set(SUPERV_LIMIT_MAX_FILES, limit_nb_files);
	(void) supervisor_limit_set(SUPERV_LIMIT_THREAD_STACK, limit_thread_stack * 1024);

	/* Loads the default UID/GID for the services*/
	if (*buf_user && *buf_group) {
		gint32 uid, gid;

		uid = gid = -1;
		if (!uid_exists(buf_user, &uid)) {
			WARN("Invalid default UID [%s] : errno=%d %s", buf_user, errno, strerror(errno));
			uid = -1;
		}
		if (!gid_exists(buf_group, &gid)) {
			WARN("Invalid default GID [%s] : errno=%d %s", buf_user, errno, strerror(errno));
			gid = -1;
		}
		if (uid>0 && gid>0) {
			default_uid = uid;
			default_gid = gid;
			NOTICE("Default UID/GID set to %"G_GINT32_FORMAT"/%"G_GINT32_FORMAT, default_uid, default_gid);
		}
	}

	/* Loads the service files */
	if (*buf_includes) {
		if (config_subdir)
			g_free(config_subdir);
		config_subdir = g_strndup(buf_includes, sizeof(buf_includes));
	}

	return TRUE;
}

static gboolean
_cfg_reload_file(GKeyFile *kf, gboolean services_only, GError **err)
{
	gboolean rc = FALSE;
	gchar **groups=NULL, **p_group=NULL;

	groups = g_key_file_get_groups(kf, NULL);

	if (!groups) {
		*err = g_error_new(g_quark_from_static_string("gridinit"), EINVAL, "no group");
		return FALSE;
	}

	for (p_group=groups; *p_group ;p_group++) {

		TRACE("Reading section [%s]", *p_group);

		if (g_str_has_prefix(*p_group, "service.")
				 || g_str_has_prefix(*p_group, "Service.")) {
			INFO("reconfigure : managing service section [%s]", *p_group);
			if (!_cfg_section_service(kf, *p_group, err)) {
				WARN("invalid service section");
				goto label_exit;
			}
		}
		else if (!services_only && !g_ascii_strcasecmp(*p_group, "default")) {
			INFO("reconfigure : loading main parameters from section [%s]", *p_group);
			if (!_cfg_section_default(kf, *p_group, err)) {
				WARN("invalid default section");
				goto label_exit;
			}
		}
		else if (!services_only && !g_ascii_strcasecmp(*p_group, "alerts")) {
			INFO("reconfigure : loading alerting parameters from section [%s]", *p_group);
			if (!_cfg_section_alert(kf, *p_group, err)) {
				WARN("Invalid alerts section");
				goto label_exit;
			}
		}
		else {
			INFO("reconfigure : ignoring section [%s]", *p_group);
		}
	}
	rc = TRUE;

label_exit:
	g_strfreev(groups);
	return rc;
}

static gboolean
_cfg_reload(gboolean services_only, GError **err)
{
	gboolean rc = FALSE;
	GKeyFile *kf = NULL;
	
	kf = g_key_file_new();

	if (!g_key_file_load_from_file(kf, config_path, 0, err)) {
		ERROR("Conf not parseable from [%s]", config_path);
		goto label_exit;
	}

	/* First load the main files */
	if (!_cfg_reload_file(kf, services_only, err)) {
		ERROR("Conf not loadable from [%s]", config_path);
		goto label_exit;
	}

	/* Then load "globbed" sub files, but only services */
	if (config_subdir) {
		int notify_error(const char *path, int en) {
			NOTICE("errno=%d %s : %s", en, path, strerror(en));
			return 0;
		}
		int glob_rc;
		glob_t subfiles_glob;

		bzero(&subfiles_glob, sizeof(subfiles_glob));

		DEBUG("Loading services files matching [%s]", config_subdir);

		glob_rc = glob(config_subdir, GLOB_NOSORT|GLOB_MARK, notify_error, &subfiles_glob);
		if (glob_rc != 0) {
			if (glob_rc == GLOB_NOMATCH)
				NOTICE("Service file pattern matched no file!");
			else
				ERROR("reconfigure : glob error : %s", strerror(errno));
		}
		else {
			char **p_str;

			DEBUG("reconfigure : glob done, %"G_GSIZE_FORMAT" elements found", subfiles_glob.gl_pathc);
			for (p_str=subfiles_glob.gl_pathv; p_str && *p_str ;p_str++) {
				GError *gerr_local = NULL;
				GKeyFile *sub_kf = NULL;

				TRACE("Loading a new file");

				sub_kf = g_key_file_new();
				if (!g_key_file_load_from_file(sub_kf, *p_str, 0, &gerr_local))
					ERROR("Configuration file [%s] not parsed : %s", *p_str,
						gerr_local ? gerr_local->message : "");
				else if (!_cfg_reload_file(sub_kf, TRUE, &gerr_local))
					ERROR("Configuration file [%s] not loaded : %s", *p_str,
						gerr_local ? gerr_local->message : "");
				else
					INFO("Loaded service file [%s]", *p_str);

				if (gerr_local)
					g_clear_error(&gerr_local);
				g_key_file_free(sub_kf);
			}
			globfree(&subfiles_glob);
		}
	}

	rc = TRUE;
	INFO("Configuration loaded from [%s]", config_path);
	
label_exit:
	if (kf)
		g_key_file_free(kf);
	return rc;	
}

/* ------------------------------------------------------------------------- */

static void
__parse_options(int argc, char ** args)
{
	int c;
	GError *error_local = NULL;

	bzero(pidfile_path, sizeof(pidfile_path));

	while (-1 != (c = getopt(argc, args, "qd"))) {
		switch (c) {
			case 'd':
				flag_daemon = ~0;
				break;
			case 'q':
				flag_quiet = ~0;
				break;
			default:
				if (!flag_quiet)
					g_printerr("Unexpected option : %c\n", c);
				exit(1);
		}
	}
	
	/* check for additionnal arguments */
	if (optind >= argc) {
		if (!flag_quiet)
			g_printerr("Usage: %s [OPTIONS]... CONFIG_PATH [LOG4C_PATH]\n", args[0]);
		exit(1);
	}
	
	/* Loads the log4c configuration */
	if (optind + 1 < argc) {
		int rc;
		typeof(errno) errsav;
		const char *log4crc_path = args[optind+1];
		
		rc = log4c_load(log4crc_path);
		errsav = errno;
		if (!flag_quiet)
			g_printerr("Loaded the log4c configuration from [%s] : rc=%d %s (%s)\n",
				log4crc_path, rc, strerror(rc), strerror(errsav));
	}
	
	/* configuration loading */
	config_path = g_strdup(args[optind]);
	if (!flag_quiet)
		g_printerr("Reading the config from [%s]\n", config_path);
	if (!_cfg_reload(FALSE, &error_local)) {
		if (!flag_quiet)
			g_printerr("Configuration loading error from [%s] : %s\n", config_path, error_local->message);
		exit(1);	
	}
}

static void
write_pid_file(void)
{
	FILE *stream_pidfile;

	if (!*pidfile_path)
		return ;

	stream_pidfile = fopen(pidfile_path, "w+");
	if (!stream_pidfile) {
		ERROR("write_pid_file() error : [%s] : %s", pidfile_path, strerror(errno));
		return ;
	}

	fprintf(stream_pidfile, "%d", getpid());
	fclose(stream_pidfile);
}

int
main(int argc, char ** args)
{
	int rc = 1;
	struct event_base *libevents_handle = NULL;
	
	void postfork(void *udata) {
		(void) udata;
		if (libevents_handle)
			event_reinit(libevents_handle);
	}

	bzero(sock_path, sizeof(sock_path));
	bzero(pidfile_path, sizeof(pidfile_path));
	bzero(default_working_directory, sizeof(default_working_directory));

	g_strlcpy(sock_path, GRIDINIT_SOCK_PATH, sizeof(sock_path)-1);

	log4c_init();
	supervisor_children_init();
	__parse_options(argc, args);
#if 0
	(void) supervisor_rights_lose();
#endif

	close(0);/* We will never read the standard input */
	if (flag_daemon) {
		if (0 != daemon(1,0)) {
			FATAL("Failed to daemonize : %s", strerror(errno));
			goto label_exit;
		}
		close(1);
		close(2);
		write_pid_file();
	}
	
	if (-1 == servers_save_unix(sock_path)) {
		ERROR("Failed to open the UNIX socket for commands : %s",
			strerror(errno));
		goto label_exit;
	}
	
	/* Starts the network and the signal management */
	DEBUG("Initiating the network and signals management");
	libevents_handle = event_init();

	supervisor_set_callback_postfork(postfork, NULL);

	signals_manage(SIGTERM);
	signals_manage(SIGABRT);
	signals_manage(SIGINT);
	signals_manage(SIGALRM);
	signals_manage(SIGQUIT);
	signals_manage(SIGUSR1);
	signals_manage(SIGUSR2);
	signals_manage(SIGCHLD);
	if (!servers_monitor_all()) {
		ERROR("Failed to monitor the server sockets");
		goto label_exit;
	}

	timer_event_arm(TRUE);
	
	DEBUG("Starting the event loop!");
	do { /* main loop */
		guint proc_count;

		/* start all the enabled processes */
		proc_count = supervisor_children_startall(NULL, alert_proc_started);
		DEBUG("First started %u processes", proc_count);

		while (flag_running) {
			
			/* alert for the services that died */
			supervisor_run_services(NULL, alert_send_deferred);
			if (!flag_running)
				break;

			/* some status changed */
			proc_count = supervisor_children_kill_disabled();
			if (proc_count)
				INFO("Killed %u disabled/stopped services", proc_count);
			if (!flag_running)
				break;

			proc_count = supervisor_children_start_enabled(NULL, alert_proc_started);
			if (proc_count)
				INFO("Started %u enabled services", proc_count);
			if (!flag_running)
				break;
			if (flag_check_socket)
				servers_ensure();
			
			/* Be sure to wake */
			alarm(1);

			/* Manages the connections pool */
			if (0 > event_loop(EVLOOP_ONCE)) {
				ERROR("event_loop() error : %s", strerror(errno));
				break;
			}
		}
	} while (0);

	rc = 0;

label_exit:
	/* stop all the processes */
	DEBUG("Stopping all the children");
	(void) supervisor_children_stopall(4);

	/* clean the working structures */
	DEBUG("Cleaning the working structures");
	if (libevents_handle)
		event_base_free(libevents_handle);

	(void) supervisor_children_catharsis(NULL, alert_proc_died);
	supervisor_children_cleanall();
	servers_clean();
	signals_clean();
	g_free(config_path);

	gridinit_alerting_close();
	log4c_fini();
	return rc;
}

