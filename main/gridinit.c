#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridinit"
#endif

#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <math.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <log4c.h>
#include <event.h>
#include <glib.h>

#include <gridinit-utils.h>
#include "./gridinit_internals.h"
#include "../lib/gridinit-internals.h"

#ifdef HAVE_EXTRA_DEBUG
# define XDEBUG DEBUG
# define XTRACE TRACE
#else
# define XDEBUG(FMT,...)
# define XTRACE(FMT,...)
#endif

struct server_sock_s {
	int family;
	int fd;
	char *url;
	struct event event;
	struct stat unix_stat_path;
	struct stat unix_stat_sock;
};

static GList *list_of_servers = NULL;

static char sock_path[1024];
static char pidfile_path[1024];
static char *config_path;

static volatile int flag_quiet = 0;
static volatile int flag_daemon = 0;
static volatile int flag_running = ~0;
static volatile int flag_reconfigure = 0;
static volatile int flag_check_socket = 0;
static volatile int flag_restart_children = 0;

static gboolean _reconfigure(gboolean services_only, GError **err);

static void servers_ensure(void);


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
command_start(struct bufferevent *bevent, int argc, char **argv)
{
	guint count_ok = 0, count_ko = 0;
	int i;

	if (argc<2) {
		__reply_sprintf(bevent, "error: missing argument\n");
		__reply_sprintf(bevent, "Usage: %s KEY [KEY...]\n", argv[0]);
		__reply_sprintf(bevent, "result: ok=%u ko=%u\n", count_ok, count_ko);
		return 0;
	}

	for (i=1; i<argc ;i++) {
		int rc = supervisor_children_enable(argv[i], TRUE);
		switch (rc) {
		case -1:
			count_ko++;
			__reply_sprintf(bevent, "notfound: %s\n", argv[i]);
			break;
		case 0:
			count_ok++;
			__reply_sprintf(bevent, "already: %s\n", argv[i]);
			break;
		case 1:
			count_ok++;
			__reply_sprintf(bevent, "enabled: %s\n", argv[i]);
			break;
		}
	}
	
	if (count_ok) {
		if (count_ko)
			__reply_sprintf(bevent, "No process started, there were %u errors\n", count_ko);
		else {
			guint count = supervisor_children_startall();
			__reply_sprintf(bevent, "Started %u processes\n", count);
		}
	}

	__reply_sprintf(bevent, "result: ok=%u ko=%u\n", count_ok, count_ko);
	REPLY_STR_CONTANT(bevent, "\n");
	return 0;
}

static int 
command_stop(struct bufferevent *bevent, int argc, char **argv)
{
	guint count_ok = 0, count_ko = 0;
	int i, rc;

	if (argc<2) {
		REPLY_STR_CONTANT(bevent, "Error: missing argument\n");
		__reply_sprintf(bevent, "Usage: %s KEY [KEY...]\n", argv[0]);
		__reply_sprintf(bevent, "result: ok=%u ko=%u\n", count_ok, count_ko);
		return 0;
	}

	for (i=1; i<argc ;i++) {
		rc = supervisor_children_enable(argv[i], FALSE);
		switch (rc) {
		case -1:
			count_ko ++;
			__reply_sprintf(bevent, "notfound: %s\n", argv[i]);
			break;
		case 0:
			count_ok ++;
			__reply_sprintf(bevent, "already: %s\n", argv[i]);
			break;
		case 1:
			count_ok ++;
			__reply_sprintf(bevent, "stopped: %s\n", argv[i]);
			break;
		}
	}

	if (count_ok) {
		if (count_ko)
			__reply_sprintf(bevent, "No process killed, there were %u errors\n", count_ko);
		else {
			guint count = supervisor_children_kill_disabled();
			__reply_sprintf(bevent, "killed %u processes\n", count);
		}
	}
	
	__reply_sprintf(bevent, "result: ok=%u ko=%u\n", count_ok, count_ko);
	REPLY_STR_CONTANT(bevent, "\n");
	return 0;
}

static int
command_show(struct bufferevent *bevent, int argc, char **argv)
{
	void run_service(void *udata, struct child_info_s *ci) {
		gsize buff_size;
		gchar buff[1024];
		
		(void) udata;
		buff_size = g_snprintf(buff, sizeof(buff), "%5d %d %5d %5d %s %s\n",
			ci->pid, ci->enabled,
			ci->counter_started, ci->counter_died, ci->key, ci->cmd);
		bufferevent_write(bevent, buff, buff_size);
	}

	(void) argc;
	(void) argv;
	supervisor_run_services(NULL, run_service);
	REPLY_STR_CONTANT(bevent, "\n");
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

	if (!_reconfigure(TRUE, &error_local)) {
		__reply_sprintf(bevent, "error: Failed to reload the configuration from [%s]\n", config_path);
		__reply_sprintf(bevent, "cause: %s\n", error_local ? error_local->message : "NULL");

		REPLY_STR_CONTANT(bevent, "Failed!\n\n");
	}
	else {
		__reply_sprintf(bevent, "Services refreshed\n");

		count = supervisor_children_kill_obsolete();
		__reply_sprintf(bevent, "Killed %u obsolete services\n", count);

		count = supervisor_children_kill_disabled();
		__reply_sprintf(bevent, "Killed %u disabled services\n", count);

		count = supervisor_children_startall();
		__reply_sprintf(bevent, "Started %u new processes\n", count);

		REPLY_STR_CONTANT(bevent, "Done!\n\n");
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
	REPLY_STR_CONTANT(bevent, "\t(show|status|stat) : stops the process with the given ID\n");
	REPLY_STR_CONTANT(bevent, "\t reload            : reloads the configuration and restores a UNIX socket if necessary\n");
	REPLY_STR_CONTANT(bevent, "\t(help|usage)       : displays this help section\n");
	REPLY_STR_CONTANT(bevent, "\n");
	return 0;
}

typedef int (*cmd_f)(struct bufferevent *bevent, int argc, char **argv);

struct cmd_mapping_s {
	const gchar *cmd_name;
	cmd_f cmd_callback;
};

static struct cmd_mapping_s COMMANDS [] = {
	{"show",    command_show },
	{"status",  command_show },
	{"stat",    command_show },
	{"reload",  command_reload },
	{"check",   command_check },
	{"start",   command_start },
	{"stop",    command_stop },
	{"help",    command_help },
	{"usage",   command_help },
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


/* ------------------------------------------------------------------------- */

static void
supervisor_signal_handler(int s, short flags, void *udata)
{
	(void) udata;
	(void) flags;

	switch (s) {
	case SIGUSR1: /* ignored */
		return;
	case SIGUSR2: /* ignored */
		flag_check_socket = ~0;
		return;
	case SIGPIPE: /* ignored */
		return;
	case SIGINT:
	case SIGQUIT:
	case SIGKILL:
	case SIGTERM:
		flag_running = FALSE;
		return;
	case SIGCHLD:
		if (0 < supervisor_children_catharsis())
			flag_restart_children = ~0;
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
	int opt_len = sizeof(i_opt);
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
__servers_is_unix(struct server_sock_s *server)
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
__servers_is_the_same(struct server_sock_s *server)
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
__servers_unmonitor(struct server_sock_s *server)
{
	if (server->fd < 0) {
		/* server socket already stopped */
		return ;
	}

	/* Stop the libevent management right now */	
	event_del(&(server->event));

	/* If the current socket is a UNIX socket, remove the socket file
	 * on disk only if this file is exactly the same that the file
	 * this socket created. We must avoid deleting a socket file
	 * opened by another process */
	if (__servers_is_unix(server) && __servers_is_the_same(server))
		unlink(server->url);

	shutdown(server->fd, SHUT_RDWR);
	close(server->fd);
	server->fd = -1;
}

/* starts the server monitoring with the libevent.
 * The inner file descriptor must be a valid socket filedes */
static gboolean
__servers_monitor(struct server_sock_s *server)
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

static int
servers_monitor_none(void)
{
	GList *l;

	TRACE("About to stop all the server sockets");
	for (l=list_of_servers; l ;l=l->next) {
		struct server_sock_s *s = l->data;
		__servers_unmonitor(s);
	}

	errno = 0;
}

static int
servers_monitor_all(void)
{
	GList *l;
	
	TRACE("About to monitor all the server sockets");
	
	for (l=list_of_servers; l ;l=l->next) {
		struct server_sock_s *s = l->data;
		if (!__servers_monitor(s))
			return FALSE;
	}

	errno = 0;
	return TRUE;
}

#if 0
static int
servers_save_inet(const char *url)
{
	int sock;

	if (-1 == (sock = __open_inet_server(url)))
		goto label_error;

	if (!servers_save_fd(sock, url))
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
#endif

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

static void
servers_clean(void)
{
	GList *l;

	servers_monitor_none();

	TRACE("About to clean the server sockets");
	
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

static void
servers_ensure(void)
{
	GList *l;
	
	flag_check_socket = 0;
	TRACE("About to ensure the server sockets");

	for (l=list_of_servers; l ; l=l->next) {
		struct server_sock_s *p_server = l->data;

		NOTICE("Ensuring socket fd=%d bond to [%s]", p_server->fd, p_server->url);

		if (__servers_is_unix(p_server) && !__servers_is_the_same(p_server)) {

			/* close */
			__servers_unmonitor(p_server);

			/* reopen */
			p_server->fd = __open_unix_server(p_server->url);
			if (p_server->fd < 0) {
				WARN("unix: failed to reopen a server bond to [%s] : %s",
						p_server->url, strerror(errno));
			}
			else if (!__servers_monitor(p_server)) {
				WARN("unix: failed to monitor a server bond to [%s] : %s",
						p_server->url, strerror(errno));
				__servers_unmonitor(p_server);
			}
		}
	}
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

static gboolean
_reload_service(GKeyFile *kf, const gchar *section, GError **err)
{
	gboolean rc = FALSE, rc_enable;
	gchar *str_key;
	gchar *str_command = NULL, *str_enabled = NULL;

	str_key = strchr(section, '.');
	str_key ++;
	str_command = g_key_file_get_string(kf, section, "command", err);
	str_enabled = g_key_file_get_string(kf, section, "enabled", NULL);

	if (!supervisor_children_register(str_key, str_command, err))
		goto label_exit;

	rc_enable = supervisor_children_enable(str_key, _cfg_value_is_true(str_enabled));
	if (0 > rc_enable) {
		*err = g_error_printf(LOG_DOMAIN, EINVAL, "Service [%s] cannot be marked [%s] : rc=%d",
		                        str_key, (_cfg_value_is_true(str_enabled)?"ENABLED":"DISABLED"),
					rc_enable);
		goto label_exit;
	}
	
	rc = TRUE;

label_exit:
	if (str_command)
		g_free(str_command);
	if (str_enabled)
		g_free(str_enabled);
	return rc;
}

static gboolean
_reconfigure_default_section(GKeyFile *kf, const gchar *section, GError **err)
{
	GError *error_local = NULL;
	gchar buf_user[256], buf_group[256];
	long limit_thread_stack = 1024;
	long limit_core_size = -1;
	long limit_nb_files = 32768;
	gchar **p_key, **keys;

	keys = g_key_file_get_keys(kf, section, NULL, err);
	if (!keys)
		return FALSE;

	/* Load the system limit and the pidfule path */
	for (p_key=keys; *p_key ;p_key++) {
		gchar *str;

		str = g_key_file_get_string(kf, section, *p_key, NULL);

		if (!g_ascii_strcasecmp(*p_key, CFG_KEY_LIMIT_CORESIZE)) {
			limit_core_size = atol(str);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_LIMIT_NBFILES)) {
			limit_nb_files = atol(str);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_LIMIT_STACKSIZE)) {
			limit_thread_stack = atol(str);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_PATH_PIDFILE)) {
			bzero(pidfile_path, sizeof(pidfile_path));
			g_strlcpy(pidfile_path, str, sizeof(pidfile_path)-1);
		}
		else if (!g_ascii_strcasecmp(*p_key, CFG_KEY_LISTEN)) {
			if (str[0] == '/') {
				bzero(sock_path, sizeof(sock_path));
				g_strlcpy(sock_path, str, sizeof(sock_path));
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

		g_free(str);
	}
	g_strfreev(keys);

	if (!supervisor_rights_init(buf_user, buf_group, &error_local)) {
		g_printerr("Failed to set privileges : %s\n", error_local->message);
		g_clear_error(&error_local);
	}

	(void) supervisor_limit_set(SUPERV_LIMIT_CORE_SIZE, limit_core_size * 1024 * 1024);
	(void) supervisor_limit_set(SUPERV_LIMIT_MAX_FILES, limit_nb_files);
	(void) supervisor_limit_set(SUPERV_LIMIT_THREAD_STACK, limit_thread_stack * 1024);

	return TRUE;
}

static gboolean
_reconfigure(gboolean services_only, GError **err)
{
	gboolean rc = FALSE;
	gchar **groups=NULL, **p_group=NULL;
	GKeyFile *kf = NULL;
	
	kf = g_key_file_new();

	if (!g_key_file_load_from_file(kf, config_path, 0, err)) {
		g_key_file_free(kf);
		return FALSE;
	}
		
	groups = g_key_file_get_groups(kf, NULL);
	if (!groups) {
		g_key_file_free(kf);
		return FALSE;
	}
	
	for (p_group=groups; *p_group ;p_group++) {
		if (g_str_has_prefix(*p_group, "service.")) {
			TRACE("reconfigure : managing section [%s]", *p_group);
			if (!_reload_service(kf, *p_group, err))
				goto label_exit;
		}
		else if (!g_ascii_strcasecmp(*p_group, "default")) {
			if (services_only) {
				TRACE("reconfigure : skipping section [%s]", *p_group);
				continue;
			}
			
			TRACE("reconfigure : loadig main parameters from section [%s]", *p_group);
			if (!_reconfigure_default_section(kf, *p_group, err))
				goto label_exit;
		}
		else {
			INFO("reconfigure : ignoring section [%s]", *p_group);
		}
	}

	rc = TRUE;
	
label_exit:
	g_strfreev(groups);
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
	if (!_reconfigure(FALSE, &error_local)) {
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

static void
__manage_signal(int s)
{
	struct event *signal_event;
	signal_event = g_malloc0(sizeof(*signal_event));
	event_set(signal_event, s, EV_SIGNAL|EV_PERSIST, supervisor_signal_handler, NULL);
	event_add(signal_event, NULL);
}

int
main(int argc, char ** args)
{
	struct event_base *libevents_handle = NULL;

	bzero(sock_path, sizeof(sock_path));
	g_strlcpy(sock_path, GRIDINIT_SOCK_PATH, sizeof(sock_path)-1);

	log4c_init();
	supervisor_children_init();
	__parse_options(argc, args);
	(void) supervisor_rights_lose();

	close(0);/* We will never read the standard input */
	if (flag_daemon) {
		close(1);
		close(2);
		daemon(1,0);
		write_pid_file();
	}
	
	if (-1 == servers_save_unix(sock_path))
		abort();
	
	/* Starts the network and the signal management */
	DEBUG("Initiating the network and signals management");
	libevents_handle = event_init();
	__manage_signal(SIGTERM);
	__manage_signal(SIGABRT);
	__manage_signal(SIGINT);
	__manage_signal(SIGQUIT);
	__manage_signal(SIGUSR1);
	__manage_signal(SIGUSR2);
	__manage_signal(SIGCHLD);
	if (!servers_monitor_all()) {
		ERROR("Failed to monitor the server sockets");
		exit(1);
	}
	
	DEBUG("Starting the event loop!");
	do { /* main loop */
		guint proc_count;

		/* start all the enabled processes */
		proc_count = supervisor_children_startall();
		DEBUG("First started %u processes", proc_count);

		while (flag_running) {

			if (flag_restart_children) {
				proc_count = supervisor_children_startall();
				DEBUG("Started %u processes", proc_count);
				flag_restart_children = 0;
			}

			/* Manages the connections pool */
			if (0 > event_loop(EVLOOP_ONCE)) {
				ERROR("event_loop() error : %s", strerror(errno));
				break;
			}

			if (flag_check_socket)
				servers_ensure();
		}
	} while (0);

	/* stop all the processes */
	DEBUG("Stopping all the children");
	supervisor_children_stopall(4);
	supervisor_children_catharsis();

	/* clean the working structures */
	DEBUG("Cleaning the working structures");
	event_base_free(libevents_handle);
	supervisor_children_cleanall();
	servers_clean();
	return 0;
}

