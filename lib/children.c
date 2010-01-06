#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
 
#include <glib.h>

#include "./gridinit-utils.h"

struct child_s {

	gchar key[SUPERVISOR_LIMIT_CHILDKEYSIZE];

	gboolean obsolete;
	gboolean disabled;

	guint counter_started;
	guint counter_died;

	time_t last_start_attempt;
	time_t last_kill_attempt;

	pid_t pid;
	gchar *command;

	struct child_s *next;
};

static struct child_s SRV_BEACON = {
	{0,0},
	FALSE,
	FALSE,
	0U, 0U,
	0L, 0L,
	
	-1,
	NULL,

	NULL
};

static void
sighandler_NOOP(int s)
{
	signal(s, sighandler_NOOP);
}

static void
reset_sighandler(void)
{
	signal(SIGQUIT, sighandler_NOOP);
	signal(SIGTERM, sighandler_NOOP);
	signal(SIGINT,  sighandler_NOOP);
	signal(SIGPIPE, sighandler_NOOP);
	signal(SIGUSR1, sighandler_NOOP);
	signal(SIGUSR2, sighandler_NOOP);
	signal(SIGCHLD, sighandler_NOOP);
}

static guint
_wait_for_dead_child(pid_t *ptr_pid)
{
	register pid_t pid, pid_exited;

	pid = *ptr_pid;
	if (pid < 0)
		return 0;

	errno = 0;
	pid_exited = waitpid(pid, NULL, WNOHANG);
	if (pid_exited>0 || errno==ECHILD) {
		*ptr_pid = -1;
		return 1;
	}

	return 0;
}

/**
 * @return <li>-1 when the fork failed;<li>0 when the service does not meet the
 * conditions to start;<li>1 when the service has been forked successfuly.
 */
static gint
_child_start(struct child_s *sd)
{
	typeof(errno) errsav;
	gint argc;
	gchar **args;
	pid_t pid_father;
	
	if (!sd || !sd->command) {
		errno = EINVAL;
		return -1;
	}

	if (!g_shell_parse_argv(sd->command, &argc, &args, NULL)) {
		errno = EINVAL;
		return -1;
	}
	
	pid_father = getpid();
	sd->last_start_attempt = time(0);

	sd->pid = fork();

	switch (sd->pid) {

	case -1: /*error*/
		errsav = errno;
		g_strfreev(args);
		errno = errsav;
		return -1;

	case 0: /*child*/
		reset_sighandler();
		
		sd->command = NULL;
		
		supervisor_children_cleanall();
		execv(args[0], args);
		exit(-1);
		return 0;/*makes everybody happy*/

	default: /*father*/
		sd->counter_started ++;
		errsav = errno;
		g_strfreev(args);
		errno = errsav;
		return 0;
	}
}

guint
supervisor_children_killall(int sig)
{
	guint count;
	struct child_s *sd;

	count = 0;
	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
		if (sd->pid > 0) {
			kill(sd->pid, sig);
			count ++;
		}
	}

	return count;
}

guint
supervisor_children_startall(void)
{
	guint count, proc_count;
	struct child_s *sd;

	count = proc_count = 0U;
	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
		proc_count ++;
		if (sd->pid > 0) {
			if (1U == _wait_for_dead_child(&(sd->pid)))
				sd->counter_died ++;
		}
		if (sd->pid <= 0 && !sd->disabled) {
			GError *error_local = NULL;
			if (0 == _child_start(sd))
				count ++;
			if (error_local)
				g_error_free(error_local);
		}
	}

	return count;
}

guint
supervisor_children_mark_obsolete(void)
{
	guint count;
	struct child_s *sd;

	count = 0;
	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
		sd->obsolete = TRUE;
		count ++;
	}

	return count;
}

guint
supervisor_children_kill_obsolete(void)
{
	guint count;
	time_t now;
	struct child_s *sd;

	now = time(0);
	count = 0U;

	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
		if (sd->pid>1 && sd->obsolete) {
			register int allow_sigkill = now - sd->last_kill_attempt > SUPERVISOR_DEFAULT_TIMEOUT_KILL;
			kill(sd->pid, (allow_sigkill ? SIGKILL : SIGTERM));
			sd->last_kill_attempt = now;
			count ++;
		}
	}
	
	return count;
}

guint
supervisor_children_catharsis(void)
{
	pid_t pid_dead;
	guint count;
	struct child_s *sd;
	
	count = 0;
	while ((pid_dead = waitpid(0, NULL, WNOHANG)) > 0) {
		for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
			if (sd->pid == pid_dead) {
				count++;
				sd->pid = -1;
				sd->counter_died ++;
				break;
			}
		}
	}
	return count;
}

void
supervisor_children_stopall(guint max_retries)
{
	guint retries;

	for (retries=0; retries<max_retries ;retries++) {
		if (!supervisor_children_killall(SIGTERM))
			return;
		sleep(1);
	}

	supervisor_children_killall(SIGKILL);
}

guint
supervisor_children_cleanall(void)
{
	struct child_s *sd, *sd_next;
	guint count;

	count = 0;
	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd_next) {
		if (sd->command)
			g_free(sd->command);
		sd_next = sd->next;
		memset(sd, 0x00, sizeof(struct child_s));
		g_free(sd);
		count ++;
	}
	SRV_BEACON.next = &SRV_BEACON;

	return count;
}

void
supervisor_children_init(void)
{
	SRV_BEACON.next = &SRV_BEACON;
}

void
supervisor_children_fini(void)
{
	/* nothing to do yet */
}


gboolean
supervisor_children_register(const gchar *key, const gchar *cmd, GError **error)
{
	static struct child_s CHILD_INIT = {{0,0}, FALSE,FALSE, 0U,0U, 0L,0L, -1, NULL,NULL};
	struct child_s *sd;

	/*check if the service is present*/
	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
		if (0 == g_ascii_strcasecmp(sd->key, key)) {
			sd->obsolete = FALSE;
			return TRUE;
		}
	}

	/*Child not found, it will be created*/
	if (NULL == (sd = g_memdup(&CHILD_INIT, sizeof(struct child_s)))) {
		errno = ENOMEM;
		return FALSE;
	}
	g_strlcpy(sd->key, key, sizeof(sd->key)-1);
	sd->command = g_strdup(cmd);
	
	/*ring insertion*/
	sd->next = SRV_BEACON.next;
	SRV_BEACON.next = sd;

	return TRUE;
}

gboolean
supervisor_run_services(void *udata, supervisor_cb_f callback)
{
	struct child_info_s ci;
	struct child_s *sd;

	if (!callback) {
		errno = EINVAL;
		return FALSE;
	}

	/*check if the service is present*/
	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
		memset(&ci, 0x00, sizeof(ci));
		ci.key = sd->key;
		ci.enabled = (sd->disabled ? FALSE : TRUE);
		ci.cmd = sd->command;
		ci.pid = sd->pid;
		ci.counter_started = sd->counter_started;
		ci.counter_died = sd->counter_died;
		ci.last_start_attempt = sd->last_start_attempt;
		ci.last_kill_attempt = sd->last_kill_attempt;
		callback(udata, &ci);
	}

	return TRUE;
}

guint
supervisor_children_kill_disabled(void)
{
	guint count;
	time_t now;
	struct child_s *sd;

	now = time(0);
	count = 0U;

	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
		if (sd->pid>1 && sd->disabled) {
			register int allow_sigkill = now - sd->last_kill_attempt > SUPERVISOR_DEFAULT_TIMEOUT_KILL;
			kill(sd->pid, (allow_sigkill ? SIGKILL : SIGTERM));
			sd->last_kill_attempt = now;
			count ++;
		}
	}
	
	return count;
}

int
supervisor_children_enable(const char *key, gboolean enable)
{
	gboolean value;
	struct child_s *sd;

	if (!key) {
		errno = EINVAL;
		return -1;
	}
	
	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
		if (0 == g_ascii_strcasecmp(sd->key, key)) {
			errno = 0;
			value = (enable ? 0 : 1);
			if (sd->disabled == value)
				return 0;
			sd->disabled = value;
			return 1;
		}
	}
	
	errno = EAGAIN;
	return -1;
}

