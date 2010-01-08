#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
 
#include <glib.h>

#include "./gridinit-utils.h"

#define MASK_OBSOLETE     0x01
#define MASK_DISABLED     0x02
#define MASK_RESPAWN      0x04
#define MASK_STARTED      0x08

#define FLAG_SET(sd,M) do { sd->flags |= (M); } while (0)
#define FLAG_DEL(sd,M) do { sd->flags &= ~(M); } while (0)
#define FLAG_HAS(sd,M) (sd->flags & (M))

struct child_s {
	struct child_s *next;
	gchar *command;
	pid_t pid;
	uid_t uid;
	gid_t gid;
	guint8 flags;

	gchar key[SUPERVISOR_LIMIT_CHILDKEYSIZE];

	/* Useful stats */
	guint counter_started;
	guint counter_died;
	time_t last_start_attempt;
	time_t last_kill_attempt;

	/* Child's startup properties */
	struct {
		long core_size;
		long stack_size;
		long nb_files;
	} rlimits;
};

static struct child_s SRV_BEACON = { NULL, NULL, -1 };

static void
_child_get_info(struct child_s *c, struct child_info_s *ci)
{
	memset(ci, 0x00, sizeof(*ci));
	ci->key = c->key;
	ci->enabled = !FLAG_HAS(c,MASK_DISABLED);
	ci->respawn = !FLAG_HAS(c,MASK_RESPAWN);
	ci->cmd = c->command;
	ci->pid = c->pid;
	ci->uid = c->uid;
	ci->gid = c->gid;
	ci->counter_started = c->counter_started;
	ci->counter_died = c->counter_died;
	ci->last_start_attempt = c->last_start_attempt;
	ci->last_kill_attempt = c->last_kill_attempt;
	memcpy(&(ci->rlimits), &(c->rlimits), sizeof(c->rlimits));
}

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
_child_start(struct child_s *sd, void *udata, supervisor_cb_f cb)
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
		sd->pid = getpid();
		
		if (cb) {
			struct child_info_s ci;
			_child_get_info(sd, &ci);
			cb(udata, &ci);
		}

		/*sd->command = NULL;*/
		supervisor_children_cleanall();
		execv(args[0], args);
		exit(-1);
		return 0;/*makes everybody happy*/

	default: /*father*/
		FLAG_SET(sd,MASK_STARTED);
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
supervisor_children_startall(void *udata, supervisor_cb_f cb)
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
		if (sd->pid <= 0 && !FLAG_HAS(sd,MASK_DISABLED) &&
			(!FLAG_HAS(sd,MASK_STARTED) || FLAG_HAS(sd,MASK_RESPAWN)))
		{
			GError *error_local = NULL;
			if (0 == _child_start(sd, udata, cb))
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
		FLAG_SET(sd,MASK_OBSOLETE);
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
		if (sd->pid>1 && FLAG_HAS(sd,MASK_OBSOLETE)) {
			register int allow_sigkill = now - sd->last_kill_attempt > SUPERVISOR_DEFAULT_TIMEOUT_KILL;
			kill(sd->pid, (allow_sigkill ? SIGKILL : SIGTERM));
			sd->last_kill_attempt = now;
			count ++;
		}
	}
	
	return count;
}

guint
supervisor_children_catharsis(void *udata, supervisor_cb_f cb)
{
	pid_t pid_dead;
	guint count;
	struct child_s *sd;
	
	count = 0;
	while ((pid_dead = waitpid(0, NULL, WNOHANG)) > 0) {
		for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
			if (sd->pid == pid_dead) {
				count++;
				sd->counter_died ++;
				if (cb) {
					struct child_info_s ci;
					_child_get_info(sd, &ci);
					cb(udata, &ci);
				}
				sd->pid = -1;
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
	struct child_s *sd;

	/*check if the service is present*/
	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
		if (0 == g_ascii_strcasecmp(sd->key, key)) {
			FLAG_DEL(sd,MASK_OBSOLETE);
			return TRUE;
		}
	}

	/*Child not found, it will be created*/
	sd = g_try_malloc0(sizeof(struct child_s));
	if (NULL == sd) {
		errno = ENOMEM;
		return FALSE;
	}

	g_strlcpy(sd->key, key, sizeof(sd->key)-1);
	sd->flags = MASK_RESPAWN;
	sd->command = g_strdup(cmd);
	sd->pid = -1;
	sd->uid = getuid();
	sd->gid = getgid();
	sd->rlimits.core_size = -1;
	sd->rlimits.stack_size = 8192;
	sd->rlimits.nb_files = 32768;
	
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
		_child_get_info(sd, &ci);
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
		if (sd->pid>1 && FLAG_HAS(sd,MASK_DISABLED)) {
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
	struct child_s *sd;

	if (!key) {
		errno = EINVAL;
		return -1;
	}
	
	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
		if (0 == g_ascii_strcasecmp(sd->key, key)) {
			errno = 0;
			if (!enable) {
				if (FLAG_HAS(sd,MASK_DISABLED))
					return 0;
				FLAG_SET(sd,MASK_DISABLED); 
				return 1;
			}
			else {
				if (!FLAG_HAS(sd,MASK_DISABLED))
					return 0;
				FLAG_DEL(sd,MASK_DISABLED); 
				return 1;
			}
		}
	}
	
	errno = ENOENT;
	return -1;
}

int
supervisor_children_set_respawn(const char *key, gboolean enabled)
{
	struct child_s *sd;

	if (!key) {
		errno = EINVAL;
		return -1;
	}
	
	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
		if (0 == g_ascii_strcasecmp(sd->key, key)) {
			errno = 0;
			if (enabled) {
				if (FLAG_HAS(sd,MASK_RESPAWN))
					return 0;
				FLAG_SET(sd,MASK_RESPAWN);
				return 1;
			}
			else {
				if (!FLAG_HAS(sd,MASK_RESPAWN))
					return 0;
				FLAG_DEL(sd,MASK_RESPAWN);
				return 1;
			}
		}
	}
	
	errno = ENOENT;
	return -1;
}

