#ifndef __SUPERV_UTILS_H__
# define __SUPERV_UTILS_H__
# include <glib.h>
# ifndef  SUPERVISOR_LIMIT_CHILDKEYSIZE
#  define SUPERVISOR_LIMIT_CHILDKEYSIZE 256
# endif
# ifndef  SUPERVISOR_DEFAULT_TIMEOUT_KILL
#  define SUPERVISOR_DEFAULT_TIMEOUT_KILL 5
# endif
# include <sys/types.h>
# include <unistd.h>

void supervisor_children_init(void);

void supervisor_children_fini(void);

guint supervisor_children_cleanall(void);

guint supervisor_children_startall(void);

void supervisor_children_stopall(guint max_retries);

guint supervisor_children_killall(int sig);

guint supervisor_children_catharsis(void);

gboolean supervisor_children_register(const gchar *key, const gchar *cmd, GError **error);

guint supervisor_children_kill_obsolete(void);

guint supervisor_children_mark_obsolete(void);

guint supervisor_children_kill_disabled(void);

int supervisor_children_enable(const char *key, gboolean enable);

struct child_info_s {
	const char *key;
	const char *cmd;
	pid_t pid;
	gboolean enabled;
	time_t last_start_attempt;
	time_t last_kill_attempt;
	guint counter_started;
	guint counter_died;
};

typedef void (supervisor_cb_f) (void *udata, struct child_info_s *ci);

gboolean supervisor_run_services(void *ptr, supervisor_cb_f callback);

/* Fork and pipe */

int command_get_pipe(const gchar *str_cmd);

/* Privileges */

gboolean supervisor_rights_init(const char *user_name, const char *group_name, GError ** error);

int supervisor_rights_gain(void);

int supervisor_rights_lose(void);

/* Processus limits */

enum supervisor_limit_e {
	SUPERV_LIMIT_THREAD_STACK=1,
	SUPERV_LIMIT_MAX_FILES=2,
	SUPERV_LIMIT_CORE_SIZE=3
};

int supervisor_limit_set(enum supervisor_limit_e what, int value);

#endif
