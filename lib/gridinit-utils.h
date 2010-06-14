#ifndef __SUPERV_UTILS_H__
# define __SUPERV_UTILS_H__
# include <glib.h>
# ifndef  SUPERVISOR_LIMIT_CHILDKEYSIZE
#  define SUPERVISOR_LIMIT_CHILDKEYSIZE 128
# endif
# ifndef  SUPERVISOR_LIMIT_GROUPSIZE
#  define SUPERVISOR_LIMIT_GROUPSIZE 256
# endif
# ifndef  SUPERVISOR_DEFAULT_TIMEOUT_KILL
#  define SUPERVISOR_DEFAULT_TIMEOUT_KILL 5
# endif
# include <sys/types.h>
# include <unistd.h>

/* Children monitoring ----------------------------------------------------- */

enum supervisor_limit_e {
	SUPERV_LIMIT_THREAD_STACK=1,
	SUPERV_LIMIT_MAX_FILES=2,
	SUPERV_LIMIT_CORE_SIZE=3
};

struct child_info_s {
	const char *key;
	const char *cmd;
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

	/* added at the end for binary backward compatibility */
	gboolean broken;
	gboolean breakable;
	guint32 user_flags;
	const char *group;
};

typedef void (supervisor_cb_f) (void *udata, struct child_info_s *ci);


void supervisor_children_init(void);

void supervisor_children_fini(void);

guint supervisor_children_cleanall(void);

guint supervisor_children_startall(void *udata, supervisor_cb_f cb);

void supervisor_children_stopall(guint max_retries);

guint supervisor_children_killall(int sig);

guint supervisor_children_catharsis(void *udata, supervisor_cb_f cb);

gboolean supervisor_children_register(const gchar *key, const gchar *cmd,
		GError **error);

guint supervisor_children_kill_obsolete(void);

guint supervisor_children_mark_obsolete(void);

int supervisor_children_set_user_flags(const gchar *key, guint32 flags);

/**
 * Stops the service (SIGKILL until expiration, then SIGTERM)
 */
guint supervisor_children_kill_disabled(void);

/**
 * Sets the 'enabled' flag on the service
 */
int supervisor_children_enable(const char *key, gboolean enable);

/**
 * Sets the 'autorespawn' flag on this service
 */
int supervisor_children_set_respawn(const char *key, gboolean enabled);

/**
 * Starts a service that died too often
 */
int supervisor_children_repair(const char *key);

/**
 * Calls supervisor_children_repair() on each broken service
 */
int supervisor_children_repair_all(void);

/**
 *
 */
int supervisor_children_set_limit(const gchar *key,
		enum supervisor_limit_e what, gint64 value);

/**
 * Runs the children list and call the callback fnction on each
 * element
 */
gboolean supervisor_run_services(void *ptr, supervisor_cb_f callback);

/**
 *
 * @param key
 * @param dir
 * @return
 */
int supervisor_children_set_working_directory(const gchar *key,
		const gchar *dir);

/**
 *
 * @param key
 * @param envkey
 * @param envval
 * @return
 */
int supervisor_children_setenv(const gchar *key, const gchar *envkey,
	const gchar *envval);

/**
 *
 * @param key
 * @return
 */
int supervisor_children_clearenv(const gchar *key);

/**
 * @param key
 * @param flags
 * @return
 */
int supervisor_children_set_user_flags(const gchar *key, guint32 flags);

/**
 * @param key
 * @param group NULL to clear the group
 * @return
 */
int supervisor_children_set_group(const gchar *key, const gchar *group);

/**
 *
 * @param key
 * @param ci
 * @return
 */
int supervisor_children_get_info(const gchar *key, struct child_info_s *ci);

/* Fork and pipe ----------------------------------------------------------- */

/** 
 *
 * @param str_cmd
 * @return
 */
int command_get_pipe(const gchar *str_cmd);

/* Privileges -------------------------------------------------------------- */

/**
 *
 * @param user_name
 * @param group_name
 * @param error
 * @return
 */
gboolean supervisor_rights_init(const char *user_name, const char *group_name,
		GError ** error);

/**
 *
 * @return
 */
int supervisor_rights_gain(void);

/**
 *
 * @return
 */
int supervisor_rights_lose(void);

/* Processus limits */

/**
 *
 * @param what
 * @param value
 * @return
 */
int supervisor_limit_set(enum supervisor_limit_e what, gint64 value);

/**
 *
 * @param what
 * @param value
 * @return
 */
int supervisor_limit_get(enum supervisor_limit_e what, gint64 *value);

#endif
