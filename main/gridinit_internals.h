#ifndef  __GRIDINIT_INTERNALS_H__
# define __GRIDINIT_INTERNALS_H__ 1

# ifndef  GRIDINIT_SOCK_PATH
#  define GRIDINIT_SOCK_PATH "/GRID/common/run/gridinit.sock"
# endif

#ifndef  CFG_KEY_LISTEN
# define CFG_KEY_LISTEN "listen"
#endif

#ifndef  CFG_KEY_PATH_PIDFILE
# define CFG_KEY_PATH_PIDFILE "pidfile"
#endif

#ifndef  CFG_KEY_LIMIT_STACKSIZE
# define CFG_KEY_LIMIT_STACKSIZE "limit.stack_size"
#endif

#ifndef  CFG_KEY_LIMIT_CORESIZE
# define CFG_KEY_LIMIT_CORESIZE "limit.core_size"
#endif

#ifndef  CFG_KEY_LIMIT_NBFILES
# define CFG_KEY_LIMIT_NBFILES "limit.max_files"
#endif

#ifndef  CFG_KEY_GROUP
# define CFG_KEY_GROUP "group"
#endif

#ifndef  CFG_KEY_USER
# define CFG_KEY_USER "user"
#endif

int __open_unix_server(const char *path);

int __open_unix_client(const char *path);

int __open_inet_server(const char *url);

/* Alerting */

gboolean gridinit_alerting_configure(const gchar *path, const gchar *symbol, GHashTable *ht, GError **err);

void gridinit_alerting_send(int event, const char *msg);

void gridinit_alerting_close(void);

#endif
