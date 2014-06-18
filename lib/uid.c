#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridinit.privileges"
#endif

#include "./gridinit-utils.h"
#include "./gridinit-internals.h"

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

static volatile uid_t effective_uid = 0;
static volatile uid_t effective_gid = 0;

static volatile uid_t real_uid = 0;
static volatile uid_t real_gid = 0;

gboolean
supervisor_rights_init(const char *user_name, const char *group_name, GError ** error)
{
	struct passwd *pwd = NULL;
	struct group *grp = NULL;

	pwd = getpwnam(user_name);
	if (pwd == NULL) {
		*error = g_error_printf(LOG_DOMAIN, errno, "User [%s] not found in /etc/passwd", user_name);
		return FALSE;
	}

	grp = getgrnam(group_name);
	if (grp == NULL) {
		*error = g_error_printf(LOG_DOMAIN, errno, "Group [%s] not found in /etc/group", group_name);
		return FALSE;
	}

	effective_gid = grp->gr_gid;
	effective_uid = pwd->pw_uid;
	NOTICE("rights_init : effective id set to %d:%d", effective_uid, effective_gid);
	
	real_gid = getuid();
	real_uid = getgid();
	NOTICE("rights_init : real id saved (%d:%d)", real_uid, real_gid);
	
	return TRUE;
}

int
supervisor_rights_gain(void)
{
	int status;

#ifdef _POSIX_SAVED_IDS
	status = seteuid(real_uid);
#else
	status = setreuid(-1, real_uid);
#endif
	return status;
}

int
supervisor_rights_lose(void)
{
	int status;

#ifdef _POSIX_SAVED_IDS
	status = seteuid(effective_uid);
#else
	status = setreuid(-1, effective_uid);
#endif
	return status;
}

