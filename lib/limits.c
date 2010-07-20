#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridinit.limits"
#endif

#include "./gridinit-utils.h"
#include "./gridinit-internals.h"

#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <unistd.h>

#if 0
static rlim_t
limit_min(rlim_t r1, rlim_t r2)
{
	if (r2 == RLIM_INFINITY)
		return r1;
	if (r1 == RLIM_INFINITY)
		return r2;
	return MIN(r1,r2);
}

static rlim_t
limit_max(rlim_t r1, rlim_t r2)
{
	if (r2 == RLIM_INFINITY)
		return r2;
	if (r1 == RLIM_INFINITY)
		return r1;
	return MAX(r1,r2);
}
#endif

static const char*
get_rlimit_name(enum supervisor_limit_e what)
{
	switch (what) {
	case SUPERV_LIMIT_THREAD_STACK: return "RLIMIT_STACK";
	case SUPERV_LIMIT_MAX_FILES: return "RLIMIT_NOFILE";
	case SUPERV_LIMIT_CORE_SIZE: return "RLIMIT_CORE";
	}
	return "INVALID";
}

static int
get_rlimit_id(enum supervisor_limit_e what)
{
	switch (what) {
	case SUPERV_LIMIT_THREAD_STACK: return RLIMIT_STACK;
	case SUPERV_LIMIT_MAX_FILES: return RLIMIT_NOFILE;
	case SUPERV_LIMIT_CORE_SIZE: return RLIMIT_CORE;
	}
	
	errno = EINVAL;
	return -1;
}

static int
my_setrlimit(int res_id, struct rlimit *rl)
{
	int rc;
	typeof(errno) errsav;

	supervisor_rights_gain();
	errno = 0;
	rc = setrlimit(res_id, rl);
	errsav = errno;

	supervisor_rights_lose();
	errno = errsav;

	return rc;
}

static rlim_t
get_rlim_from_i64(gint64 i64)
{
	rlim_t res;
	if (i64 == RLIM_INFINITY || i64 < 0)
		return RLIM_INFINITY;
	return (res = i64);
}

int
supervisor_limit_set(enum supervisor_limit_e what, gint64 value)
{
	struct rlimit rl, rl_old;
	rlim_t _val;
	int res_id;

	_val = get_rlim_from_i64(value);
	res_id = get_rlimit_id(what);

	/* Try with the raw value */
	rl.rlim_cur = _val;
	rl.rlim_max = _val;
	if (0 == my_setrlimit(res_id, &rl))
		return 0;
	if (errno != EPERM) {
		WARN("supervisor_limit_set(%s,%"G_GINT64_FORMAT") error : %s",
				get_rlimit_name(what), value, strerror(errno));
		return -1;
	}
				
	/* The process has no special privileges, set the maximum available */
	if (-1 == getrlimit(res_id, &rl_old)) {
		WARN("supervisor_limit_get(%s,%"G_GINT64_FORMAT") error : %s",
				get_rlimit_name(what), value, strerror(errno));
		return -1;
	}

	rl.rlim_cur = rl_old.rlim_max;
	rl.rlim_max = rl_old.rlim_max;
	if (0 == my_setrlimit(res_id, &rl))
		return 0;
				
	WARN("supervisor_limit_set(%s,%"G_GINT64_FORMAT") error : %s",
			get_rlimit_name(what), value, strerror(errno));
	return -1;
}

int
supervisor_limit_get(enum supervisor_limit_e what, gint64 *value)
{
	struct rlimit rl;
	int res_id;

	if (!value) {
		errno = EINVAL;
		return -1;
	}

	res_id = get_rlimit_id(what);
	if (-1 == getrlimit(res_id, &rl))
		return -1;

	*value = (rl.rlim_cur == RLIM_INFINITY) ? 1 : rl.rlim_cur;
	return 0;
}

