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

int
supervisor_limit_set(enum supervisor_limit_e what, int32_t value)
{
	struct rlimit rl, rl_old;
	int res_id;

	res_id = get_rlimit_id(what);
	if (-1 == getrlimit(res_id, &rl_old)) {
		WARN("supervisor_limit_set(%s,%ld) error : %s", get_rlimit_name(what), value, strerror(errno));
		return -1;
	}

#ifdef HAVE_EXTRA_DEBUG
	TRACE("supervisor_limit_set(%s,%ld) : current {%ld,%ld}",
		get_rlimit_name(what), value, rl_old.rlim_cur, rl_old.rlim_max);
#endif

	/* Try with the raw value */
	rl.rlim_cur = value;
	rl.rlim_max = limit_max(value, rl_old.rlim_max);
	if (0 == my_setrlimit(res_id, &rl)) {
		NOTICE("supervisor_limit_set(%s,%ld) : new {%ld,%ld}",
			get_rlimit_name(what), value, rl.rlim_cur, rl.rlim_max);
		return 0;
	}
	if (errno != EPERM) {
		WARN("supervisor_limit_set(%s,%ld) error : %s", get_rlimit_name(what), value, strerror(errno));
		return -1;
	}
				
	/* The process has no special privileges, set the maximum available */
	rl.rlim_cur = limit_min(value, rl_old.rlim_max);
	rl.rlim_max = rl_old.rlim_max;
	if (0 == my_setrlimit(res_id, &rl)) {
		NOTICE("supervisor_limit_set(%s,%ld) : truncated {%ld,%ld}",
			get_rlimit_name(what), value, rl.rlim_cur, rl.rlim_max);
		return 0;
	}
				
	WARN("supervisor_limit_set(%s,%ld) error : %s", get_rlimit_name(what), value, strerror(errno));
	return -1;
}

