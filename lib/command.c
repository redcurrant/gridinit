#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include <glib.h>
#include "./gridinit-utils.h"

#define IDX_IN 0
#define IDX_OUT 1

static void
dup2_or_exit(int fd1, int fd2)
{
	if (-1 == dup2(fd1, fd2)) {
		/*ERROR("dup2(%d,%d) error : %s", fd1, fd2, strerror(errno));*/
		exit(1);
	}
}

static void
run_command(int fd_out, const char *cmd)
{
	gint argc = 0;
	gchar **argv = NULL;

	if (!g_shell_parse_argv(cmd, &argc, &argv, NULL))
		exit(1);

	dup2_or_exit(fd_out, fileno(stdout));
	dup2_or_exit(fd_out, fileno(stderr));

	execv(argv[0], argv);
	g_strfreev(argv);
	exit(1);
}

int
command_get_pipe(const gchar *str_cmd)
{
	typeof(errno) errsav;
	int fd[2];
	
	if (!str_cmd) {
		errno = EINVAL;
		return -1;
	}
	
	if (0 != pipe(fd)) {
		return -1;
	}

	/*TRACE("pipe opened (IN=%d,OUT=%d)", fd[IDX_IN], fd[IDX_OUT]);*/

	switch (fork()) {
		
	case -1: /* ERROR */
		errsav = errno;
		close(fd[IDX_IN]);
		close(fd[IDX_OUT]);
		errno = errsav;
		return -1;
		
	case 0: /* CHILD */
		close(fd[IDX_IN]);
		/*TRACE("Child writing in fd=%d", fd[IDX_OUT]);*/
		run_command(fd[IDX_OUT], str_cmd); /*never returns on success*/
		return -1;/* makes everybody happy*/
		
	default: /* FATHER */
		close(fd[IDX_OUT]);
		/*TRACE("Father reading from fd=%d", fd[IDX_IN]);*/
		return fd[IDX_IN];
	}
}

