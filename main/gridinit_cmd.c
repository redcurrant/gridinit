#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridinit_cmd"
#endif

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <strings.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#include <event.h>
#include <log4c.h>
#include <glib.h>

#include "./gridinit_internals.h"
#include "../lib/gridinit-internals.h"

#define EV_FLAG(F) ((F)|EV_PERSIST)

static gchar sock_path[1024];

static int in_fd = -1;
static struct bufferevent *in_bevent = NULL;

static int out_fd = -1;
static struct bufferevent *out_bevent = NULL;

static void
__close_bevent(struct bufferevent **bevent, int *fd)
{
	if (bevent && *bevent) {
		bufferevent_disable(*bevent, EV_READ);
		bufferevent_disable(*bevent, EV_WRITE);
		shutdown(*fd, SHUT_RDWR);
		close(*fd);
		bufferevent_free(*bevent);

		*fd = -1;
		*bevent = NULL;
	}
}

static void
__event_in(struct bufferevent *p_bevent, void *udata)
{
	size_t read_size;
	static gchar buff[2048];
	(void) udata;

	TRACE("Input buffer available for fd=%d", *(int*)udata);

	if (p_bevent == out_bevent) {
		/* This should never happen */
		abort();
	}
	
	read_size = bufferevent_read(p_bevent, buff, sizeof(buff));
	if (0 != bufferevent_write(out_bevent, buff, read_size)) {
		TRACE("Invalid output buffer : %s", strerror(errno));
		__close_bevent(&in_bevent, &in_fd);
		__close_bevent(&out_bevent, &out_fd);
	}
	else {
		/* restore read from input */
		bufferevent_enable(in_bevent, EV_FLAG(EV_READ));
		bufferevent_disable(in_bevent, EV_WRITE);

		/* enable writing to output */
		bufferevent_disable(out_bevent, EV_READ);
		bufferevent_enable(out_bevent, EV_FLAG(EV_WRITE));
	}
}

static void
__event_out(struct bufferevent *p_bevent, void *udata)
{
	(void) udata;

	TRACE("Output buffer empty for fd=%d", *(int*)udata);

	if (p_bevent == out_bevent) {
		/* the output buffer is empty ... nothing to do and wait
		 * for input data if the input is not down */
		if (in_bevent) {
			TRACE("Waiting for input");
			bufferevent_disable(out_bevent, EV_READ);
			bufferevent_disable(out_bevent, EV_WRITE);
		
			bufferevent_enable(in_bevent, EV_FLAG(EV_READ));
			bufferevent_disable(in_bevent, EV_WRITE);
		}
		else {
			TRACE("Closing both endpoints");
			__close_bevent(&in_bevent, &in_fd);
			__close_bevent(&out_bevent, &out_fd);
		}
		return;
	}

	if (p_bevent == in_bevent) {

		TRACE("Request sent, waiting reply from the server");

		/* The command has been sent, now enable only reading from this end */
		bufferevent_enable(in_bevent, EV_FLAG(EV_READ));
		bufferevent_disable(in_bevent, EV_WRITE);
		/* nothing to write yet */
		bufferevent_disable(out_bevent, EV_READ);
		bufferevent_disable(out_bevent, EV_WRITE);
		return;
	}
}

static void
__event_error(struct bufferevent *p_bevent, short flags, void *udata)
{
	int in_down, out_down;
	(void) p_bevent;
	(void) udata;
	(void) flags;

	TRACE("Connection down for fd=%d", *(int*)udata);
	
	in_down = (p_bevent == in_bevent);
	out_down = (p_bevent == out_bevent);
	
	/* close the output if it is concerned */
	if (out_down)
		__close_bevent(&out_bevent, &out_fd);

	/* If the output is down, we close everything! */
	if (in_down || out_down)
		__close_bevent(&in_bevent, &in_fd);
}

int
main(int argc, char ** args)
{
	int i, rc = 1;
	struct event_base *libevents_handle = NULL;

	bzero(sock_path, sizeof(sock_path));
	g_strlcpy(sock_path, GRIDINIT_SOCK_PATH, sizeof(sock_path)-1);
	close(0);
	log4c_init();
	libevents_handle = event_init();
	
	/* Create input with the UNIX socket */
	in_fd = __open_unix_client(sock_path);
	if (-1 == in_fd) {
		g_printerr("Connection to UNIX socket [%s] failed : %s\n", sock_path, strerror(errno));
		return 1;
	}

	in_bevent = bufferevent_new(in_fd, __event_in, __event_out, __event_error, &in_fd);
	bufferevent_settimeout(in_bevent, 30000, 30000);
	/* send the commands then enable writing */
	for (i=1; i<argc ;i++) {
		bufferevent_write(in_bevent, args[i], strlen(args[i]));
		bufferevent_write(in_bevent, " ", 1);
	}
	bufferevent_write(in_bevent, "\n", 1);
	bufferevent_base_set(libevents_handle, in_bevent);
	bufferevent_enable(in_bevent, EV_FLAG(EV_READ));
	bufferevent_enable(in_bevent, EV_FLAG(EV_WRITE));

	/* Wrap standard output, but do not monitor it yet (nothing to send) */
	out_fd = 1;
	out_bevent = bufferevent_new(out_fd, __event_in, __event_out, __event_error, &out_fd);
	bufferevent_settimeout(out_bevent, 30000, 30000);
	bufferevent_base_set(libevents_handle, out_bevent);
	bufferevent_disable(out_bevent, EV_READ);
	bufferevent_disable(out_bevent, EV_WRITE);

	/* Wait for something to happen */
	while (in_fd!=-1 && out_fd!=-1) {
		if (0 > event_loop(EVLOOP_ONCE)) {
			g_printerr("libevent error : %s\n", strerror(errno));
			goto label_error;
		}
	}
	
	/* Ensure both ends have been closed and disabled */
	__close_bevent(&in_bevent, &in_fd);
	__close_bevent(&out_bevent, &out_fd);

	rc = 0;

label_error:
	event_base_free(libevents_handle);
	return rc;
}

