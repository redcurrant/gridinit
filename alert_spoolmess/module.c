#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridinit.spoolmess"
#endif
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include <glib.h>
#include <log4c.h>

#include "../main/gridinit_alerts.h"

# define JOURNAL(Prio,Format,...) log4c_category_log(log4c_category_get(LOG_DOMAIN), \
	Prio, "%u "Format, getpid(), ##__VA_ARGS__)

# define FATAL(Format,...)  JOURNAL(LOG4C_PRIORITY_FATAL,  Format, ##__VA_ARGS__)
# define ALERT(Format,...)  JOURNAL(LOG4C_PRIORITY_ALERT,  Format, ##__VA_ARGS__)
# define CRIT(Format,...)   JOURNAL(LOG4C_PRIORITY_CRIT,   Format, ##__VA_ARGS__)
# define ERROR(Format,...)  JOURNAL(LOG4C_PRIORITY_ERROR,  Format, ##__VA_ARGS__)
# define WARN(Format,...)   JOURNAL(LOG4C_PRIORITY_WARN,   Format, ##__VA_ARGS__)
# define NOTICE(Format,...) JOURNAL(LOG4C_PRIORITY_NOTICE, Format, ##__VA_ARGS__)
# define INFO(Format,...)   JOURNAL(LOG4C_PRIORITY_INFO,   Format, ##__VA_ARGS__)
# define DEBUG(Format,...)  JOURNAL(LOG4C_PRIORITY_DEBUG,  Format, ##__VA_ARGS__)
# define TRACE(Format,...)  JOURNAL(LOG4C_PRIORITY_TRACE,  Format, ##__VA_ARGS__)

#define DEFAULT_SOPCODE "MUT-GRD-7000"

/* Merci Frederic Gerard  de ne pas fournir de .h ! */
extern int spoolmess(const char *identifier, const char *criticity, const char *format, ...);

static char SOPCODE[sizeof(DEFAULT_SOPCODE)+1] = DEFAULT_SOPCODE;
static char CODE_CLIENT[64] = "";
static char CODE_OBJET[64] = "";

static void
gridinit_spoolmess_handle(void *udata, int event, const char *msg)
{
	int _s;
	size_t offset;
	char working_message[1024];
	const char *criticity;
	const char *default_msg;

	if (!msg) {
		abort();
		return;
	}

	switch (event) {
	case GRIDINIT_EVENT_STARTED:
		criticity = "WARNING";
		default_msg = "a process has been started";
		break;
	case GRIDINIT_EVENT_DIED:
		criticity = "MINOR";
		default_msg = "a process died";
		break;
	case GRIDINIT_EVENT_BROKEN:
		criticity = "CRITIC";
		default_msg = "a process could not be respawned";
		break;
	default:
		criticity = "WARNING";
		default_msg = "something happened to a process";
		break;
	}
	
	(void) udata;
	offset = 0;

	if (*CODE_CLIENT)
		offset += g_snprintf(working_message+offset, sizeof(working_message)-offset,
			"[~BCL]%.*s[~ECL]", (_s = sizeof(CODE_CLIENT)), CODE_CLIENT);

	if (*CODE_OBJET)
		offset += g_snprintf(working_message+offset, sizeof(working_message)-offset,
			"[~BCO]%.*s[~ECO]", (_s = sizeof(CODE_OBJET)), CODE_OBJET);

	if (offset < sizeof(working_message)) {
		offset += g_snprintf(working_message+offset, sizeof(working_message)-offset,
			"%s", (*msg ? msg : default_msg));
	}
	
	spoolmess(SOPCODE, criticity, working_message);
}

static void
gridinit_spoolmess_init(void *udata, GHashTable *params)
{
	char *str;

	(void) udata;
	if (!params) {
		abort();
		return;
	}

	str = g_hash_table_lookup(params, "sopcode");
	if (str) {
		bzero(SOPCODE, sizeof(SOPCODE));
		g_strlcpy(SOPCODE, str, sizeof(SOPCODE)-1);
	}

	str = g_hash_table_lookup(params, "client");
	if (str) {
		bzero(CODE_CLIENT, sizeof(CODE_CLIENT));
		g_strlcpy(CODE_CLIENT, str, sizeof(CODE_CLIENT)-1);
	}

	str = g_hash_table_lookup(params, "projet");
	if (str) {
		bzero(CODE_OBJET, sizeof(CODE_OBJET));
		g_strlcpy(CODE_OBJET, str, sizeof(CODE_OBJET)-1);
	}

	NOTICE("SOPCODE = [%s]", SOPCODE);
	NOTICE("CODE_CLIENT = [%s]", CODE_CLIENT);
	NOTICE("CODE_OBJET = [%s]", CODE_OBJET);
}

static void
gridinit_spoolmess_fini(void *udata)
{
	(void) udata;
}

struct gridinit_alert_handle_s MODULE_EXPORT = {
	NULL /**/,
	gridinit_spoolmess_init,
	gridinit_spoolmess_fini,
	gridinit_spoolmess_handle
};

