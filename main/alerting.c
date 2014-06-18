#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridinit"
#endif

#include <log4c.h>
#include <event.h>
#include <glib.h>
#include <gmodule.h>

#include <gridinit-utils.h>
#include "./gridinit_internals.h"
#include "./gridinit_alerts.h"
#include "../lib/gridinit-internals.h"

static GModule *module = NULL;
static struct gridinit_alert_handle_s *handle = NULL;

/* ------------------------------------------------------------------------- */

gboolean
gridinit_alerting_configure(const gchar *path, const gchar *symbol,
	GHashTable *ht_params, GError **err)
{
	TRACE("trying to configure the alerting with the module [%s] and the symbol [%s]",
		path, symbol);
	if (!symbol || !path) {
		if (err)
			*err = g_error_printf(LOG_DOMAIN, 500, "Invalid parameter");
			return FALSE;
	}
	if (module != NULL) {
		if (err)
			*err = g_error_printf(LOG_DOMAIN, 500, "Module already loaded");
		return FALSE;
	}

	/* Open the module and locate the exported symbol */
	if (NULL == (module = g_module_open (path, 0))) {
		if (err)
			*err = g_error_printf(LOG_DOMAIN, 500,
				"Cannot load the plug-in from file %s (%s)",
				path, g_module_error());
		return FALSE;
	}

	gpointer pointer = NULL;
	if (!g_module_symbol(module, symbol, &pointer) || !pointer) {
		if (err)
			*err = g_error_printf(LOG_DOMAIN, 500,
				"Cannot get the exported structure (%s) from the plug-in %p (%s)",
				symbol, (void*)module, g_module_error());
		return FALSE;
	}

	handle = pointer;
	if (handle->init)
		handle->init(handle->module_data, ht_params);
	
	return TRUE;
}


void
gridinit_alerting_send(int event, const char *msg)
{
	WARN("Process alert: %s", msg);

	if (!module || !handle || !handle->send)
		return;

	handle->send(handle->module_data, event, msg);
}

void
gridinit_alerting_close(void)
{
	if (handle && handle->fini)
		handle->fini(handle->module_data);
	if (module)
		g_module_close(module);

	module = NULL;
	handle = NULL;
}

