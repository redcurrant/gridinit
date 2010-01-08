#ifndef __GRIDINIT_ALERTS_H__
# define __GRIDINIT_ALERTS_H__

#define GRIDINIT_EVENT_STARTED 1
#define GRIDINIT_EVENT_DIED 2
#define GRIDINIT_EVENT_NOTRESPAWNED 3

/**
 * @param udata the user data provided in the exported structure 
 */
typedef void (*gridinit_alert_handler_f) (void *udata, int event, const char *msg);

/**
 * @param udata the user data provided in the exported structure 
 */
typedef void (*gridinit_alert_init_f) (void *udata, GHashTable *params);

/**
 * @param udata the user data provided in the exported structure 
 */
typedef void (*gridinit_alert_fini_f) (void *udata);

/**
 * The type of structure that must be exported by the module
 * under the name MODULE_HANDLER_gridnit_alert;
 */
struct gridinit_alert_handle_s {
	void *module_data;
	gridinit_alert_init_f init;
	gridinit_alert_fini_f fini;
	gridinit_alert_handler_f send;
};

#endif
