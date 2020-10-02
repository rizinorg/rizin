/* radare - LGPL - Copyright 2018 - pancake */

#ifndef RZ_EVENT_H
#define RZ_EVENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ht_up.h>
#include <rz_vector.h>

typedef struct rz_event_t {
	void *user;
	bool incall;
	HtUP *callbacks;
	RzVector all_callbacks;
	int next_handle;
} REvent;

typedef struct rz_event_callback_handle_t {
	int handle;
	int type;
} REventCallbackHandle;

typedef void (*REventCallback)(REvent *ev, int type, void *user, void *data);

typedef enum {
	RZ_EVENT_ALL = 0,
	RZ_EVENT_META_SET, // REventMeta
	RZ_EVENT_META_DEL, // REventMeta
	RZ_EVENT_META_CLEAR, // REventMeta
	RZ_EVENT_CLASS_NEW, // REventClass
	RZ_EVENT_CLASS_DEL, // REventClass
	RZ_EVENT_CLASS_RENAME, // REventClassRename
	RZ_EVENT_CLASS_ATTR_SET, // REventClassAttr
	RZ_EVENT_CLASS_ATTR_DEL, // REventClassAttrSet
	RZ_EVENT_CLASS_ATTR_RENAME, // REventClassAttrRename
	RZ_EVENT_DEBUG_PROCESS_FINISHED, // REventDebugProcessFinished
	RZ_EVENT_MAX,
} REventType;

typedef struct rz_event_meta_t {
	int type;
	ut64 addr;
	const char *string;
} REventMeta;

typedef struct rz_event_class_t {
	const char *name;
} REventClass;

typedef struct rz_event_class_rename_t {
	const char *name_old;
	const char *name_new;
} REventClassRename;

typedef struct rz_event_class_attr_t {
	const char *class_name;
	int attr_type; // RzAnalClassAttrType
	const char *attr_id;
} REventClassAttr;

typedef struct rz_event_class_attr_set_t {
	REventClassAttr attr;
	const char *content;
} REventClassAttrSet;

typedef struct rz_event_class_attr_rename_t {
	REventClassAttr attr;
	const char *attr_id_new;
} REventClassAttrRename;

typedef struct rz_event_debug_process_finished_t {
	int pid;
} REventDebugProcessFinished;

RZ_API REvent *rz_event_new(void *user);
RZ_API void rz_event_free(REvent *ev);
RZ_API REventCallbackHandle rz_event_hook(REvent *ev, int type, REventCallback cb, void *user);
RZ_API void rz_event_unhook(REvent *ev, REventCallbackHandle handle);
RZ_API void rz_event_send(REvent *ev, int type, void *data);

#ifdef __cplusplus
}
#endif

#endif
