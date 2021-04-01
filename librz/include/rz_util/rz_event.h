// SPDX-FileCopyrightText: 2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

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
} RzEvent;

typedef struct rz_event_callback_handle_t {
	int handle;
	int type;
} RzEventCallbackHandle;

typedef void (*RzEventCallback)(RzEvent *ev, int type, void *user, void *data);

typedef enum {
	RZ_EVENT_ALL = 0,
	RZ_EVENT_META_SET, // RzEventMeta
	RZ_EVENT_META_DEL, // RzEventMeta
	RZ_EVENT_META_CLEAR, // RzEventMeta
	RZ_EVENT_CLASS_NEW, // RzEventClass
	RZ_EVENT_CLASS_DEL, // RzEventClass
	RZ_EVENT_CLASS_RENAME, // RzEventClassRename
	RZ_EVENT_CLASS_ATTR_SET, // RzEventClassAttr
	RZ_EVENT_CLASS_ATTR_DEL, // RzEventClassAttrSet
	RZ_EVENT_CLASS_ATTR_RENAME, // RzEventClassAttrRename
	RZ_EVENT_DEBUG_PROCESS_FINISHED, // RzEventDebugProcessFinished
	RZ_EVENT_IO_WRITE, // RzEventIOWrite
	RZ_EVENT_MAX,
} RzEventType;

typedef struct rz_event_meta_t {
	int type;
	ut64 addr;
	const char *string;
} RzEventMeta;

typedef struct rz_event_class_t {
	const char *name;
} RzEventClass;

typedef struct rz_event_class_rename_t {
	const char *name_old;
	const char *name_new;
} RzEventClassRename;

typedef struct rz_event_class_attr_t {
	const char *class_name;
	int attr_type; // RzAnalysisClassAttrType
	const char *attr_id;
} RzEventClassAttr;

typedef struct rz_event_class_attr_set_t {
	RzEventClassAttr attr;
	const char *content;
} RzEventClassAttrSet;

typedef struct rz_event_class_attr_rename_t {
	RzEventClassAttr attr;
	const char *attr_id_new;
} RzEventClassAttrRename;

typedef struct rz_event_debug_process_finished_t {
	int pid;
} RzEventDebugProcessFinished;

typedef struct rz_event_io_write_t {
	ut64 addr;
	const ut8 *buf;
	int len;
} RzEventIOWrite;

RZ_API RzEvent *rz_event_new(void *user);
RZ_API void rz_event_free(RzEvent *ev);
RZ_API RzEventCallbackHandle rz_event_hook(RzEvent *ev, int type, RzEventCallback cb, void *user);
RZ_API void rz_event_unhook(RzEvent *ev, RzEventCallbackHandle handle);
RZ_API void rz_event_send(RzEvent *ev, int type, void *data);

#ifdef __cplusplus
}
#endif

#endif
