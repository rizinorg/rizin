/* rizin - MIT - Copyright 2018 - pancake */

#include <rz_util.h>
#include <rz_vector.h>

typedef struct rz_event_callback_hook_t {
	RzEventCallback cb;
	void *user;
	int handle;
} RzEventCallbackHook;

static void ht_callback_free(HtUPKv *kv) {
	rz_vector_free((RzVector *)kv->value);
}

RZ_API RzEvent *rz_event_new(void *user) {
	RzEvent *ev = RZ_NEW0(RzEvent);
	if (!ev) {
		return NULL;
	}

	ev->user = user;
	ev->next_handle = 0;
	ev->callbacks = ht_up_new(NULL, ht_callback_free, NULL);
	if (!ev->callbacks) {
		goto err;
	}
	rz_vector_init(&ev->all_callbacks, sizeof(RzEventCallbackHook), NULL, NULL);
	return ev;
err:
	rz_event_free(ev);
	return NULL;
}

RZ_API void rz_event_free(RzEvent *ev) {
	if (!ev) {
		return;
	}
	ht_up_free(ev->callbacks);
	rz_vector_clear(&ev->all_callbacks);
	free(ev);
}

static RzVector *get_cbs(RzEvent *ev, int type) {
	RzVector *cbs = ht_up_find(ev->callbacks, (ut64)type, NULL);
	if (!cbs) {
		cbs = rz_vector_new(sizeof(RzEventCallbackHook), NULL, NULL);
		if (cbs) {
			ht_up_insert(ev->callbacks, (ut64)type, cbs);
		}
	}
	return cbs;
}

RZ_API RzEventCallbackHandle rz_event_hook(RzEvent *ev, int type, RzEventCallback cb, void *user) {
	RzEventCallbackHandle handle = { 0 };
	RzEventCallbackHook hook;

	rz_return_val_if_fail(ev, handle);
	hook.cb = cb;
	hook.user = user;
	hook.handle = ev->next_handle++;
	if (type == RZ_EVENT_ALL) {
		rz_vector_push(&ev->all_callbacks, &hook);
	} else {
		RzVector *cbs = get_cbs(ev, type);
		if (!cbs) {
			return handle;
		}
		rz_vector_push(cbs, &hook);
	}
	handle.handle = hook.handle;
	handle.type = type;
	return handle;
}

static bool del_hook(void *user, const ut64 k, const void *v) {
	int handle = *(int *)user;
	RzVector *cbs = (RzVector *)v;
	RzEventCallbackHook *hook;
	size_t i;
	rz_return_val_if_fail(cbs, false);
	rz_vector_enumerate(cbs, hook, i) {
		if (hook->handle == handle) {
			rz_vector_remove_at(cbs, i, NULL);
			break;
		}
	}
	return true;
}

RZ_API void rz_event_unhook(RzEvent *ev, RzEventCallbackHandle handle) {
	rz_return_if_fail(ev);
	if (handle.type == RZ_EVENT_ALL) {
		// try to delete it both from each list of callbacks and from
		// the "all_callbacks" vector
		ht_up_foreach(ev->callbacks, del_hook, &handle.handle);
		del_hook(&handle.handle, 0, &ev->all_callbacks);
	} else {
		RzVector *cbs = ht_up_find(ev->callbacks, (ut64)handle.type, NULL);
		rz_return_if_fail(cbs);
		del_hook(&handle.handle, 0, cbs);
	}
}

RZ_API void rz_event_send(RzEvent *ev, int type, void *data) {
	RzEventCallbackHook *hook;
	rz_return_if_fail(ev && !ev->incall);

	// send to both the per-type callbacks and to the all_callbacks
	ev->incall = true;
	rz_vector_foreach(&ev->all_callbacks, hook) {
		hook->cb(ev, type, hook->user, data);
	}
	ev->incall = false;

	RzVector *cbs = ht_up_find(ev->callbacks, (ut64)type, NULL);
	if (!cbs) {
		return;
	}
	ev->incall = true;
	rz_vector_foreach(cbs, hook) {
		hook->cb(ev, type, hook->user, data);
	}
	ev->incall = false;
}
