#include "rz_th.h"
#include "rz_types.h"
#include "rz_util/rz_assert.h"
#include <rz_inquiry/rz_interpreter.h>

enum rz_intp_state_flag {
	RZ_INTP_STATE_INIT, ///< Initialization state.
	RZ_INTP_STATE_EMU, ///< Emulation state.
	RZ_INTP_STATE_CLEAN, ///< Cleaning state.
	RZ_INTP_STATE_TERM, ///< Termination state.
};

struct rz_intp_state {
	RzThreadLock *lock; ///< The mutex around the state flag.
	RzIntpStateFlag flag; ///< The current set state.
};

RZ_API const char *rz_intp_state_flag_str(RzIntpStateFlag flag) {
	switch (flag) {
	case RZ_INTP_STATE_INIT:
		return "I";
	case RZ_INTP_STATE_EMU:
		return "O";
	case RZ_INTP_STATE_CLEAN:
		return "C";
	case RZ_INTP_STATE_TERM:
		return "T";
	}
	rz_warn_if_reached();
	return "-";
}

RZ_API RZ_OWN RzIntpState *rz_intp_state_new() {
	RzIntpState *state = RZ_NEW0(RzIntpState);
	if (!state) {
		return NULL;
	}
	state->flag = RZ_INTP_STATE_INIT;
	state->lock = rz_th_lock_new(false);
	if (!state->lock) {
		free(state);
		return NULL;
	}
	return state;
}

RZ_API void rz_intp_state_free(RZ_OWN RZ_NULLABLE RzIntpState *state) {
	if (!state) {
		return;
	}
	rz_th_lock_free(state->lock);
	free(state);
}

RZ_API RzIntpStateFlag rz_intp_state_get(RZ_BORROW RZ_NONNULL RzIntpState *state) {
	rz_return_val_if_fail(state, RZ_INTP_STATE_TERM);
	rz_th_lock_enter(state->lock);
	RzIntpStateFlag flag = state->flag;
	rz_th_lock_leave(state->lock);
	return flag;
}

RZ_API void rz_intp_state_set(RZ_BORROW RZ_NONNULL RzIntpState *state, RzIntpStateFlag flag) {
	rz_th_lock_enter(state->lock);
	state->flag = flag;
	rz_th_lock_leave(state->lock);
}
