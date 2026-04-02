#include "rz_th.h"
#include "rz_types.h"
#include "rz_util/rz_assert.h"
#include <rz_inquiry/rz_interpreter.h>

struct rz_intp_run_state {
	RzThreadLock *lock; ///< The mutex around the state flag.
	RzIntpRunStateFlag flag; ///< The current set state.
};

RZ_API const char *rz_intp_run_state_flag_str(RzIntpRunStateFlag flag) {
	switch (flag) {
	case RZ_INTP_RUN_STATE_OUT_OF_LOOP:
		return "-";
	case RZ_INTP_RUN_STATE_INIT:
		return "I";
	case RZ_INTP_RUN_STATE_EMU:
		return "O";
	case RZ_INTP_RUN_STATE_CLEAN:
		return "C";
	case RZ_INTP_RUN_STATE_TERM:
		return "T";
	}
	rz_warn_if_reached();
	return "-";
}

RZ_API RZ_OWN RzIntpRunState *rz_intp_run_state_new() {
	RzIntpRunState *state = RZ_NEW0(RzIntpRunState);
	if (!state) {
		return NULL;
	}
	state->flag = RZ_INTP_RUN_STATE_OUT_OF_LOOP;
	state->lock = rz_th_lock_new(false);
	if (!state->lock) {
		free(state);
		return NULL;
	}
	return state;
}

RZ_API void rz_intp_run_state_free(RZ_OWN RZ_NULLABLE RzIntpRunState *state) {
	if (!state) {
		return;
	}
	rz_th_lock_free(state->lock);
	free(state);
}

RZ_API RzIntpRunStateFlag rz_intp_run_state_get(RZ_BORROW RZ_NONNULL RzIntpRunState *state) {
	rz_return_val_if_fail(state, RZ_INTP_RUN_STATE_TERM);
	rz_th_lock_enter(state->lock);
	RzIntpRunStateFlag flag = state->flag;
	rz_th_lock_leave(state->lock);
	return flag;
}

/**
 * \brief Sets the run state.
 * This function is declared IPI, so it is not used outside of the interpreter module!
 */
RZ_IPI void rz_intp_run_state_set(RZ_BORROW RZ_NONNULL RzIntpRunState *state, RzIntpRunStateFlag flag) {
	rz_th_lock_enter(state->lock);
	state->flag = flag;
	rz_th_lock_leave(state->lock);
}
