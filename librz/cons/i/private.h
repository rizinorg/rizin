// SPDX-FileCopyrightText: 2026 Ehab-24 <ehabs1775@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_CONS_PRIVATE_H_
#define RZ_CONS_PRIVATE_H_

#include <rz_util.h>
#include <rz_types.h>
#include <rz_cons.h>

typedef enum {
	EMACS_MODIFY_CAPITALIZE,
	EMACS_MODIFY_TOLOWER,
	EMACS_MODIFY_TOUPPER
} RzEmacsModeModifyOp;

typedef struct {
	RzEmacsModeModifyOp op;
	bool move_cursor; ///< if true, cursor is moved to the end of the last word.
	bool word_count_provided; ///< if true \p word_count is used, else a single word is modified.
	size_t word_count; ///< number of words to modify.
} RzEmacsModeModifyOpts;

typedef RzVector /*<RzCodePoint>*/ RzCodePoints;
typedef RzVector /*<RzUnicodeCaseMapping>*/ RzUnicodeCaseMappings;

RZ_IPI void rz_emacs_mode_modify_opts_reset(RZ_NONNULL RzEmacsModeModifyOpts *opts);
RZ_IPI bool rz_emacs_mode_modify(RZ_NONNULL RzEmacsModeModifyOpts *opts, RZ_NONNULL RzLine *line);

#endif
