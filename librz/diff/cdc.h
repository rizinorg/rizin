// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_DIFF_CDC_H
#define RZ_DIFF_CDC_H

#include <rz_diff.h>

/**
 * \brief FastCDC-anchored byte matches for rz_diff_matches_new() on large inputs.
 *
 * Produces the same kind of list as the exact byte matcher (RzDiffMatch spans
 * sorted by (a, b), terminated by a zero-size sentinel at (a_size, b_size)) by
 * running the exact matcher only inside the gaps between byte-identical FastCDC
 * anchors and emitting the anchors as equal spans. Returns NULL below the CDC
 * size threshold so the caller falls back to the exact global matcher.
 */
RZ_IPI RZ_OWN RzList /*<RzDiffMatch *>*/ *rz_diff_bytes_cdc_matches(RZ_NONNULL const ut8 *a, ut32 a_size, RZ_NONNULL const ut8 *b, ut32 b_size);

#endif
