// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2025-2026 Rot127 <rot127@posteo.com>
// SPDX-FileCopyrightText: 2026 Sumeetd04 <sumeetdhangare38@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ABSINT_IO_H
#define RZ_ABSINT_IO_H

#include <rz_inquiry/rz_absint.h>

/**
 * \brief Serve an IL memory read request of an abstract interpreter.
 *
 * This is the serving side of the interpreter IO channel. The driver only
 * transports requests from the interpreter threads to the main thread and
 * back; the actual read from the IL context's memories happens here, on the
 * main thread, where full access to rizin is available.
 *
 * \param il_ctx IL context holding the memories to read from.
 * \param io_req The read request to serve. \p io_req->ld_data is filled on success.
 * \return The result to deliver back to the requesting interpreter.
 */
RZ_IPI RzAbsIntIOReadResult rz_absint_io_read(RZ_NONNULL const RzAnalysisILContext *il_ctx, RZ_NONNULL RzAbsIntIOReadRequest *io_req);

#endif // RZ_ABSINT_IO_H