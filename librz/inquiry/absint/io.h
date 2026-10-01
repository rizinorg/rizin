// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2025-2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ABSINT_IO_H
#define RZ_ABSINT_IO_H

#include <rz_inquiry/rz_absint.h>

/**
 * \brief Serve an abstract interpreter memory read from an IL context.
 *
 * This is the non-threaded part of the abstract interpreter IO service. The
 * driver is responsible for transporting requests from interpreter threads;
 * this function only handles the request once it reaches the main thread.
 */
RZ_IPI RzAbsIntIOReadResult rz_absint_io_read(
	RZ_NONNULL const RzAnalysisILContext *il_ctx,
	RZ_NONNULL RzAbsIntIOReadRequest *io_req);

#endif
