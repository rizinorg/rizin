// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file This is a file with dummy debugger functions for when
 *       the native debugger is unsupported.
 */

RZ_API ut64 rz_debug_get_tls(RZ_NONNULL RzDebug *dbg, int tid) {
	return 0;
}

RZ_API RZ_OWN RzList /*<RzDebugPid *>*/ *rz_debug_native_threads(RzDebug *dbg, int pid) {
	return rz_list_new();
}
