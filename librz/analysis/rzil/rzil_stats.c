// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>

// TODO : rewrite this file when migrate to new op structure

/**
 * In ESIL, stats is used to collect these info :
 * 1: ops.list : ESIL op
 * 2: flg.read : List<flag> list of flag been read from
 * 3: flg.write : List<flag> list of flags been written to
 * 4: mem.read : List<memory address> list of memory address
 * 5: mem.write : List<memory address> list of memory address
 * 6: reg.read : List<register names> list of register names
 * 7: reg.write : List<register names> list of register names
 * These infos seems be used in `cmd_search_rop.c` only
 *
 * In the New IL, we should have the similar behavior at first
 *
 * CHECK_ME : flag read and write never been called in ESIL ??
*/

/**
 * Record memory R/W address, register R/W names. similar to `trace`
 * \param analysis RzAnalysis
 * \param rzil RZIL instance
 * \param op  a general RZIL op structure (Designed for switching between different implementations of RZIL op struct)
 */
RZ_API void rz_analysis_rzil_record_stats(RzAnalysis *analysis, RzAnalysisRzil *rzil, RzAnalysisRzilOp *op) {
	// ready for rewriting this file
}
