// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ANALYSIS_PRIVATE_H
#define RZ_ANALYSIS_PRIVATE_H

#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_arch.h>
#include <rz_lib.h>
#include <rz_list.h>
#include <rz_vector.h>

/**
 * TODO: rename & document AnalysisLeAddrPair
 * This structure is used for something
 * and requires a better name.
 * (deroad)
 */
typedef struct analysis_le_addr_pair_s {
	ut64 op_addr;
	ut64 le_addr;
	char *reg_name;
} AnalysisLeAddrPair;

struct rz_analysis_t {
	void *core;
	ut8 ptr_alignment_I;
	// NOTE: Do not change the order of fields above!
	// They are used in pointer passing hacks in rz_types.h.
	char *cpu; // analysis.cpu
	char *os; // asm.os
	int bits; // asm.bits
	int lineswidth; // asm.lines.width
	int big_endian; // cfg.bigendian
	ut64 sleep; // analysis.sleep, sleep some usecs before analyzing more (avoid 100% cpu usages)
	RzAnalysisCPPABI cpp_abi; // analysis.cpp.abi
	void *plugin_data;
	ut64 gp; // analysis.gp, global pointer. used for mips. but can be used by other arches too in the future
	RBTree bb_tree; // all basic blocks by address. They can overlap each other, but must never start at the same address.
	RzList /*<RzAnalysisFunction *>*/ *fcns;
	HtUP *ht_addr_fun; // address => function
	HtSP *ht_name_fun; // name => function
	RzReg *reg;
	ut8 *last_disasm_reg;
	RzSyscall *syscall;
	RzIOBind iob;
	RzFlagBind flb;
	RzBinBind binb; // Set only from core when an analysis plugin is called.
	RzCoreBind coreb;
	int maxreflines; // asm.lines.maxref
	ut32 pcalign; // asm.pcalign
	RzAnalysisEsil *esil;
	RzAnalysisILVM *il_vm; ///< user-faced VM, NEVER use this for any analysis passes!
	RzAnalysisPlugin *cur;
	RzInterval limit; // analysis.from, analysis.to
	HtSP /*<RzAnalysisPlugin *>*/ *plugins;
	Sdb *sdb_noret;
	Sdb *sdb_fmts;
	HtUP *ht_xrefs_from;
	HtUP *ht_xrefs_to;
	bool recursive_noreturn; // analysis.rnr
	// moved from RzAnalysisFcn
	Sdb *sdb; // root
	HtUP /*<RzVector<RzAnalysisAddrHintRecord>>*/ *addr_hints; // all hints that correspond to a single address
	RBTree /*<RzAnalysisArchHintRecord>*/ arch_hints;
	RBTree /*<RzAnalysisArchBitsRecord>*/ bits_hints;
	RHintCb hint_cbs;
	RzIntervalTree meta;
	RzSpaces meta_spaces;
	RzTypeDB *typedb; // Types management
	Sdb *sdb_cc; // calling conventions
	Sdb *sdb_classes;
	Sdb *sdb_classes_attrs;
	RzAnalysisCallbacks cb;
	RzAnalysisOptions opt;
	RzPVector /*<RzAnalysisRefline *>*/ *reflines;
	// RzList *noreturn;
	RzListComparator column_sort;
	int seggrn;
	RzEvent *ev;
	RzList /*<char *>*/ *imports; // global imports
	RzSetU *visited;
	RzStrConstPool constpool;
	RzList /*<AnalysisLeAddrPair *>*/ *leaddrs;
	RzPlatformTarget *arch_target;
	RzPlatformTargetIndex *platform_target;
	HtSP *ht_global_var; // global variables
	HtUP *ht_gadget_semantics; ///< cache gadget semantic information
	HtUP *ht_gadget; ///< cache gadget address list
	RBTree global_var_tree; // global variables by address. must not overlap
	RzHash *hash;
	RzAnalysisDebugInfo *debug_info; ///< store all debug info parsed from DWARF, etc..
	char *sdb_types_path; ///<  system path prefix, whether created in initialization or passed by RzCore.
	ut64 cmpval; ///< last compare value for jump table.
	ut64 lea_jmptbl_ip; ///< jump table x86 lea ip
	ut64 gnu_thumb1_case_uqi_addr; ///< address of a `__gnu_thumb1_case_uqi_addr` function (specific to ARM / Thumb-1)
	HtSP /*<const char *, RzSetU *>*/ *ht_virtual_xrefs; ///< addresses of virtual function calls
};

#endif // RZ_ANALYSIS_PRIVATE_H
