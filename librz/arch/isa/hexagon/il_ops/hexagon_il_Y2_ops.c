// SPDX-FileCopyrightText: 2021 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: c2b89fc9e45d325282b8eb6536f6145282dc3fdf
// LLVM commit date: 2024-12-23 13:36:28 -0600 (ISO 8601 format)
// Date of code generation: 2025-02-22 07:05:24-05:00
//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#include <rz_il/rz_il_opbuilder_begin.h>
#include "../hexagon_il.h"
#include <hexagon/hexagon.h>
#include <rz_il/rz_il_opcodes.h>

// barrier
RzILOpEffect *hex_il_op_y2_barrier(HexInsnPktBundle *bundle) {
	return NOP();
}

// brkpt
RzILOpEffect *hex_il_op_y2_break(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// ciad(Rs)
RzILOpEffect *hex_il_op_y2_ciad(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// crswap(Rx,sgp0)
RzILOpEffect *hex_il_op_y2_crswap0(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// cswi(Rs)
RzILOpEffect *hex_il_op_y2_cswi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// dccleana(Rs)
RzILOpEffect *hex_il_op_y2_dccleana(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// dccleanidx(Rs)
RzILOpEffect *hex_il_op_y2_dccleanidx(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// dccleaninva(Rs)
RzILOpEffect *hex_il_op_y2_dccleaninva(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// dccleaninvidx(Rs)
RzILOpEffect *hex_il_op_y2_dccleaninvidx(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// dcfetch(Rs+Ii)
RzILOpEffect *hex_il_op_y2_dcfetchbo(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// dcinva(Rs)
RzILOpEffect *hex_il_op_y2_dcinva(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// dcinvidx(Rs)
RzILOpEffect *hex_il_op_y2_dcinvidx(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// dckill
RzILOpEffect *hex_il_op_y2_dckill(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = dctagr(Rs)
RzILOpEffect *hex_il_op_y2_dctagr(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// dctagw(Rs,Rt)
RzILOpEffect *hex_il_op_y2_dctagw(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// dczeroa(Rs)
RzILOpEffect *hex_il_op_y2_dczeroa(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = getimask(Rs)
RzILOpEffect *hex_il_op_y2_getimask(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = iassignr(Rs)
RzILOpEffect *hex_il_op_y2_iassignr(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// iassignw(Rs)
RzILOpEffect *hex_il_op_y2_iassignw(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = icdatar(Rs)
RzILOpEffect *hex_il_op_y2_icdatar(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// icdataw(Rs,Rt)
RzILOpEffect *hex_il_op_y2_icdataw(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// icinva(Rs)
RzILOpEffect *hex_il_op_y2_icinva(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// icinvidx(Rs)
RzILOpEffect *hex_il_op_y2_icinvidx(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// ickill
RzILOpEffect *hex_il_op_y2_ickill(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = ictagr(Rs)
RzILOpEffect *hex_il_op_y2_ictagr(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// ictagw(Rs,Rt)
RzILOpEffect *hex_il_op_y2_ictagw(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// isync
RzILOpEffect *hex_il_op_y2_isync(HexInsnPktBundle *bundle) {
	return NOP();
}

// k0lock
RzILOpEffect *hex_il_op_y2_k0lock(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// k0unlock
RzILOpEffect *hex_il_op_y2_k0unlock(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// l2cleaninvidx(Rs)
RzILOpEffect *hex_il_op_y2_l2cleaninvidx(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// l2kill
RzILOpEffect *hex_il_op_y2_l2kill(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// resume(Rs)
RzILOpEffect *hex_il_op_y2_resume(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// setimask(Pt,Rs)
RzILOpEffect *hex_il_op_y2_setimask(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// setprio(Pt,Rs)
RzILOpEffect *hex_il_op_y2_setprio(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// start(Rs)
RzILOpEffect *hex_il_op_y2_start(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// stop(Rs)
RzILOpEffect *hex_il_op_y2_stop(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// swi(Rs)
RzILOpEffect *hex_il_op_y2_swi(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// syncht
RzILOpEffect *hex_il_op_y2_syncht(HexInsnPktBundle *bundle) {
	return NOP();
}

// Rd = Ss
RzILOpEffect *hex_il_op_y2_tfrscrr(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Sd = Rs
RzILOpEffect *hex_il_op_y2_tfrsrcr(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// tlblock
RzILOpEffect *hex_il_op_y2_tlblock(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rd = tlbp(Rs)
RzILOpEffect *hex_il_op_y2_tlbp(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// Rdd = tlbr(Rs)
RzILOpEffect *hex_il_op_y2_tlbr(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// tlbunlock
RzILOpEffect *hex_il_op_y2_tlbunlock(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// tlbw(Rss,Rt)
RzILOpEffect *hex_il_op_y2_tlbw(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

// wait(Rs)
RzILOpEffect *hex_il_op_y2_wait(HexInsnPktBundle *bundle) {
	NOT_IMPLEMENTED;
}

#include <rz_il/rz_il_opbuilder_end.h>