// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * Lifting C6000 code together with its pipeline.
 *
 * The RzIL VM runs one effect per step and knows nothing of a pipeline, while
 * on a C6000 an instruction's result lands a fixed number of cycles after it
 * issues, a branch takes effect six cycles after it issues with the packets in
 * between still running, and the SPLOOP buffer replays a loop body by itself.
 * So the effect for an address is built by running a cycle simulator over the
 * code from there, at lift time:
 *
 *   - one execute packet issues per cycle, or fewer after a multi-cycle NOP,
 *     the NOPs of a BNOP or ADDKPC, the five a CALLP inserts, or the four a
 *     load inserts in a protected compact fetch packet;
 *   - every instruction of a packet reads the registers as the packet found
 *     them, and a result that something could see land late is held in a
 *     local until the end of the cycle it lands in (c6x_write_delay());
 *   - a branch is recorded when it issues, with its predicate and a register
 *     target read there, and the packet it reaches issues six cycles later.
 *
 * The simulation stops at the first cycle with nothing in flight, and the
 * effect ends with a jump to the packet that would issue next. So each step
 * leaves the VM where the hardware also stands with nothing pending, and as
 * every address that starts an execute packet lifts this way from scratch, it
 * does not matter where the VM is put.
 *
 * Everything static is decided at lift time: the cycle each packet issues in,
 * the cycle each result lands in, the packet a branch with a constant target
 * reaches. What is dynamic -- a predicate, a register target -- is read into a
 * local when the instruction issues, as the hardware reads it. A branch whose
 * predicate cannot be known forks the simulation, and the two paths become the
 * arms of an RzIL branch. Branches testing the same register with no write to
 * it in between share one sample, so a fork decides all of them at once.
 *
 * The SPLOOP buffer is modelled on top, see sim_loop().
 */

#include <rz_util.h>
#include "c6x.h"

#include <rz_il/rz_il_opbuilder_begin.h>

// RzIL keeps a variable name as a const char * and never copies it, so every
// local an effect names has to outlive the effect. The simulator draws them
// from these tables of string literals.
// clang-format off
/// A result in flight, from issue to landing.
static const char *const sim_held_names[128] = {
	"_xh0", "_xh1", "_xh2", "_xh3", "_xh4", "_xh5", "_xh6", "_xh7",
	"_xh8", "_xh9", "_xh10", "_xh11", "_xh12", "_xh13", "_xh14", "_xh15",
	"_xh16", "_xh17", "_xh18", "_xh19", "_xh20", "_xh21", "_xh22", "_xh23",
	"_xh24", "_xh25", "_xh26", "_xh27", "_xh28", "_xh29", "_xh30", "_xh31",
	"_xh32", "_xh33", "_xh34", "_xh35", "_xh36", "_xh37", "_xh38", "_xh39",
	"_xh40", "_xh41", "_xh42", "_xh43", "_xh44", "_xh45", "_xh46", "_xh47",
	"_xh48", "_xh49", "_xh50", "_xh51", "_xh52", "_xh53", "_xh54", "_xh55",
	"_xh56", "_xh57", "_xh58", "_xh59", "_xh60", "_xh61", "_xh62", "_xh63",
	"_xh64", "_xh65", "_xh66", "_xh67", "_xh68", "_xh69", "_xh70", "_xh71",
	"_xh72", "_xh73", "_xh74", "_xh75", "_xh76", "_xh77", "_xh78", "_xh79",
	"_xh80", "_xh81", "_xh82", "_xh83", "_xh84", "_xh85", "_xh86", "_xh87",
	"_xh88", "_xh89", "_xh90", "_xh91", "_xh92", "_xh93", "_xh94", "_xh95",
	"_xh96", "_xh97", "_xh98", "_xh99", "_xh100", "_xh101", "_xh102", "_xh103",
	"_xh104", "_xh105", "_xh106", "_xh107", "_xh108", "_xh109", "_xh110", "_xh111",
	"_xh112", "_xh113", "_xh114", "_xh115", "_xh116", "_xh117", "_xh118", "_xh119",
	"_xh120", "_xh121", "_xh122", "_xh123", "_xh124", "_xh125", "_xh126", "_xh127"
};

/// A predicate sampled when its instruction issued.
static const char *const sim_pred_names[64] = {
	"_xq0", "_xq1", "_xq2", "_xq3", "_xq4", "_xq5", "_xq6", "_xq7",
	"_xq8", "_xq9", "_xq10", "_xq11", "_xq12", "_xq13", "_xq14", "_xq15",
	"_xq16", "_xq17", "_xq18", "_xq19", "_xq20", "_xq21", "_xq22", "_xq23",
	"_xq24", "_xq25", "_xq26", "_xq27", "_xq28", "_xq29", "_xq30", "_xq31",
	"_xq32", "_xq33", "_xq34", "_xq35", "_xq36", "_xq37", "_xq38", "_xq39",
	"_xq40", "_xq41", "_xq42", "_xq43", "_xq44", "_xq45", "_xq46", "_xq47",
	"_xq48", "_xq49", "_xq50", "_xq51", "_xq52", "_xq53", "_xq54", "_xq55",
	"_xq56", "_xq57", "_xq58", "_xq59", "_xq60", "_xq61", "_xq62", "_xq63"
};

/// A register branch target, read when the branch issued.
static const char *const sim_tgt_names[16] = {
	"_xt0", "_xt1", "_xt2", "_xt3", "_xt4", "_xt5", "_xt6", "_xt7",
	"_xt8", "_xt9", "_xt10", "_xt11", "_xt12", "_xt13", "_xt14", "_xt15"
};

/// A register as the packet being staged found it.
static const char *const sim_snap_names[48] = {
	"_xs0", "_xs1", "_xs2", "_xs3", "_xs4", "_xs5", "_xs6", "_xs7",
	"_xs8", "_xs9", "_xs10", "_xs11", "_xs12", "_xs13", "_xs14", "_xs15",
	"_xs16", "_xs17", "_xs18", "_xs19", "_xs20", "_xs21", "_xs22", "_xs23",
	"_xs24", "_xs25", "_xs26", "_xs27", "_xs28", "_xs29", "_xs30", "_xs31",
	"_xs32", "_xs33", "_xs34", "_xs35", "_xs36", "_xs37", "_xs38", "_xs39",
	"_xs40", "_xs41", "_xs42", "_xs43", "_xs44", "_xs45", "_xs46", "_xs47"
};

/// What one slot of the packet being staged wrote.
static const char *const sim_cap_names[64] = {
	"_xc0", "_xc1", "_xc2", "_xc3", "_xc4", "_xc5", "_xc6", "_xc7",
	"_xc8", "_xc9", "_xc10", "_xc11", "_xc12", "_xc13", "_xc14", "_xc15",
	"_xc16", "_xc17", "_xc18", "_xc19", "_xc20", "_xc21", "_xc22", "_xc23",
	"_xc24", "_xc25", "_xc26", "_xc27", "_xc28", "_xc29", "_xc30", "_xc31",
	"_xc32", "_xc33", "_xc34", "_xc35", "_xc36", "_xc37", "_xc38", "_xc39",
	"_xc40", "_xc41", "_xc42", "_xc43", "_xc44", "_xc45", "_xc46", "_xc47",
	"_xc48", "_xc49", "_xc50", "_xc51", "_xc52", "_xc53", "_xc54", "_xc55",
	"_xc56", "_xc57", "_xc58", "_xc59", "_xc60", "_xc61", "_xc62", "_xc63"
};

/// Whether one loop instruction runs in the cycle being staged.
static const char *const sim_guard_names[32] = {
	"_xg0", "_xg1", "_xg2", "_xg3", "_xg4", "_xg5", "_xg6", "_xg7",
	"_xg8", "_xg9", "_xg10", "_xg11", "_xg12", "_xg13", "_xg14", "_xg15",
	"_xg16", "_xg17", "_xg18", "_xg19", "_xg20", "_xg21", "_xg22", "_xg23",
	"_xg24", "_xg25", "_xg26", "_xg27", "_xg28", "_xg29", "_xg30", "_xg31"
};

/// A loop result in flight, one per block it spends in flight.
static const char *const sim_loop_val_names[160] = {
	"_xlv0", "_xlv1", "_xlv2", "_xlv3", "_xlv4", "_xlv5", "_xlv6", "_xlv7",
	"_xlv8", "_xlv9", "_xlv10", "_xlv11", "_xlv12", "_xlv13", "_xlv14", "_xlv15",
	"_xlv16", "_xlv17", "_xlv18", "_xlv19", "_xlv20", "_xlv21", "_xlv22", "_xlv23",
	"_xlv24", "_xlv25", "_xlv26", "_xlv27", "_xlv28", "_xlv29", "_xlv30", "_xlv31",
	"_xlv32", "_xlv33", "_xlv34", "_xlv35", "_xlv36", "_xlv37", "_xlv38", "_xlv39",
	"_xlv40", "_xlv41", "_xlv42", "_xlv43", "_xlv44", "_xlv45", "_xlv46", "_xlv47",
	"_xlv48", "_xlv49", "_xlv50", "_xlv51", "_xlv52", "_xlv53", "_xlv54", "_xlv55",
	"_xlv56", "_xlv57", "_xlv58", "_xlv59", "_xlv60", "_xlv61", "_xlv62", "_xlv63",
	"_xlv64", "_xlv65", "_xlv66", "_xlv67", "_xlv68", "_xlv69", "_xlv70", "_xlv71",
	"_xlv72", "_xlv73", "_xlv74", "_xlv75", "_xlv76", "_xlv77", "_xlv78", "_xlv79",
	"_xlv80", "_xlv81", "_xlv82", "_xlv83", "_xlv84", "_xlv85", "_xlv86", "_xlv87",
	"_xlv88", "_xlv89", "_xlv90", "_xlv91", "_xlv92", "_xlv93", "_xlv94", "_xlv95",
	"_xlv96", "_xlv97", "_xlv98", "_xlv99", "_xlv100", "_xlv101", "_xlv102", "_xlv103",
	"_xlv104", "_xlv105", "_xlv106", "_xlv107", "_xlv108", "_xlv109", "_xlv110", "_xlv111",
	"_xlv112", "_xlv113", "_xlv114", "_xlv115", "_xlv116", "_xlv117", "_xlv118", "_xlv119",
	"_xlv120", "_xlv121", "_xlv122", "_xlv123", "_xlv124", "_xlv125", "_xlv126", "_xlv127",
	"_xlv128", "_xlv129", "_xlv130", "_xlv131", "_xlv132", "_xlv133", "_xlv134", "_xlv135",
	"_xlv136", "_xlv137", "_xlv138", "_xlv139", "_xlv140", "_xlv141", "_xlv142", "_xlv143",
	"_xlv144", "_xlv145", "_xlv146", "_xlv147", "_xlv148", "_xlv149", "_xlv150", "_xlv151",
	"_xlv152", "_xlv153", "_xlv154", "_xlv155", "_xlv156", "_xlv157", "_xlv158", "_xlv159"
};

/// Whether that loop result lands.
static const char *const sim_loop_pred_names[160] = {
	"_xlp0", "_xlp1", "_xlp2", "_xlp3", "_xlp4", "_xlp5", "_xlp6", "_xlp7",
	"_xlp8", "_xlp9", "_xlp10", "_xlp11", "_xlp12", "_xlp13", "_xlp14", "_xlp15",
	"_xlp16", "_xlp17", "_xlp18", "_xlp19", "_xlp20", "_xlp21", "_xlp22", "_xlp23",
	"_xlp24", "_xlp25", "_xlp26", "_xlp27", "_xlp28", "_xlp29", "_xlp30", "_xlp31",
	"_xlp32", "_xlp33", "_xlp34", "_xlp35", "_xlp36", "_xlp37", "_xlp38", "_xlp39",
	"_xlp40", "_xlp41", "_xlp42", "_xlp43", "_xlp44", "_xlp45", "_xlp46", "_xlp47",
	"_xlp48", "_xlp49", "_xlp50", "_xlp51", "_xlp52", "_xlp53", "_xlp54", "_xlp55",
	"_xlp56", "_xlp57", "_xlp58", "_xlp59", "_xlp60", "_xlp61", "_xlp62", "_xlp63",
	"_xlp64", "_xlp65", "_xlp66", "_xlp67", "_xlp68", "_xlp69", "_xlp70", "_xlp71",
	"_xlp72", "_xlp73", "_xlp74", "_xlp75", "_xlp76", "_xlp77", "_xlp78", "_xlp79",
	"_xlp80", "_xlp81", "_xlp82", "_xlp83", "_xlp84", "_xlp85", "_xlp86", "_xlp87",
	"_xlp88", "_xlp89", "_xlp90", "_xlp91", "_xlp92", "_xlp93", "_xlp94", "_xlp95",
	"_xlp96", "_xlp97", "_xlp98", "_xlp99", "_xlp100", "_xlp101", "_xlp102", "_xlp103",
	"_xlp104", "_xlp105", "_xlp106", "_xlp107", "_xlp108", "_xlp109", "_xlp110", "_xlp111",
	"_xlp112", "_xlp113", "_xlp114", "_xlp115", "_xlp116", "_xlp117", "_xlp118", "_xlp119",
	"_xlp120", "_xlp121", "_xlp122", "_xlp123", "_xlp124", "_xlp125", "_xlp126", "_xlp127",
	"_xlp128", "_xlp129", "_xlp130", "_xlp131", "_xlp132", "_xlp133", "_xlp134", "_xlp135",
	"_xlp136", "_xlp137", "_xlp138", "_xlp139", "_xlp140", "_xlp141", "_xlp142", "_xlp143",
	"_xlp144", "_xlp145", "_xlp146", "_xlp147", "_xlp148", "_xlp149", "_xlp150", "_xlp151",
	"_xlp152", "_xlp153", "_xlp154", "_xlp155", "_xlp156", "_xlp157", "_xlp158", "_xlp159"
};
// clang-format on
/// Names of the loop-control locals; see sim_loop().
#define SIM_SPB  "_spb" ///< block being run, counted from the loop start
#define SIM_SPL  "_spl" ///< last iteration started, -1 for none
#define SIM_SPT  "_spt" ///< no further iteration starts
#define SIM_SPA  "_spa" ///< the loop stopped abruptly, dropping what was in flight
#define SIM_SPH0 "_sph0" ///< SPLOOPW predicate at the start of this cycle
#define SIM_SPH1 "_sph1" ///< ... one cycle back
#define SIM_SPH2 "_sph2" ///< ... two cycles back
#define SIM_SPH3 "_sph3" ///< ... three cycles back

/// A branch reaches its target this many cycles after it issues.
#define SIM_BRANCH_DELAY 6
/// Cycles one path may run before the simulation gives up.
#define SIM_MAX_CYCLES 64
/// Packets issued over all paths of one effect.
#define SIM_MAX_PACKETS 256
/// Forks over all paths of one effect.
#define SIM_MAX_FORKS 32
/// Results one path can have in flight.
#define SIM_MAX_HELD 64
/// Branches one path can have in flight.
#define SIM_MAX_BRANCHES 8
/// Predicates one path can have sampled.
#define SIM_MAX_LATCHES 32
/// Registers one packet can write.
#define SIM_PK_REGS 48
/// Instructions one packet can hold, a staged SPLOOP cycle included.
#define SIM_PK_SLOTS 16
/// Longest loop body the SPLOOP buffer holds, in cycles.
#define SIM_LOOP_LEN 48
/// Instructions one cycle of a loop body can hold.
#define SIM_LOOP_SLOTS 8
/// Results a loop body can write late.
#define SIM_LOOP_WRITES 64
/// Blocks a loop result can be in flight over, plus one.
#define SIM_LOOP_GENS 12

/* ---- effect lists ---- */

/** Effects in program order, folded into one at the end. */
typedef struct {
	RzPVector /*<RzILOpEffect *>*/ v; ///< owned
} SimEffs;

static void effs_init(SimEffs *e) {
	rz_pvector_init(&e->v, NULL);
}

static void effs_fini(SimEffs *e) {
	void **it;
	rz_pvector_foreach (&e->v, it) {
		rz_il_op_effect_free(*it);
	}
	rz_pvector_fini(&e->v);
}

// Append \p x and take it over. NULL stands for a failure to lift and is
// reported as false.
static bool effs_add(SimEffs *e, RzILOpEffect *x) {
	if (!x) {
		return false;
	}
	if (x->code == RZ_IL_OP_NOP) {
		rz_il_op_effect_free(x);
		return true;
	}
	if (!rz_pvector_push(&e->v, x)) {
		rz_il_op_effect_free(x);
		return false;
	}
	return true;
}

// A balanced fold, so that a long loop does not nest thousands of seq deep. A
// jump only ever comes last, which keeps it on the right-hand spine of every
// seq, where RzIL allows one.
static RzILOpEffect *effs_fold(void **a, size_t n) {
	if (n == 1) {
		return a[0];
	}
	size_t h = n / 2;
	RzILOpEffect *l = effs_fold(a, h);
	return SEQ2(l, effs_fold(a + h, n - h));
}

// The list as one effect; the list is left empty.
static RzILOpEffect *effs_take(SimEffs *e) {
	size_t n = rz_pvector_len(&e->v);
	void **a = rz_pvector_data(&e->v);
	RzILOpEffect *r;
	if (!n) {
		r = NOP();
	} else if (n <= 16) {
		r = a[n - 1];
		for (size_t i = n - 1; i-- > 0;) {
			r = SEQ2(a[i], r);
		}
	} else {
		r = effs_fold(a, n);
	}
	rz_pvector_clear(&e->v);
	return r;
}

/* ---- what instructions do ---- */

static bool sim_reg_is(const char *a, const char *b) {
	return a && b && !strcmp(a, b);
}

static bool sim_is_branch(const C6xInsn *insn) {
	switch (insn->id) {
	case C6X_INS_B:
	case C6X_INS_BNOP:
	case C6X_INS_CALLP:
	case C6X_INS_BDEC:
	case C6X_INS_BPOS:
		return true;
	default:
		return false;
	}
}

static bool sim_is_sploop(const C6xInsn *insn) {
	return insn->id == C6X_INS_SPLOOP || insn->id == C6X_INS_SPLOOPD || insn->id == C6X_INS_SPLOOPW;
}

static bool sim_is_loop_insn(const C6xInsn *insn) {
	switch (insn->id) {
	case C6X_INS_SPLOOP:
	case C6X_INS_SPLOOPD:
	case C6X_INS_SPLOOPW:
	case C6X_INS_SPKERNEL:
	case C6X_INS_SPKERNELR:
	case C6X_INS_SPMASK:
	case C6X_INS_SPMASKR:
		return true;
	default:
		return false;
	}
}

// A store names its memory operand last.
static bool sim_is_store(const C6xInsn *insn) {
	return insn->nops && insn->ops[insn->nops - 1].kind == C6X_OP_MEM;
}

// A load names its memory operand first, and a register last.
static bool sim_is_load(const C6xInsn *insn) {
	return insn->nops > 1 && insn->ops[0].kind == C6X_OP_MEM && !sim_is_store(insn);
}

// Whether an addressing mode writes the updated address back to the base.
static bool sim_writes_back(C6xAddrMode m) {
	switch (m) {
	case C6X_AM_PREDEC_CST:
	case C6X_AM_PREINC_CST:
	case C6X_AM_POSTDEC_CST:
	case C6X_AM_POSTINC_CST:
	case C6X_AM_PREDEC_REG:
	case C6X_AM_PREINC_REG:
	case C6X_AM_POSTDEC_REG:
	case C6X_AM_POSTINC_REG:
		return true;
	default:
		return false;
	}
}

// Whether an addressing mode takes its offset from a register.
static bool sim_reg_offset(C6xAddrMode m) {
	switch (m) {
	case C6X_AM_NEG_REG:
	case C6X_AM_POS_REG:
	case C6X_AM_PREDEC_REG:
	case C6X_AM_PREINC_REG:
	case C6X_AM_POSTDEC_REG:
	case C6X_AM_POSTINC_REG:
		return true;
	default:
		return false;
	}
}

// Where CALLP leaves the return address: its second operand, or, for the
// compact form, which has none, A3 or B3 by the side of its unit.
static const char *sim_link_reg(const C6xInsn *insn) {
	if (insn->nops > 1 && insn->ops[1].kind == C6X_OP_REG) {
		return c6x_il_reg_name(insn->ops[1].v.reg.side, insn->ops[1].v.reg.num);
	}
	return c6x_il_reg_name(insn->unit_side, 3);
}

static bool sim_push_write(C6xWrite *out, size_t *n, const char *reg, ut8 delay) {
	if (!reg || *n >= C6X_MAX_WRITES) {
		return false;
	}
	out[*n].reg = reg;
	out[*n].delay = delay;
	(*n)++;
	return true;
}

/**
 * \brief The registers \p insn writes, and the delay slots before each lands.
 *
 * A branch reports what it writes besides the program counter: BDEC its
 * counter and CALLP its return address. A load or store with an updating
 * addressing mode writes its base register back at once. NOPs and the SPLOOP
 * controls write nothing.
 *
 * \return false for a destination shape this does not recognise; the caller
 *         then has to lift the instruction without staging it.
 */
RZ_IPI bool c6x_insn_writes(const C6xInsn *insn, RZ_OUT C6xWrite *out, RZ_OUT size_t *n) {
	rz_return_val_if_fail(insn && out && n, false);
	*n = 0;
	if (insn->is_header || sim_is_loop_insn(insn)) {
		return true;
	}
	switch (insn->id) {
	case C6X_INS_NOP:
	case C6X_INS_IDLE:
	case C6X_INS_FPHEAD:
	case C6X_INS_B:
	case C6X_INS_BNOP:
	case C6X_INS_BPOS:
		return true;
	case C6X_INS_CALLP:
		return sim_push_write(out, n, sim_link_reg(insn), 0);
	case C6X_INS_BDEC:
	case C6X_INS_ADDKPC:
		return insn->nops > 1 && OP(1).kind == C6X_OP_REG &&
			sim_push_write(out, n, c6x_il_reg_name(OP(1).v.reg.side, OP(1).v.reg.num), 0);
	default:
		break;
	}
	if (!insn->nops) {
		return true;
	}
	for (ut8 i = 0; i < insn->nops; i++) {
		const C6xOperand *o = &OP(i);
		if (o->kind == C6X_OP_MEM && sim_writes_back(o->v.mem.mode) &&
			!sim_push_write(out, n, c6x_il_reg_name(o->v.mem.base_side, o->v.mem.base), 0)) {
			return false;
		}
	}
	const C6xOperand *d = &OP(insn->nops - 1);
	switch (d->kind) {
	case C6X_OP_REG:
		return sim_push_write(out, n, c6x_il_reg_name(d->v.reg.side, d->v.reg.num), c6x_write_delay(insn, true));
	case C6X_OP_REGPAIR:
		return sim_push_write(out, n, c6x_il_reg_name(d->v.reg.side, d->v.reg.num), c6x_write_delay(insn, false)) &&
			sim_push_write(out, n, c6x_il_reg_name(d->v.reg.side, d->v.reg.num + 1), c6x_write_delay(insn, true));
	case C6X_OP_REGQUAD:
		for (ut8 k = 0; k < 4; k++) {
			if (!sim_push_write(out, n, c6x_il_reg_name(d->v.reg.side, d->v.reg.num + k), c6x_write_delay(insn, true))) {
				return false;
			}
		}
		return true;
	case C6X_OP_CTRLREG:
		if (!d->v.ctrl || sim_reg_is(d->v.ctrl, "pce1")) {
			return false;
		}
		// a control register the VM does not have is not written at all
		return !c6x_il_reg_bound(d->v.ctrl) || sim_push_write(out, n, d->v.ctrl, c6x_write_delay(insn, true));
	case C6X_OP_MEM:
		return true; // a store writes memory, and at once
	default:
		return false;
	}
}

/**
 * \brief Whether \p insn reads or writes \p reg in any way: as an operand, as
 *        its predicate, in an address, or implicitly.
 */
RZ_IPI bool c6x_insn_mentions(const C6xInsn *insn, const char *reg) {
	rz_return_val_if_fail(insn && reg, false);
	if (sim_reg_is(c6x_pred_reg_name(insn->creg), reg)) {
		return true;
	}
	for (ut8 i = 0; i < insn->nops; i++) {
		const C6xOperand *o = &OP(i);
		switch (o->kind) {
		case C6X_OP_REG:
		case C6X_OP_REGPAIR:
		case C6X_OP_REGQUAD: {
			ut8 width = o->kind == C6X_OP_REG ? 1 : o->kind == C6X_OP_REGPAIR ? 2
											  : 4;
			for (ut8 k = 0; k < width; k++) {
				if (sim_reg_is(c6x_il_reg_name(o->v.reg.side, o->v.reg.num + k), reg)) {
					return true;
				}
			}
			break;
		}
		case C6X_OP_CTRLREG:
			if (sim_reg_is(o->v.ctrl, reg)) {
				return true;
			}
			break;
		case C6X_OP_MEM:
			if (sim_reg_is(c6x_il_reg_name(o->v.mem.base_side, o->v.mem.base), reg) ||
				(sim_reg_offset(o->v.mem.mode) &&
					sim_reg_is(c6x_il_reg_name(o->v.mem.base_side, o->v.mem.off_reg), reg))) {
				return true;
			}
			break;
		default:
			break;
		}
	}
	return insn->id == C6X_INS_CALLP && sim_reg_is(sim_link_reg(insn), reg);
}

/* ---- decoding ---- */

// Decode every slot of the execute packet holding \p addr; false unless all of
// them decode, so that half a packet is never lifted.
static bool sim_decode(const C6xImage *img, ut64 addr, RZ_OUT C6xPacketRef *pkt, RZ_OUT C6xInsn *ins) {
	if (!c6x_packet_at(img->read, img->user, addr, img->big_endian, pkt) || !pkt->n) {
		return false;
	}
	for (size_t i = 0; i < pkt->n; i++) {
		// A compact slot only decodes together with its fetch-packet header,
		// at the end of the fetch packet, so the decoder gets everything from
		// the slot on rather than the slot's own bytes.
		ut8 raw[C6X_FETCH_PACKET_SIZE * 2];
		size_t want = sizeof(raw);
		if (!img->read(img->user, pkt->slots[i].addr, raw, want)) {
			want = C6X_FETCH_PACKET_SIZE;
			if (!img->read(img->user, pkt->slots[i].addr, raw, want)) {
				return false;
			}
		}
		if (!c6x_decode(img->desc, raw, (int)want, pkt->slots[i].addr, img->big_endian, &ins[i]) ||
			ins[i].size != pkt->slots[i].size) {
			return false; // the decoder disagrees with the packet; do not guess
		}
	}
	return true;
}

// Cycles until the next packet issues. One, or more after a multi-cycle NOP,
// the NOPs a BNOP or ADDKPC carries, the five NOPs CALLP inserts, or the four a
// load inserts in a protected compact fetch packet. All of them happen whatever
// the predicates say.
static ut32 sim_packet_cycles(const C6xPacketRef *pkt, const C6xInsn *ins) {
	ut32 cyc = 1;
	for (size_t i = 0; i < pkt->n; i++) {
		const C6xInsn *insn = &ins[i];
		ut32 c = 1;
		switch (insn->id) {
		case C6X_INS_NOP:
			if (insn->nops && OP(0).kind == C6X_OP_IMM && OP(0).v.imm.value > 0) {
				c = (ut32)OP(0).v.imm.value;
			}
			break;
		case C6X_INS_BNOP:
			if (insn->nops > 1 && OP(1).kind == C6X_OP_IMM && OP(1).v.imm.value > 0) {
				c = 1 + (ut32)OP(1).v.imm.value;
			}
			break;
		case C6X_INS_ADDKPC:
			if (insn->nops > 2 && OP(2).kind == C6X_OP_IMM && OP(2).v.imm.value > 0) {
				c = 1 + (ut32)OP(2).v.imm.value;
			}
			break;
		case C6X_INS_CALLP:
			c = SIM_BRANCH_DELAY;
			break;
		default:
			if (pkt->slots[i].prot && sim_is_load(insn)) {
				c = 5;
			}
			break;
		}
		cyc = RZ_MAX(cyc, c);
	}
	return cyc;
}

/* ---- the state of a path ---- */

/** A result issued but not landed yet. */
typedef struct {
	const char *reg; ///< IL global written
	const char *val; ///< local holding the value
	const char *cond; ///< local holding whether it lands, NULL when it always does
	bool neg; ///< it lands when \c cond is false
	ut32 land; ///< cycle at whose end it lands
	ut32 order; ///< issue order, for results landing in the same cycle
} SimHeld;

/** A branch issued but not taken effect yet. */
typedef struct {
	ut32 at; ///< cycle whose packet comes from the target
	const char *cond; ///< local holding whether it is taken, NULL when it always is
	bool neg; ///< it is taken when \c cond is false
	const char *tgt; ///< local holding a register target, or NULL
	ut64 target; ///< the constant target when \c tgt is NULL
} SimBranch;

/** A predicate sampled into a local. */
typedef struct {
	const char *name; ///< the local
	ut8 creg; ///< predicate register sampled; 0 for a compound condition
	bool z; ///< the local holds (reg == 0) rather than (reg != 0)
	ut32 ver; ///< writes to that register seen when it was sampled
	st8 known; ///< the value this path committed to, or -1
} SimLatch;

/** One path through the code: where it stands and what it has in flight. */
typedef struct {
	ut32 cycle; ///< cycle the next packet issues in
	ut64 pc; ///< address of that packet
	SimHeld held[SIM_MAX_HELD];
	size_t nheld;
	SimBranch br[SIM_MAX_BRANCHES];
	size_t nbr;
	SimLatch lat[SIM_MAX_LATCHES];
	size_t nlat;
	ut32 ver[8]; ///< writes seen to each predicate register, by creg code
	ut32 issued; ///< packets issued
	ut32 resolved; ///< branches that took effect
	ut32 order; ///< next issue order
	size_t nh; ///< next free name in sim_held_names
	size_t nq; ///< next free name in sim_pred_names
	size_t nt; ///< next free name in sim_tgt_names
	bool loop; ///< an SPLOOP packet issued, and its loop has yet to run
	C6xInsn loop_insn; ///< the SPLOOP instruction
	ut64 loop_body; ///< address of the first packet of its body
	/// Results still in flight when the SPLOOP packet issued. They land
	/// before the loop runs; sim_loop() checks that nothing tells.
	const char *early[SIM_MAX_HELD];
	ut32 early_at[SIM_MAX_HELD]; ///< cycles after the SPLOOP's at whose end each one lands
	size_t nearly;
} SimPath;

/** The simulation behind one effect, over all its paths. */
typedef struct {
	const C6xImage *img;
	ut64 fallthrough; ///< where the VM goes when the effect does not jump
	ut32 packets; ///< packets issued over all paths
	ut32 forks; ///< forks taken
} Sim;

static RzILOpBool *sim_cond(const char *name, bool neg) {
	return neg ? INV(VARL(name)) : VARL(name);
}

// What \p p knows of a condition: 1 true, 0 false, -1 not known.
static int sim_known(const SimPath *p, const char *cond, bool neg) {
	if (!cond) {
		return 1;
	}
	for (size_t i = 0; i < p->nlat; i++) {
		if (p->lat[i].name == cond) {
			return p->lat[i].known < 0 ? -1 : (p->lat[i].known ^ (int)neg);
		}
	}
	return -1;
}

// Commit \p p to the sample \p cond holding \p value, and drop the branches
// that are then never taken.
static void sim_commit(SimPath *p, const char *cond, bool value) {
	for (size_t i = 0; i < p->nlat; i++) {
		if (p->lat[i].name == cond) {
			p->lat[i].known = value;
		}
	}
	for (size_t i = 0; i < p->nbr;) {
		if (!sim_known(p, p->br[i].cond, p->br[i].neg)) {
			memmove(&p->br[i], &p->br[i + 1], (p->nbr - i - 1) * sizeof(SimBranch));
			p->nbr--;
		} else {
			i++;
		}
	}
}

// Count a write to \p reg, so that a later sample of it is not taken for an
// earlier one.
static void sim_bump(SimPath *p, const char *reg) {
	for (ut8 c = 1; c < 7; c++) {
		if (sim_reg_is(c6x_pred_reg_name(c), reg)) {
			p->ver[c]++;
		}
	}
}

static void sim_bump_all(SimPath *p) {
	for (ut8 c = 1; c < 7; c++) {
		p->ver[c]++;
	}
}

/**
 * Sample the predicate of \p insn into a local now. A sample of the same
 * register with no write to it since is shared, so that branches testing one
 * register are decided together.
 *
 * \param name Receives the local, or NULL when \p insn is unconditional.
 * \param neg Receives whether the predicate holds when the local is false.
 */
static bool sim_sample(SimPath *p, const C6xInsn *insn, SimEffs *e, const char **name, bool *neg) {
	*name = NULL;
	*neg = false;
	ut8 creg = insn->creg & 7;
	const char *reg = c6x_pred_reg_name(creg);
	if (!reg) {
		return true;
	}
	for (size_t i = 0; i < p->nlat; i++) {
		const SimLatch *l = &p->lat[i];
		if (l->creg == creg && l->ver == p->ver[creg]) {
			*name = l->name;
			*neg = l->z != insn->z;
			return true;
		}
	}
	if (p->nq >= RZ_ARRAY_SIZE(sim_pred_names) || p->nlat >= SIM_MAX_LATCHES) {
		return false;
	}
	const char *q = sim_pred_names[p->nq++];
	if (!effs_add(e, SETL(q, insn->z ? IS_ZERO(VARG(reg)) : NON_ZERO(VARG(reg))))) {
		return false;
	}
	p->lat[p->nlat++] = (SimLatch){ q, creg, insn->z, p->ver[creg], -1 };
	*name = q;
	return true;
}

// Sample a compound condition into a fresh local.
static const char *sim_sample_cond(SimPath *p, RzILOpBool *cond, SimEffs *e) {
	if (p->nq >= RZ_ARRAY_SIZE(sim_pred_names) || p->nlat >= SIM_MAX_LATCHES) {
		rz_il_op_pure_free(cond);
		return NULL;
	}
	const char *q = sim_pred_names[p->nq++];
	if (!effs_add(e, SETL(q, cond))) {
		return NULL;
	}
	p->lat[p->nlat++] = (SimLatch){ q, 0, false, 0, -1 };
	return q;
}

// Land held result \p i.
static bool sim_land(SimPath *p, size_t i, SimEffs *e) {
	SimHeld h = p->held[i];
	memmove(&p->held[i], &p->held[i + 1], (p->nheld - i - 1) * sizeof(SimHeld));
	p->nheld--;
	int k = sim_known(p, h.cond, h.neg);
	if (!k) {
		return true; // its instruction did not run
	}
	sim_bump(p, h.reg);
	RzILOpEffect *set = SETG(h.reg, VARL(h.val));
	if (k < 0) {
		set = BRANCH(sim_cond(h.cond, h.neg), set, NOP());
	}
	return effs_add(e, set);
}

// Land every held result due before cycle \p before, in the order they land.
static bool sim_land_before(SimPath *p, ut32 before, SimEffs *e) {
	for (;;) {
		size_t best = SIZE_MAX;
		for (size_t i = 0; i < p->nheld; i++) {
			const SimHeld *h = &p->held[i];
			if (h->land >= before) {
				continue;
			}
			if (best == SIZE_MAX || h->land < p->held[best].land ||
				(h->land == p->held[best].land && h->order < p->held[best].order)) {
				best = i;
			}
		}
		if (best == SIZE_MAX) {
			return true;
		}
		if (!sim_land(p, best, e)) {
			return false;
		}
	}
}

/* ---- staging a packet ---- */

/** One instruction of a packet being staged. */
typedef struct {
	const C6xInsn *insn;
	ut64 addr; ///< where it sits, for pc-relative operands
	RzILOpEffect *body; ///< owned effect to run instead of lifting it, or NULL
	const char *cond; ///< local holding whether it runs, or NULL to test its predicate inline
	bool neg; ///< it runs when \c cond is false
	size_t nw;
	C6xWrite w[C6X_MAX_WRITES];
	bool late[C6X_MAX_WRITES]; ///< lands after the cycle the packet issues in
	const char *cap[C6X_MAX_WRITES]; ///< local the value is captured in, NULL to pick one
} SimSlot;

static void sim_slots_fini(SimSlot *s, size_t n) {
	for (size_t i = 0; i < n; i++) {
		rz_il_op_effect_free(s[i].body);
		s[i].body = NULL;
	}
}

static size_t sim_find(const char *const *regs, size_t n, const char *reg) {
	for (size_t i = 0; i < n; i++) {
		if (sim_reg_is(regs[i], reg)) {
			return i;
		}
	}
	return SIZE_MAX;
}

// What one slot does, against the register state the packet found.
static RzILOpEffect *sim_slot_effect(SimSlot *s) {
	if (s->body) {
		RzILOpEffect *b = s->body;
		s->body = NULL;
		return b;
	}
	if (!s->cond) {
		return c6x_lift(s->insn, s->addr); // the predicate is tested inline
	}
	C6xInsn bare = *s->insn;
	bare.creg = 0;
	bare.z = false;
	RzILOpEffect *eff = c6x_lift(&bare, s->addr);
	return eff ? BRANCH(sim_cond(s->cond, s->neg), eff, NOP()) : NULL;
}

/**
 * Stage a packet. Every slot of an execute packet reads the registers as the
 * packet found them, but RzIL runs the slots one after another, so:
 *
 *     save every register the packet writes
 *     for each slot: restore what earlier slots changed, run it, capture what it wrote
 *     write back what lands now, and restore what only lands later
 *
 * The captures of the late writes go to locals the caller picked, for it to
 * land later. A register written by more than one slot needs every predicated
 * writer to come with a \c cond, so that a writer that does not run leaves the
 * others' value alone. Slots that read memory run before slots that write it,
 * since a load and a store to one address in a packet load the old value
 * (SPRUFE8B 4.2).
 *
 * \return false when a slot cannot be lifted.
 */
static bool sim_stage(SimSlot *slots, size_t n, SimEffs *e) {
	const char *regs[SIM_PK_REGS];
	size_t nregs = 0;
	bool late = false;
	for (size_t i = 0; i < n; i++) {
		for (size_t j = 0; j < slots[i].nw; j++) {
			late |= slots[i].late[j];
			if (sim_find(regs, nregs, slots[i].w[j].reg) != SIZE_MAX) {
				continue;
			}
			if (nregs == SIM_PK_REGS) {
				return false;
			}
			regs[nregs++] = slots[i].w[j].reg;
		}
	}
	bool snap = late || (n > 1 && nregs);
	for (size_t r = 0; snap && r < nregs; r++) {
		if (!effs_add(e, SETL(sim_snap_names[r], VARG(regs[r])))) {
			return false;
		}
	}
	size_t order[SIM_PK_SLOTS];
	size_t no = 0;
	for (size_t i = 0; i < n && no < SIM_PK_SLOTS; i++) {
		if (!sim_is_store(slots[i].insn)) {
			order[no++] = i;
		}
	}
	for (size_t i = 0; i < n && no < SIM_PK_SLOTS; i++) {
		if (sim_is_store(slots[i].insn)) {
			order[no++] = i;
		}
	}
	if (no != n) {
		return false;
	}
	bool dirty[SIM_PK_REGS] = { 0 };
	size_t ncap = 0;
	for (size_t o = 0; o < no; o++) {
		SimSlot *s = &slots[order[o]];
		for (size_t r = 0; snap && r < nregs; r++) {
			if (dirty[r]) {
				dirty[r] = false;
				if (!effs_add(e, SETG(regs[r], VARL(sim_snap_names[r])))) {
					return false;
				}
			}
		}
		if (!effs_add(e, sim_slot_effect(s))) {
			return false;
		}
		for (size_t j = 0; snap && j < s->nw; j++) {
			if (!s->cap[j]) {
				if (ncap == RZ_ARRAY_SIZE(sim_cap_names)) {
					return false;
				}
				s->cap[j] = sim_cap_names[ncap++];
			}
			if (!effs_add(e, SETL(s->cap[j], VARG(s->w[j].reg)))) {
				return false;
			}
			dirty[sim_find(regs, nregs, s->w[j].reg)] = true;
		}
	}
	for (size_t r = 0; snap && r < nregs; r++) {
		size_t writers = 0;
		const char *only = NULL;
		for (size_t i = 0; i < n; i++) {
			for (size_t j = 0; j < slots[i].nw; j++) {
				if (!slots[i].late[j] && sim_reg_is(slots[i].w[j].reg, regs[r])) {
					writers++;
					only = slots[i].cap[j];
				}
			}
		}
		if (writers < 2) {
			// a single writer captured the old value if it did not run
			if (!effs_add(e, SETG(regs[r], VARL(writers ? only : sim_snap_names[r])))) {
				return false;
			}
			continue;
		}
		if (!effs_add(e, SETG(regs[r], VARL(sim_snap_names[r])))) {
			return false;
		}
		for (size_t i = 0; i < n; i++) {
			for (size_t j = 0; j < slots[i].nw; j++) {
				if (slots[i].late[j] || !sim_reg_is(slots[i].w[j].reg, regs[r])) {
					continue;
				}
				RzILOpEffect *set = SETG(regs[r], VARL(slots[i].cap[j]));
				if (slots[i].cond) {
					set = BRANCH(sim_cond(slots[i].cond, slots[i].neg), set, NOP());
				}
				if (!effs_add(e, set)) {
					return false;
				}
			}
		}
	}
	return true;
}

/* ---- issuing a packet ---- */

// Could anything tell a write of \p reg landing at the end of cycle \p land
// from one landing when the packet issued in cycle \p t ends? Something can
// when a packet issuing in between mentions the register, when another slot of
// the packet writes it too, or when a branch takes effect first: the code it
// reaches is not looked at. The scan gives up on a packet it cannot decode or
// on the SPLOOP controls, and lets the write land at once.
static bool sim_observed(Sim *sim, const SimPath *p, const C6xPacketRef *pkt, const C6xInsn *ins,
	const C6xInsn *self, const char *reg, ut32 t, ut32 cyc, ut32 land) {
	for (size_t i = 0; i < pkt->n; i++) {
		const C6xInsn *insn = &ins[i];
		if (insn == self) {
			continue;
		}
		if (sim_is_branch(insn) && t + SIM_BRANCH_DELAY <= land) {
			return true;
		}
		C6xWrite w[C6X_MAX_WRITES];
		size_t n = 0;
		if (!c6x_insn_writes(insn, w, &n)) {
			return true;
		}
		for (size_t j = 0; j < n; j++) {
			if (sim_reg_is(w[j].reg, reg)) {
				return true;
			}
		}
	}
	for (size_t i = 0; i < p->nbr; i++) {
		if (p->br[i].at <= land) {
			return true;
		}
	}
	ut64 at = pkt->next;
	for (ut32 c = t + cyc; c <= land;) {
		C6xPacketRef q;
		C6xInsn qi[C6X_FP_SLOTS];
		if (!sim_decode(sim->img, at, &q, qi)) {
			return false;
		}
		for (size_t i = 0; i < q.n; i++) {
			if (sim_is_loop_insn(&qi[i])) {
				return false;
			}
			if (c6x_insn_mentions(&qi[i], reg) ||
				(sim_is_branch(&qi[i]) && c + SIM_BRANCH_DELAY <= land)) {
				return true;
			}
		}
		c += sim_packet_cycles(&q, qi);
		at = q.next;
	}
	return false;
}

// Record a branch issuing now. Its condition and a register target are read
// now, and the packet it reaches issues SIM_BRANCH_DELAY cycles on. The count
// BDEC decrements and the return address CALLP leaves are register writes of
// the packet, so they come back in \p s to be staged with the rest.
static bool sim_issue_branch(SimPath *p, const C6xPacketRef *pkt, size_t i, const C6xInsn *insn,
	SimSlot *s, SimEffs *e) {
	if (p->nbr == SIM_MAX_BRANCHES) {
		return false;
	}
	SimBranch b = { .at = p->cycle + SIM_BRANCH_DELAY };
	ut64 addr = pkt->slots[i].addr;
	if (insn->id == C6X_INS_BDEC || insn->id == C6X_INS_BPOS) {
		// taken while the counter is not negative, and BDEC then counts it down
		if (insn->nops < 2 || OP(1).kind != C6X_OP_REG) {
			return false;
		}
		const char *cnt = c6x_il_reg_name(OP(1).v.reg.side, OP(1).v.reg.num);
		RzILOpBool *cond = SGE(VARG(cnt), S32(0));
		RzILOpBool *pred = c6x_il_pred_cond(insn);
		b.cond = sim_sample_cond(p, pred ? AND(pred, cond) : cond, e);
		if (!b.cond) {
			return false;
		}
		if (insn->id == C6X_INS_BDEC) {
			s->insn = insn;
			s->addr = addr;
			s->cond = b.cond;
			sim_push_write(s->w, &s->nw, cnt, 0);
			s->body = BRANCH(VARL(b.cond), SETG(cnt, SUB(VARG(cnt), U32(1))), NOP());
		}
	} else if (!sim_sample(p, insn, e, &b.cond, &b.neg)) {
		return false;
	}
	const C6xOperand *t = &OP(0);
	if (t->kind == C6X_OP_PCREL) {
		b.target = c6x_packet_base(addr) + t->v.imm.value;
	} else if (t->kind == C6X_OP_REG || t->kind == C6X_OP_CTRLREG) {
		const char *reg = t->kind == C6X_OP_REG ? c6x_il_reg_name(t->v.reg.side, t->v.reg.num) : t->v.ctrl;
		if (!c6x_il_reg_bound(reg) || p->nt == RZ_ARRAY_SIZE(sim_tgt_names)) {
			return false;
		}
		b.tgt = sim_tgt_names[p->nt++];
		if (!effs_add(e, SETL(b.tgt, VARG(reg)))) {
			return false;
		}
	} else {
		return false;
	}
	if (insn->id == C6X_INS_CALLP) {
		// the callee returns to the execute packet after this one
		const char *link = sim_link_reg(insn);
		s->insn = insn;
		s->addr = addr;
		sim_push_write(s->w, &s->nw, link, 0);
		s->body = SETG(link, U32((ut32)pkt->next));
	}
	p->br[p->nbr++] = b;
	return true;
}

// Issue the packet \p pkt on \p p in its current cycle. The SPLOOP controls in
// it are left to the caller.
static bool sim_issue(Sim *sim, SimPath *p, const C6xPacketRef *pkt, const C6xInsn *ins, SimEffs *e) {
	ut32 t = p->cycle;
	ut32 cyc = sim_packet_cycles(pkt, ins);
	SimSlot slots[SIM_PK_SLOTS];
	memset(slots, 0, sizeof(slots));
	size_t ns = 0;
	size_t seq[C6X_FP_SLOTS];
	size_t nseq = 0;
	bool ok = false;
	for (size_t i = 0; i < pkt->n; i++) {
		const C6xInsn *insn = &ins[i];
		if (insn->is_header || insn->id == C6X_INS_NOP || insn->id == C6X_INS_IDLE ||
			sim_is_loop_insn(insn)) {
			continue;
		}
		SimSlot *s = &slots[ns];
		if (sim_is_branch(insn)) {
			if (!sim_issue_branch(p, pkt, i, insn, s, e)) {
				goto out;
			}
			ns += s->insn != NULL;
			continue;
		}
		if (!c6x_insn_writes(insn, s->w, &s->nw)) {
			// a shape that cannot be staged runs after the rest
			s->nw = 0;
			seq[nseq++] = i;
			continue;
		}
		s->insn = insn;
		s->addr = pkt->slots[i].addr;
		ns++;
	}
	// a result is held when something could see it land late
	size_t nlate = 0;
	for (size_t i = 0; i < ns; i++) {
		SimSlot *s = &slots[i];
		for (size_t j = 0; j < s->nw; j++) {
			s->late[j] = s->w[j].delay &&
				sim_observed(sim, p, pkt, ins, s->insn, s->w[j].reg, t, cyc, t + s->w[j].delay);
			nlate += s->late[j];
		}
	}
	if (p->nheld + nlate > SIM_MAX_HELD || p->nh + nlate > RZ_ARRAY_SIZE(sim_held_names)) {
		goto out;
	}
	// A predicated slot whose result lands late, or which shares its
	// destination with another slot, has its predicate sampled now.
	for (size_t i = 0; i < ns; i++) {
		SimSlot *s = &slots[i];
		if (s->cond || !s->insn->creg) {
			continue;
		}
		bool need = false;
		for (size_t j = 0; j < s->nw; j++) {
			need |= s->late[j];
			for (size_t k = 0; k < ns && !need; k++) {
				for (size_t m = 0; k != i && m < slots[k].nw; m++) {
					need |= sim_reg_is(slots[k].w[m].reg, s->w[j].reg);
				}
			}
		}
		if (need && !sim_sample(p, s->insn, e, &s->cond, &s->neg)) {
			goto out;
		}
	}
	for (size_t i = 0; i < ns; i++) {
		for (size_t j = 0; j < slots[i].nw; j++) {
			if (slots[i].late[j]) {
				slots[i].cap[j] = sim_held_names[p->nh++];
			}
		}
	}
	if (!sim_stage(slots, ns, e)) {
		goto out;
	}
	for (size_t i = 0; i < ns; i++) {
		SimSlot *s = &slots[i];
		for (size_t j = 0; j < s->nw; j++) {
			if (!s->late[j]) {
				sim_bump(p, s->w[j].reg);
				continue;
			}
			p->held[p->nheld++] = (SimHeld){
				.reg = s->w[j].reg,
				.val = s->cap[j],
				.cond = s->cond,
				.neg = s->neg,
				.land = t + s->w[j].delay,
				.order = p->order++,
			};
		}
	}
	for (size_t k = 0; k < nseq; k++) {
		if (!effs_add(e, c6x_lift(&ins[seq[k]], pkt->slots[seq[k]].addr))) {
			goto out;
		}
		sim_bump_all(p);
	}
	ok = true;
out:
	sim_slots_fini(slots, RZ_ARRAY_SIZE(slots));
	return ok;
}

// Move on to the cycle the next packet issues in: after this packet's cycles,
// or sooner when a branch takes effect, which cuts a multi-cycle NOP short.
// What lands on the way lands.
static bool sim_advance(SimPath *p, ut32 cyc, ut64 next, SimEffs *e) {
	ut32 nc = p->cycle + cyc;
	for (size_t i = 0; i < p->nbr; i++) {
		if (p->br[i].at > p->cycle && p->br[i].at < nc) {
			nc = p->br[i].at;
		}
	}
	if (!sim_land_before(p, nc, e)) {
		return false;
	}
	p->cycle = nc;
	p->pc = next;
	return true;
}

/* ---- the SPLOOP buffer ---- */

/** One instruction of a loop body. */
typedef struct {
	C6xInsn insn;
	ut64 addr;
	bool masked; ///< SPMASKed: runs from program memory, in the first iteration only
	size_t nw;
	C6xWrite w[C6X_MAX_WRITES];
	size_t wid[C6X_MAX_WRITES]; ///< its entry in the loop's late writes, or SIZE_MAX
} SimLoopSlot;

/**
 * A result of the loop body that lands in a later cycle. It is issued once per
 * block, so the values in flight form a shift register: generation g holds the
 * one issued g blocks ago, and the last generation lands.
 */
typedef struct {
	const char *reg;
	ut32 gens; ///< blocks from issue to landing, plus one
	ut32 lc; ///< cycle of the block at whose end it lands
	const char *val[SIM_LOOP_GENS];
	const char *pred[SIM_LOOP_GENS]; ///< whether that value lands
} SimLoopWrite;

/** A loop body, read out of program memory. */
typedef struct {
	C6xInsnId kind; ///< SPLOOP, SPLOOPD or SPLOOPW
	ut32 ii; ///< iteration interval: cycles from one iteration start to the next
	ut32 len; ///< cycles one iteration takes
	ut32 stages; ///< blocks of ii cycles one iteration spans
	ut8 creg; ///< SPLOOPW: the predicate ending the loop
	bool z;
	ut64 post; ///< where execution goes on after the loop
	ut32 kfield; ///< SPKERNEL's fstg/fcyc field
	bool kfield_ok; ///< SPKERNEL had that field
	SimLoopSlot slot[SIM_LOOP_LEN][SIM_LOOP_SLOTS];
	ut8 nslot[SIM_LOOP_LEN];
	SimLoopWrite w[SIM_LOOP_WRITES];
	size_t nw;
} SimLoop;

/** Which part of the loop a block belongs to. */
typedef enum {
	SIM_PROLOG, ///< blocks 0 to stages - 1, unrolled
	SIM_KERNEL, ///< blocks with every stage running, repeated
	SIM_EPILOG, ///< blocks after the last iteration started
} SimPhase;

// SPMASK's bit for the unit of \p insn, or -1.
static int sim_unit_bit(const C6xInsn *insn) {
	int u;
	switch (insn->unit) {
	case C6X_UNIT_L: u = 0; break;
	case C6X_UNIT_S: u = 2; break;
	case C6X_UNIT_D: u = 4; break;
	case C6X_UNIT_M: u = 6; break;
	default: return -1;
	}
	return u + (insn->unit_side & 1);
}

// Read the loop body: the packets from \p at up to the one holding SPKERNEL, by
// the cycle each issues in. A multi-cycle NOP, or a load in a protected compact
// fetch packet, leaves cycles with nothing to buffer, and SPMASKed instructions
// are not buffered but run once. A branch in the body, a nested loop or the
// reload forms are not modelled.
static bool sim_loop_body(Sim *sim, SimLoop *L, ut64 at) {
	for (ut32 r = 0; r < SIM_LOOP_LEN;) {
		C6xPacketRef q;
		C6xInsn qi[C6X_FP_SLOTS];
		if (!sim_decode(sim->img, at, &q, qi)) {
			return false;
		}
		ut8 mask = 0;
		bool kernel = false;
		for (size_t i = 0; i < q.n; i++) {
			const C6xInsn *insn = &qi[i];
			if (insn->id == C6X_INS_SPMASK) {
				mask |= insn->nops && OP(0).kind == C6X_OP_UNITMASK ? OP(0).v.units : 0;
			} else if (insn->id == C6X_INS_SPKERNEL) {
				kernel = true;
				L->kfield_ok = insn->nops && OP(0).kind == C6X_OP_IMM;
				L->kfield = L->kfield_ok ? (ut32)OP(0).v.imm.value : 0;
			} else if (sim_is_loop_insn(insn) || sim_is_branch(insn)) {
				return false;
			}
		}
		for (size_t i = 0; i < q.n; i++) {
			const C6xInsn *insn = &qi[i];
			if (insn->is_header || insn->id == C6X_INS_NOP || insn->id == C6X_INS_IDLE ||
				sim_is_loop_insn(insn)) {
				continue;
			}
			if (L->nslot[r] == SIM_LOOP_SLOTS) {
				return false;
			}
			SimLoopSlot *s = &L->slot[r][L->nslot[r]++];
			s->insn = *insn;
			s->addr = q.slots[i].addr;
			int bit = sim_unit_bit(insn);
			s->masked = bit >= 0 && (mask & (1u << bit));
			if (!c6x_insn_writes(insn, s->w, &s->nw)) {
				return false;
			}
		}
		if (kernel) {
			L->len = r + 1;
			L->post = q.next;
			return true;
		}
		r += sim_packet_cycles(&q, qi);
		at = q.next;
	}
	return false;
}

// Give every late write of the body its shift register.
static bool sim_loop_writes(SimLoop *L) {
	size_t nval = 0, npred = 0;
	for (ut32 o = 0; o < L->len; o++) {
		for (ut8 j = 0; j < L->nslot[o]; j++) {
			SimLoopSlot *s = &L->slot[o][j];
			for (size_t k = 0; k < s->nw; k++) {
				s->wid[k] = SIZE_MAX;
				if (!s->w[k].delay) {
					continue;
				}
				ut32 c = o % L->ii;
				ut32 gens = (c + s->w[k].delay) / L->ii + 1;
				if (L->nw == SIM_LOOP_WRITES || gens > SIM_LOOP_GENS ||
					nval + gens > RZ_ARRAY_SIZE(sim_loop_val_names) ||
					npred + gens > RZ_ARRAY_SIZE(sim_loop_pred_names)) {
					return false;
				}
				SimLoopWrite *w = &L->w[L->nw];
				w->reg = s->w[k].reg;
				w->gens = gens;
				w->lc = (c + s->w[k].delay) % L->ii;
				for (ut32 g = 0; g < gens; g++) {
					w->val[g] = sim_loop_val_names[nval++];
					w->pred[g] = sim_loop_pred_names[npred++];
				}
				s->wid[k] = L->nw++;
			}
		}
	}
	return true;
}

// Issue cycle \p c of block \p b -- a static block number in the prolog only:
// every stage whose body offset falls in it, staged as one packet, then the late
// writes landing at its end.
static bool sim_loop_cycle(SimLoop *L, SimPhase ph, ut32 b, ut32 c, SimEffs *e) {
	if (L->kind == C6X_INS_SPLOOPW && ph != SIM_EPILOG) {
		// the stage boundary tests the predicate as it was three cycles back
		const char *reg = c6x_pred_reg_name(L->creg);
		if (!effs_add(e, SETL(SIM_SPH3, VARL(SIM_SPH2))) ||
			!effs_add(e, SETL(SIM_SPH2, VARL(SIM_SPH1))) ||
			!effs_add(e, SETL(SIM_SPH1, VARL(SIM_SPH0))) ||
			!effs_add(e, SETL(SIM_SPH0, L->z ? IS_ZERO(VARG(reg)) : NON_ZERO(VARG(reg))))) {
			return false;
		}
	}
	SimSlot slots[SIM_PK_SLOTS];
	memset(slots, 0, sizeof(slots));
	size_t ns = 0, ng = 0;
	for (ut32 s = 0; s < L->stages; s++) {
		ut32 o = s * L->ii + c;
		st64 k = ph == SIM_PROLOG ? (st64)b - (st64)s : 1;
		if (o >= L->len || k < 0) {
			continue;
		}
		for (ut8 j = 0; j < L->nslot[o]; j++) {
			SimLoopSlot *ls = &L->slot[o][j];
			// whether iteration k exists, or for a masked instruction, that it
			// is the first one
			RzILOpBool *guard = NULL;
			if (ls->masked) {
				if (ph != SIM_PROLOG || k) {
					continue;
				}
			} else if (ph == SIM_PROLOG) {
				if (k) {
					guard = SLE(S32((st32)k), VARL(SIM_SPL));
				} else if (L->kind == C6X_INS_SPLOOP) {
					guard = SGE(VARL(SIM_SPL), S32(0)); // ILC was not zero
				}
				if ((ut64)b * L->ii + c >= L->len) {
					// past the first iteration, an abrupt exit has dropped it
					RzILOpBool *live = INV(VARL(SIM_SPA));
					guard = guard ? AND(guard, live) : live;
				}
			} else if (ph == SIM_EPILOG) {
				guard = SLE(SUB(VARL(SIM_SPB), U32(s)), VARL(SIM_SPL));
			}
			RzILOpBool *pred = c6x_il_pred_cond(&ls->insn);
			RzILOpBool *cond = guard && pred ? AND(guard, pred) : guard ? guard
										    : pred;
			if (ns == SIM_PK_SLOTS || (cond && ng == RZ_ARRAY_SIZE(sim_guard_names))) {
				rz_il_op_pure_free(cond);
				return false;
			}
			SimSlot *x = &slots[ns++];
			x->insn = &ls->insn;
			x->addr = ls->addr;
			x->nw = ls->nw;
			memcpy(x->w, ls->w, sizeof(x->w));
			if (cond) {
				x->cond = sim_guard_names[ng++];
				if (!effs_add(e, SETL(x->cond, cond))) {
					return false;
				}
			}
			for (size_t m = 0; m < x->nw; m++) {
				x->late[m] = ls->wid[m] != SIZE_MAX;
				x->cap[m] = x->late[m] ? L->w[ls->wid[m]].val[0] : NULL;
			}
			for (size_t m = 0; m < x->nw; m++) {
				if (x->late[m] &&
					!effs_add(e, SETL(L->w[ls->wid[m]].pred[0], x->cond ? VARL(x->cond) : IL_TRUE))) {
					return false;
				}
			}
		}
	}
	if (ns && !sim_stage(slots, ns, e)) {
		sim_slots_fini(slots, ns);
		return false;
	}
	// land what is due at the end of this cycle, the longest in flight first
	for (ut32 gens = SIM_LOOP_GENS; gens > 0; gens--) {
		for (size_t i = 0; i < L->nw; i++) {
			SimLoopWrite *w = &L->w[i];
			if (w->gens != gens || w->lc != c) {
				continue;
			}
			const char *val = w->val[gens - 1], *pred = w->pred[gens - 1];
			if (!effs_add(e, BRANCH(VARL(pred), SETG(w->reg, VARL(val)), NOP())) ||
				!effs_add(e, SETL(pred, IL_FALSE))) {
				return false;
			}
		}
	}
	return true;
}

// Whether the next iteration starts, decided at the end of block \p b (static
// in the prolog only). SPLOOPD and SPLOOPW start the iterations beginning in
// the first three cycles without a test. SPLOOPW stops at once, dropping the
// iterations in flight, when its predicate was false three cycles earlier;
// SPLOOP and SPLOOPD stop starting iterations when ILC is zero, and count ILC
// down otherwise.
static bool sim_loop_boundary(SimLoop *L, SimPhase ph, ut32 b, SimEffs *e) {
	bool early_static = false;
	RzILOpBool *early = NULL;
	if (L->kind != C6X_INS_SPLOOP) {
		if (ph == SIM_PROLOG) {
			early_static = (b + 1) * L->ii <= 3;
		} else if ((L->stages + 1) * L->ii <= 3) {
			early = ULE(MUL(ADD(VARL(SIM_SPB), U32(1)), U32(L->ii)), U32(3));
		}
	}
#define SIM_NEXT SETL(SIM_SPL, ADD(VARL(SIM_SPB), U32(1)))
	RzILOpEffect *test;
	if (early_static) {
		test = SIM_NEXT;
	} else if (L->kind == C6X_INS_SPLOOPW) {
		RzILOpBool *stop = INV(VARL(SIM_SPH3));
		if (early) {
			stop = AND(INV(early), stop);
		}
		test = BRANCH(stop, SEQ2(SETL(SIM_SPA, IL_TRUE), SETL(SIM_SPT, IL_TRUE)), SIM_NEXT);
	} else {
		test = BRANCH(IS_ZERO(VARG("ilc")), SETL(SIM_SPT, IL_TRUE),
			SEQ2(SETG("ilc", SUB(VARG("ilc"), U32(1))), SIM_NEXT));
		if (early) {
			test = BRANCH(early, SIM_NEXT, test);
		}
	}
#undef SIM_NEXT
	return effs_add(e, BRANCH(AND(INV(VARL(SIM_SPT)), INV(VARL(SIM_SPA))), test, NOP()));
}

// Run one block of ii cycles, then the stage boundary, and move the shift
// registers on.
static bool sim_loop_block(SimLoop *L, SimPhase ph, ut32 b, SimEffs *e) {
	for (ut32 c = 0; c < L->ii; c++) {
		if (!sim_loop_cycle(L, ph, b, c, e)) {
			return false;
		}
	}
	if (ph != SIM_EPILOG && !sim_loop_boundary(L, ph, b, e)) {
		return false;
	}
	if (!effs_add(e, SETL(SIM_SPB, ADD(VARL(SIM_SPB), U32(1))))) {
		return false;
	}
	for (size_t i = 0; i < L->nw; i++) {
		SimLoopWrite *w = &L->w[i];
		for (ut32 g = w->gens - 1; g > 0; g--) {
			if (!effs_add(e, SETL(w->val[g], VARL(w->val[g - 1]))) ||
				!effs_add(e, SETL(w->pred[g], VARL(w->pred[g - 1])))) {
				return false;
			}
		}
		if (w->gens > 1 && !effs_add(e, SETL(w->pred[0], IL_FALSE))) {
			return false;
		}
	}
	return true;
}

// Cycles from the last kernel stage boundary until program memory fetch comes
// back, from SPKERNEL's fstg/fcyc field (SPRU732H 7.9.4): fcyc takes as many
// low bits as ii needs, fstg the rest, its most significant bit lowest, and
// the delay is fstg * ii + fcyc. 0, the earliest, when it cannot be told.
static ut32 sim_loop_fetch_delay(const SimLoop *L) {
	ut32 fcyc_bits;
	if (!L->kfield_ok) {
		return 0;
	} else if (L->ii <= 1) {
		fcyc_bits = 0;
	} else if (L->ii <= 2) {
		fcyc_bits = 1;
	} else if (L->ii <= 4) {
		fcyc_bits = 2;
	} else if (L->ii <= 8) {
		fcyc_bits = 3;
	} else if (L->ii <= 14) {
		fcyc_bits = 4;
	} else {
		return 0;
	}
	ut32 fstg = 0;
	for (ut32 i = fcyc_bits; i < 6; i++) {
		fstg = (fstg << 1) | ((L->kfield >> i) & 1);
	}
	return fstg * L->ii + (L->kfield & ((1u << fcyc_bits) - 1));
}

// Whether \p insn writes control registers it names nowhere.
static bool sim_writes_implicit(const C6xInsn *insn, const char **regs, size_t *n) {
	*n = 0;
	if (insn->id == C6X_INS_DINT || insn->id == C6X_INS_RINT) {
		regs[(*n)++] = "tsr";
		regs[(*n)++] = "csr";
	}
	return *n > 0;
}

/**
 * Whether the results in flight when the SPLOOP packet issued can land before
 * the loop runs, as sim_run() lands them. One landing at the end of the cycle
 * \c early_at cycles after the SPLOOP's is seen from loop cycle \c early_at
 * on, while slot o of the body issues at loop cycle o at the soonest, in the
 * first iteration; so no slot before that may touch it. SPLOOPW samples its
 * predicate from the start. SPLOOP tests ILC in its own cycle, so a count
 * must be in by then; SPLOOPD reads it at no stage boundary in its first
 * three cycles, so a count written in parallel with it, which lands at the
 * end of the third, is in time.
 *
 * \param at Receives the loop cycle from which they have all landed.
 */
static bool sim_loop_entry_ok(const SimLoop *L, const SimPath *p, ut32 *at) {
	*at = 0;
	for (size_t i = 0; i < p->nearly; i++) {
		const char *reg = p->early[i];
		ut32 when = p->early_at[i];
		if (sim_reg_is(reg, "ilc") && L->kind != C6X_INS_SPLOOPW) {
			if (L->kind == C6X_INS_SPLOOP || when > 3) {
				return false;
			}
			continue;
		}
		if (!when) {
			continue; // lands at the end of the SPLOOP's cycle, in time
		}
		if (L->kind == C6X_INS_SPLOOPW && sim_reg_is(reg, c6x_pred_reg_name(L->creg))) {
			return false;
		}
		for (ut32 o = 0; o < when && o < L->len; o++) {
			for (ut8 j = 0; j < L->nslot[o]; j++) {
				if (c6x_insn_mentions(&L->slot[o][j].insn, reg)) {
					return false;
				}
			}
		}
		*at = RZ_MAX(*at, when);
	}
	return true;
}

// When slot \p o of the body issues for the last time: in the last iteration,
// counting from its start, or for SPLOOPW, which stops at a stage boundary, in
// the last block, counting from the start of that block.
static ut32 sim_loop_last_issue(const SimLoop *L, ut32 o) {
	return L->kind == C6X_INS_SPLOOPW ? o % L->ii : o;
}

/**
 * Whether the code after the loop can run after it, as the loop is lifted:
 * once the last iteration has issued and its results have landed.
 *
 * On the hardware that code starts sooner (SPRU732H 7.9.4). Program memory
 * fetch comes back fstg * ii + fcyc cycles after the last kernel stage
 * boundary, or once the loop buffer goes idle, so the first packets after the
 * loop issue beside the rest of the epilog, and beside the loop's results that
 * have still to land. SPLOOPW has no epilog, but what it issued before it
 * stopped lands late as well. Counting from where sim_loop_last_issue() does,
 * the code after the loop starts at ii plus that delay, or later when the
 * loop ran fewer iterations than it has stages. Every packet of it that issues
 * before the loop is done has to see what it would see after the loop:
 *
 *   - it touches no register before the loop's last write to it has landed;
 *   - the loop reads no register after the packet's write to it has landed;
 *   - it reaches memory only after the loop's last store, or for a store,
 *     after the loop's last load or store;
 *   - it starts no loop, and no branch of it takes effect while the loop is
 *     still running.
 *
 * Otherwise the code is not lifted.
 *
 * \param early Cycles after the loop starts by which the results from before
 *              it, which sim_run() landed at its start, have landed.
 */
static bool sim_loop_exit_ok(Sim *sim, const SimLoop *L, const SimPath *p, ut32 early) {
	ut32 epilog = L->kind == C6X_INS_SPLOOPW || L->len <= L->ii ? 0 : L->len - L->ii;
	ut32 start = L->ii + RZ_MIN(sim_loop_fetch_delay(L), epilog);
	// the first cycle with nothing of the loop left to issue or land
	ut32 end = early;
	for (ut32 o = 0; o < L->len; o++) {
		for (ut8 j = 0; j < L->nslot[o]; j++) {
			const SimLoopSlot *s = &L->slot[o][j];
			ut32 t = sim_loop_last_issue(L, o);
			end = RZ_MAX(end, t + 1);
			for (size_t k = 0; k < s->nw; k++) {
				end = RZ_MAX(end, t + s->w[k].delay + 1);
			}
		}
	}
	ut64 at = L->post;
	for (ut32 t = start; t < end;) {
		C6xPacketRef q;
		C6xInsn qi[C6X_FP_SLOTS];
		if (!sim_decode(sim->img, at, &q, qi) || q.addr != at) {
			return false;
		}
		for (size_t i = 0; i < q.n; i++) {
			const C6xInsn *insn = &qi[i];
			if (insn->is_header || insn->id == C6X_INS_NOP) {
				continue;
			}
			if (sim_is_loop_insn(insn) || (sim_is_branch(insn) && t + SIM_BRANCH_DELAY < end)) {
				return false;
			}
			C6xWrite w[C6X_MAX_WRITES + 2];
			size_t nw;
			if (!c6x_insn_writes(insn, w, &nw)) {
				return false;
			}
			const char *imp[2];
			size_t nimp;
			if (sim_writes_implicit(insn, imp, &nimp)) {
				for (size_t k = 0; k < nimp; k++) {
					w[nw++] = (C6xWrite){ .reg = imp[k], .delay = 0 };
				}
			}
			bool st = sim_is_store(insn), mem = st || sim_is_load(insn);
			for (ut32 o = 0; o < L->len; o++) {
				for (ut8 j = 0; j < L->nslot[o]; j++) {
					const SimLoopSlot *s = &L->slot[o][j];
					ut32 ts = sim_loop_last_issue(L, o);
					if (mem && ts >= t && (sim_is_store(&s->insn) || (st && sim_is_load(&s->insn)))) {
						return false;
					}
					for (size_t k = 0; k < s->nw; k++) {
						if (ts + s->w[k].delay >= t && c6x_insn_mentions(insn, s->w[k].reg)) {
							return false;
						}
					}
					for (size_t k = 0; k < nw; k++) {
						if (ts > t + w[k].delay && c6x_insn_mentions(&s->insn, w[k].reg)) {
							return false;
						}
					}
				}
			}
			for (size_t k = 0; k < p->nearly; k++) {
				if (p->early_at[k] > t && c6x_insn_mentions(insn, p->early[k])) {
					return false;
				}
			}
		}
		t += sim_packet_cycles(&q, qi);
		at = q.next;
	}
	return true;
}

/**
 * Run the SPLOOP whose instruction \p sploop issued in the cycle before p's.
 *
 * The loop buffer (SPRUFE8B chapter 8) starts iteration k at cycle k * ii of
 * the loop, and an iteration runs the body, len cycles long, from there. Cut
 * into blocks of ii cycles, block b runs stage s of iteration b - s for every
 * stage s that iteration has. Which iterations exist is only known when the
 * loop runs -- ILC or the SPLOOPW predicate decide at every block end whether
 * the next one starts -- so the loop lifts as:
 *
 *     prolog:  blocks 0 .. stages-1, unrolled; each instruction runs when its
 *              iteration exists, i.e. was started and not dropped
 *     kernel:  repeat while iterations still start: a block running every stage
 *     epilog:  stages-1 blocks, each instruction guarded likewise, unless the
 *              loop stopped abruptly
 *
 * with the stage boundary at the end of every block before the epilog. The
 * first iteration issues from program memory, which is where the SPMASKed
 * instructions run, once. A result landing in a later cycle goes through a
 * shift register of locals, the same in every block, and lands from the last
 * one; what is in flight when the loop ends lands at its end. The code after
 * the loop then runs after it, although on the hardware its first packets
 * overlap the epilog and the results still landing; sim_loop_exit_ok() makes
 * sure they cannot tell the difference. Likewise, what was in flight when the
 * loop started has landed by then (sim_loop_entry_ok()).
 */
static bool sim_loop(Sim *sim, SimPath *p, const C6xInsn *sploop, ut64 body, SimEffs *e) {
	if (sploop->nops < 1 || sploop->ops[0].kind != C6X_OP_IMM || sploop->ops[0].v.imm.value < 1) {
		return false;
	}
	SimLoop *L = RZ_NEW0(SimLoop);
	if (!L) {
		return false;
	}
	L->kind = sploop->id;
	L->ii = (ut32)sploop->ops[0].v.imm.value;
	L->creg = sploop->creg & 7;
	L->z = sploop->z;
	bool ok = false;
	if (!sim_loop_body(sim, L, body) || !sim_loop_writes(L) ||
		(L->kind == C6X_INS_SPLOOPW && !c6x_pred_reg_name(L->creg))) {
		goto out;
	}
	L->stages = (L->len + L->ii - 1) / L->ii;
	ut32 early;
	if (!sim_loop_entry_ok(L, p, &early) || !sim_loop_exit_ok(sim, L, p, early)) {
		goto out;
	}
	// starting state
	if (!effs_add(e, SETL(SIM_SPB, U32(0))) || !effs_add(e, SETL(SIM_SPA, IL_FALSE))) {
		goto out;
	}
	if (L->kind == C6X_INS_SPLOOP) {
		// with ILC zero no iteration starts; otherwise the first one counts
		if (!effs_add(e, BRANCH(IS_ZERO(VARG("ilc")), SEQ2(SETL(SIM_SPT, IL_TRUE), SETL(SIM_SPL, S32(-1))), SEQ3(SETG("ilc", SUB(VARG("ilc"), U32(1))), SETL(SIM_SPT, IL_FALSE), SETL(SIM_SPL, U32(0)))))) {
			goto out;
		}
	} else if (!effs_add(e, SETL(SIM_SPT, IL_FALSE)) || !effs_add(e, SETL(SIM_SPL, U32(0)))) {
		goto out;
	}
	if (L->kind == C6X_INS_SPLOOPW) {
		const char *h[] = { SIM_SPH0, SIM_SPH1, SIM_SPH2, SIM_SPH3 };
		for (size_t i = 0; i < RZ_ARRAY_SIZE(h); i++) {
			if (!effs_add(e, SETL(h[i], IL_FALSE))) {
				goto out;
			}
		}
	}
	for (size_t i = 0; i < L->nw; i++) {
		for (ut32 g = 0; g < L->w[i].gens; g++) {
			if (!effs_add(e, SETL(L->w[i].val[g], U32(0))) || !effs_add(e, SETL(L->w[i].pred[g], IL_FALSE))) {
				goto out;
			}
		}
	}
	for (ut32 b = 0; b < L->stages; b++) {
		if (!sim_loop_block(L, SIM_PROLOG, b, e)) {
			goto out;
		}
	}
	SimEffs k;
	effs_init(&k);
	if (!sim_loop_block(L, SIM_KERNEL, 0, &k)) {
		effs_fini(&k);
		goto out;
	}
	if (!effs_add(e, REPEAT(AND(INV(VARL(SIM_SPT)), INV(VARL(SIM_SPA))), effs_take(&k)))) {
		effs_fini(&k);
		goto out;
	}
	effs_fini(&k);
	if (L->stages > 1) {
		SimEffs ep;
		effs_init(&ep);
		for (ut32 b = 1; b < L->stages; b++) {
			if (!sim_loop_block(L, SIM_EPILOG, 0, &ep)) {
				effs_fini(&ep);
				goto out;
			}
		}
		if (!effs_add(e, BRANCH(INV(VARL(SIM_SPA)), effs_take(&ep), NOP()))) {
			effs_fini(&ep);
			goto out;
		}
		effs_fini(&ep);
	}
	// what is still in flight lands, in the order it would have
	for (ut32 at = 0; at < SIM_LOOP_GENS * L->ii; at++) {
		for (size_t i = 0; i < L->nw; i++) {
			SimLoopWrite *w = &L->w[i];
			for (ut32 g = w->gens - 1; g > 0; g--) {
				if ((w->gens - 1 - g) * L->ii + w->lc != at) {
					continue;
				}
				if (!effs_add(e, BRANCH(VARL(w->pred[g]), SETG(w->reg, VARL(w->val[g])), NOP()))) {
					goto out;
				}
			}
		}
	}
	sim_bump_all(p);
	p->pc = L->post;
	p->cycle += L->len;
	ok = true;
out:
	free(L);
	return ok;
}

/* ---- running a path ---- */

static RzILOpEffect *sim_run(Sim *sim, SimPath *p);

// Leave the simulation through register branch \p b: what is in flight lands
// first, as the code it reaches cannot be followed.
static bool sim_leave(SimPath *p, const SimBranch *b, SimEffs *e) {
	if (p->nbr) {
		return false; // another branch would still take effect
	}
	return sim_land_before(p, UT32_MAX, e) && effs_add(e, JMP(VARL(b->tgt)));
}

// Take branch \p b on \p p, and run the path on from where it goes.
static RzILOpEffect *sim_take(Sim *sim, SimPath *p, const SimBranch *b) {
	if (!b->tgt) {
		p->pc = b->target;
		p->resolved++;
		p->loop = false; // a branch taking effect ends a loop before it runs
		return sim_run(sim, p);
	}
	SimEffs e;
	effs_init(&e);
	RzILOpEffect *r = sim_leave(p, b, &e) ? effs_take(&e) : NULL;
	effs_fini(&e);
	return r;
}

// Run \p p until nothing is in flight, and return what it does from here.
static RzILOpEffect *sim_run(Sim *sim, SimPath *p) {
	SimEffs e;
	effs_init(&e);
	for (;;) {
		// a branch taking effect now
		size_t due = SIZE_MAX, ndue = 0;
		for (size_t i = 0; i < p->nbr; i++) {
			if (p->br[i].at == p->cycle) {
				due = i;
				ndue++;
			}
		}
		if (ndue > 1) {
			goto fail; // two transfers in one cycle
		}
		if (ndue) {
			SimBranch b = p->br[due];
			memmove(&p->br[due], &p->br[due + 1], (p->nbr - due - 1) * sizeof(SimBranch));
			p->nbr--;
			int taken = sim_known(p, b.cond, b.neg);
			if (taken < 0) {
				if (++sim->forks > SIM_MAX_FORKS) {
					goto fail;
				}
				SimPath *pt = rz_mem_dup(p, sizeof(*p));
				SimPath *pn = rz_mem_dup(p, sizeof(*p));
				RzILOpEffect *et = NULL, *en = NULL;
				if (pt && pn) {
					sim_commit(pt, b.cond, !b.neg);
					sim_commit(pn, b.cond, b.neg);
					et = sim_take(sim, pt, &b);
					en = et ? sim_run(sim, pn) : NULL;
				}
				free(pt);
				free(pn);
				if (!et || !en) {
					rz_il_op_effect_free(et);
					rz_il_op_effect_free(en);
					goto fail;
				}
				if (!effs_add(&e, BRANCH(sim_cond(b.cond, b.neg), et, en))) {
					goto fail;
				}
				break;
			}
			if (taken && b.tgt) {
				if (!sim_leave(p, &b, &e)) {
					goto fail;
				}
				break;
			}
			if (taken) {
				p->pc = b.target;
				p->resolved++;
				p->loop = false;
			}
		}
		if (p->loop) {
			// the loop runs once nothing from before it is in flight
			if (p->nbr || !sim_land_before(p, UT32_MAX, &e) ||
				!sim_loop(sim, p, &p->loop_insn, p->loop_body, &e)) {
				goto fail;
			}
			p->loop = false;
			continue;
		}
		if (p->issued && !p->nheld && !p->nbr) {
			// a single packet that falls through needs no jump
			if (p->issued > 1 || p->resolved || p->pc != sim->fallthrough) {
				if (!effs_add(&e, JMP(U32((ut32)p->pc)))) {
					goto fail;
				}
			}
			break;
		}
		if (p->cycle >= SIM_MAX_CYCLES || sim->packets >= SIM_MAX_PACKETS) {
			goto fail;
		}
		C6xPacketRef pkt;
		C6xInsn ins[C6X_FP_SLOTS];
		if (!sim_decode(sim->img, p->pc, &pkt, ins) || pkt.addr != p->pc) {
			goto fail; // not code, or the middle of an execute packet
		}
		const C6xInsn *sploop = NULL;
		for (size_t i = 0; i < pkt.n; i++) {
			if (sim_is_sploop(&ins[i])) {
				sploop = &ins[i];
			}
		}
		if (!sim_issue(sim, p, &pkt, ins, &e)) {
			goto fail;
		}
		p->issued++;
		sim->packets++;
		if (sploop) {
			// The rest of the SPLOOP packet ran normally; the loop starts in the
			// next cycle, unless a branch taking effect then cuts it off.
			for (size_t i = 0; i < p->nbr; i++) {
				if (p->br[i].at != p->cycle + 1) {
					goto fail;
				}
			}
			// what is in flight lands now, before the loop; sim_loop()
			// checks that the loop and the code after it cannot tell
			p->nearly = 0;
			for (size_t i = 0; i < p->nheld; i++) {
				const SimHeld *h = &p->held[i];
				if (h->land >= p->cycle && sim_known(p, h->cond, h->neg)) {
					p->early[p->nearly] = h->reg;
					p->early_at[p->nearly++] = h->land - p->cycle;
				}
			}
			if (!sim_land_before(p, UT32_MAX, &e)) {
				goto fail;
			}
			p->loop = true;
			p->loop_insn = *sploop;
			p->loop_body = pkt.next;
			p->cycle++;
			p->pc = pkt.next;
			continue;
		}
		if (!sim_advance(p, sim_packet_cycles(&pkt, ins), pkt.next, &e)) {
			goto fail;
		}
	}
	RzILOpEffect *r = effs_take(&e);
	effs_fini(&e);
	return r;
fail:
	effs_fini(&e);
	return NULL;
}

/**
 * \brief Lift the code at \p addr together with the pipeline: the execute
 *        packet there and whatever it sets in motion, up to the first cycle
 *        with nothing in flight.
 *
 * \param img Where to read the code.
 * \param addr Address to lift.
 * \param handled Receives whether \p addr could be decoded as part of an
 *                execute packet; when it could not, there was nothing to read,
 *                and the caller may lift the instruction it has by itself.
 *
 * \return The effect, a NOP inside an execute packet, whose first address
 *         covers it, or NULL when the code cannot be simulated.
 */
RZ_IPI RZ_OWN RzILOpEffect *c6x_lift_at(const C6xImage *img, ut64 addr, RZ_NULLABLE bool *handled) {
	rz_return_val_if_fail(img && img->read && img->desc, NULL);
	if (handled) {
		*handled = false;
	}
	C6xPacketRef pkt;
	C6xInsn ins[C6X_FP_SLOTS];
	if (!sim_decode(img, addr, &pkt, ins)) {
		return NULL;
	}
	if (handled) {
		*handled = true;
	}
	if (pkt.addr != addr) {
		return NOP(); // lifted with the first address of its packet
	}
	Sim sim = { .img = img, .fallthrough = addr + pkt.slots[0].size };
	SimPath *p = RZ_NEW0(SimPath);
	if (!p) {
		return NULL;
	}
	p->pc = addr;
	RzILOpEffect *eff = sim_run(&sim, p);
	free(p);
	return eff;
}

#include <rz_il/rz_il_opbuilder_end.h>
