// SPDX-FileCopyrightText: 2020 Khairulmizam Samsudin <xource@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#include "minunit.h"
#if __linux__
#include <sys/user.h>

#ifndef offsetof
#define offsetof(type, field) ((size_t) & ((type *)0)->field)
#endif

#endif //__linux__

bool test_rz_debug_use(void) {
	RzDebug *dbg;
	bool res;

	RzBreakpointContext bp_ctx = { 0 };
	dbg = rz_debug_new(&bp_ctx);
	mu_assert_notnull(dbg, "rz_debug_new () failed");

	res = rz_debug_use(dbg, "null");
	mu_assert_eq(res, true, "rz_debug_use () failed");

	rz_debug_free(dbg);
	mu_end;
}

bool test_rz_debug_reg_offset(void) {
#if __linux__
#ifdef __x86_64__
#define FPREGS struct user_fpregs_struct
	FPREGS regs;
	mu_assert_eq(sizeof(regs.cwd), 2, "cwd size");
	mu_assert_eq(offsetof(FPREGS, cwd), 0, "cwd offset");

	mu_assert_eq(sizeof(regs.rip), 8, "rip size");
	mu_assert_eq(offsetof(FPREGS, rip), 8, "rip offset");

	mu_assert_eq(sizeof(regs.mxcsr), 4, "mxcsr size");
	mu_assert_eq(offsetof(FPREGS, mxcsr), 24, "mxcsr offset");

	mu_assert_eq(sizeof(regs.mxcr_mask), 4, "mxcr_mask size");
	mu_assert_eq(offsetof(FPREGS, mxcr_mask), 28, "mxcr_mask offset");

	mu_assert_eq(sizeof(regs.st_space[0]) * 2, 8, "st0 size");
	mu_assert_eq(offsetof(FPREGS, st_space[0]), 32, "st0 offset");

	mu_assert_eq(sizeof(regs.xmm_space[0]) * 4, 16, "xmm0 size");
	mu_assert_eq(offsetof(FPREGS, xmm_space[0]), 160, "xmm0 offset");

	mu_assert_eq(offsetof(FPREGS, padding[0]), 416, "x64");
#endif //__x86_64__
#endif //__linux__
	mu_end;
}

/**
 * \name Debug Mock Plugins
 * The below plugin can be used for unit tests to test RzDebug without having
 * to rely on any system-specific behavior.
 * @{
 */

/**
 * Side-channel to signal failure from inside the plugin
 * This is fine to be global since unit-tests are single-threaded.
 */
static bool dbg_mock_failed = false;

static void dbg_mock_fail() {
	// use an extra function to debug the tests easier
	dbg_mock_failed = true;
}

typedef struct {
	ut64 addr;
	ut64 size;
	int perm; ///< RZ_PERM_RWX
} DebugMockHWBP;

typedef struct {
	ut64 pc;
	ut8 a; ///< accumulator
	bool running;
	RzStrBuf output; ///< output of print instructions
	bool is_thumb; ///< only used in multibits variant below
	RzVector /* <DebugMockHWBP> */ hwbps;
} DebugMockCtx;

static bool dbg_mock_init(RzDebug *dbg, void **user) {
	DebugMockCtx *ctx = RZ_NEW0(DebugMockCtx);
	ctx->pc = 0x30;
	ctx->a = 0;
	ctx->running = false;
	rz_strbuf_init(&ctx->output);
	rz_vector_init(&ctx->hwbps, sizeof(DebugMockHWBP), NULL, NULL);
	*user = ctx;
	return true;
}

static void dbg_mock_fini(RzDebug *dbg, void *user) {
	DebugMockCtx *ctx = user;
	rz_strbuf_fini(&ctx->output);
	rz_vector_fini(&ctx->hwbps);
	free(ctx);
}

static int dbg_mock_attach(RzDebug *dbg, int pid) {
	return true;
}

static bool mock_isa_hwbp_at(DebugMockCtx *ctx, ut64 addr, int perm) {
	DebugMockHWBP *bp;
	rz_vector_foreach (&ctx->hwbps, bp) {
		if (bp->addr <= addr && bp->addr + bp->size > addr && (bp->perm & perm)) {
			return true;
		}
	}
	return false;
}

static RzDebugReasonType mock_isa_step(DebugMockCtx *ctx, RzIO *io) {
	// mock mini instruction set:
	static const char *op_nop = "\x00\x00\x00\x00"; ///< nop
	static const char *op_break = "STOP"; ///< software breakpoint
	static const char *op_print = "PRNT"; ///< print something to ctx->output
	static const char op_pfx_load = 'L'; ///< "L<3-nibble hex addr>" load memory at the given addr into a
	static const char op_pfx_store = 'S'; ///< "S<3-nibble hex addr>" store a into memory at given addr

	if (mock_isa_hwbp_at(ctx, ctx->pc, RZ_PERM_X)) {
		return RZ_DEBUG_REASON_BREAKPOINT;
	}

	ut8 opcode[4];
	rz_io_read_at(io, ctx->pc, opcode, sizeof(opcode));
	ctx->pc += sizeof(opcode);
	if (!memcmp(opcode, op_nop, sizeof(opcode))) {
		return RZ_DEBUG_REASON_NONE;
	}
	if (!memcmp(opcode, op_break, sizeof(opcode))) {
		return RZ_DEBUG_REASON_BREAKPOINT;
	}
	if (!memcmp(opcode, op_print, sizeof(opcode))) {
		rz_strbuf_appendf(&ctx->output, "PRNT with next pc = 0x%" PFMT64x "\n", ctx->pc);
		return RZ_DEBUG_REASON_NONE;
	}
	if (*opcode == op_pfx_load || *opcode == op_pfx_store) {
		char val[4];
		memcpy(val, opcode + 1, 3);
		val[3] = 0;
		ut64 addr = strtoul(val, NULL, 16);
		int perm;
		if (*opcode == op_pfx_load) {
			rz_io_read_at(io, addr, &ctx->a, 1);
			perm = RZ_PERM_R;
		} else {
			rz_io_write_at(io, addr, &ctx->a, 1);
			perm = RZ_PERM_W;
		}
		if (mock_isa_hwbp_at(ctx, addr, perm)) {
			return RZ_DEBUG_REASON_BREAKPOINT;
		}
		return RZ_DEBUG_REASON_NONE;
	}
	// invalid instruction
	dbg_mock_fail();
	return RZ_DEBUG_REASON_ILLEGAL;
}

static bool dbg_mock_step(RzDebug *dbg) {
	DebugMockCtx *ctx = dbg->plugin_data;
	mock_isa_step(ctx, dbg->iob.io);
	return true;
}

static int dbg_mock_cont(RzDebug *dbg, int pid, int tid, int sig) {
	DebugMockCtx *ctx = dbg->plugin_data;
	ctx->running = true;
	return RZ_DEBUG_REASON_NONE;
}

RzDebugReasonType dbg_mock_wait(RzDebug *dbg, int pid) {
	DebugMockCtx *ctx = dbg->plugin_data;
	if (!ctx->running) {
		return RZ_DEBUG_REASON_NONE;
	}
	RzIO *io = dbg->iob.io;
	RzDebugReasonType r = RZ_DEBUG_REASON_NONE;
	for (ut64 fuel = 0x100; fuel; fuel--) {
		r = mock_isa_step(ctx, io);
		if (r != RZ_DEBUG_REASON_NONE) {
			break;
		}
	}
	ctx->running = false;
	return r;
}

#define DBG_MOCK_REG_PROFILE_SIZE 9

int dbg_mock_reg_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	if (type != RZ_REG_TYPE_GPR) {
		return 0;
	}
	DebugMockCtx *ctx = dbg->plugin_data;
	if (size < DBG_MOCK_REG_PROFILE_SIZE) {
		dbg_mock_fail();
		return 0;
	}
	rz_write_at_le64(buf, ctx->pc, 0);
	buf[8] = ctx->a;
	return DBG_MOCK_REG_PROFILE_SIZE;
}

int dbg_mock_reg_write(RzDebug *dbg, int type, const ut8 *buf, int size) {
	if (type != RZ_REG_TYPE_GPR) {
		return 0;
	}
	DebugMockCtx *ctx = dbg->plugin_data;
	if (size < DBG_MOCK_REG_PROFILE_SIZE) {
		dbg_mock_fail();
		return 0;
	}
	ctx->pc = rz_read_at_le64(buf, 0);
	ctx->a = buf[8];
	return DBG_MOCK_REG_PROFILE_SIZE;
}

char *dbg_mock_reg_profile(RzDebug *dbg) {
	return strdup(
		"=PC	pc\n"
		"gpr	pc	.64	0	0\n"
		"gpr	a	.8	8	0\n");
}

static int dbg_mock_breakpoint(RzBreakpoint *bp, RzBreakpointItem *b, bool set) {
	RzDebug *dbg = bp->user;
	DebugMockCtx *ctx = dbg->plugin_data;
	if (set) {
		DebugMockHWBP hwbp = {
			.addr = b->addr,
			.size = b->size,
			.perm = b->perm
		};
		rz_vector_push(&ctx->hwbps, &hwbp);
		return true;
	}
	for (size_t i = 0; i < rz_vector_len(&ctx->hwbps); i++) {
		DebugMockHWBP *hwbp = rz_vector_index_ptr(&ctx->hwbps, i);
		if (hwbp->addr == b->addr) {
			rz_vector_remove_at(&ctx->hwbps, i, NULL);
			return true;
		}
	}
	return false;
}

static RzDebugPlugin dbg_mock_plugin = {
	.name = "mock_dbg",
	.license = "LGPL3",
	.arch = "mock_arch",
	.init = dbg_mock_init,
	.fini = dbg_mock_fini,
	.attach = dbg_mock_attach,
	.step = dbg_mock_step,
	.cont = dbg_mock_cont,
	.wait = dbg_mock_wait,
	.breakpoint = dbg_mock_breakpoint,
	.reg_read = dbg_mock_reg_read,
	.reg_write = dbg_mock_reg_write,
	.reg_profile = dbg_mock_reg_profile
};

static RzBreakpointArch bp_mock_plugin_bps[] = {
	{ .bits = 0, .length = 4, .endian = 0, .bytes = (const ut8 *)"STOP" },
	{ 0, 0, 0, NULL }
};

static RzBreakpointPlugin bp_mock_plugin = {
	.name = "mock_bp",
	.arch = "moch_arch",
	.nbps = 1,
	.bps = bp_mock_plugin_bps,
};

bool bp_everything_is_mapped(ut64 addr, int perm, void *user) {
	return true;
}

static RzBreakpointContext bp_ctx = {
	.is_mapped = bp_everything_is_mapped,
};

/// @}

/**
 * \name "Thumb" Debug Mock Plugins
 * This is an extension to the above plugin, which supports dynamically switching
 * between two instruction sets, like arm thumb.
 * @{
 */

static RzDebugReasonType mock_isa_multibits_step(DebugMockCtx *ctx, RzIO *io) {
	if (ctx->is_thumb) {
		static const char *op_nop = "\x00\x00"; ///< nop
		static const char *op_break = "st"; ///< software breakpoint
		static const char *op_print = "pr"; ///< print something (just to have something other than 0s)
		static const char *op_switch = "sw"; ///< switch to 32bit isa

		ut8 opcode[2];
		rz_io_read_at(io, ctx->pc, opcode, sizeof(opcode));
		ctx->pc += sizeof(opcode);
		if (!memcmp(opcode, op_nop, sizeof(opcode))) {
			return RZ_DEBUG_REASON_NONE;
		}
		if (!memcmp(opcode, op_break, sizeof(opcode))) {
			return RZ_DEBUG_REASON_BREAKPOINT;
		}
		if (!memcmp(opcode, op_print, sizeof(opcode))) {
			rz_strbuf_appendf(&ctx->output, "pr with next pc = 0x%" PFMT64x "\n", ctx->pc);
			return RZ_DEBUG_REASON_NONE;
		}
		if (!memcmp(opcode, op_switch, sizeof(opcode))) {
			ctx->is_thumb = false;
			return RZ_DEBUG_REASON_NONE;
		}
	} else {
		static const char *op_nop = "\x00\x00\x00\x00"; ///< nop
		static const char *op_break = "STOP"; ///< software breakpoint
		static const char *op_print = "PRNT"; ///< print something (just to have something other than 0s)
		static const char *op_switch = "SWCH"; ///< switch to 16bit isa

		ut8 opcode[4];
		rz_io_read_at(io, ctx->pc, opcode, sizeof(opcode));
		ctx->pc += sizeof(opcode);
		if (!memcmp(opcode, op_nop, sizeof(opcode))) {
			return RZ_DEBUG_REASON_NONE;
		}
		if (!memcmp(opcode, op_break, sizeof(opcode))) {
			return RZ_DEBUG_REASON_BREAKPOINT;
		}
		if (!memcmp(opcode, op_print, sizeof(opcode))) {
			rz_strbuf_appendf(&ctx->output, "PRNT with next pc = 0x%" PFMT64x "\n", ctx->pc);
			return RZ_DEBUG_REASON_NONE;
		}
		if (!memcmp(opcode, op_switch, sizeof(opcode))) {
			ctx->is_thumb = true;
			return RZ_DEBUG_REASON_NONE;
		}
	}
	// invalid instruction
	dbg_mock_fail();
	return RZ_DEBUG_REASON_ILLEGAL;
}

RzDebugReasonType dbg_mock_multibits_wait(RzDebug *dbg, int pid) {
	DebugMockCtx *ctx = dbg->plugin_data;
	if (!ctx->running) {
		return RZ_DEBUG_REASON_NONE;
	}
	RzIO *io = dbg->iob.io;
	RzDebugReasonType r = RZ_DEBUG_REASON_NONE;
	for (ut64 fuel = 0x100; fuel; fuel--) {
		r = mock_isa_multibits_step(ctx, io);
		if (r != RZ_DEBUG_REASON_NONE) {
			break;
		}
	}
	ctx->running = false;
	return r;
}

bool dbg_mock_multibits_step(RzDebug *dbg) {
	mock_isa_multibits_step(dbg->plugin_data, dbg->iob.io);
	return true;
}

static RzDebugPlugin dbg_mock_multibits_plugin = {
	.name = "mock_multibits_dbg",
	.license = "LGPL3",
	.arch = "mock_multibits_arch",
	.init = dbg_mock_init,
	.fini = dbg_mock_fini,
	.attach = dbg_mock_attach,
	.cont = dbg_mock_cont,
	.wait = dbg_mock_multibits_wait,
	.step = dbg_mock_multibits_step,
	.reg_read = dbg_mock_reg_read,
	.reg_write = dbg_mock_reg_write,
	.reg_profile = dbg_mock_reg_profile
};

static RzBreakpointArch bp_mock_multibits_plugin_bps[] = {
	{ .bits = 16, .length = 2, .endian = 0, .bytes = (const ut8 *)"st" },
	{ .bits = 32, .length = 4, .endian = 0, .bytes = (const ut8 *)"STOP" },
	{ 0, 0, 0, NULL }
};

static RzBreakpointPlugin bp_mock_multibits_plugin = {
	.name = "mock_multibits_bp",
	.arch = "moch_multibits_arch",
	.nbps = 2,
	.bps = bp_mock_multibits_plugin_bps,
};

/// @}

#define SETUP_DEBUG(dbg_plugin, bp_plugin, bp_ctx) \
	do { \
		dbg_mock_failed = false; \
		dbg = rz_debug_new(bp_ctx); \
		mu_assert_notnull(dbg, "create debug"); \
		bool succ = rz_debug_plugin_add(dbg, dbg_plugin); \
		mu_assert_true(succ, "add mock debug plugin"); \
		succ = rz_bp_plugin_add(dbg->bp, bp_plugin); \
		mu_assert_true(succ, "add mock bp plugin"); \
		io = rz_io_new(); \
		rz_io_bind(io, &dbg->iob); \
		rz_io_bind(io, &dbg->bp->iob); \
		succ = rz_debug_use(dbg, (dbg_plugin)->name); \
		mu_assert_true(succ, "use mock debug plugin"); \
		rz_bp_use(dbg->bp, (bp_plugin)->name); \
		mu_assert_true(succ, "use mock bp plugin"); \
	} while (0)

/**
 * \brief Simple sw breakpoint test
 * Start at 0x30, set breakpoint at 0x50 and continue until it gets hit.
 */
static bool test_debug_sw_bp(void) {
	RzDebug *dbg;
	RzIO *io;
	SETUP_DEBUG(&dbg_mock_plugin, &bp_mock_plugin, &bp_ctx);

	rz_io_open_at(io, "malloc://0x1000", RZ_PERM_RW, 0644, 0x0, NULL);
	rz_io_write_at(io, 0x50, (const ut8 *)"PRNT", 4);

	int r = rz_debug_attach(dbg, 42);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_true(r, "attach");

	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
	mu_assert_false(dbg_mock_failed, "global failure");
	ut64 pc = rz_reg_get_value_by_role(dbg->reg, RZ_REG_NAME_PC);
	mu_assert_eq(pc, 0x30, "initial pc");

	RzBreakpointItem *b = rz_debug_bp_add(dbg, 0x50, 0, false, false, 0, NULL, 0);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_notnull(b, "add bp");
	mu_assert_false(b->hw, "bp is software");

	r = rz_debug_continue(dbg);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_true(r, "continue");

	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
	mu_assert_false(dbg_mock_failed, "global failure");
	pc = rz_reg_get_value_by_role(dbg->reg, RZ_REG_NAME_PC);
	mu_assert_eq(pc, 0x50, "pc recoiled after hitting sw breakpoint at 0x54");

	ut8 data[4];
	rz_io_read_at(io, 0x50, data, sizeof(data));
	mu_assert_memeq(data, (const ut8 *)"PRNT", 4, "restored original bytes");

	DebugMockCtx *ctx = dbg->plugin_data;
	mu_assert_streq(rz_strbuf_get(&ctx->output), "", "no print hit");

	rz_debug_free(dbg);
	rz_io_free(io);
	mu_end;
}

/**
 * \name Thumb/Non-thumb software breakpoint test
 * Set up some mixed thumb and non-thumb code, put breakpoints in both parts and check that
 * all of them are set up correctly (selecting the right byte patterns from the bp plugin) and hit.
 * @{
 */

int sw_bp_multibits_bits_at(ut64 addr, void *user) {
	// this corresponds to the instruction of the program written into io in test_debug_sw_bp_multibits()
	return addr >= 0x58 && addr < 0x60 ? 16 : 32;
}

static bool test_debug_sw_bp_multibits(void) {
	RzBreakpointContext bp_ctx = {
		.is_mapped = bp_everything_is_mapped,
		.bits_at = sw_bp_multibits_bits_at
	};

	RzDebug *dbg;
	RzIO *io;
	SETUP_DEBUG(&dbg_mock_multibits_plugin, &bp_mock_multibits_plugin, &bp_ctx);

	rz_io_open_at(io, "malloc://0x1000", RZ_PERM_RW, 0644, 0x0, NULL);
	// program is some non-thumb code with a chunk of thumb in between
	rz_io_write_at(io, 0x50, (const ut8 *)"PRNT", 4);
	rz_io_write_at(io, 0x54, (const ut8 *)"SWCH", 4);
	rz_io_write_at(io, 0x58, (const ut8 *)"pr", 2);
	rz_io_write_at(io, 0x5a, (const ut8 *)"pr", 2);
	rz_io_write_at(io, 0x5e, (const ut8 *)"sw", 2);
	rz_io_write_at(io, 0x60, (const ut8 *)"PRNT", 2);
	const char full_code[] =
		/* 0x4c */ "\x00\x00\x00\x00"
			   /* 0x50 */ "PRNT"
			   /* 0x54 */ "SWCH"
			   /* 0x58 */ "pr"
			   /* 0x5a */ "pr"
			   /* 0x5c */ "\x00\x00"
			   /* 0x5e */ "sw"
			   /* 0x60 */ "PRNT"
			   /* 0x64 */ "\x00\x00\x00\x00"
			   /* 0x68 */ "\x00\x00\x00\x00"
			   /* 0x6c */ "\x00\x00\x00\x00";
#define FULL_CODE_SIZE (0x70 - 0x4c)
	mu_assert_eq(sizeof(full_code) - 1, FULL_CODE_SIZE, "code size");
	rz_io_write_at(io, 0x4c, (const ut8 *)full_code, FULL_CODE_SIZE);

	int r = rz_debug_attach(dbg, 42);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_true(r, "attach");

	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
	mu_assert_false(dbg_mock_failed, "global failure");
	ut64 pc = rz_reg_get_value_by_role(dbg->reg, RZ_REG_NAME_PC);
	mu_assert_eq(pc, 0x30, "initial pc");

	RzBreakpointItem *b = rz_debug_bp_add(dbg, 0x50, 0, false, false, 0, NULL, 0);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_notnull(b, "add bp in non-thumb");
	mu_assert_eq(b->size, 4, "non-thumb bp size");
	b = rz_debug_bp_add(dbg, 0x54, 0, false, false, 0, NULL, 0);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_notnull(b, "add bp at the end of non-thumb");
	mu_assert_eq(b->size, 4, "non-thumb bp size");
	b = rz_debug_bp_add(dbg, 0x58, 0, false, false, 0, NULL, 0);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_notnull(b, "add bp at the beginning of thumb");
	mu_assert_eq(b->size, 2, "thumb bp size");
	b = rz_debug_bp_add(dbg, 0x5a, 0, false, false, 0, NULL, 0);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_notnull(b, "add bp in the middle of thumb");
	mu_assert_eq(b->size, 2, "thumb bp size");
	b = rz_debug_bp_add(dbg, 0x5e, 0, false, false, 0, NULL, 0);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_notnull(b, "add bp at the end of thumb");
	mu_assert_eq(b->size, 2, "thumb bp size");
	b = rz_debug_bp_add(dbg, 0x68, 0, false, false, 0, NULL, 0);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_notnull(b, "add bp after thumb");
	mu_assert_eq(b->size, 4, "non-thumb bp size");

	DebugMockCtx *ctx = dbg->plugin_data;

	r = rz_debug_continue(dbg);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_true(r, "continue");
	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
	mu_assert_false(dbg_mock_failed, "global failure");
	pc = rz_reg_get_value_by_role(dbg->reg, RZ_REG_NAME_PC);
	mu_assert_eq(pc, 0x50, "pc recoiled after hitting sw breakpoint at 0x54");
	mu_assert_streq(rz_strbuf_get(&ctx->output), "", "output");
	ut8 data[FULL_CODE_SIZE];
	rz_io_read_at(io, 0x4c, data, sizeof(data));
	mu_assert_memeq(data, (const ut8 *)full_code, sizeof(data), "restored original bytes");

	r = rz_debug_continue(dbg);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_true(r, "continue");
	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
	mu_assert_false(dbg_mock_failed, "global failure");
	pc = rz_reg_get_value_by_role(dbg->reg, RZ_REG_NAME_PC);
	mu_assert_eq(pc, 0x54, "pc recoiled after hitting sw breakpoint at 0x54");
	mu_assert_streq(rz_strbuf_get(&ctx->output),
		"PRNT with next pc = 0x54\n",
		"output");
	rz_io_read_at(io, 0x4c, data, sizeof(data));
	mu_assert_memeq(data, (const ut8 *)full_code, sizeof(data), "restored original bytes");

	r = rz_debug_continue(dbg);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_true(r, "continue");
	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
	mu_assert_false(dbg_mock_failed, "global failure");
	pc = rz_reg_get_value_by_role(dbg->reg, RZ_REG_NAME_PC);
	mu_assert_eq(pc, 0x58, "pc recoiled after hitting sw breakpoint at 0x54");
	mu_assert_streq(rz_strbuf_get(&ctx->output),
		"PRNT with next pc = 0x54\n",
		"output");
	rz_io_read_at(io, 0x4c, data, sizeof(data));
	mu_assert_memeq(data, (const ut8 *)full_code, sizeof(data), "restored original bytes");

	r = rz_debug_continue(dbg);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_true(r, "continue");
	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
	mu_assert_false(dbg_mock_failed, "global failure");
	pc = rz_reg_get_value_by_role(dbg->reg, RZ_REG_NAME_PC);
	mu_assert_eq(pc, 0x5a, "pc recoiled after hitting sw breakpoint at 0x54");
	mu_assert_streq(rz_strbuf_get(&ctx->output),
		"PRNT with next pc = 0x54\n"
		"pr with next pc = 0x5a\n",
		"output");
	rz_io_read_at(io, 0x4c, data, sizeof(data));
	mu_assert_memeq(data, (const ut8 *)full_code, sizeof(data), "restored original bytes");

	r = rz_debug_continue(dbg);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_true(r, "continue");
	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
	mu_assert_false(dbg_mock_failed, "global failure");
	pc = rz_reg_get_value_by_role(dbg->reg, RZ_REG_NAME_PC);
	mu_assert_eq(pc, 0x5e, "pc recoiled after hitting sw breakpoint at 0x54");
	mu_assert_streq(rz_strbuf_get(&ctx->output),
		"PRNT with next pc = 0x54\n"
		"pr with next pc = 0x5a\n"
		"pr with next pc = 0x5c\n",
		"output");
	rz_io_read_at(io, 0x4c, data, sizeof(data));
	mu_assert_memeq(data, (const ut8 *)full_code, sizeof(data), "restored original bytes");

	r = rz_debug_continue(dbg);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_true(r, "continue");
	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
	mu_assert_false(dbg_mock_failed, "global failure");
	pc = rz_reg_get_value_by_role(dbg->reg, RZ_REG_NAME_PC);
	mu_assert_eq(pc, 0x68, "pc recoiled after hitting sw breakpoint at 0x54");
	mu_assert_streq(rz_strbuf_get(&ctx->output),
		"PRNT with next pc = 0x54\n"
		"pr with next pc = 0x5a\n"
		"pr with next pc = 0x5c\n"
		"PRNT with next pc = 0x64\n",
		"output");
	rz_io_read_at(io, 0x4c, data, sizeof(data));
	mu_assert_memeq(data, (const ut8 *)full_code, sizeof(data), "restored original bytes");

#undef FULL_CODE_SIZE
	rz_debug_free(dbg);
	rz_io_free(io);
	mu_end;
}
/// @}

/**
 * \brief Simple hw breakpoint test
 * Start at 0x30, set breakpoint at 0x50 and 0x80
 */
static bool test_debug_hw_bp(void) {
	RzDebug *dbg;
	RzIO *io;
	SETUP_DEBUG(&dbg_mock_plugin, &bp_mock_plugin, &bp_ctx);

	rz_io_open_at(io, "malloc://0x1000", RZ_PERM_RW, 0644, 0x0, NULL);
	rz_io_write_at(io, 0x50, (const ut8 *)"PRNT", 4);

	int r = rz_debug_attach(dbg, 42);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_true(r, "attach");

	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
	mu_assert_false(dbg_mock_failed, "global failure");
	ut64 pc = rz_reg_get_value_by_role(dbg->reg, RZ_REG_NAME_PC);
	mu_assert_eq(pc, 0x30, "initial pc");

	RzBreakpointItem *b = rz_debug_bp_add(dbg, 0x50, 0, true, false, 0, NULL, 0);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_notnull(b, "add bp");
	mu_assert_true(b->hw, "bp is hardware");

	b = rz_debug_bp_add(dbg, 0x60, 0, true, false, 0, NULL, 0);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_notnull(b, "add bp");
	mu_assert_true(b->hw, "bp is hardware");

	r = rz_debug_continue(dbg);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_true(r, "continue");

	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
	mu_assert_false(dbg_mock_failed, "global failure");
	pc = rz_reg_get_value_by_role(dbg->reg, RZ_REG_NAME_PC);
	mu_assert_eq(pc, 0x50, "pc after hitting hw breakpoint at 0x54");

	ut8 data[4];
	rz_io_read_at(io, 0x50, data, sizeof(data));
	mu_assert_memeq(data, (const ut8 *)"PRNT", 4, "original bytes");

	DebugMockCtx *ctx = dbg->plugin_data;
	mu_assert_streq(rz_strbuf_get(&ctx->output), "", "no print hit");

	r = rz_debug_continue(dbg);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_true(r, "continue");

	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
	mu_assert_false(dbg_mock_failed, "global failure");
	pc = rz_reg_get_value_by_role(dbg->reg, RZ_REG_NAME_PC);
	mu_assert_eq(pc, 0x60, "pc after hitting hw breakpoint at 0x54");
	mu_assert_streq(rz_strbuf_get(&ctx->output), "PRNT with next pc = 0x54\n", "print hit");

	rz_debug_free(dbg);
	rz_io_free(io);
	mu_end;
}

/**
 * \brief Simple hw watchpoint test
 * Start at 0x30, set a watchpoint and run until hit
 */
static bool test_debug_hw_watch(void) {
	RzDebug *dbg;
	RzIO *io;
	SETUP_DEBUG(&dbg_mock_plugin, &bp_mock_plugin, &bp_ctx);

	rz_io_open_at(io, "malloc://0x1000", RZ_PERM_RW, 0644, 0x0, NULL);
	const char *code =
		"PRNT" // 0x50
		"L050" // 0x54
		"PRNT" // 0x58
		"S04f" // 0x5c
		"L04f" // 0x60
		"PRNT" // 0x64
		"STOP"; // 0x68
	rz_io_write_at(io, 0x50, (const ut8 *)code, strlen(code));
	int r = rz_debug_attach(dbg, 42);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_true(r, "attach");

	RzBreakpointItem *b = rz_debug_bp_add(dbg, 0x4c, 4, true, true, RZ_PERM_R, NULL, 0);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_notnull(b, "add wp");
	mu_assert_true(b->hw, "bp is hardware");

	r = rz_debug_continue(dbg);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_true(r, "continue");

	rz_debug_reg_sync(dbg, RZ_REG_TYPE_ANY, false);
	mu_assert_false(dbg_mock_failed, "global failure");
	ut64 pc = rz_reg_get_value_by_role(dbg->reg, RZ_REG_NAME_PC);
	mu_assert_eq(pc, 0x64, "pc after hitting watchpoint");

	DebugMockCtx *ctx = dbg->plugin_data;
	mu_assert_streq(rz_strbuf_get(&ctx->output), "PRNT with next pc = 0x54\nPRNT with next pc = 0x5c\n",
		"side effects at watchpoint hit");
	mu_assert_eq(rz_reg_getv(dbg->reg, "a"), 'P', "acc side effects at watchpoint hit");

	r = rz_debug_continue(dbg);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_true(r, "continue");
	mu_assert_streq(rz_strbuf_get(&ctx->output),
		"PRNT with next pc = 0x54\nPRNT with next pc = 0x5c\nPRNT with next pc = 0x68\n",
		"print hit");

	rz_debug_free(dbg);
	rz_io_free(io);
	mu_end;
}

int all_tests() {
	rz_cons_new(); // there is some windows-specific code in debug that accesses the cons singleton
	mu_run_test(test_rz_debug_use);
	mu_run_test(test_rz_debug_reg_offset);
	mu_run_test(test_debug_sw_bp);
	mu_run_test(test_debug_sw_bp_multibits);
	mu_run_test(test_debug_hw_bp);
	mu_run_test(test_debug_hw_watch);
	rz_cons_free();
	return tests_passed != tests_run;
}

mu_main(all_tests)
