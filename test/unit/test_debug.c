// SPDX-FileCopyrightText: 2020 Khairulmizam Samsudin <xource@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_debug.h>
#include <dmp_specs.h>
#include <pe_specs.h>
#include "minunit.h"
#if __UNIX__
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif
#if __linux__
#include <sys/user.h>

#ifndef offsetof
#define offsetof(type, field) ((size_t)&((type *)0)->field)
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
	ut8 flags; ///< flags register, in the gpr arena like x86 rflags
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
	rz_io_read_at_mapped(io, ctx->pc, opcode, sizeof(opcode));
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
			rz_io_read_at_mapped(io, addr, &ctx->a, 1);
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

#define DBG_MOCK_REG_PROFILE_SIZE 10

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
	buf[9] = ctx->flags;
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
	ctx->flags = buf[9];
	return DBG_MOCK_REG_PROFILE_SIZE;
}

char *dbg_mock_reg_profile(RzDebug *dbg) {
	return strdup(
		"=PC	pc\n"
		"gpr	pc	.64	0	0\n"
		"gpr	a	.8	8	0\n"
		"flg	f	.8	9	0\n");
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

static bool bp_everything_is_mapped(ut64 addr, int perm, void *user) {
	return true;
}

static RzStrBuf *bp_mock_sw_opcode_at(ut64 addr, void *user) {
	return rz_strbuf_new("STOP");
}

static size_t bp_mock_sw_opcode_size_at(ut64 addr, void *user) {
	return 4;
}

static RzBreakpointContext bp_ctx = {
	.is_mapped = bp_everything_is_mapped,
	.get_sw_breakpoint_at = bp_mock_sw_opcode_at,
	.get_sw_breakpoint_size_at = bp_mock_sw_opcode_size_at,
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
		rz_io_read_at_mapped(io, ctx->pc, opcode, sizeof(opcode));
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
		rz_io_read_at_mapped(io, ctx->pc, opcode, sizeof(opcode));
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

/// @}

#define SETUP_DEBUG(dbg_plugin, bp_ctx) \
	do { \
		dbg_mock_failed = false; \
		dbg = rz_debug_new(bp_ctx); \
		mu_assert_notnull(dbg, "create debug"); \
		bool succ = rz_debug_plugin_add(dbg, dbg_plugin); \
		mu_assert_true(succ, "add mock debug plugin"); \
		io = rz_io_new(); \
		rz_io_bind(io, &dbg->iob); \
		rz_io_bind(io, &dbg->bp->iob); \
		succ = rz_debug_use(dbg, (dbg_plugin)->name); \
		mu_assert_true(succ, "use mock debug plugin"); \
	} while (0)

/**
 * \brief Simple sw breakpoint test
 * Start at 0x30, set breakpoint at 0x50 and continue until it gets hit.
 */
static bool test_debug_sw_bp(void) {
	RzDebug *dbg;
	RzIO *io;
	SETUP_DEBUG(&dbg_mock_plugin, &bp_ctx);

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
	rz_io_read_at_mapped(io, 0x50, data, sizeof(data));
	mu_assert_memeq(data, (const ut8 *)"PRNT", 4, "restored original bytes");

	DebugMockCtx *ctx = dbg->plugin_data;
	mu_assert_streq(rz_strbuf_get(&ctx->output), "", "no print hit");

	rz_debug_free(dbg);
	rz_io_free(io);
	mu_end;
}

/**
 * Set up some mixed thumb and non-thumb code, put breakpoints in both parts and check that
 * all of them are set up correctly (selecting the right byte patterns from the bp plugin) and hit.
 */
static RzStrBuf *bp_mock_sw_bp_multibits_opcode_at(ut64 addr, void *user) {
	// this corresponds to the instruction of the program written into io in test_debug_sw_bp_multibits()
	if (addr >= 0x58 && addr < 0x60) {
		return rz_strbuf_new("st");
	}
	return rz_strbuf_new("STOP");
}

static size_t bp_mock_sw_bp_multibits_size_at(ut64 addr, void *user) {
	// this corresponds to the instruction of the program written into io in test_debug_sw_bp_multibits()
	return addr >= 0x58 && addr < 0x60 ? 2 : 4;
}

static bool test_debug_sw_bp_multibits(void) {
	RzBreakpointContext bp_ctx = {
		.is_mapped = bp_everything_is_mapped,
		.get_sw_breakpoint_at = bp_mock_sw_bp_multibits_opcode_at,
		.get_sw_breakpoint_size_at = bp_mock_sw_bp_multibits_size_at,
	};

	RzDebug *dbg;
	RzIO *io;
	SETUP_DEBUG(&dbg_mock_multibits_plugin, &bp_ctx);

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
	rz_io_read_at_mapped(io, 0x4c, data, sizeof(data));
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
	rz_io_read_at_mapped(io, 0x4c, data, sizeof(data));
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
	rz_io_read_at_mapped(io, 0x4c, data, sizeof(data));
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
	rz_io_read_at_mapped(io, 0x4c, data, sizeof(data));
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
	rz_io_read_at_mapped(io, 0x4c, data, sizeof(data));
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
	rz_io_read_at_mapped(io, 0x4c, data, sizeof(data));
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
	SETUP_DEBUG(&dbg_mock_plugin, &bp_ctx);

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
	rz_io_read_at_mapped(io, 0x50, data, sizeof(data));
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
	SETUP_DEBUG(&dbg_mock_plugin, &bp_ctx);

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

/**
 * \brief Sync a register type whose registers live in another arena
 * Like rflags in the x86-64 profiles, the mock flags register lives in the
 * gpr arena, the only one the mock plugin transfers.
 */
static bool test_debug_reg_sync_flg(void) {
	RzDebug *dbg;
	RzIO *io;
	SETUP_DEBUG(&dbg_mock_plugin, &bp_ctx);

	int r = rz_debug_attach(dbg, 42);
	mu_assert_false(dbg_mock_failed, "global failure");
	mu_assert_true(r, "attach");
	mu_assert_true(rz_list_empty(dbg->reg->regset[RZ_REG_TYPE_FLG].regs), "no register lives in the flg arena");

	DebugMockCtx *ctx = dbg->plugin_data;
	ctx->flags = 0x24;
	mu_assert_true(rz_debug_reg_sync(dbg, RZ_REG_TYPE_FLG, false), "read flags");
	mu_assert_eq(rz_reg_getv(dbg->reg, "f"), 0x24, "flags read through the gpr arena");

	mu_assert_true(rz_reg_setv(dbg->reg, "f", 0x42), "set flags");
	mu_assert_true(rz_debug_reg_sync(dbg, RZ_REG_TYPE_FLG, true), "write flags");
	mu_assert_eq(ctx->flags, 0x42, "flags written through the gpr arena");
	mu_assert_false(dbg_mock_failed, "global failure");

	rz_debug_free(dbg);
	rz_io_free(io);
	mu_end;
}

static bool dmp_mock_check(RzIO *io, const char *file, bool many) {
	(void)io;
	(void)many;
	return !strncmp(file, "dmpnoclose://", 13);
}

static RzIOPlugin dmp_mock_noclose_plugin;

static RzIODesc *dmp_mock_open(RzIO *io, const char *file, int rw, int mode) {
	(void)mode;
	RzIODesc *d = rz_io_desc_new(io, &dmp_mock_noclose_plugin, file, rw, NULL);
	if (d && !strcmp(file, "dmpnoclose://noplug")) {
		d->plugin = NULL;
	}
	return d;
}

static RzIOPlugin dmp_mock_noclose_plugin = {
	.name = "dmp_mock_noclose",
	.desc = "Mock IO plugin without close callback",
	.uris = "dmpnoclose://",
	.license = "LGPL3",
	.open = dmp_mock_open,
	.check = dmp_mock_check,
};

static bool test_io_dmp_open_close(void) {
	RzIO *io = rz_io_new();
	mu_assert_notnull(io, "rz_io_new()");
	mu_assert_true(rz_io_plugin_add(io, &dmp_mock_noclose_plugin), "add mock dmp backend plugin");

	mu_assert_null(rz_io_open_nomap(io, "dmp:///nonexistent_rz_dmp_dir/missing.dmp", RZ_PERM_R, 0),
		"dmp:// open fails cleanly when backend fails");

	RzIODesc *desc = rz_io_open_nomap(io, "dmp://malloc://64", RZ_PERM_R, 0);
	mu_assert_notnull(desc, "dmp://malloc://64 opens");
	RzIOPlugin *dmp_plugin = desc->plugin;
	mu_assert_notnull(dmp_plugin, "dmp plugin");
	mu_assert_eq(dmp_plugin->close(NULL), 0, "dmp close(NULL) is a safe no-op");
	RzIODesc empty_desc = { 0 };
	mu_assert_eq(dmp_plugin->close(&empty_desc), 0, "dmp close(NULL data) is a safe no-op");
	mu_assert_true(rz_io_desc_close(desc), "dmp:// close returns success and frees backend");

	desc = rz_io_open_nomap(io, "dmp://dmpnoclose://close", RZ_PERM_R, 0);
	mu_assert_notnull(desc, "dmp://dmpnoclose://close opens");
	mu_assert_true(rz_io_desc_close(desc), "dmp:// close handles backend without close callback");

	desc = rz_io_open_nomap(io, "dmp://dmpnoclose://noplug", RZ_PERM_R, 0);
	mu_assert_notnull(desc, "dmp://dmpnoclose://noplug opens");
	mu_assert_true(rz_io_desc_close(desc), "dmp:// close handles backend with NULL plugin");

	// Leave exactly 1 fd in the pool so backend open succeeds and outer rz_io_desc_new() fails
	RzIO *io_full = rz_io_new();
	mu_assert_notnull(io_full, "rz_io_new for exhausted dmp pool");
	ut32 saved_next_id = io_full->files->pool->next_id;
	io_full->files->pool->next_id = io_full->files->pool->last_id - 1;
	mu_assert_null(rz_io_open_nomap(io_full, "dmp://malloc://64", RZ_PERM_R, 0),
		"dmp:// open cleans up backend when outer desc allocation fails");
	io_full->files->pool->next_id = saved_next_id;
	rz_io_free(io_full);

	rz_io_free(io);
	mu_end;
}

static bool test_debug_dmp_reinit(void) {
	ut8 *raw = calloc(1, sizeof(dmp64_header));
	if (!raw) {
		return false;
	}
	memcpy(raw, DMP64_MAGIC, 8);
	rz_write_le32(raw + rz_offsetof(dmp64_header, MajorVersion), 15);
	rz_write_le32(raw + rz_offsetof(dmp64_header, MinorVersion), 19041);
	rz_write_le32(raw + rz_offsetof(dmp64_header, MachineImageType), PE_IMAGE_FILE_MACHINE_AMD64);
	rz_write_le32(raw + rz_offsetof(dmp64_header, NumberProcessors), 0);
	memcpy(raw + rz_offsetof(dmp64_header, PhysicalMemoryBlockBuffer), DMP_UNUSED_MAGIC, 4);
	rz_write_le32(raw + rz_offsetof(dmp64_header, DumpType), DMP_DUMPTYPE_HEADER);

	char *uri = rz_str_newf("dmp://malloc://%" PFMT64u, (ut64)sizeof(dmp64_header));
	if (!uri) {
		free(raw);
		return false;
	}

	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "rz_core_new for dmp reinit");
	RzCoreFile *cf = rz_core_file_open(core, uri, RZ_PERM_RW, 0);
	mu_assert_notnull(cf, "open synthetic dmp://malloc://");
	mu_assert_eq(rz_io_desc_write_at(core->io->desc, 0, raw, sizeof(dmp64_header)),
		(int)sizeof(dmp64_header), "write dmp64 header");
	mu_assert_true(rz_core_bin_load(core, uri, UT64_MAX), "load synthetic dmp64 bin");

	mu_assert_true(rz_debug_use(core->dbg, "dmp"), "first debug_dmp init");
	mu_assert_true(rz_debug_use(core->dbg, "dmp"), "second debug_dmp re-init without leaks");
	rz_core_free(core);

	// Unknown Windows build with no built-in profile must fail cleanly without leaks
	rz_write_le32(raw + rz_offsetof(dmp64_header, MinorVersion), 99999);
	RzCore *core2 = rz_core_new();
	mu_assert_notnull(core2, "rz_core_new for unknown dmp build");
	cf = rz_core_file_open(core2, uri, RZ_PERM_RW, 0);
	mu_assert_notnull(cf, "open synthetic dmp://malloc:// 2");
	mu_assert_eq(rz_io_desc_write_at(core2->io->desc, 0, raw, sizeof(dmp64_header)),
		(int)sizeof(dmp64_header), "write dmp64 header 2");
	mu_assert_true(rz_core_bin_load(core2, uri, UT64_MAX), "load synthetic dmp64 bin 2");
	mu_assert_false(rz_debug_use(core2->dbg, "dmp"), "unknown build fails dmp init cleanly");
	rz_core_free(core2);

	free(uri);
	free(raw);
	mu_end;
}

#if __UNIX__
#define MOCK_KD_KERNEL_BASE 0xfffff80000000000ULL
#define MOCK_KD_DBG_PTR     0xfffff80000010000ULL
#define MOCK_KD_DBG_BLOCK   0xfffff80000020000ULL
#define MOCK_KD_CSD_PTR     0xfffff80000030000ULL
#define MOCK_KD_TIMESTAMP   0x11223344U
#define MOCK_KD_SIZEOFIMAGE 0x2000U

typedef struct {
	int listen_fd;
	ut8 pe_image[0x400];
} MockKdServer;

static void build_mock_ntoskrnl_pe(ut8 *buf, size_t sz) {
	memset(buf, 0, sz);
	// DOS header
	buf[0] = 'M';
	buf[1] = 'Z';
	rz_write_le32(buf + 0x3c, 0x40);
	// PE signature + COFF header at 0x40
	memcpy(buf + 0x40, "PE\0\0", 4);
	rz_write_le16(buf + 0x44, PE_IMAGE_FILE_MACHINE_AMD64);
	rz_write_le16(buf + 0x46, 1); // NumberOfSections
	rz_write_le32(buf + 0x48, MOCK_KD_TIMESTAMP);
	rz_write_le16(buf + 0x54, 0xf0); // SizeOfOptionalHeader (PE32+)
	rz_write_le16(buf + 0x56, 0x0022); // Characteristics
	// PE32+ OptionalHeader at 0x58
	rz_write_le16(buf + 0x58, PE_IMAGE_FILE_TYPE_PE32PLUS);
	rz_write_le64(buf + 0x70, 0x140000000ULL); // ImageBase
	rz_write_le32(buf + 0x78, 0x1000); // SectionAlignment
	rz_write_le32(buf + 0x7c, 0x200); // FileAlignment
	rz_write_le32(buf + 0x90, MOCK_KD_SIZEOFIMAGE); // SizeOfImage (pe_off + 0x50)
	rz_write_le32(buf + 0x94, 0x200); // SizeOfHeaders
	rz_write_le16(buf + 0x9c, PE_IMAGE_SUBSYSTEM_NATIVE);
	rz_write_le32(buf + 0xc4, 16); // NumberOfRvaAndSizes
	// DataDirectory[6] (DEBUG) at 0x58 + 112 + 6 * 8 = 0xf8
	rz_write_le32(buf + 0xf8, 0x1000); // VirtualAddress
	rz_write_le32(buf + 0xfc, 28); // Size
	// Section header ".rdata" at 0x148
	memcpy(buf + 0x148, ".rdata", 6);
	rz_write_le32(buf + 0x150, 0x200); // VirtualSize
	rz_write_le32(buf + 0x154, 0x1000); // VirtualAddress
	rz_write_le32(buf + 0x158, 0x200); // SizeOfRawData
	rz_write_le32(buf + 0x15c, 0x200); // PointerToRawData
	rz_write_le32(buf + 0x16c, PE_IMAGE_SCN_MEM_READ);
	// Debug directory entry at 0x200
	rz_write_le32(buf + 0x204, MOCK_KD_TIMESTAMP);
	rz_write_le32(buf + 0x20c, IMAGE_DEBUG_TYPE_CODEVIEW);
	rz_write_le32(buf + 0x210, 37); // SizeOfData
	rz_write_le32(buf + 0x214, 0x1020); // AddressOfRawData
	rz_write_le32(buf + 0x218, 0x220); // PointerToRawData
	// CodeView RSDS record at 0x220
	memcpy(buf + 0x220, "RSDS", 4);
	rz_write_le32(buf + 0x224, 0x01020304);
	rz_write_le16(buf + 0x228, 0x0506);
	rz_write_le16(buf + 0x22a, 0x0708);
	const ut8 d4[8] = { 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
	memcpy(buf + 0x22c, d4, sizeof(d4));
	rz_write_le32(buf + 0x234, 1); // age
	memcpy(buf + 0x238, "ntkrnlmp.pdb", 13);
}

static bool mock_kd_recv_all(int fd, ut8 *buf, size_t len) {
	size_t off = 0;
	while (off < len) {
		ssize_t r = recv(fd, buf + off, len - off, 0);
		if (r <= 0) {
			return false;
		}
		off += (size_t)r;
	}
	return true;
}

static bool mock_kd_send_all(int fd, const ut8 *buf, size_t len) {
	size_t off = 0;
	while (off < len) {
		ssize_t w = send(fd, buf + off, len - off, 0);
		if (w <= 0) {
			return false;
		}
		off += (size_t)w;
	}
	return true;
}

static bool mock_kd_send_pkt(int fd, ut32 leader, ut16 type, ut32 id, const ut8 *data, ut16 len) {
	ut32 csum = 0;
	for (ut16 i = 0; i < len; i++) {
		csum += data[i];
	}
	ut8 hdr[16];
	rz_write_le32(hdr + 0, leader);
	rz_write_le16(hdr + 4, type);
	rz_write_le16(hdr + 6, len);
	rz_write_le32(hdr + 8, id);
	rz_write_le32(hdr + 12, csum);
	if (!mock_kd_send_all(fd, hdr, sizeof(hdr))) {
		return false;
	}
	if (len && !mock_kd_send_all(fd, data, len)) {
		return false;
	}
	if (leader == 0x30303030U) {
		const ut8 trailer = 0xAA;
		if (!mock_kd_send_all(fd, &trailer, 1)) {
			return false;
		}
	}
	return true;
}

static void *mock_kd_server_fn(void *user) {
	MockKdServer *srv = user;
	int cfd = accept(srv->listen_fd, NULL, NULL);
	if (cfd < 0) {
		return NULL;
	}
	ut32 srv_id = 0x80800001U;
	for (;;) {
		ut8 hdr[16];
		if (!mock_kd_recv_all(cfd, hdr, 1)) {
			break;
		}
		if (hdr[0] == 'b') {
			continue;
		}
		if (!mock_kd_recv_all(cfd, hdr + 1, sizeof(hdr) - 1)) {
			break;
		}
		ut32 leader = rz_read_le32(hdr + 0);
		ut16 type = rz_read_le16(hdr + 4);
		ut16 len = rz_read_le16(hdr + 6);
		ut32 id = rz_read_le32(hdr + 8);
		if (leader == 0x69696969U) { // KD_PACKET_CTRL
			if (type == 6) { // KD_PACKET_TYPE_RESET
				if (!mock_kd_send_pkt(cfd, 0x69696969U, 6, 0x80800000U, NULL, 0)) {
					break;
				}
				ut8 stc[64] = { 0 };
				rz_write_le32(stc + 0, 0x00003030U); // DbgKdExceptionStateChange
				rz_write_le32(stc + 8, 1); // cpu_count
				if (!mock_kd_send_pkt(cfd, 0x30303030U, 7, srv_id++, stc, sizeof(stc))) {
					break;
				}
			}
			continue;
		}
		if (leader != 0x30303030U || len > 0x480) {
			break;
		}
		ut8 payload[0x480];
		ut8 trailer = 0;
		if (len && !mock_kd_recv_all(cfd, payload, len)) {
			break;
		}
		if (!mock_kd_recv_all(cfd, &trailer, 1)) {
			break;
		}
		// Acknowledge client's data packet
		if (!mock_kd_send_pkt(cfd, 0x69696969U, 4, id, NULL, 0)) {
			break;
		}
		if (len < 56) {
			continue;
		}
		ut32 req = rz_read_le32(payload);
		if (req == 0x00003146U) { // DbgKdGetVersionApi
			ut8 resp[56] = { 0 };
			rz_write_le32(resp + 0, 0x00003146U);
			rz_write_le16(resp + 16, 15); // major
			rz_write_le16(resp + 18, 19041); // minor (Win10 20H2 x64)
			resp[20] = 2; // proto_major
			rz_write_le16(resp + 22, 0x0006); // DBGKD_VERS_FLAG_DATA | DBGKD_VERS_FLAG_PTR64
			rz_write_le16(resp + 24, 0x8664); // KD_MACH_AMD64
			rz_write_le64(resp + 32, MOCK_KD_KERNEL_BASE);
			rz_write_le64(resp + 48, MOCK_KD_DBG_PTR);
			if (!mock_kd_send_pkt(cfd, 0x30303030U, 2, srv_id++, resp, sizeof(resp))) {
				break;
			}
		} else if (req == 0x00003130U) { // DbgKdReadVirtualMemoryApi
			ut64 addr = rz_read_le64(payload + 16);
			ut32 rlen = rz_read_le32(payload + 24);
			if (rlen > 0x400) {
				rlen = 0x400;
			}
			ut8 resp[56 + 0x400] = { 0 };
			rz_write_le32(resp + 0, 0x00003130U);
			rz_write_le64(resp + 16, addr);
			rz_write_le32(resp + 24, rlen);
			rz_write_le32(resp + 28, rlen);
			if (addr == MOCK_KD_DBG_PTR && rlen >= 8) {
				rz_write_le64(resp + 56, MOCK_KD_DBG_BLOCK);
			} else if (addr == MOCK_KD_DBG_BLOCK + 0x036 && rlen >= 2) {
				rz_write_le16(resp + 56, 1); // K_PaeEnabled
			} else if (addr == MOCK_KD_DBG_BLOCK + 0x268 && rlen >= 8) {
				rz_write_le64(resp + 56, MOCK_KD_CSD_PTR); // K_CmNtCSDVersion
			} else if (addr >= MOCK_KD_KERNEL_BASE && addr + rlen <= MOCK_KD_KERNEL_BASE + sizeof(srv->pe_image)) {
				memcpy(resp + 56, srv->pe_image + (addr - MOCK_KD_KERNEL_BASE), rlen);
			}
			if (!mock_kd_send_pkt(cfd, 0x30303030U, 2, srv_id++, resp, (ut16)(56 + rlen))) {
				break;
			}
		} else {
			ut8 resp[56] = { 0 };
			rz_write_le32(resp + 0, req);
			rz_write_le32(resp + 8, 0xC0000001U); // KD_RET_ERR
			if (!mock_kd_send_pkt(cfd, 0x30303030U, 2, srv_id++, resp, sizeof(resp))) {
				break;
			}
		}
	}
	close(cfd);
	return NULL;
}

static int mock_winkd_cmdf(void *core, const char *fmt, ...) {
	(void)core;
	(void)fmt;
	return 0;
}

static bool test_debug_winkd_attach_and_read_ver(void) {
	char *tmp_base = rz_file_temp("rz_winkd");
	mu_assert_notnull(tmp_base, "rz_file_temp for winkd test");
	rz_file_rm(tmp_base);
	mu_assert_true(rz_sys_mkdirp(tmp_base), "mkdir winkd temp dir");

	char *sock_path = rz_str_newf("%s/kd.sock", tmp_base);
	char *symstore = rz_str_newf("%s/sym", tmp_base);
	char *exe_dir = rz_str_newf("%s/ntoskrnl.exe/112233442000", symstore);
	char *exe_path = rz_str_newf("%s/ntoskrnl.exe", exe_dir);
	char *pdb_dir = rz_str_newf("%s/ntkrnlmp.pdb/0102030405060708090A0B0C0D0E0F101", symstore);
	char *pdb_path = rz_str_newf("%s/ntkrnlmp.pdb", pdb_dir);
	char *exe_parent = rz_str_newf("%s/ntoskrnl.exe", symstore);
	char *pdb_parent = rz_str_newf("%s/ntkrnlmp.pdb", symstore);
	char *uri = rz_str_newf("winkd://%s", sock_path);

	MockKdServer srv = { .listen_fd = -1 };
	build_mock_ntoskrnl_pe(srv.pe_image, sizeof(srv.pe_image));

	srv.listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	mu_assert_neq(srv.listen_fd, -1, "create AF_UNIX socket");
	struct sockaddr_un sa = { 0 };
	sa.sun_family = AF_UNIX;
	rz_str_ncpy(sa.sun_path, sock_path, sizeof(sa.sun_path));
	mu_assert_eq(bind(srv.listen_fd, (struct sockaddr *)&sa, sizeof(sa)), 0, "bind AF_UNIX socket");
	mu_assert_eq(listen(srv.listen_fd, 1), 0, "listen AF_UNIX socket");

	RzThread *th = rz_th_new(mock_kd_server_fn, &srv);
	mu_assert_notnull(th, "start mock KD server thread");

	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "rz_core_new for winkd");
	core->dbg->corebind.cmdf = mock_winkd_cmdf;
	rz_config_set(core->config, "pdb.symstore", symstore);
	rz_config_set(core->config, "pdb.server", "");

	RzCoreFile *cf = rz_core_file_open(core, uri, RZ_PERM_RW, 0);
	mu_assert_notnull(cf, "open winkd:// mock socket");
	// rz_debug_use() triggers reg_profile -> winkd_attach (which syncs, runs winkd_read_ver, and fails download)
	mu_assert_true(rz_debug_use(core->dbg, "winkd"), "select winkd debug plugin");

	// Detach resets syncd so explicit attach re-runs winkd_read_ver (replacing old profile) and hits download failure
	mu_assert_true(rz_debug_detach(core->dbg, 0), "winkd detach before explicit fail attach");
	mu_assert_false(rz_debug_attach(core->dbg, 0), "winkd attach fails when pdb.server is empty");

	// Populate local symstore cache so download succeeds without network traffic
	mu_assert_true(rz_sys_mkdirp(exe_dir), "mkdir cached ntoskrnl.exe dir");
	mu_assert_true(rz_file_dump(exe_path, srv.pe_image, sizeof(srv.pe_image), false), "dump cached ntoskrnl.exe");
	mu_assert_true(rz_sys_mkdirp(pdb_dir), "mkdir cached pdb dir");
	const ut8 dummy_pdb[4] = { 'P', 'D', 'B', 0 };
	mu_assert_true(rz_file_dump(pdb_path, dummy_pdb, sizeof(dummy_pdb), false), "dump cached pdb");

	// Detach resets syncd so second attach re-runs winkd_read_ver (replacing old profile) and succeeds
	mu_assert_true(rz_debug_detach(core->dbg, 0), "winkd detach");
	rz_config_set(core->config, "pdb.server", "http://127.0.0.1:1");
	mu_assert_true(rz_debug_attach(core->dbg, 0), "winkd attach succeeds with cached module and pdb");

	rz_core_free(core);
	rz_th_wait(th);
	rz_th_free(th);
	close(srv.listen_fd);

	rz_file_rm(exe_path);
	rz_file_rm(pdb_path);
	unlink(sock_path);
	rmdir(exe_dir);
	rmdir(exe_parent);
	rmdir(pdb_dir);
	rmdir(pdb_parent);
	rmdir(symstore);
	rmdir(tmp_base);

	free(uri);
	free(pdb_parent);
	free(exe_parent);
	free(pdb_path);
	free(pdb_dir);
	free(exe_path);
	free(exe_dir);
	free(symstore);
	free(sock_path);
	free(tmp_base);
	mu_end;
}
#endif

int all_tests() {
	RzCons *cons = rz_cons_new(); // there is some windows-specific code in debug that accesses the cons singleton
	mu_run_test(test_rz_debug_use);
	mu_run_test(test_rz_debug_reg_offset);
	mu_run_test(test_debug_sw_bp);
	mu_run_test(test_debug_sw_bp_multibits);
	mu_run_test(test_debug_hw_bp);
	mu_run_test(test_debug_hw_watch);
	mu_run_test(test_debug_reg_sync_flg);
	mu_run_test(test_io_dmp_open_close);
	mu_run_test(test_debug_dmp_reinit);
#if __UNIX__
	mu_run_test(test_debug_winkd_attach_and_read_ver);
#endif
	rz_cons_free(cons);
	return tests_passed != tests_run;
}

mu_main(all_tests)
