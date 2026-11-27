// SPDX-FileCopyrightText: 2020 Khairulmizam Samsudin <xource@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_socket.h>
#include <rz_debug.h>
#include <libgdbr.h>
#include <gdbclient/commands.h>
#include <gdbclient/xml.h>
#include "minunit.h"
#if __UNIX__
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
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

static bool test_debug_gdb_disconnected(void) {
	RzBreakpointContext local_bp_ctx = { 0 };
	RzDebug *dbg = rz_debug_new(&local_bp_ctx);
	mu_assert_notnull(dbg, "rz_debug_new()");
	RzAnalysis *analysis = rz_analysis_new(NULL);
	mu_assert_notnull(analysis, "rz_analysis_new()");
	rz_analysis_use(analysis, "x86");
	rz_analysis_set_bits(analysis, 64);
	dbg->analysis = analysis;
	mu_assert_true(rz_debug_use(dbg, "gdb"), "use gdb debug plugin");

	// Attach with unbound IO, NULL dbg, NULL fini ctx, and NULL bp/item must fail safely
	mu_assert_false(dbg->cur->attach(NULL, 1), "attach fails when dbg is NULL");
	dbg->cur->fini(dbg, NULL);
	mu_assert_false(rz_debug_attach(dbg, 1), "attach fails when iob.io is NULL");
	RzBreakpoint null_bp = { 0 };
	RzBreakpointItem bp_item = { .addr = 0x1000, .size = 4, .perm = RZ_PERM_X };
	mu_assert_false(dbg->cur->breakpoint(&null_bp, &bp_item, true), "gdb bp fails on NULL dbg");
	mu_assert_false(dbg->cur->breakpoint(dbg->bp, NULL, true), "gdb bp fails on NULL item");

	RzIO *io = rz_io_new();
	mu_assert_notnull(io, "rz_io_new()");
	rz_io_bind(io, &dbg->iob);
	rz_io_bind(io, &dbg->bp->iob);

	// io_gdb __close handles NULL fd and NULL fd->data safely
	RzIOPlugin *gdb_io_plugin = rz_io_plugin_resolve(io, "gdb://127.0.0.1:1234", false);
	mu_assert_notnull(gdb_io_plugin, "resolve io_gdb plugin");
	RzIODesc empty_gdb_desc = { .plugin = gdb_io_plugin, .data = NULL };
	mu_assert_eq(gdb_io_plugin->close(NULL), 0, "io_gdb __close(NULL) returns 0");
	mu_assert_eq(gdb_io_plugin->close(&empty_gdb_desc), 0, "io_gdb __close(empty data) returns 0");

	// NULL plugin_data guard in debug_gdb_get_desc
	void *saved_plugin_data = dbg->plugin_data;
	dbg->plugin_data = NULL;
	mu_assert_null(dbg->cur->threads(dbg, 1), "gdb threads NULL when plugin_data is NULL");
	dbg->plugin_data = saved_plugin_data;

	// Failed gdb:// open must clean up libgdbr resources cleanly
	mu_assert_null(rz_io_open_nomap(io, "gdb:///nonexistent_rz_gdb_serial_dev", RZ_PERM_RWX, 0),
		"gdb:// open fails cleanly when connect fails");

	// Non-gdb IO descriptor must be rejected cleanly by attach
	RzIODesc *mem_desc = rz_io_open_at(io, "malloc://0x10000", RZ_PERM_RWX, 0644, 0x1000, NULL);
	mu_assert_notnull(mem_desc, "open malloc:// for gdb/fuzzy test");
	mu_assert_false(rz_debug_attach(dbg, 1), "attach fails on non-gdb IO desc");

	// Disconnected gdb plugin guards must fail cleanly without UAF/crash
	dbg->pid = 1;
	mu_assert_null(dbg->cur->threads(dbg, 1), "gdb threads NULL when disconnected");
	mu_assert_null(dbg->cur->pids(dbg, 1), "gdb pids NULL when disconnected");
	mu_assert_eq(rz_debug_detach(dbg, 1), -1, "gdb detach fails when disconnected");
	mu_assert_false(rz_debug_kill(dbg, 1, 1, 9), "gdb kill fails when disconnected");
	mu_assert_false(rz_debug_select(dbg, 1, 1), "gdb select fails when disconnected");
	mu_assert_null(rz_debug_info(dbg, NULL), "gdb info NULL when disconnected");
	mu_assert_false(dbg->cur->set_reg_profile(dbg, "gpr eax .32 0 0\n"),
		"gdb set_reg_profile fails when disconnected");
	mu_assert_false(dbg->cur->breakpoint(dbg->bp, &bp_item, true),
		"gdb bp fails when disconnected");
	(void)rz_debug_reg_profile_sync(dbg);
	(void)rz_debug_step(dbg, 1);
	(void)rz_debug_wait(dbg, NULL);

	rz_debug_free(dbg);
	rz_analysis_free(analysis);
	rz_io_free(io);
	mu_end;
}

static bool test_rzgdb_profile_and_cleanup(void) {
	libgdbr_t g;
	mu_assert_eq(gdbr_init(&g, false), 0, "gdbr_init");
	mu_assert_eq(gdbr_init(NULL, false), -1, "gdbr_init NULL");
	mu_assert_eq(gdbr_disconnect(NULL), -1, "gdbr_disconnect NULL");
	mu_assert_eq(gdbr_set_reg_profile(NULL, "gpr eax .32 0 0\n"), -1, "set_reg_profile NULL g");
	mu_assert_eq(gdbr_set_reg_profile(&g, NULL), -1, "set_reg_profile NULL str");

	mu_assert_true(gdbr_set_architecture(&g, RZ_SYS_ARCH_X86, 64), "set_architecture x86 64");
	mu_assert_true(g.target.valid, "target.valid set on success");
	mu_assert_notnull(g.target.regprofile, "target.regprofile set");
	mu_assert_notnull(g.registers, "registers parsed");
	mu_assert_true(gdbr_set_architecture(&g, RZ_SYS_ARCH_X86, 64), "set_architecture cached");

	char *prev_profile = g.target.regprofile;
	gdb_reg_t *prev_regs = g.registers;
	mu_assert_eq(gdbr_set_reg_profile(&g, "gpr eax .0 0\n"), -1,
		"invalid reg profile rejected");
	mu_assert_ptreq(g.target.regprofile, prev_profile, "old regprofile preserved on failure");
	mu_assert_ptreq(g.registers, prev_regs, "old registers preserved on failure");

	mu_assert_eq(gdbr_set_reg_profile(&g, "gpr eax .32 0 0\n"), 0, "replace reg profile 1");
	mu_assert_eq(gdbr_set_reg_profile(&g, "gpr rax .64 0 0\n"), 0, "replace reg profile 2");
	// Teardown disconnect must not dereference a freed intr (rz_core_fini order)
	// and must still release target state when isbreaked is set.
	RzInterrupt *intr = rz_interrupt_new();
	mu_assert_notnull(intr, "rz_interrupt_new");
	gdbr_set_interrupt(&g, intr);
	rz_interrupt_free(intr);
	g.isbreaked = true;
	mu_assert_eq(gdbr_disconnect(&g), 0, "gdbr_disconnect clears target state");
	mu_assert_null(g.target.regprofile, "regprofile cleared by disconnect");
	mu_assert_null(g.registers, "registers cleared by disconnect");
	mu_assert_false(g.target.valid, "target.valid cleared by disconnect");
	gdbr_set_interrupt(&g, NULL);
	g.isbreaked = false;

	// Repopulate and verify gdbr_cleanup frees target.regprofile and registers directly
	mu_assert_false(gdbr_set_architecture(&g, RZ_SYS_ARCH_X86, 128), "unsupported bits fails");
	mu_assert_eq(gdbr_set_reg_profile(&g, "gpr eax .32 0 0\n"), 0, "repopulate reg profile");
	mu_assert_eq(gdbr_cleanup(&g), 0, "gdbr_cleanup frees buffers and reg profile");
	mu_assert_null(g.target.regprofile, "regprofile cleared by cleanup");
	mu_assert_null(g.registers, "registers cleared by cleanup");

#if __UNIX__
	// gdbr_disconnect with NULL gdbr_lock and already-closed fd returns -1 safely
	int tmp_fds[2] = { -1, -1 };
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, tmp_fds) == 0) {
		close(tmp_fds[0]);
		close(tmp_fds[1]);
		libgdbr_t g_nolock = { 0 };
		g_nolock.sock = rz_socket_new_from_fd(tmp_fds[0]);
		mu_assert_eq(gdbr_disconnect(&g_nolock), -1,
			"gdbr_disconnect without lock on closed fd returns -1");
		rz_socket_free(g_nolock.sock);
	}
#endif
	mu_end;
}

#if __UNIX__
typedef struct {
	int fd;
	const char *const *replies;
	size_t count;
} MockGdbServer;

static bool mock_gdb_send_all(int fd, const void *buf, size_t len) {
	const ut8 *p = buf;
	size_t sent = 0;
	while (sent < len) {
		ssize_t n = send(fd, p + sent, len - sent, 0);
		if (n <= 0) {
			return false;
		}
		sent += (size_t)n;
	}
	return true;
}

static bool mock_gdb_read_packet(int fd, char *out, size_t out_sz) {
	char ch = 0;
	bool in_pkt = false;
	size_t pos = 0;
	while (true) {
		ssize_t n = recv(fd, &ch, 1, 0);
		if (n <= 0) {
			return false;
		}
		if (!in_pkt) {
			if (ch == '$') {
				in_pkt = true;
				pos = 0;
			}
			continue;
		}
		if (ch == '#') {
			char csum[2];
			size_t got = 0;
			while (got < 2) {
				n = recv(fd, csum + got, 2 - got, 0);
				if (n <= 0) {
					return false;
				}
				got += (size_t)n;
			}
			if (out && out_sz > 0) {
				out[pos] = '\0';
			}
			return true;
		}
		if (out && pos + 1 < out_sz) {
			out[pos++] = ch;
		}
	}
}

static bool mock_gdb_send_packet(int fd, const char *payload) {
	size_t len = strlen(payload);
	ut8 sum = 0;
	for (size_t j = 0; j < len; j++) {
		sum += (ut8)payload[j];
	}
	size_t pkt_len = 1 + len + 3;
	char *pkt = malloc(pkt_len + 1);
	if (!pkt) {
		return false;
	}
	pkt[0] = '$';
	if (len > 0) {
		memcpy(pkt + 1, payload, len);
	}
	snprintf(pkt + 1 + len, 4, "#%02x", sum);
	bool ok = mock_gdb_send_all(fd, pkt, pkt_len);
	free(pkt);
	return ok;
}

static void *mock_gdb_server_th(void *user) {
	MockGdbServer *srv = user;
	for (size_t i = 0; i < srv->count; i++) {
		if (!mock_gdb_read_packet(srv->fd, NULL, 0)) {
			break;
		}
		if (!mock_gdb_send_packet(srv->fd, srv->replies[i])) {
			break;
		}
	}
	return NULL;
}

static void *mock_gdb_dispatch_th(void *user) {
	int fd = *(int *)user;
	char req[256];
	while (mock_gdb_read_packet(fd, req, sizeof(req))) {
		const char *reply = "OK";
		if (!strcmp(req, "g")) {
			reply = "0000000000000000";
		} else if (rz_str_startswith(req, "qXfer:exec-file:read:")) {
			reply = "l/bin/test";
		} else if (!strcmp(req, "qfThreadInfo")) {
			reply = "mp2a.2a";
		} else if (!strcmp(req, "qsThreadInfo")) {
			reply = "l";
		} else if (!strcmp(req, "?")) {
			reply = "T05thread:p2a.2a;";
		}
		if (!mock_gdb_send_packet(fd, reply)) {
			break;
		}
	}
	return NULL;
}

static void *mock_gdb_err_dispatch_th(void *user) {
	int fd = *(int *)user;
	char req[256];
	while (mock_gdb_read_packet(fd, req, sizeof(req))) {
		const char *reply = "";
		if (!strcmp(req, "g")) {
			reply = "0000000000000000";
		} else if (rz_str_startswith(req, "Hg")) {
			reply = "OK";
		}
		if (!mock_gdb_send_packet(fd, reply)) {
			break;
		}
	}
	return NULL;
}

static bool mock_gdb_socketpair(int fds[2]) {
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
		return false;
	}
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
	(void)setsockopt(fds[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(fds[1], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	return true;
}

static void *mock_gdb_tcp_attach_fail_th(void *user) {
	int listen_fd = *(int *)user;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
	(void)setsockopt(listen_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	int cfd = accept(listen_fd, NULL, NULL);
	if (cfd < 0) {
		return NULL;
	}
	(void)setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	char req[256];
	while (mock_gdb_read_packet(cfd, req, sizeof(req))) {
		const char *reply = "OK";
		if (rz_str_startswith(req, "qSupported")) {
			reply = "PacketSize=4000;QStartNoAckMode+;multiprocess+";
		} else if (!strcmp(req, "QStartNoAckMode")) {
			reply = "OK";
		} else if (!strcmp(req, "qGDBServerVersion")) {
			reply = "";
		} else if (!strcmp(req, "qC")) {
			reply = "QCp2a.2a";
		} else if (!strcmp(req, "vCont?")) {
			reply = "vCont;c;s";
		} else if (!strcmp(req, "!")) {
			// Reject extended mode so gdbr_attach() returns < 0
			reply = "";
		}
		if (!mock_gdb_send_packet(cfd, reply)) {
			break;
		}
		if (!strcmp(req, "!")) {
			break;
		}
	}
	close(cfd);
	return NULL;
}

static bool test_rzgdb_and_debug_gdb_mock_rsp(void) {
	// 1. Direct rzgdb protocol tests: >4095B cmdline clamping, empty cmdline, xml read fail,
	//    xml cleanup, target.xml, qfThreadInfo/qsThreadInfo pids & threads success + error paths
	int fds[2] = { -1, -1 };
	mu_assert_true(mock_gdb_socketpair(fds), "socketpair 1");

	// Build two osdata chunks totaling >4095B command to test stack-buffer clamping
	const char *xml_prefix = "m<osdata type=\"processes\">"
				 "<item><column name=\"pid\">42</column><column name=\"command\">";
	const char *xml_suffix = "</column></item>"
				 "<item><column name=\"pid\">99</column><column name=\"command\">other</column></item>"
				 "<item><column name=\"pid\">43</column><column name=\"command\"></column></item>"
				 "<item><column name=\"pid\">44</column><column name=\"command\">failread</column></item>"
				 "</osdata>";
	size_t prefix_len = strlen(xml_prefix);
	size_t suffix_len = strlen(xml_suffix);
	char *chunk1 = malloc(prefix_len + 2500 + 1);
	char *chunk2 = malloc(1 + 1700 + suffix_len + 1);
	if (!chunk1 || !chunk2) {
		free(chunk1);
		free(chunk2);
		close(fds[0]);
		close(fds[1]);
		return false;
	}
	memcpy(chunk1, xml_prefix, prefix_len);
	memset(chunk1 + prefix_len, 'A', 2500);
	chunk1[prefix_len + 2500] = '\0';
	chunk2[0] = 'l';
	memset(chunk2 + 1, 'A', 1700);
	memcpy(chunk2 + 1 + 1700, xml_suffix, suffix_len + 1);

	const char *target_xml =
		"l<target><architecture>i386:x86-64</architecture>"
		"<feature name=\"org.gnu.gdb.i386.core\">"
		"<reg name=\"rax\" bitsize=\"64\"/><reg name=\"rip\" bitsize=\"64\"/>"
		"</feature></target>";
	const char *bad_proc_xml = "l<osdata type=\"processes\"><item><column name=\"pid\">42</column>";

	const char *replies1[] = {
		// gdbr_pids_list (processes XML: 4200B cmdline, filtered pid 99, empty cmdline 43, read-fail 44)
		chunk1,
		chunk2,
		"F-1,2", // vFile:open /proc/42/status -> fallback pid_info with clamped cmdline
		"F5", // vFile:open /proc/99/status -> fd 5
		"F1f;State:\tS\nPPid:\t1\nUid:\t0\nGid:\t0\n", // vFile:pread
		"F0;", // vFile:pread EOF
		"F0", // vFile:close
		"F-1,2", // vFile:open /proc/43/status (empty cmdline -> copy_len == 0)
		"F6", // vFile:open /proc/44/status -> fd 6
		"E01", // vFile:pread fails (returns -1) -> pid_info remains NULL -> continue
		"F0", // vFile:close
		// gdbr_read_processes_xml malformed XML cleanup
		bad_proc_xml,
		// gdbr_read_target_xml replacing existing g->registers
		target_xml,
		// gdbr_pids_list fallback (qfThreadInfo/qsThreadInfo) success with dup pid
		"l/bin/test", // qXfer:exec-file:read
		"mp2a.2a,p2a.2b,p2c.2c", // qfThreadInfo
		"l", // qsThreadInfo
		// gdbr_pids_list with qXfer_exec_file_read = false
		"mp2a.2a",
		"l",
		// gdbr_pids_list with qXfer_exec_file_read = true returning empty
		"",
		"mp2a.2a",
		"l",
		// gdbr_pids_list fallback error cleanup (empty qsThreadInfo)
		"l/bin/test",
		"mp2a.2a",
		"",
		// gdbr_threads_list success (alive + dead thread)
		"l/bin/test",
		"mp2a.2a,p2a.2b",
		"l",
		"OK", // Tp2a.2a alive
		"E01", // Tp2a.2b dead
		// gdbr_threads_list with qXfer_exec_file_read = false
		"mp2a.2a",
		"l",
		"OK",
		// gdbr_threads_list with qXfer_exec_file_read = true returning empty + qfThreadInfo failure (list == NULL)
		"",
		"",
		// gdbr_threads_list error cleanup (empty qsThreadInfo)
		"l/bin/test",
		"mp2a.2a",
		"",
	};
	MockGdbServer srv1 = { .fd = fds[1], .replies = replies1, .count = RZ_ARRAY_SIZE(replies1) };
	RzThread *th1 = rz_th_new(mock_gdb_server_th, &srv1);
	mu_assert_notnull(th1, "start mock gdb server 1");

	libgdbr_t g;
	mu_assert_eq(gdbr_init(&g, false), 0, "gdbr_init mock 1");
	rz_socket_free(g.sock);
	g.sock = rz_socket_new_from_fd(fds[0]);
	g.no_ack = true;
	g.connected = 1;
	g.num_retries = 16;
	g.pid = 0x2a;
	g.tid = 0x2a;
	g.stub_features.pkt_sz = 3000;
	g.stub_features.multiprocess = true;
	g.stub_features.qXfer_features_read = true;
	g.stub_features.qXfer_threads_read = true;
	g.stub_features.qXfer_exec_file_read = true;
	mu_assert_true(gdbr_set_architecture(&g, RZ_SYS_ARCH_X86, 64), "set arch before target xml");

	RzList *pids = gdbr_pids_list(&g, 42);
	mu_assert_notnull(pids, "gdbr_pids_list via processes xml");
	pids->free = (RzListFree)rz_debug_pid_free;
	mu_assert_eq(rz_list_length(pids), 1, "only matching pid 42 kept");
	RzDebugPid *p0 = rz_list_first_val(pids);
	mu_assert_notnull(p0, "pid 42 entry");
	mu_assert_eq(p0->pid, 42, "pid 42 value");
	mu_assert_eq(strlen(p0->path), 4095, "4200B cmdline clamped to 4095B");
	rz_list_free(pids);

	RzList *bad_list = rz_list_newf((RzListFree)rz_debug_pid_free);
	mu_assert_eq(gdbr_read_processes_xml(&g, 42, bad_list), -1, "malformed processes xml fails");
	rz_list_free(bad_list);

	mu_assert_eq(gdbr_read_target_xml(&g), 0, "gdbr_read_target_xml replaces registers cleanly");

	g.stub_features.qXfer_threads_read = false;
	pids = gdbr_pids_list(&g, 0x2a);
	mu_assert_notnull(pids, "gdbr_pids_list qfThreadInfo fallback");
	pids->free = (RzListFree)rz_debug_pid_free;
	mu_assert_eq(rz_list_length(pids), 2, "deduplicated pids 0x2a and child 0x2c");
	rz_list_free(pids);

	g.stub_features.qXfer_exec_file_read = false;
	pids = gdbr_pids_list(&g, 0x2a);
	mu_assert_notnull(pids, "gdbr_pids_list without exec_file feature");
	pids->free = (RzListFree)rz_debug_pid_free;
	mu_assert_eq(rz_list_length(pids), 1, "one pid without exec_file");
	rz_list_free(pids);

	g.stub_features.qXfer_exec_file_read = true;
	pids = gdbr_pids_list(&g, 0x2a);
	mu_assert_notnull(pids, "gdbr_pids_list when exec_file reply empty");
	pids->free = (RzListFree)rz_debug_pid_free;
	mu_assert_eq(rz_list_length(pids), 1, "one pid with empty exec_file");
	rz_list_free(pids);

	mu_assert_null(gdbr_pids_list(&g, 0x2a), "gdbr_pids_list error path frees partial list");

	RzList *threads = gdbr_threads_list(&g, 0x2a);
	mu_assert_notnull(threads, "gdbr_threads_list success");
	threads->free = (RzListFree)rz_debug_pid_free;
	mu_assert_eq(rz_list_length(threads), 2, "two threads parsed");
	RzDebugPid *t1 = rz_list_get_n(threads, 1);
	mu_assert_notnull(t1, "second thread");
	mu_assert_eq(t1->status, RZ_DBG_PROC_DEAD, "second thread marked dead");
	rz_list_free(threads);

	g.stub_features.qXfer_exec_file_read = false;
	threads = gdbr_threads_list(&g, 0x2a);
	mu_assert_notnull(threads, "gdbr_threads_list without exec_file feature");
	threads->free = (RzListFree)rz_debug_pid_free;
	mu_assert_eq(rz_list_length(threads), 1, "one thread without exec_file");
	rz_list_free(threads);

	g.stub_features.qXfer_exec_file_read = true;
	mu_assert_null(gdbr_threads_list(&g, 0x2a),
		"gdbr_threads_list fails before list alloc -> gdbr_pid_list_free(NULL)");

	mu_assert_null(gdbr_threads_list(&g, 0x2a), "gdbr_threads_list error path frees partial list");

	mu_assert_eq(gdbr_disconnect(&g), 0, "gdbr_disconnect on connected socketpair");
	gdbr_cleanup(&g);
	rz_th_wait(th1);
	rz_th_free(th1);
	close(fds[1]);
	free(chunk1);
	free(chunk2);

	// 2. Live debug_gdb + io_gdb::__close + debug_gdb_get_desc() stale-fd & reused-fd tests
	int fds2[2] = { -1, -1 };
	mu_assert_true(mock_gdb_socketpair(fds2), "socketpair 2");
	RzThread *th2 = rz_th_new(mock_gdb_dispatch_th, &fds2[1]);
	mu_assert_notnull(th2, "start mock gdb server 2");

	RzBreakpointContext bp_ctx = { 0 };
	RzDebug *dbg = rz_debug_new(&bp_ctx);
	mu_assert_notnull(dbg, "rz_debug_new mock");
	RzAnalysis *analysis = rz_analysis_new(NULL);
	mu_assert_notnull(analysis, "rz_analysis_new mock");
	rz_analysis_use(analysis, "x86");
	rz_analysis_set_bits(analysis, 64);
	dbg->analysis = analysis;
	RzIO *io = rz_io_new();
	mu_assert_notnull(io, "rz_io_new mock");
	rz_io_bind(io, &dbg->iob);
	rz_io_bind(io, &dbg->bp->iob);
	mu_assert_true(rz_debug_use(dbg, "gdb"), "use gdb plugin mock");

	RzIOPlugin *gdb_plugin = rz_io_plugin_resolve(io, "gdb://127.0.0.1:1234", false);
	mu_assert_notnull(gdb_plugin, "resolve io_gdb plugin");
	libgdbr_t *gd = RZ_NEW0(libgdbr_t);
	if (!gd) {
		rz_debug_free(dbg);
		rz_analysis_free(analysis);
		rz_io_free(io);
		close(fds2[0]);
		rz_th_wait(th2);
		rz_th_free(th2);
		close(fds2[1]);
		return false;
	}
	mu_assert_eq(gdbr_init(gd, false), 0, "gdbr_init io_gdb desc");
	rz_socket_free(gd->sock);
	gd->sock = rz_socket_new_from_fd(fds2[0]);
	gd->no_ack = true;
	gd->connected = 1;
	gd->num_retries = 16;
	gd->pid = 0x2a;
	gd->tid = 0x2a;
	gd->stub_features.multiprocess = true;
	gd->stub_features.qXfer_exec_file_read = true;

	RzIODesc *gdb_desc = rz_io_desc_new(io, gdb_plugin, "gdb://127.0.0.1:1234", RZ_PERM_RWX, gd);
	mu_assert_notnull(gdb_desc, "rz_io_desc_new gdb");
	mu_assert_true(rz_io_desc_add(io, gdb_desc), "rz_io_desc_add gdb");
	io->desc = gdb_desc;

	mu_assert_true(rz_debug_attach(dbg, 0x2a), "rz_debug_attach succeeds on gdb desc");
	dbg->pid = 0x2a;
	dbg->tid = 0x2a;
	mu_assert_true(rz_debug_reg_profile_sync(dbg), "sync gdb reg profile");
	mu_assert_true(rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false), "live gdb reg read");

	RzDebugInfo *info = rz_debug_info(dbg, NULL);
	mu_assert_notnull(info, "live rz_debug_info");
	mu_assert_eq(info->pid, 0x2a, "info pid");
	mu_assert_streq(info->exe, "/bin/test", "info exe");
	rz_debug_info_free(info);

	RzList *live_pids = dbg->cur->pids(dbg, 0x2a);
	mu_assert_notnull(live_pids, "live gdb pids");
	mu_assert_eq(rz_list_length(live_pids), 1, "live gdb pids count");
	rz_list_free(live_pids);

	mu_assert_true(rz_debug_select(dbg, 0x2a, 0x2a), "live gdb select");
	mu_assert_eq(dbg->cur->set_reg_profile(dbg, "gpr eax .32 0 0\n"), 0, "live set_reg_profile");
	mu_assert_false(dbg->cur->set_reg_profile(dbg, NULL), "live set_reg_profile NULL str");

	// Exercise all breakpoint and watchpoint set/remove paths
	RzBreakpointItem bp_sw = { .addr = 0x1000, .size = 4, .perm = RZ_PERM_X, .hw = false };
	RzBreakpointItem bp_hw = { .addr = 0x1004, .size = 4, .perm = RZ_PERM_X, .hw = true };
	RzBreakpointItem wp_w = { .addr = 0x2000, .size = 1, .perm = RZ_PERM_W, .hw = true };
	RzBreakpointItem wp_r = { .addr = 0x2004, .size = 1, .perm = RZ_PERM_R, .hw = true };
	RzBreakpointItem wp_a = { .addr = 0x2008, .size = 1, .perm = RZ_PERM_ACCESS, .hw = true };
	mu_assert_true(dbg->cur->breakpoint(dbg->bp, &bp_sw, true), "live gdb sw bp set");
	mu_assert_true(dbg->cur->breakpoint(dbg->bp, &bp_sw, false), "live gdb sw bp remove");
	mu_assert_true(dbg->cur->breakpoint(dbg->bp, &bp_hw, true), "live gdb hw bp set");
	mu_assert_true(dbg->cur->breakpoint(dbg->bp, &bp_hw, false), "live gdb hw bp remove");
	mu_assert_true(dbg->cur->breakpoint(dbg->bp, &wp_w, true), "live gdb hww set");
	mu_assert_true(dbg->cur->breakpoint(dbg->bp, &wp_w, false), "live gdb hww remove");
	mu_assert_true(dbg->cur->breakpoint(dbg->bp, &wp_r, true), "live gdb hwr set");
	mu_assert_true(dbg->cur->breakpoint(dbg->bp, &wp_r, false), "live gdb hwr remove");
	mu_assert_true(dbg->cur->breakpoint(dbg->bp, &wp_a, true), "live gdb hwa set");
	mu_assert_true(dbg->cur->breakpoint(dbg->bp, &wp_a, false), "live gdb hwa remove");

	mu_assert_true(rz_debug_kill(dbg, 0x2a, 0x2a, 9), "live gdb kill");
	gd->pid = 0;
	mu_assert_false(rz_debug_kill(dbg, 0x2a, 0x2a, 9), "live gdb kill fails when gd->pid <= 0");
	gd->pid = 0x2a;

	mu_assert_eq(rz_debug_detach(dbg, 0x2b), 0, "live gdb detach other pid");

	// Exercise remaining debug_gdb_get_desc() validation guards while attached
	RzIO *saved_io = dbg->iob.io;
	dbg->iob.io = NULL;
	mu_assert_false(rz_debug_select(dbg, 0x2a, 0x2a), "select fails when iob.io is NULL");
	dbg->iob.io = saved_io;

	RzIODescGet saved_desc_get = dbg->iob.desc_get;
	dbg->iob.desc_get = NULL;
	mu_assert_null(dbg->cur->threads(dbg, 0x2a), "threads NULL when desc_get is NULL");
	dbg->iob.desc_get = saved_desc_get;
	mu_assert_true(rz_debug_attach(dbg, 0x2a), "re-attach after desc_get NULL");

	gdb_desc->plugin = NULL;
	mu_assert_null(dbg->cur->threads(dbg, 0x2a), "threads NULL when desc->plugin is NULL");
	gdb_desc->plugin = gdb_plugin;
	mu_assert_true(rz_debug_attach(dbg, 0x2a), "re-attach after plugin NULL");

	RzIOPlugin nameless_plugin = *gdb_plugin;
	nameless_plugin.name = NULL;
	gdb_desc->plugin = &nameless_plugin;
	mu_assert_null(dbg->cur->threads(dbg, 0x2a), "threads NULL when plugin->name is NULL");
	gdb_desc->plugin = gdb_plugin;
	mu_assert_true(rz_debug_attach(dbg, 0x2a), "re-attach after plugin->name NULL");

	nameless_plugin.name = "malloc";
	gdb_desc->plugin = &nameless_plugin;
	mu_assert_null(dbg->cur->threads(dbg, 0x2a), "threads NULL when plugin->name != gdb");
	gdb_desc->plugin = gdb_plugin;
	mu_assert_true(rz_debug_attach(dbg, 0x2a), "re-attach after plugin->name mismatch");

	gdb_desc->data = &nameless_plugin;
	mu_assert_null(dbg->cur->threads(dbg, 0x2a), "threads NULL when desc->data != ctx->desc");
	gdb_desc->data = gd;
	mu_assert_true(rz_debug_attach(dbg, 0x2a), "re-attach after desc->data mismatch");

	int saved_fd = gdb_desc->fd;
	gdb_desc->fd = -1;
	mu_assert_true(rz_debug_attach(dbg, 0x2a), "attach copies negative io_fd");
	mu_assert_null(dbg->cur->threads(dbg, 0x2a), "threads NULL when ctx->io_fd < 0");
	gdb_desc->fd = saved_fd;
	mu_assert_true(rz_debug_attach(dbg, 0x2a), "re-attach restoring valid io_fd");

	// Exercise gdbr_detach() paths (pid <= 0 and !multiprocess; note gdbr_detach disconnects sock)
	mu_assert_eq(rz_debug_detach(dbg, 0), -1, "live gdb detach pid <= 0 calls gdbr_detach");
	gd->stub_features.multiprocess = false;
	(void)rz_debug_detach(dbg, 0x2b);
	gd->stub_features.multiprocess = true;

	// Close underlying gdb IO desc while debug_gdb holds ctx->desc/ctx->io_fd -> must invalidate
	mu_assert_true(rz_io_desc_close(gdb_desc), "io_gdb __close returns success");
	rz_th_wait(th2);
	rz_th_free(th2);
	close(fds2[1]);

	mu_assert_null(rz_debug_info(dbg, NULL), "stale gdb desc invalidated on rz_debug_info");
	mu_assert_null(dbg->cur->threads(dbg, 0x2a), "threads NULL after stale desc invalidation");

	// Reused fd invalidation: close gdb desc, open malloc:// reusing the fd, then query debug_gdb
	libgdbr_t *gd2 = RZ_NEW0(libgdbr_t);
	if (!gd2) {
		rz_debug_free(dbg);
		rz_analysis_free(analysis);
		rz_io_free(io);
		return false;
	}
	mu_assert_eq(gdbr_init(gd2, false), 0, "gdbr_init desc 2");
	gd2->num_retries = 1;
	RzIODesc *gdb_desc2 = rz_io_desc_new(io, gdb_plugin, "gdb://127.0.0.1:1234", RZ_PERM_RWX, gd2);
	mu_assert_notnull(gdb_desc2, "rz_io_desc_new gdb 2");
	mu_assert_true(rz_io_desc_add(io, gdb_desc2), "rz_io_desc_add gdb 2");
	io->desc = gdb_desc2;
	mu_assert_true(rz_debug_attach(dbg, 0x2a), "re-attach gdb desc 2");
	mu_assert_true(rz_io_desc_close(gdb_desc2), "close gdb desc 2");
	RzIODesc *reused = rz_io_open_nomap(io, "malloc://32", RZ_PERM_RW, 0);
	mu_assert_notnull(reused, "open malloc:// reusing closed fd");
	mu_assert_null(dbg->cur->pids(dbg, 0x2a), "reused non-gdb fd invalidated safely");

	// Detach matching dbg->pid clears ctx->desc and ctx->io_fd
	int fds3[2] = { -1, -1 };
	mu_assert_true(mock_gdb_socketpair(fds3), "socketpair 3");
	RzThread *th3 = rz_th_new(mock_gdb_dispatch_th, &fds3[1]);
	mu_assert_notnull(th3, "start mock gdb server 3");

	libgdbr_t *gd3 = RZ_NEW0(libgdbr_t);
	if (!gd3) {
		rz_debug_free(dbg);
		rz_analysis_free(analysis);
		rz_io_free(io);
		close(fds3[0]);
		rz_th_wait(th3);
		rz_th_free(th3);
		close(fds3[1]);
		return false;
	}
	mu_assert_eq(gdbr_init(gd3, false), 0, "gdbr_init desc 3");
	rz_socket_free(gd3->sock);
	gd3->sock = rz_socket_new_from_fd(fds3[0]);
	gd3->no_ack = true;
	gd3->connected = 1;
	gd3->num_retries = 16;
	gd3->pid = 0x2a;
	gd3->stub_features.multiprocess = true;
	RzIODesc *gdb_desc3 = rz_io_desc_new(io, gdb_plugin, "gdb://127.0.0.1:1234", RZ_PERM_RWX, gd3);
	mu_assert_notnull(gdb_desc3, "rz_io_desc_new gdb 3");
	mu_assert_true(rz_io_desc_add(io, gdb_desc3), "rz_io_desc_add gdb 3");
	io->desc = gdb_desc3;
	mu_assert_true(rz_debug_attach(dbg, 0x2a), "attach gdb desc 3");
	mu_assert_eq(rz_debug_detach(dbg, 0x2a), 0, "detach matching pid clears ctx->desc/io_fd");
	mu_assert_null(dbg->cur->threads(dbg, 0x2a), "disconnected after matching detach");
	mu_assert_true(rz_io_desc_close(gdb_desc3), "close gdb desc 3");
	rz_th_wait(th3);
	rz_th_free(th3);
	close(fds3[1]);

	// 3. Live debug_gdb error replies (threads NULL, pids NULL, info with stop_reason failure)
	int fds4[2] = { -1, -1 };
	mu_assert_true(mock_gdb_socketpair(fds4), "socketpair 4");
	RzThread *th4 = rz_th_new(mock_gdb_err_dispatch_th, &fds4[1]);
	mu_assert_notnull(th4, "start mock gdb server 4");

	libgdbr_t *gd4 = RZ_NEW0(libgdbr_t);
	if (!gd4) {
		rz_debug_free(dbg);
		rz_analysis_free(analysis);
		rz_io_free(io);
		close(fds4[0]);
		rz_th_wait(th4);
		rz_th_free(th4);
		close(fds4[1]);
		return false;
	}
	mu_assert_eq(gdbr_init(gd4, false), 0, "gdbr_init desc 4");
	rz_socket_free(gd4->sock);
	gd4->sock = rz_socket_new_from_fd(fds4[0]);
	gd4->no_ack = true;
	gd4->connected = 1;
	gd4->num_retries = 16;
	gd4->pid = 0x2a;
	RzIODesc *gdb_desc4 = rz_io_desc_new(io, gdb_plugin, "gdb://127.0.0.1:1234", RZ_PERM_RWX, gd4);
	mu_assert_notnull(gdb_desc4, "rz_io_desc_new gdb 4");
	mu_assert_true(rz_io_desc_add(io, gdb_desc4), "rz_io_desc_add gdb 4");
	io->desc = gdb_desc4;
	mu_assert_true(rz_debug_attach(dbg, 0x2a), "attach gdb desc 4");
	dbg->pid = 0x2a;
	dbg->tid = 0x2a;
	mu_assert_null(dbg->cur->threads(dbg, 0x2a), "live gdb threads returns NULL on stub error");
	mu_assert_null(dbg->cur->pids(dbg, 0x2a), "live gdb pids returns NULL on stub error");
	RzDebugInfo *info_err = rz_debug_info(dbg, NULL);
	mu_assert_notnull(info_err, "live gdb info still succeeds when stop_reason fails");
	rz_debug_info_free(info_err);
	mu_assert_true(rz_io_desc_close(gdb_desc4), "close gdb desc 4");
	rz_th_wait(th4);
	rz_th_free(th4);
	close(fds4[1]);

	// 4. Loopback TCP io_gdb __open attach-failure cleanup + gdbr_connect reg_cache_init
	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd >= 0) {
		struct sockaddr_in addr = { 0 };
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr.sin_port = 0;
		socklen_t alen = sizeof(addr);
		if (bind(listen_fd, (struct sockaddr *)&addr, alen) == 0 &&
			listen(listen_fd, 1) == 0 &&
			getsockname(listen_fd, (struct sockaddr *)&addr, &alen) == 0) {
			int port = ntohs(addr.sin_port);
			RzThread *th_tcp = rz_th_new(mock_gdb_tcp_attach_fail_th, &listen_fd);
			mu_assert_notnull(th_tcp, "start mock gdb tcp server");
			char uri[64];
			snprintf(uri, sizeof(uri), "gdb://127.0.0.1:%d/42", port);
			mu_assert_null(rz_io_open_nomap(io, uri, RZ_PERM_RWX, 0),
				"gdb:// open cleans up when gdbr_attach fails");
			rz_th_wait(th_tcp);
			rz_th_free(th_tcp);
		}
		close(listen_fd);
	}

	rz_debug_free(dbg);
	rz_analysis_free(analysis);
	rz_io_free(io);
	mu_end;
}
#endif // __UNIX__

int all_tests() {
	RzCons *cons = rz_cons_new(); // there is some windows-specific code in debug that accesses the cons singleton
	mu_run_test(test_rz_debug_use);
	mu_run_test(test_rz_debug_reg_offset);
	mu_run_test(test_debug_sw_bp);
	mu_run_test(test_debug_sw_bp_multibits);
	mu_run_test(test_debug_hw_bp);
	mu_run_test(test_debug_hw_watch);
	mu_run_test(test_debug_reg_sync_flg);
	mu_run_test(test_debug_gdb_disconnected);
	mu_run_test(test_rzgdb_profile_and_cleanup);
#if __UNIX__
	mu_run_test(test_rzgdb_and_debug_gdb_mock_rsp);
#endif
	rz_cons_free(cons);
	return tests_passed != tests_run;
}

mu_main(all_tests)
