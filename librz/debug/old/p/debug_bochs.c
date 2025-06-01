// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file debug_bochs.c
 * Implements the debugger support using the io_bochs plugin.
 *
 * Website: https://bochs.sourceforge.io/
 *
 * Bochs is a highly portable open source IA-32 (x86) PC emulator written in C++, that runs on most popular
 * platforms. It includes emulation of the Intel x86 CPU, common I/O devices, and a custom BIOS.
 *
 * This plugin uses the spawned process used by io_bochs plugin to set/unset breakpoints, to get and set the
 * registers of the CPU.
 *
 * The plugin uses the following commands to handle the debugger commands from rizin:
 *
 * - `break <addr>` is used to set the breakpoint at a given address.
 *
 * - `step` is used to set execute one instruction and break again.
 *
 * - `continue` is used to continue the execution till `CTRL+C` is pressed by the user.
 *
 * - `info break` is used to fetch all the breakpoint indexes; each time a breakpoint is created, the bochs
 *   emulator assigns an index, which is then required as input to remove it. An example of output can be
 *   seen below:
 *
 *   <bochs:4> info break
 *   Num Type           Disp Enb Address
 *     1 pbreakpoint    keep y   0x000000012345
 *
 * - `delete <breakpoint index>` is used to remove a specific breakpoint using the index provided by
 *   the `info break` command.
 *
 * - `regs` is used to fetch the x86 general purpose registers; bochs always uses the 64 bits registers in
 *   the output even when in real mode. It has to be mentioned that the `rip` register is never represented
 *   as `(16 * CS) + IP` even though the emulator uses this for the internal program counter. The plugin
 *   automatically converts this to the proper value and assigns it to the RzReg arena. An example of the
 *   output can be seen below:
 *
 *   <bochs:4> regs
 *   CPU0:
 *   rax: 00000000_00000000
 *   rbx: 00000000_00000000
 *   rcx: 00000000_00000000
 *   [...]
 *   r15: 00000000_00000000
 *   rip: 00000000_0000fff0
 *   eflags 0x00000002: id vip vif ac vm rf nt IOPL=0 of df if tf sf zf af pf cf
 *
 * - `sreg` is used to fetch the x86 segment registers. An example of the output can be seen below:
 *
 *   <bochs:4> sreg
 *   es:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
 *   	Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
 *   cs:0xf000, dh=0xff0093ff, dl=0x0000ffff, valid=7
 *   	Data segment, base=0xffff0000, limit=0x0000ffff, Read/Write, Accessed
 *   ss:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
 *   	Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
 *   ds:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
 *   	Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
 *   fs:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
 *   	Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
 *   gs:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
 *   	Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
 *   ldtr:0x0000, dh=0x00008200, dl=0x0000ffff, valid=1
 *   tr:0x0000, dh=0x00008b00, dl=0x0000ffff, valid=1
 *   gdtr:base=0x0000000000000000, limit=0xffff
 *   idtr:base=0x0000000000000000, limit=0xffff
 *
 * - `dreg` is used to fetch the x86 debug registers. An example of the output can be seen below:
 *
 *   <bochs:4> dreg
 *   DR0=0x0000000000000000
 *   DR1=0x0000000000000000
 *   DR2=0x0000000000000000
 *   DR3=0x0000000000000000
 *   DR6=0xffff0ff0: bt bs bd b3 b2 b1 b0
 *   DR7=0x00000400: DR3=Code-Byte DR2=Code-Byte DR1=Code-Byte DR0=Code-Byte gd | ge le | g3 l3 g2 l2 g1 l1 g0 l0
 *
 * - `set <reg name> = <value>` is used to set the internal registers to any value specified by the user.
 *
 * - `info tab` is used to get the emulator page tables, unfortunately this command when executed at the beginning
 *   will always output `paging off`, but when then the tables are set, the plugin can update the tables using the
 *   new output which contains virtual address mapping to physical addresses. An example of the output can be seen
 *   below:
 *
 *   <bochs:4> info tab
 *   cr3: 0x000000101000
 *   0x00000000c0000000-0x00000000c1ffffff -> 0x000000000000-0x000001ffffff
 *   0x00000000ffffd000-0x00000000ffffdfff -> 0x0000fec00000-0x0000fec00fff
 *   0x00000000ffffe000-0x00000000ffffefff -> 0x0000fee00000-0x0000fee00fff
 */

#include <rz_debug.h>
#include <rz_util.h>

#define BOCHS_STDIN_SIZE 256

static void debug_bochs_wait_till_prompt(RzSubprocess *bochs) {
	RzStrBuf *sb = NULL;
	while ((sb = rz_subprocess_stdout_readline(bochs, 5))) {
		const char *line = rz_strbuf_get(sb);
		if (strstr(line, "<bochs:")) {
			break;
		}
	}
}

static char *debug_bochs_send_command(RzSubprocess *bochs, bool wait_output, const char *format, ...) {
	char command[BOCHS_STDIN_SIZE] = { 0 };
	va_list args;

	va_start(args, format);
	vsnprintf(command, BOCHS_STDIN_SIZE, format, args);
	va_end(args);

	// send command
	rz_subprocess_stdin_write(bochs, (ut8 *)command, strlen(command));

	if (!wait_output) {
		debug_bochs_wait_till_prompt(bochs);
		return NULL;
	}
	// wait for output

	RzStrBuf *output = rz_strbuf_new("");
	if (!output) {
		return NULL;
	}

	RzStrBuf *sb = NULL;
	while ((sb = rz_subprocess_stdout_readline(bochs, 5))) {
		const char *line = rz_strbuf_get(sb);
		if (strstr(line, "<bochs:")) {
			break;
		}
		rz_strbuf_append_n(output, line, sb->len);
	}

	return rz_strbuf_drain(output);
}

static bool bochs_is_io(RzDebug *dbg) {
	if (!dbg->iob.io || !dbg->iob.io->desc) {
		return false;
	}
	RzIODesc *d = dbg->iob.io->desc;
	return d->plugin && d->plugin->name && !strcmp("bochs", d->plugin->name);
}

static int bochs_find_breakpoint_index(RzSubprocess *bochs, ut64 address) {
	char *output = debug_bochs_send_command(bochs, true, "info break\n");
	if (!output) {
		RZ_LOG_ERROR("io: bochs: Failed to get breakpoints.\n");
		return -1;
	}

	char hexaddr[128];
	rz_strf(hexaddr, "0x%012" PFMT64x, address);
	char *match = strstr(output, hexaddr);
	if (!match) {
		free(output);
		return -1;
	}

	char *line = output;
	char *end = NULL;
	while (RZ_STR_ISNOTEMPTY(line)) {
		if ((end = strchr(line, '\n'))) {
			*end = 0;
			end++;
		}

		if (match < end) {
			break;
		}
		line = end;
	}

	ut64 index = rz_num_math(NULL, line);
	free(output);
	return index;
}

static int bochs_breakpoint(RzBreakpoint *bp, RzBreakpointItem *b, bool set) {
	RzDebug *dbg = bp->user;
	if (!dbg) {
		return false;
	}

	RzIODesc *fd = dbg->iob.io->desc;
	RzSubprocess *bochs = fd ? fd->data : NULL;
	if (!bochs) {
		return false;
	}

	if (set) {
		debug_bochs_send_command(bochs, false, "break 0x%" PFMT64x "\n", b->addr);
		return bochs_find_breakpoint_index(bochs, b->addr) > -1;
	}

	int index = bochs_find_breakpoint_index(bochs, b->addr);
	if (index < 0) {
		return false;
	}
	debug_bochs_send_command(bochs, false, "delete %d\n", index);
	return true;
}

static bool bochs_sync_profile(RzSubprocess *bochs, RzReg *reg) {
	ut8 regbuf[32] = { 0 };
	/*
		example of output:
		CPU0:
		rax: 00000000_00000000
		rbx: 00000000_00000000
		rcx: 00000000_00000000
		rdx: 00000000_00000000
		rsp: 00000000_00000000
		rbp: 00000000_00000000
		rsi: 00000000_00000000
		rdi: 00000000_00000000
		r8 : 00000000_00000000
		r9 : 00000000_00000000
		r10: 00000000_00000000
		r11: 00000000_00000000
		r12: 00000000_00000000
		r13: 00000000_00000000
		r14: 00000000_00000000
		r15: 00000000_00000000
		rip: 00000000_0000fff0
		eflags 0x00000002: id vip vif ac vm rf nt IOPL=0 of df if tf sf zf af pf cf
	*/
	char *raw = debug_bochs_send_command(bochs, true, "regs\n");
	char *output = raw ? strstr(raw, "CPU0:") : NULL;
	if (!output) {
		free(raw);
		RZ_LOG_ERROR("io: bochs: Failed to get registers.\n");
		return false;
	}

	ut64 csip_reg = 0;

	char *line = output + 5;
	while (RZ_STR_ISNOTEMPTY(line)) {
		if (line[3] == ':') {
			char *underscore = strchr(line, '_');
			if (underscore) {
				*underscore = ' ';
			}
			rz_hex_str2bin(line + 4, regbuf);
			ut64 number = rz_read_be64(regbuf);

			if (line[2] == ' ') {
				line[2] = 0;
			}
			line[3] = 0;
			if (!strcmp(line, "rip")) {
				// it is always cs:ip, not a real rip
				csip_reg = number & UT16_MAX;
			} else {
				RzRegItem *item = rz_reg_get(reg, line, -1);
				if (item) {
					rz_reg_set_value(reg, item, number);
				} else {
					RZ_LOG_ERROR("io: bochs: Failed to find register %s.\n", line);
				}
			}
			line[3] = ':';
			if (!line[2]) {
				line[2] = ' ';
			}
		} else if (!strncmp(line, "eflags ", strlen("eflags "))) {
			rz_hex_str2bin(line + 7, regbuf);
			ut64 number = rz_read_be32(regbuf);
			RzRegItem *item = rz_reg_get(reg, "eflags", -1);
			rz_reg_set_value(reg, item, number);
		}
		if ((line = strchr(line, '\n'))) {
			line++;
		}
	}

	free(raw);

	/*
		example of output:
		es:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
			Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
		cs:0xf000, dh=0xff0093ff, dl=0x0000ffff, valid=7
			Data segment, base=0xffff0000, limit=0x0000ffff, Read/Write, Accessed
		ss:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
			Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
		ds:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
			Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
		fs:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
			Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
		gs:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
			Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
		ldtr:0x0000, dh=0x00008200, dl=0x0000ffff, valid=1
		tr:0x0000, dh=0x00008b00, dl=0x0000ffff, valid=1
		gdtr:base=0x0000000000000000, limit=0xffff
		idtr:base=0x0000000000000000, limit=0xffff
	*/
	raw = debug_bochs_send_command(bochs, true, "sreg\n");
	if (!raw) {
		RZ_LOG_ERROR("io: bochs: Failed to get SEG registers.\n");
		return false;
	}

	line = raw;
	while (RZ_STR_ISNOTEMPTY(line)) {
		if (line[2] == ':' && line[9] == ',') {

			line[9] = 0; // comma
			line[2] = 0; // colon
			RzRegItem *item = rz_reg_get(reg, line, -1);
			if (item) {
				rz_hex_str2bin(line + 3, regbuf);
				ut64 number = rz_read_be16(regbuf);
				rz_reg_set_value(reg, item, number);
				if (!strcmp(line, "cs")) {
					// csip = (16 * CS) + IP;
					csip_reg += (number << 4);
				}
			}
			line[2] = ':';
			line[9] = ',';
		}
		if ((line = strchr(line, '\n'))) {
			line++;
		}
	}
	free(raw);

	rz_reg_set_value(reg, rz_reg_get(reg, "rip", -1), csip_reg);

	/*
		example of output:
		DR0=0x0000000000000000
		DR1=0x0000000000000000
		DR2=0x0000000000000000
		DR3=0x0000000000000000
		DR6=0xffff0ff0: bt bs bd b3 b2 b1 b0
		DR7=0x00000400: DR3=Code-Byte DR2=Code-Byte DR1=Code-Byte DR0=Code-Byte gd | ge le | g3 l3 g2 l2 g1 l1 g0 l0
	*/
	raw = debug_bochs_send_command(bochs, true, "dreg\n");
	if (!raw) {
		RZ_LOG_ERROR("io: bochs: Failed to get DRX registers.\n");
		return false;
	}

	line = raw;
	while (RZ_STR_ISNOTEMPTY(line)) {
		if (line[0] == 'D' && line[1] == 'R' && line[3] == '=') {
			char *colon = strchr(line, ':');
			if (colon) {
				*colon = 0;
			}
			line[0] = 'd';
			line[1] = 'r';
			line[3] = 0; // equal
			RzRegItem *item = rz_reg_get(reg, line, -1);
			if (item) {
				rz_hex_str2bin(line + 3, regbuf);
				ut64 number = rz_read_be16(regbuf);
				rz_reg_set_value(reg, item, number);
			}
			line[3] = '=';
			if (colon) {
				*colon = ':';
			}
		}
		if ((line = strchr(line, '\n'))) {
			line++;
		}
	}

	free(raw);
	return true;
}

static const char *bochs_updatable_registers[] = {
	"es", "cs", "ss", "ds", "fs", "gs",
	"dr0", "dr1", "dr2", "dr3", "dr6", "dr7",
	"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip",
	"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "eip"
};

static bool bochs_sync_debugger(RzSubprocess *bochs, RzReg *reg) {
	for (size_t i = 0; i < RZ_ARRAY_SIZE(bochs_updatable_registers); ++i) {
		const char *name = bochs_updatable_registers[i];
		RzRegItem *item = rz_reg_get(reg, name, -1);
		if (!item) {
			continue;
		}

		ut64 value = rz_reg_get_value(reg, item);
		debug_bochs_send_command(bochs, false, "set %s = 0x%" PFMT64x "\n", name, value);
	}

	// ensure the output buffer is alywas empty
	free(rz_subprocess_out(bochs, NULL));
	return true;
}

static bool bochs_sync_registers(RzDebug *dbg, RzReg *reg, bool to_debugger) {
	rz_return_val_if_fail(dbg && reg, false);
	if (!bochs_is_io(dbg)) {
		return false;
	}

	RzIODesc *fd = dbg->iob.io->desc;
	RzSubprocess *bochs = fd ? fd->data : NULL;
	if (!bochs) {
		return false;
	}

	if (to_debugger) {
		return bochs_sync_debugger(bochs, reg);
	}
	return bochs_sync_profile(bochs, reg);
}

static RzDebugMap *bochs_map_new(ut32 idx, ut64 from, ut64 to) {
	RzDebugMap *map = RZ_NEW0(RzDebugMap);
	if (!map) {
		return NULL;
	}
	map->name = rz_str_newf("page_%u", idx);
	map->addr = from;
	map->addr_end = to;
	map->size = to - from;
	map->perm = RZ_PERM_RWX;
	map->user = 0;
	return map;
}

static RzList /*<RzDebugMap *>*/ *bochs_map_get(RzDebug *dbg) {
	if (!bochs_is_io(dbg)) {
		return NULL;
	}

	RzIODesc *fd = dbg->iob.io->desc;
	RzSubprocess *bochs = fd ? fd->data : NULL;
	if (!bochs) {
		return NULL;
	}

	RzList *list = rz_list_newf((RzListFree)rz_debug_map_free);
	if (!list) {
		return NULL;
	}

	/*
		example of output without pages:
		paging off

		example of output with pages:
		cr3: 0x000000101000
		0x00000000c0000000-0x00000000c1ffffff -> 0x000000000000-0x000001ffffff
		0x00000000ffffd000-0x00000000ffffdfff -> 0x0000fec00000-0x0000fec00fff
		0x00000000ffffe000-0x00000000ffffefff -> 0x0000fee00000-0x0000fee00fff

		we only map the virtual memory.
	*/

	char *output = debug_bochs_send_command(bochs, true, "info tab\n");
	if (!output) {
		RZ_LOG_ERROR("io: bochs: Failed to get pages.\n");
		rz_list_free(list);
		return NULL;
	}

	if (!rz_str_startswith(output, "paging off")) {
		free(output);
		RzDebugMap *map = bochs_map_new(0, 0, UT32_MAX);
		if (!map || !rz_list_append(list, map)) {
			rz_debug_map_free(map);
		}
		return list;
	}

	ut64 from, to;
	ut32 counter = 0;
	char *line = output;
	while (RZ_STR_ISNOTEMPTY(line)) {
		if (line[0] == '0' && line[1] == 'x') {
			from = to = 0;
			char *dash = strchr(line, '-');
			char *space = strchr(dash + 1, ' ');
			if (dash) {
				*dash = 0;
				from = rz_num_math(NULL, line);
			}
			if (space) {
				*space = 0;
				to = rz_num_math(NULL, dash + 1);
			}

			RzDebugMap *map = bochs_map_new(counter, from, to);
			if (!map || !rz_list_append(list, map)) {
				rz_debug_map_free(map);
				break;
			}
			counter++;
		}
		if ((line = strchr(line, '\n'))) {
			line++;
		}
	}
	free(output);

	return list;
}

static bool bochs_step(RzDebug *dbg) {
	if (!bochs_is_io(dbg)) {
		rz_warn_if_reached();
		return false;
	}
	RzIODesc *fd = dbg->iob.io->desc;
	RzSubprocess *bochs = fd ? fd->data : NULL;
	if (!bochs) {
		rz_warn_if_reached();
		return false;
	}

	debug_bochs_send_command(bochs, false, "step\n");
	return true;
}

static int bochs_continue(RzDebug *dbg, int pid, int tid, int sig) {
	if (!bochs_is_io(dbg)) {
		rz_warn_if_reached();
		return false;
	}

	RzIODesc *fd = dbg->iob.io->desc;
	RzSubprocess *bochs = fd ? fd->data : NULL;
	if (!bochs) {
		rz_warn_if_reached();
		return false;
	}

	debug_bochs_send_command(bochs, false, "continue\n");
	return true;
}

static RzDebugReasonType bochs_wait(RzDebug *dbg, int pid) {
	if (!bochs_is_io(dbg)) {
		return RZ_DEBUG_REASON_ERROR;
	}

	return RZ_DEBUG_REASON_NONE;
}

static int bochs_stop(RzDebug *dbg) {
	return true;
}

static int bochs_attach(RzDebug *dbg, int pid) {
	dbg->swstep = true;
	return true;
}

static int bochs_detach(RzDebug *dbg, int pid) {
	dbg->swstep = true;
	return true;
}

static char *bochs_reg_profile(RzDebug *dbg) {
	int bits = dbg->analysis->bits;

	if (bits == 16 || bits == 32 || bits == 64) {
		return rz_str_dup(
			"=PC	rip\n"
			"=SP	rsp\n"
			"=BP	rbp\n"
			"=A0	rax\n"
			"=A1	rbx\n"
			"=A2	rcx\n"
			"=A3	rdi\n"

			"seg	es	2	0x038	0	\n"
			"seg	cs	2	0x03A	0	\n"
			"seg	ss	2	0x03C	0	\n"
			"seg	ds	2	0x03E	0	\n"
			"seg	fs	2	0x040	0	\n"
			"seg	gs	2	0x042	0	\n"

			"gpr	eflags	4	0x044	0	\n"

			"drx	dr0	8	0x048	0	\n"
			"drx	dr1	8	0x050	0	\n"
			"drx	dr2	8	0x058	0	\n"
			"drx	dr3	8	0x060	0	\n"
			"drx	dr6	8	0x068	0	\n"
			"drx	dr7	8	0x070	0	\n"

			"gpr	rax	8	0x078	0	\n"
			"gpr	eax	4	0x078	0	\n"
			"gpr	ax	2	0x078	0	\n"
			"gpr	al	1	0x078	0	\n"
			"gpr	rcx	8	0x080	0	\n"
			"gpr	ecx	4	0x080	0	\n"
			"gpr	cx	2	0x080	0	\n"
			"gpr	cl	1	0x078	0	\n"
			"gpr	rdx	8	0x088	0	\n"
			"gpr	edx	4	0x088	0	\n"
			"gpr	dx	2	0x088	0	\n"
			"gpr	dl	1	0x088	0	\n"
			"gpr	rbx	8	0x090	0	\n"
			"gpr	ebx	4	0x090	0	\n"
			"gpr	bx	2	0x090	0	\n"
			"gpr	bl	1	0x090	0	\n"
			"gpr	rsp	8	0x098	0	\n"
			"gpr	esp	4	0x098	0	\n"
			"gpr	sp	2	0x098	0	\n"
			"gpr	spl	1	0x098	0	\n"
			"gpr	rbp	8	0x0A0	0	\n"
			"gpr	ebp	4	0x0A0	0	\n"
			"gpr	bp	2	0x0A0	0	\n"
			"gpr	bpl	1	0x0A0	0	\n"
			"gpr	rsi	8	0x0A8	0	\n"
			"gpr	esi	4	0x0A8	0	\n"
			"gpr	si	2	0x0A8	0	\n"
			"gpr	sil	1	0x0A8	0	\n"
			"gpr	rdi	8	0x0B0	0	\n"
			"gpr	edi	4	0x0B0	0	\n"
			"gpr	di	2	0x0B0	0	\n"
			"gpr	dil	1	0x0B0	0	\n"
			"gpr	r8	8	0x0B8	0	\n"
			"gpr	r8d	4	0x0B8	0	\n"
			"gpr	r8w	2	0x0B8	0	\n"
			"gpr	r8b	1	0x0B8	0	\n"
			"gpr	r9	8	0x0C0	0	\n"
			"gpr	r9d	4	0x0C0	0	\n"
			"gpr	r9w	2	0x0C0	0	\n"
			"gpr	r9b	1	0x0C0	0	\n"
			"gpr	r10	8	0x0C8	0	\n"
			"gpr	r10d	4	0x0C8	0	\n"
			"gpr	r10w	2	0x0C8	0	\n"
			"gpr	r10b	1	0x0C8	0	\n"
			"gpr	r11	8	0x0D0	0	\n"
			"gpr	r11d	4	0x0D0	0	\n"
			"gpr	r11w	2	0x0D0	0	\n"
			"gpr	r11b	1	0x0D0	0	\n"
			"gpr	r12	8	0x0D8	0	\n"
			"gpr	r12d	4	0x0D8	0	\n"
			"gpr	r12w	2	0x0D8	0	\n"
			"gpr	r12b	1	0x0D8	0	\n"
			"gpr	r13	8	0x0E0	0	\n"
			"gpr	r13d	4	0x0E0	0	\n"
			"gpr	r13w	2	0x0E0	0	\n"
			"gpr	r13b	1	0x0E0	0	\n"
			"gpr	r14	8	0x0E8	0	\n"
			"gpr	r14d	4	0x0E8	0	\n"
			"gpr	r14w	2	0x0E8	0	\n"
			"gpr	r14b	1	0x0E8	0	\n"
			"gpr	r15	8	0x0F0	0	\n"
			"gpr	r15d	4	0x0F0	0	\n"
			"gpr	r15w	2	0x0F0	0	\n"
			"gpr	r15b	1	0x0F0	0	\n"
			"gpr	rip	8	0x0F8	0	\n"
			"gpr	eip	4	0x0F8	0	\n");
	}
	return NULL;
}

RzDebugPlugin rz_debug_plugin_bochs = {
	.name = "bochs",
	.license = "LGPL3",
	.arch = "x86",
	.bits = RZ_SYS_BITS_16 | RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
	.step = bochs_step,
	.cont = bochs_continue,
	.attach = &bochs_attach,
	.detach = &bochs_detach,
	.canstep = 1,
	.stop = &bochs_stop,
	.wait = &bochs_wait,
	.map_get = bochs_map_get,
	.breakpoint = bochs_breakpoint,
	.sync_registers = &bochs_sync_registers,
	.reg_profile = &bochs_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_DBG,
	.data = &rz_debug_plugin_bochs,
	.version = RZ_VERSION
};
#endif
