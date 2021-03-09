// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_debug.h>
#include <sdb.h>
#define TN_KEY_LEN 32
#define TN_KEY_FMT "%" PFMT64u
#ifndef SIGKILL
#define SIGKILL 9
#endif

#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__
#include "rz_heap_glibc.h"
#endif

#if HAVE_JEMALLOC
#include "rz_heap_jemalloc.h"
#include "linux_heap_jemalloc.c"
#endif

#include "core_private.h"

void cmd_analysis_reg(RzCore *core, const char *str);

static const char *help_msg_d[] = {
	"Usage:", "d", " # Debug commands",
	"db", "[?]", "Breakpoints commands",
	"dbt", "[?]", "Display backtrace based on dbg.btdepth and dbg.btalgo",
	"dc", "[?]", "Continue execution",
	"dd", "[?]", "File descriptors (!fd in r1)",
	"de", "[-sc] [perm] [rm] [e]", "Debug with ESIL (see de?)",
	"dg", " <file>", "Generate a core-file (WIP)",
	"dH", " [handler]", "Transplant process to a new handler",
	"di", "[?]", "Show debugger backend information (See dh)",
	"dk", "[?]", "List, send, get, set, signal handlers of child",
	"dL", "[?]", "List or set debugger handler",
	"dm", "[?]", "Show memory maps",
	"do", "[?]", "Open process (reload, alias for 'oo')",
	"doo", "[args]", "Reopen in debug mode with args (alias for 'ood')",
	"doof", "[file]", "Reopen in debug mode from file (alias for 'oodf')",
	"doc", "", "Close debug session",
	"dp", "[?]", "List, attach to process or thread id",
	"dr", "[?]", "Cpu registers",
	"ds", "[?]", "Step, over, source line",
	"dt", "[?]", "Display instruction traces",
	"dw", " <pid>", "Block prompt until pid dies",
#if __WINDOWS__
	"dW", "", "List process windows",
	"dWi", "", "Identify window under cursor",
#endif
	"dx", "[?]", "Inject and run code on target process (See gs)",
	NULL
};

static const char *help_msg_db[] = {
	"Usage: db", "", " # Breakpoints commands",
	"db", "", "List breakpoints",
	"db*", "", "List breakpoints in r commands",
	"db", " sym.main", "Add breakpoint into sym.main",
	"db", " <addr>", "Add breakpoint",
	"dbH", " <addr>", "Add hardware breakpoint",
	"db-", " <addr>", "Remove breakpoint",
	"db-*", "", "Remove all the breakpoints",
	"db.", "", "Show breakpoint info in current offset",
	"dbj", "", "List breakpoints in JSON format",
	// "dbi", " 0x848 ecx=3", "stop execution when condition matches",
	"dbc", " <addr> <cmd>", "Run command when breakpoint is hit",
	"dbC", " <addr> <cmd>", "Run command but continue until <cmd> returns zero",
	"dbd", " <addr>", "Disable breakpoint",
	"dbe", " <addr>", "Enable breakpoint",
	"dbs", " <addr>", "Toggle breakpoint",
	"dbf", "", "Put a breakpoint into every no-return function",
	//
	"dbm", " <module> <offset>", "Add a breakpoint at an offset from a module's base",
	"dbn", " [<name>]", "Show or set name for current breakpoint",
	//
	"dbi", "", "List breakpoint indexes",
	"dbi", " <addr>", "Show breakpoint index in givengiven  offset",
	"dbi.", "", "Show breakpoint index in current offset",
	"dbi-", " <idx>", "Remove breakpoint by index",
	"dbix", " <idx> [expr]", "Set expression for bp at given index",
	"dbic", " <idx> <cmd>", "Run command at breakpoint index",
	"dbie", " <idx>", "Enable breakpoint by index",
	"dbid", " <idx>", "Disable breakpoint by index",
	"dbis", " <idx>", "Swap Nth breakpoint",
	"dbite", " <idx>", "Enable breakpoint Trace by index",
	"dbitd", " <idx>", "Disable breakpoint Trace by index",
	"dbits", " <idx>", "Swap Nth breakpoint trace",
	//
	"dbh", " x86", "Set/list breakpoint plugin handlers",
	"dbh-", " <name>", "Remove breakpoint plugin handler",
	"dbt", "[?]", "Show backtrace. See dbt? for more details",
	"dbx", " [expr]", "Set expression for bp in current offset",
	"dbw", " <addr> <r/w/rw>", "Add watchpoint",
#if __WINDOWS__
	"dbW", " <WM_DEFINE> [?|handle|name]", "Set cond. breakpoint on a window message handler",
#endif
	"drx", " number addr len perm", "Modify hardware breakpoint",
	"drx-", "number", "Clear hardware breakpoint",
	NULL
};

static const char *help_msg_dbt[] = {
	"Usage: dbt", "", " # Backtrace commands",
	"dbt", "", "Display backtrace based on dbg.btdepth and dbg.btalgo",
	"dbt*", "", "Display backtrace in flags",
	"dbt=", "", "Display backtrace in one line (see dbt=s and dbt=b for sp or bp)",
	"dbtv", "", "Display backtrace with local vars if any",
	"dbtj", "", "Display backtrace in JSON",
	"dbta", "", "Display ascii-art representation of the stack backtrace",
	"dbte", " <addr>", "Enable Breakpoint Trace",
	"dbtd", " <addr>", "Disable Breakpoint Trace",
	"dbts", " <addr>", "Swap Breakpoint Trace",
	NULL
};

static const char *help_msg_dbw[] = {
	"Usage: dbw", "<addr> <r/w/rw>", " # Add watchpoint",
	NULL
};

static const char *help_msg_dc[] = {
	"Usage: dc", "", "Execution continuation commands",
	"dc", "", "Continue execution of all children",
	"dc", " <pid>", "Continue execution of pid",
	"dc", "[-pid]", "Stop execution of pid",
	"dca", " [sym] [sym].", "Continue at every hit on any given symbol",
	"dcb", "", "Continue back until breakpoint",
	"dcc", "", "Continue until call (use step into)",
	"dccu", "", "Continue until unknown call (call reg)",
#if __WINDOWS__
	"dce", "", "Continue execution (pass exception to program)",
#endif
	"dcf", "", "Continue until fork (TODO)",
	"dck", " <signal> <pid>", "Continue sending signal to process",
	"dcp", "", "Continue until program code (mapped io section)",
	"dcr", "", "Continue until ret (uses step over)",
	"dcs", "[?] <num>", "Continue until syscall",
	"dct", " <len>", "Traptrace from curseek to len, no argument to list",
	"dcu", "[?] [..end|addr] ([end])", "Continue until address (or range)",
	/*"TODO: dcu/dcr needs dbg.untilover=true??",*/
	/*"TODO: same for only user/libs side, to avoid steping into libs",*/
	/*"TODO: support for threads?",*/
	NULL
};

static const char *help_msg_dcs[] = {
	"Usage:", "dcs", " Continue until syscall",
	"dcs", "", "Continue until next syscall",
	"dcs [str]", "", "Continue until next call to the 'str' syscall",
	"dcs", "*", "Trace all syscalls, a la strace",
	NULL
};

static const char *help_msg_dcu[] = {
	"Usage:", "dcu", " Continue until address",
	"dcu.", "", "Alias for dcu $$ (continue until current address",
	"dcu", " address", "Continue until address",
	"dcu", " [..tail]", "Continue until the range",
	"dcu", " [from] [to]", "Continue until the range",
	NULL
};

static const char *help_msg_dd[] = {
	"Usage: dd", "", "Descriptors commands",
	"dd", "", "List file descriptors",
	"dd", " <file>", "Open and map that file into the UI",
	"dd-", "<fd>", "Close stdout fd",
	"dd*", "", "List file descriptors (in rizin commands)",
	"dds", " <fd> <off>", "Seek given fd)",
	"ddd", " <fd1> <fd2>", "Dup2 from fd1 to fd2",
	"ddr", " <fd> <size>", "Read N bytes from fd",
	"ddw", " <fd> <hexpairs>", "Write N bytes to fd",
	NULL
};

static const char *help_msg_de[] = {
	"Usage:", "de", "[-sc] [perm] [rm] [expr]",
	"de", "", "List esil watchpoints",
	"de-*", "", "Delete all esil watchpoints",
	"de", " [perm] [rm] [addr|reg|from..to]", "Stop on condition",
	"dec", "", "Continue execution until matching expression",
	"des", "[?] [N]", "Step-in N instructions with esildebug",
	"desu", " [addr]", "Esildebug until specific address",
	NULL
};

static const char *help_msg_des[] = {
	"Usage:", "des", "[u] [arg]",
	"des", " [N]", "step-in N instructions with esildebug",
	"desu", " [addr]", "esildebug until specific address",
	NULL
};

static const char *help_msg_di[] = {
	"Usage: di", "", "Debugger target information",
	"di", "", "Show debugger target information",
	"di*", "", "Same as above, but in rizin commands",
	"diq", "", "Same as above, but in one line",
	"dij", "", "Same as above, but in JSON format",
	"dif", " [$a] [$b]", "Compare two files (or $alias files)",
	NULL
};

static const char *help_msg_dk[] = {
	"Usage: dk", "", "Signal commands",
	"dk", "", "List all signal handlers of child process",
	"dk", " <signal>", "Send KILL signal to child",
	"dk", " <signal>=1", "Set signal handler for <signal> in child",
	"dk?", "<signal>", "Name/signum resolver",
	"dko", "[?] <signal>", "Reset skip or cont options for given signal",
	"dko", " <signal> [|skip|cont]", "On signal SKIP handler or CONT into",
	"dkj", "", "List all signal handlers in JSON",
	NULL
};

static const char *help_msg_dko[] = {
	"Usage:", "dko", " # Signal handling commands",
	"dko", "", "List existing signal handling",
	"dko", " [signal]", "Clear handling for a signal",
	"dko", " [signal] [skip|cont]", "Set handling for a signal",
	NULL
};

static const char *help_msg_dm[] = {
	"Usage:", "dm", " # Memory maps commands",
	"dm", "", "List memory maps of target process",
	"dm", " address size", "Allocate <size> bytes at <address> (anywhere if address is -1) in child process",
	"dm=", "", "List memory maps of target process (ascii-art bars)",
	"dm.", "", "Show map name of current address",
	"dm*", "", "List memmaps in rizin commands",
	"dm-", " address", "Deallocate memory map of <address>",
	"dmd", "[a] [file]", "Dump current (all) debug map region to a file (from-to.dmp) (see Sd)",
	"dmh", "[?]", "Show map of heap",
	"dmi", " [addr|libname] [symname]", "List symbols of target lib",
	"dmi*", " [addr|libname] [symname]", "List symbols of target lib in rizin commands",
	"dmi.", "", "List closest symbol to the current address",
	"dmiv", "", "Show address of given symbol for given lib",
	"dmj", "", "List memmaps in JSON format",
	"dml", " <file>", "Load contents of file into the current map region",
	"dmm", "[?][j*]", "List modules (libraries, binaries loaded in memory)",
	"dmp", "[?] <address> <size> <perms>", "Change page at <address> with <size>, protection <perms> (perm)",
	"dms", "[?] <id> <mapaddr>", "Take memory snapshot",
	"dms-", " <id> <mapaddr>", "Restore memory snapshot",
	"dmS", " [addr|libname] [sectname]", "List sections of target lib",
	"dmS*", " [addr|libname] [sectname]", "List sections of target lib in rizin commands",
	"dmL", " address size", "Allocate <size> bytes at <address> and promote to huge page",
	//"dm, " rw- esp 9K", "set 9KB of the stack as read+write (no exec)",
	"TODO:", "", "map files in process memory. (dmf file @ [addr])",
	NULL
};

static const char *help_msg_dmi[] = {
	"Usage: dmi", "", " # List/Load Symbols",
	"dmi", "[j|q|*] [libname] [symname]", "List symbols of target lib",
	"dmia", "[j|q|*] [libname]", "List all info of target lib",
	"dmi*", "", "List symbols of target lib in rizin commands",
	"dmi.", "", "List closest symbol to the current address",
	"dmiv", "", "Show address of given symbol for given lib",
	NULL
};

static const char *help_msg_dmm[] = {
	"Usage:", "dmm", " # Module memory maps commands",
	"dmm", "", "List modules of target process",
	"dmm*", "", "List modules of target process (rizin commands)",
	"dmm.", "", "List memory map of current module",
	"dmmj", "", "List modules of target process (JSON)",
	NULL
};

static const char *help_msg_dmp[] = {
	"Usage:", "dmp", " Change page permissions",
	"dmp", " [addr] [size] [perms]", "Change permissions",
	"dmp", " [perms]", "Change dbg.map permissions",
	NULL
};

static const char *help_msg_do[] = {
	"Usage:", "do", " # Debug (re)open commands",
	"do", "", "Open process (reload, alias for 'oo')",
	"dor", " [rz_run]", "Comma separated list of k=v rz_run profile options (e dbg.profile)",
	"doe", "", "Show rz_run startup profile",
	"doe!", "", "Edit rz_run startup profile with $EDITOR",
	"doo", " [args]", "Reopen in debug mode with args (alias for 'ood')",
	"doof", " [args]", "Reopen in debug mode from file (alias for 'oodf')",
	"doc", "", "Close debug session",
	NULL
};

static const char *help_msg_dp[] = {
	"Usage:", "dp", " # Process commands",
	"dp", "", "List current pid and children",
	"dp", " <pid>", "List children of pid",
	"dpj", " <pid>", "List children of pid in JSON format",
	"dpl", "", "List all attachable pids",
	"dplj", "", "List all attachable pids in JSON format",
	"dp-", " <pid>", "Detach select pid",
	"dp=", "<pid>", "Select pid",
	"dpa", " <pid>", "Attach and select pid",
	"dpc", "", "Select forked pid (see dbg.forks)",
	"dpc*", "", "Display forked pid (see dbg.forks)",
	"dpe", "", "Show path to executable",
	"dpf", "", "Attach to pid like file fd // HACK",
	"dpk", " <pid> [<signal>]", "Send signal to process (default 0)",
	"dpn", "", "Create new process (fork)",
	"dptn", "", "Create new thread (clone)",
	"dpt", "", "List threads of current pid",
	"dptj", "", "List threads of current pid in JSON format",
	"dpt", " <pid>", "List threads of process",
	"dptj", " <pid>", "List threads of process in JSON format",
	"dpt=", "<thread>", "Attach to thread",
	NULL
};

static const char *help_msg_dr[] = {
	"Usage: dr", "", "Registers commands",
	"dr", "", "Show 'gpr' registers",
	"dr", " <register>=<val>", "Set register value",
	"dr.", " >$snapshot", "Capture current register values in rizin alias file",
	"dr,", " [table-query]", "Enumerate registers in table format",
	"dr8", "[1|2|4|8] [type]", "Display hexdump of gpr arena (WIP)",
	"dr=", "", "Show registers in columns",
	"dr?", "<register>", "Show value of given register",
	"dr??", "", "Same as dr?`drp~=[0]+` # list all reg roles alias names and values",
	"dra", "[?]", "Manage register arenas. see ara?",
	"drb", "[1|2|4|8] [type]", "Display hexdump of gpr arena (WIP)",
	"drc", " [name]", "Related to conditional flag registers",
	"drC", " [register]", "Show register comments",
	"drd", "", "Show only different registers",
	"drf", "", "Show fpu registers (80 bit long double)",
	"dri", "", "Show inverse registers dump (sorted by value)",
	"drl", "[j]", "List all register names",
	"drm", "[?]", "Show multimedia packed registers",
	//	"drm", " xmm0 0 32 = 12", "Set the first 32 bit word of the xmm0 reg to 12", // Do not advertise - broken
	"dro", "", "Show previous (old) values of registers",
	"drp", "[?] ", "Display current register profile",
	"drr", "", "Show registers references (telescoping)",
	"drrj", "", "Show registers references (telescoping) in JSON format",
	// TODO: 'drs' to swap register arenas and display old register valuez
	"drs", "[?]", "Stack register states",
	"drS", "", "Show the size of the register profile",
	"drt", "[?]", "Show all register types",
	"drw", " <hexnum>", "Set contents of the register arena",
	"drx", "[?]", "Show debug registers",
	".dr", "*", "Include common register values in flags",
	".dr", "-", "Unflag all registers",
	NULL
};

static const char *help_msg_drp[] = {
	"Usage:", "drp", " # Register profile commands",
	"drp", "", "Show the current register profile",
	"drp", " [regprofile-file]", "Set the current register profile",
	"drp", " [gdb] [regprofile-file]", "Parse gdb register profile and dump an rizin profile string",
	"drpc", "", "Show register profile comments",
	"drpi", "", "Show internal representation of the register profile",
	"drp.", "", "Show the current fake size",
	"drpj", "", "Show the current register profile (JSON)",
	"drps", " [new fake size]", "Set the fake size",
	NULL
};

static const char *help_msg_drs[] = {
	"Usage:", "drs", "register states commands",
	"drs", "", "list register stack",
	"drs", "+", "push register state",
	"drs", "-", "pop register state",
	NULL
};

static const char *help_msg_drt[] = {
	"Usage:", "drt", " [type] [size]    # debug register types",
	"drt", "", "List all available register types",
	"drt", " [size]", "Show all regs in the profile of size",
	"drt", " 16", "Show 16 bit registers",
	"drt", " [type]", "Show all regs in the profile of this type",
	"drt", " all", "Show all registers",
	"drt", " fpu", "Show fpu registers",
	"drt", " [type] [size]", "Same as above for type and size",
	"drt", " [type] [size]", "Same as above for type and size",
	"drt*", "", "List flags in r commands",
	NULL
};

static const char *help_msg_drx[] = {
	"Usage: drx", "", "Hardware breakpoints commands",
	"drx", "", "List all (x86?) hardware breakpoints",
	"drx", " <number> <address> <length> <perms>", "Modify hardware breakpoint",
	"drx-", "<number>", "Clear hardware breakpoint",
	NULL
};

static const char *help_msg_drm[] = {
	"Usage: drm", " [reg] [idx] [wordsize] [= value]", "Show multimedia packed registers",
	"drm", "", "Show XMM registers",
	"drm", " xmm0", "Show all packings of xmm0",
	"drm", " xmm0 0 32 = 12", "Set the first 32 bit word of the xmm0 reg to 12",
	"drmb", " [reg]", "Show registers as bytes",
	"drmw", " [reg]", "Show registers as words",
	"drmd", " [reg]", "Show registers as doublewords",
	"drmq", " [reg]", "Show registers as quadwords",
	"drmq", " xmm0~[0]", "Show first quadword of xmm0",
	"drmf", " [reg]", "Show registers as 32-bit floating point",
	"drml", " [reg]", "Show registers as 64-bit floating point",
	"drmyb", " [reg]", "Show YMM registers as bytes",
	"drmyw", " [reg]", "Show YMM registers as words",
	"drmyd", " [reg]", "Show YMM registers as doublewords",
	"drmyq", " [reg]", "Show YMM registers as quadwords",
	"drmq", " ymm0~[3]", "Show fourth quadword of ymm0",
	"drmyf", " [reg]", "Show YMM registers as 32-bit floating point",
	"drmyl", " [reg]", "Show YMM registers as 64-bit floating point",
	NULL
};

static const char *help_msg_ds[] = {
	"Usage: ds", "", "Step commands",
	"ds", "", "Step one instruction",
	"ds", " <num>", "Step <num> instructions",
	"dsb", "", "Step back one instruction",
	"dsf", "", "Step until end of frame",
	"dsi", " <cond>", "Continue until condition matches",
	"dsl", "", "Step one source line",
	"dsl", " <num>", "Step <num> source lines",
	"dso", " <num>", "Step over <num> instructions",
	"dsp", "", "Step into program (skip libs)",
	"dss", " <num>", "Skip <num> step instructions",
	"dsu", "[?] <address>", "Step until <address>. See 'dsu?' for other step until cmds.",
	NULL
};

static const char *help_msg_dsu[] = {
	"Usage: dsu", "", "Step until commands",
	"dsu", " <address>", "Step until <address>",
	"dsui", "[r] <instr>", "Step until an instruction that matches <instr>, use dsuir for regex match",
	"dsuo", " <optype> [<optype> ...]", "Step until an instr matches one of the <optype>s.",
	"dsue", " <esil>", "Step until <esil> expression matches",
	"dsuf", " <flag>", "Step until pc == <flag> matching name",
	NULL
};

static const char *help_msg_dt[] = {
	"Usage: dt", "", "Trace commands",
	"dt", "", "List all traces ",
	"dt", " [addr]", "Show trace info at address",
	"dt%", "", "TODO",
	"dt*", "", "List all traced opcode offsets",
	"dt+", " [addr] [times]", "Add trace for address N times",
	"dt-", "", "Reset traces (instruction/calls)",
	"dt=", "", "Show ascii-art color bars with the debug trace ranges",
	"dta", " 0x804020 ...", "Only trace given addresses",
	"dtc[?][addr]|([from] [to] [addr])", "", "Trace call/ret",
	"dtd", "[qi] [nth-start]", "List all traced disassembled (quiet, instructions)",
	"dte", "[?]", "Show esil trace logs",
	"dtg", "", "Graph call/ret trace",
	"dtg*", "", "Graph in agn/age commands. use .dtg*;aggi for visual",
	"dtgi", "", "Interactive debug trace",
	"dts", "[?]", "Trace sessions",
	"dtt", " [tag]", "Select trace tag (no arg unsets)",
	NULL
};

static const char *help_msg_dte[] = {
	"Usage:", "dte", " Show esil trace logs",
	"dte", "", "Esil trace log for a single instruction",
	"dte", " [idx]", "Show commands for that index log",
	"dte", "-*", "Delete all esil traces",
	"dtei", "", "Esil trace log single instruction",
	"dtek", " [sdb query]", "Esil trace log single instruction from sdb",
	NULL
};

static const char *help_msg_dts[] = {
	"Usage:", "dts[*]", "",
	"dts+", "", "Start trace session",
	"dts-", "", "Stop trace session",
	"dtst", " [dir] ", "Save trace sessions to disk",
	"dtsf", " [dir] ", "Read trace sessions from disk",
	"dtsm", "", "List current memory map and hash",
	NULL
};

static const char *help_msg_dx[] = {
	"Usage: dx", "", " # Code injection commands",
	"dx", " <opcode>...", "Inject opcodes",
	"dxa", " nop", "Assemble code and inject",
	"dxe", " egg-expr", "Compile egg expression and inject it",
	"dxr", " <opcode>...", "Inject opcodes and restore state",
	"dxs", " write 1, 0x8048, 12", "Syscall injection (see gs)",
	"\nExamples:", "", "",
	"dx", " 9090", "Inject two x86 nop",
	"\"dxa mov eax,6;mov ebx,0;int 0x80\"", "", "Inject and restore state",
	NULL
};

static const char *help_msg_dL[] = {
	"Usage: dL", "", " # List or set debugger handler",
	"dL", "", "List debugger handlers",
	"dLq", "", "List debugger handlers in quiet mode",
	"dLj", "", "List debugger handlers in json mode",
	"dL", " <handler>", "Set debugger handler",
	NULL
};

struct dot_trace_ght {
	RzGraph *graph;
	Sdb *graphnodes;
};

struct trace_node {
	ut64 addr;
	int refs;
};

// XXX those tmp files are never removed and we shuoldnt use files for this
static void setRarunProfileString(RzCore *core, const char *str) {
	char *file = rz_file_temp("rz_run");
	char *s = strdup(str);
	rz_config_set(core->config, "dbg.profile", file);
	rz_str_replace_char(s, ',', '\n');
	rz_file_dump(file, (const ut8 *)s, strlen(s), 0);
	rz_file_dump(file, (const ut8 *)"\n", 1, 1);
	free(file);
}

static void cmd_debug_cont_syscall(RzCore *core, const char *_str) {
	// TODO : handle more than one stopping syscall
	int i, *syscalls = NULL;
	int count = 0;
	if (_str && *_str) {
		char *str = strdup(_str);
		count = rz_str_word_set0(str);
		syscalls = calloc(sizeof(int), count);
		for (i = 0; i < count; i++) {
			const char *sysnumstr = rz_str_word_get0(str, i);
			int sig = (int)rz_num_math(core->num, sysnumstr);
			if (sig == -1) { // trace ALL syscalls
				syscalls[i] = -1;
			} else if (sig == 0) {
				sig = rz_syscall_get_num(core->analysis->syscall, sysnumstr);
				if (sig == -1) {
					eprintf("Unknown syscall number\n");
					free(str);
					free(syscalls);
					return;
				}
				syscalls[i] = sig;
			}
		}
		eprintf("Running child until syscalls:");
		for (i = 0; i < count; i++) {
			eprintf("%d ", syscalls[i]);
		}
		eprintf("\n");
		free(str);
	} else {
		eprintf("Running child until next syscall\n");
	}
	rz_reg_arena_swap(core->dbg->reg, true);
	rz_debug_continue_syscalls(core->dbg, syscalls, count);
	free(syscalls);
}

static int showreg(RzCore *core, const char *str) {
	int size = 0;
	RzRegItem *r = 0;
	const char *rname = str;
	// check for alias reg
	int role = rz_reg_get_name_idx(str);
	if (role != -1) {
		rname = rz_reg_get_name(core->dbg->reg, role);
	}
	r = rz_reg_get(core->dbg->reg, rname, -1);
	if (r) {
		utX value;
		if (r->size > 64) {
			rz_reg_get_value_big(core->dbg->reg, r, &value);
			switch (r->size) {
			case 80:
				rz_cons_printf("0x%04x%016" PFMT64x "\n", value.v80.High, value.v80.Low);
				break;
			case 96:
				rz_cons_printf("0x%08x%016" PFMT64x "\n", value.v96.High, value.v96.Low);
				break;
			case 128:
				rz_cons_printf("0x%016" PFMT64x "%016" PFMT64x "\n", value.v128.High, value.v128.Low);
				break;
			case 256:
				rz_cons_printf("0x%016" PFMT64x "%016" PFMT64x "%016" PFMT64x "%016" PFMT64x "\n",
					value.v256.High.High, value.v256.High.Low, value.v256.Low.High, value.v256.Low.Low);
				break;
			default:
				rz_cons_printf("Error while retrieving reg '%s' of %i bits\n", str + 1, r->size);
			}
		} else {
			ut64 off = rz_reg_get_value(core->dbg->reg, r);
			rz_cons_printf("0x%08" PFMT64x "\n", off);
		}
		return r->size;
	}
	char *arg = strchr(str + 1, ' ');
	if (arg && size == 0) {
		size = atoi(arg + 1);
	} else {
		size = atoi(str + 1);
	}
	return size;
}

static RzGraphNode *get_graphtrace_node(RzGraph *g, Sdb *nodes, struct trace_node *tn) {
	RzGraphNode *gn;
	char tn_key[TN_KEY_LEN];

	snprintf(tn_key, TN_KEY_LEN, TN_KEY_FMT, tn->addr);
	gn = (RzGraphNode *)(size_t)sdb_num_get(nodes, tn_key, NULL);
	if (!gn) {
		gn = rz_graph_add_node(g, tn);
		sdb_num_set(nodes, tn_key, (ut64)(size_t)gn, 0);
	}
	return gn;
}

static void dot_trace_create_node(RTreeNode *n, RTreeVisitor *vis) {
	struct dot_trace_ght *data = (struct dot_trace_ght *)vis->data;
	struct trace_node *tn = n->data;
	if (tn)
		get_graphtrace_node(data->graph, data->graphnodes, tn);
}

static void dot_trace_discover_child(RTreeNode *n, RTreeVisitor *vis) {
	struct dot_trace_ght *data = (struct dot_trace_ght *)vis->data;
	RzGraph *g = data->graph;
	Sdb *gnodes = data->graphnodes;
	RTreeNode *parent = n->parent;
	struct trace_node *tn = n->data;
	struct trace_node *tn_parent = parent->data;

	if (tn && tn_parent) {
		RzGraphNode *gn = get_graphtrace_node(g, gnodes, tn);
		RzGraphNode *gn_parent = get_graphtrace_node(g, gnodes, tn_parent);

		if (!rz_graph_adjacent(g, gn_parent, gn))
			rz_graph_add_edge(g, gn_parent, gn);
	}
}

static void dot_trace_traverse(RzCore *core, RTree *t, int fmt) {
	const char *gfont = rz_config_get(core->config, "graph.font");
	struct dot_trace_ght aux_data;
	RTreeVisitor vis = { 0 };
	const RzList *nodes;
	RzListIter *iter;
	RzGraphNode *n;

	if (fmt == 'i') {
		rz_core_agraph_reset(core);
		rz_core_cmd0(core, ".dtg*");
		rz_core_agraph_print_interactive(core);
		return;
	}
	aux_data.graph = rz_graph_new();
	aux_data.graphnodes = sdb_new0();

	/* build a callgraph from the execution trace */
	vis.data = &aux_data;
	vis.pre_visit = (RTreeNodeVisitCb)dot_trace_create_node;
	vis.discover_child = (RTreeNodeVisitCb)dot_trace_discover_child;
	rz_tree_bfs(t, &vis);

	/* traverse the callgraph to print the dot file */
	nodes = rz_graph_get_nodes(aux_data.graph);
	if (fmt == 0) {
		rz_cons_printf("digraph code {\n"
			       "graph [bgcolor=white];\n"
			       "    node [color=lightgray, style=filled"
			       " shape=box fontname=\"%s\" fontsize=\"8\"];\n",
			gfont);
	}
	rz_list_foreach (nodes, iter, n) {
		struct trace_node *tn = (struct trace_node *)n->data;
		const RzList *neighbours = rz_graph_get_neighbours(aux_data.graph, n);
		RzListIter *it_n;
		RzGraphNode *w;

		if (!fmt && tn) {
			rz_cons_printf("\"0x%08" PFMT64x "\" [URL=\"0x%08" PFMT64x
				       "\" color=\"lightgray\" label=\"0x%08" PFMT64x
				       " (%d)\"]\n",
				tn->addr, tn->addr, tn->addr, tn->refs);
		}
		rz_list_foreach (neighbours, it_n, w) {
			struct trace_node *tv = (struct trace_node *)w->data;

			if (tv && tn) {
				if (fmt) {
					rz_cons_printf("agn 0x%08" PFMT64x "\n", tn->addr);
					rz_cons_printf("agn 0x%08" PFMT64x "\n", tv->addr);
					rz_cons_printf("age 0x%08" PFMT64x " 0x%08" PFMT64x "\n",
						tn->addr, tv->addr);
				} else {
					rz_cons_printf("\"0x%08" PFMT64x "\" -> \"0x%08" PFMT64x
						       "\" [color=\"red\"];\n",
						tn->addr, tv->addr);
				}
			}
		}
	}
	if (!fmt) {
		rz_cons_printf("}\n");
	}

	rz_graph_free(aux_data.graph);
	sdb_free(aux_data.graphnodes);
}

/* TODO: refactor all those step_until* function into a single one
 * TODO: handle when the process is dead
 * TODO: handle ^C */

static int step_until(RzCore *core, ut64 addr) {
	ut64 off = rz_debug_reg_get(core->dbg, "PC");
	if (!off) {
		eprintf("Cannot 'drn PC'\n");
		return false;
	}
	if (!addr) {
		eprintf("Cannot continue until address 0\n");
		return false;
	}
	rz_cons_break_push(NULL, NULL);
	do {
		if (rz_cons_is_breaked()) {
			core->break_loop = true;
			break;
		}
		if (rz_debug_is_dead(core->dbg)) {
			core->break_loop = true;
			break;
		}
		rz_debug_step(core->dbg, 1);
		off = rz_debug_reg_get(core->dbg, "PC");
		// check breakpoint here
	} while (off != addr);
	rz_cons_break_pop();
	return true;
}

static int step_until_esil(RzCore *core, const char *esilstr) {
	if (!core || !esilstr || !core->dbg || !core->dbg->analysis || !core->dbg->analysis->esil) {
		eprintf("Not initialized %p. Run 'aei' first.\n", core->analysis->esil);
		return false;
	}
	rz_cons_break_push(NULL, NULL);
	for (;;) {
		if (rz_cons_is_breaked()) {
			core->break_loop = true;
			break;
		}
		if (rz_debug_is_dead(core->dbg)) {
			core->break_loop = true;
			break;
		}
		rz_debug_step(core->dbg, 1);
		rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_ALL, false);
		if (rz_analysis_esil_condition(core->analysis->esil, esilstr)) {
			eprintf("ESIL BREAK!\n");
			break;
		}
	}
	rz_cons_break_pop();
	return true;
}

static bool is_repeatable_inst(RzCore *core, ut64 addr) {
	// we have read the bytes already
	RzAnalysisOp *op = rz_core_op_analysis(core, addr, RZ_ANALYSIS_OP_MASK_ALL);
	bool ret = op && ((op->prefix & RZ_ANALYSIS_OP_PREFIX_REP) || (op->prefix & RZ_ANALYSIS_OP_PREFIX_REPNE));
	rz_analysis_op_free(op);
	return ret;
}

static int step_until_inst(RzCore *core, const char *instr, bool regex) {
	RzAsmOp asmop;
	ut8 buf[32];
	ut64 pc;
	int ret;
	bool is_x86 = rz_str_startswith(rz_config_get(core->config, "asm.arch"), "x86");

	instr = rz_str_trim_head_ro(instr);
	if (!core || !instr || !core->dbg) {
		eprintf("Wrong state\n");
		return false;
	}
	rz_cons_break_push(NULL, NULL);
	for (;;) {
		if (rz_cons_is_breaked()) {
			break;
		}
		if (rz_debug_is_dead(core->dbg)) {
			break;
		}
		pc = rz_debug_reg_get(core->dbg, "PC");
		if (is_x86 && is_repeatable_inst(core, pc)) {
			rz_debug_step_over(core->dbg, 1);
		} else {
			rz_debug_step(core->dbg, 1);
		}
		pc = rz_debug_reg_get(core->dbg, "PC");
		rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_ALL, false);
		/* TODO: disassemble instruction and strstr */
		rz_asm_set_pc(core->rasm, pc);
		// TODO: speedup if instructions are in the same block as the previous
		rz_io_read_at(core->io, pc, buf, sizeof(buf));
		ret = rz_asm_disassemble(core->rasm, &asmop, buf, sizeof(buf));
		eprintf("0x%08" PFMT64x " %d %s\n", pc, ret, rz_asm_op_get_asm(&asmop)); // asmop.buf_asm);
		if (ret > 0) {
			const char *buf_asm = rz_asm_op_get_asm(&asmop);
			if (regex) {
				if (rz_regex_match(instr, "e", buf_asm)) {
					eprintf("Stop.\n");
					break;
				}
			} else {
				if (strstr(buf_asm, instr)) {
					eprintf("Stop.\n");
					break;
				}
			}
		}
	}
	rz_cons_break_pop();
	return true;
}

static void dbg_follow_seek_register(RzCore *core) {
	int follow = rz_config_get_i(core->config, "dbg.follow");
	if (follow > 0) {
		ut64 pc = rz_debug_reg_get(core->dbg, "PC");
		if ((pc < core->offset) || (pc > (core->offset + follow))) {
			rz_core_seek_to_register(core, "PC", false);
		}
	}
}

static int step_until_optype(RzCore *core, RzList *optypes_list) {
	RzAnalysisOp op;
	ut8 buf[32];
	ut64 pc;
	int res = true;

	RzListIter *iter;
	char *optype;

	if (!core || !core->dbg) {
		eprintf("Wrong state\n");
		res = false;
		goto end;
	}
	if (!optypes_list) {
		eprintf("Missing optypes. Usage example: 'dsuo ucall ujmp'\n");
		res = false;
		goto end;
	}

	bool debugMode = rz_config_get_i(core->config, "cfg.debug");

	rz_cons_break_push(NULL, NULL);
	for (;;) {
		if (rz_cons_is_breaked()) {
			core->break_loop = true;
			break;
		}
		if (debugMode) {
			if (rz_debug_is_dead(core->dbg)) {
				core->break_loop = true;
				break;
			}
			rz_debug_step(core->dbg, 1);
			pc = rz_debug_reg_get(core->dbg, core->dbg->reg->name[RZ_REG_NAME_PC]);
			// 'Copy' from rz_debug_step_soft
			if (!core->dbg->iob.read_at) {
				eprintf("ERROR\n");
				res = false;
				goto cleanup_after_push;
			}
			if (!core->dbg->iob.read_at(core->dbg->iob.io, pc, buf, sizeof(buf))) {
				eprintf("ERROR\n");
				res = false;
				goto cleanup_after_push;
			}
		} else {
			rz_core_esil_step(core, UT64_MAX, NULL, NULL, false);
			pc = rz_reg_getv(core->analysis->reg, "PC");
		}
		rz_io_read_at(core->io, pc, buf, sizeof(buf));

		if (!rz_analysis_op(core->dbg->analysis, &op, pc, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC)) {
			eprintf("Error: rz_analysis_op failed\n");
			res = false;
			goto cleanup_after_push;
		}

		// This is slow because we do lots of strcmp's.
		// To improve this, the function rz_analysis_optype_string_to_int should be implemented
		// I also don't check if the opcode type exists.
		const char *optype_str = rz_analysis_optype_to_string(op.type);
		rz_list_foreach (optypes_list, iter, optype) {
			if (!strcmp(optype_str, optype)) {
				goto cleanup_after_push;
			}
		}
	}

cleanup_after_push:
	rz_cons_break_pop();
end:
	return res;
}

static int step_until_flag(RzCore *core, const char *instr) {
	const RzList *list;
	RzListIter *iter;
	RzFlagItem *f;
	ut64 pc;

	instr = rz_str_trim_head_ro(instr);
	if (!core || !instr || !core->dbg) {
		eprintf("Wrong state\n");
		return false;
	}
	rz_cons_break_push(NULL, NULL);
	for (;;) {
		if (rz_cons_is_breaked()) {
			break;
		}
		if (rz_debug_is_dead(core->dbg)) {
			break;
		}
		rz_debug_step(core->dbg, 1);
		rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_ALL, false);
		pc = rz_debug_reg_get(core->dbg, "PC");
		list = rz_flag_get_list(core->flags, pc);
		rz_list_foreach (list, iter, f) {
			if (!instr || !*instr || (f->realname && strstr(f->realname, instr))) {
				rz_cons_printf("[ 0x%08" PFMT64x " ] %s\n",
					f->offset, f->realname);
				goto beach;
			}
		}
	}
beach:
	rz_cons_break_pop();
	return true;
}

/* until end of frame */
static int step_until_eof(RzCore *core) {
	int maxLoops = 200000;
	ut64 off, now = rz_debug_reg_get(core->dbg, "SP");
	rz_cons_break_push(NULL, NULL);
	do {
		// XXX (HACK!)
		rz_debug_step_over(core->dbg, 1);
		off = rz_debug_reg_get(core->dbg, "SP");
		// check breakpoint here
		if (--maxLoops < 0) {
			eprintf("Step loop limit exceeded\n");
			break;
		}
	} while (off <= now);
	rz_cons_break_pop();
	return true;
}

static int step_line(RzCore *core, int times) {
	char file[512], file2[512];
	int find_meta, line = -1, line2 = -1;
	char *tmp_ptr = NULL;
	ut64 off = rz_debug_reg_get(core->dbg, "PC");
	if (off == 0LL) {
		eprintf("Cannot 'drn PC'\n");
		return false;
	}
	file[0] = 0;
	file2[0] = 0;
	if (rz_bin_addr2line(core->bin, off, file, sizeof(file), &line)) {
		char *ptr = rz_file_slurp_line(file, line, 0);
		eprintf("--> 0x%08" PFMT64x " %s : %d\n", off, file, line);
		eprintf("--> %s\n", ptr);
		find_meta = false;
		free(ptr);
	} else {
		eprintf("--> Stepping until dwarf line\n");
		find_meta = true;
	}
	do {
		rz_debug_step(core->dbg, 1);
		off = rz_debug_reg_get(core->dbg, "PC");
		if (!rz_bin_addr2line(core->bin, off, file2, sizeof(file2), &line2)) {
			if (find_meta)
				continue;
			eprintf("Cannot retrieve dwarf info at 0x%08" PFMT64x "\n", off);
			return false;
		}
	} while (!strcmp(file, file2) && line == line2);

	eprintf("--> 0x%08" PFMT64x " %s : %d\n", off, file2, line2);
	tmp_ptr = rz_file_slurp_line(file2, line2, 0);
	eprintf("--> %s\n", tmp_ptr);
	free(tmp_ptr);

	return true;
}

static void cmd_debug_pid(RzCore *core, const char *input) {
	int pid, sig;
	const char *ptr;
	switch (input[1]) {
	case '\0': // "dp"
		eprintf("Selected: %d %d\n", core->dbg->pid, core->dbg->tid);
		rz_debug_pid_list(core->dbg, core->dbg->pid, 0);
		break;
	case '-': // "dp-"
		if (input[2] == ' ') {
			rz_debug_detach(core->dbg, rz_num_math(core->num, input + 2));
		} else {
			rz_debug_detach(core->dbg, core->dbg->pid);
		}
		break;
	case 'c': // "dpc"
		if (core->dbg->forked_pid != -1) {
			if (input[2] == '*') {
				eprintf("dp %d\n", core->dbg->forked_pid);
			} else {
				rz_debug_select(core->dbg, core->dbg->forked_pid, core->dbg->tid);
				core->dbg->main_pid = core->dbg->forked_pid;
				core->dbg->n_threads = 0;
				core->dbg->forked_pid = -1;
			}
		} else {
			eprintf("No recently forked children\n");
		}
		break;
	case 'k': // "dpk"
		/* stop, print, pass -- just use flags*/
		/* XXX: not for threads? signal is for a whole process!! */
		/* XXX: but we want fine-grained access to process resources */
		pid = atoi(input + 2);
		if (pid > 0) {
			ptr = rz_str_trim_head_ro(input + 2);
			ptr = strchr(ptr, ' ');
			sig = ptr ? atoi(ptr + 1) : 0;
			eprintf("Sending signal '%d' to pid '%d'\n", sig, pid);
			rz_debug_kill(core->dbg, pid, false, sig);
		} else
			eprintf("cmd_debug_pid: Invalid arguments (%s)\n", input);
		break;
	case 'n': // "dpn"
		eprintf("TODO: debug_fork: %d\n", rz_debug_child_fork(core->dbg));
		break;
	case 't': // "dpt"
		switch (input[2]) {
		case '\0': // "dpt"
			rz_debug_thread_list(core->dbg, core->dbg->pid, 0);
			break;
		case 'j': // "dptj"
			if (input[3] != ' ') { // "dptj"
				rz_debug_thread_list(core->dbg, core->dbg->pid, 'j');
			} else { // "dptj "
				rz_debug_thread_list(core->dbg, atoi(input + 3), 'j');
			}
			break;
		case ' ': // "dpt "
			rz_debug_thread_list(core->dbg, atoi(input + 2), 0);
			break;
		case '=': // "dpt="
			rz_debug_select(core->dbg, core->dbg->pid,
				(int)rz_num_math(core->num, input + 3));
			break;
		case 'n': // "dptn"
			eprintf("TODO: debug_clone: %d\n", rz_debug_child_clone(core->dbg));
			break;
		case '?': // "dpt?"
		default:
			rz_core_cmd_help(core, help_msg_dp);
			break;
		}
		break;
	case 'a': // "dpa"
		if (input[2]) {
			int pid = rz_num_math(core->num, input + 2);
			rz_core_debug_attach(core, pid);
		} else {
			rz_core_debug_attach(core, 0);
		}
		break;
	case 'f': // "dpf"
		if (core->file && core->io) {
			rz_debug_select(core->dbg, rz_io_fd_get_pid(core->io, core->file->fd),
				rz_io_fd_get_tid(core->io, core->file->fd));
		}
		break;
	case '=': // "dp="
		rz_debug_select(core->dbg,
			(int)rz_num_math(core->num, input + 2), core->dbg->tid);
		core->dbg->main_pid = rz_num_math(core->num, input + 2);
		break;
	case 'l': // "dpl"
		switch (input[2]) {
		case '\0': // "dpl"
			rz_debug_pid_list(core->dbg, 0, 0);
			break;
		case 'j': // "dplj"
			rz_debug_pid_list(core->dbg, 0, 'j');
			break;
		}
		break;
	case 'j': // "dpj"
		switch (input[2]) {
		case '\0': // "dpj"
			rz_debug_pid_list(core->dbg, core->dbg->pid, 'j');
			break;
		case ' ': // "dpj "
			rz_debug_pid_list(core->dbg,
				(int)RZ_MAX(0, (int)rz_num_math(core->num, input + 2)), 'j');
			break;
		}
		break;
	case 'e': // "dpe"
	{
		int pid = (input[2] == ' ') ? atoi(input + 2) : core->dbg->pid;
		char *exe = rz_sys_pid_to_path(pid);
		if (exe) {
			rz_cons_println(exe);
			free(exe);
		}
	} break;
	case ' ': // "dp "
		rz_debug_pid_list(core->dbg,
			(int)RZ_MAX(0, (int)rz_num_math(core->num, input + 2)), 0);
		break;
	case '?': // "dp?"
	default:
		rz_core_cmd_help(core, help_msg_dp);
		break;
	}
}

static void cmd_debug_backtrace(RzCore *core, const char *input) {
	RzAnalysisOp analop;
	ut64 addr, len = rz_num_math(core->num, input);
	if (!len) {
		rz_bp_traptrace_list(core->dbg->bp);
	} else {
		ut64 oaddr = 0LL;
		eprintf("Trap tracing 0x%08" PFMT64x "-0x%08" PFMT64x "\n",
			core->offset, core->offset + len);
		rz_reg_arena_swap(core->dbg->reg, true);
		rz_bp_traptrace_reset(core->dbg->bp, true);
		rz_bp_traptrace_add(core->dbg->bp, core->offset, core->offset + len);
		rz_bp_traptrace_enable(core->dbg->bp, true);
		do {
			ut8 buf[32];
			rz_debug_continue(core->dbg);
			addr = rz_debug_reg_get(core->dbg, "PC");
			if (!addr) {
				eprintf("pc=0\n");
				break;
			}
			if (addr == oaddr) {
				eprintf("pc=opc\n");
				break;
			}
			oaddr = addr;
			/* XXX Bottleneck..we need to reuse the bytes read by traptrace */
			// XXX Do asm.arch should define the max size of opcode?
			rz_io_read_at(core->io, addr, buf, 32); // XXX longer opcodes?
			rz_analysis_op(core->analysis, &analop, addr, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC);
		} while (rz_bp_traptrace_at(core->dbg->bp, addr, analop.size));
		rz_bp_traptrace_enable(core->dbg->bp, false);
	}
}

static int grab_bits(RzCore *core, const char *arg, int *pcbits2) {
	int pcbits = atoi(arg);
	if (pcbits2) {
		*pcbits2 = 0;
	}
	if (pcbits < 1) {
		if (!strcmp(rz_config_get(core->config, "asm.arch"), "avr")) {
			pcbits = 8;
			if (pcbits2) {
				*pcbits2 = 32;
			}
		} else {
			const char *pcname = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
			RzRegItem *reg = rz_reg_get(core->analysis->reg, pcname, 0);
			if (reg) {
				if (core->rasm->bits != reg->size)
					pcbits = reg->size;
			}
		}
	}
	return pcbits ? pcbits : core->analysis->bits;
}

#define MAX_MAP_SIZE 1024 * 1024 * 512
static int dump_maps(RzCore *core, int perm, const char *filename) {
	RzDebugMap *map;
	RzListIter *iter;
	rz_debug_map_sync(core->dbg); // update process memory maps
	ut64 addr = core->offset;
	int do_dump = false;
	int ret = !rz_list_empty(core->dbg->maps);
	rz_list_foreach (core->dbg->maps, iter, map) {
		do_dump = false;
		if (perm == -1) {
			if (addr >= map->addr && addr < map->addr_end) {
				do_dump = true;
			}
		} else if (perm == 0) {
			do_dump = true;
		} else if (perm == (map->perm & perm)) {
			do_dump = true;
		}
		if (do_dump) {
			ut8 *buf = malloc(map->size);
			//TODO: use mmap here. we need a portable implementation
			if (!buf) {
				eprintf("Cannot allocate 0x%08" PFMT64x " bytes\n", map->size);
				free(buf);
				/// XXX: TODO: read by blocks!!1
				continue;
			}
			if (map->size > MAX_MAP_SIZE) {
				eprintf("Do not dumping 0x%08" PFMT64x " because it's too big\n", map->addr);
				free(buf);
				continue;
			}
			rz_io_read_at(core->io, map->addr, buf, map->size);
			char *file = filename
				? strdup(filename)
				: rz_str_newf("0x%08" PFMT64x "-0x%08" PFMT64x "-%s.dmp",
					  map->addr, map->addr_end, rz_str_rwx_i(map->perm));
			if (!rz_file_dump(file, buf, map->size, 0)) {
				eprintf("Cannot write '%s'\n", file);
				ret = 0;
			} else {
				eprintf("Dumped %d byte(s) into %s\n", (int)map->size, file);
			}
			free(file);
			free(buf);
		}
	}
	//eprintf ("No debug region found here\n");
	return ret;
}

static void cmd_debug_modules(RzCore *core, int mode) { // "dmm"
	ut64 addr = core->offset;
	RzDebugMap *map;
	RzList *list;
	RzListIter *iter;

	/* avoid processing the list if the user only wants help */
	if (mode == '?') {
	show_help:
		rz_core_cmd_help(core, help_msg_dmm);
		return;
	}
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = rz_core_pj_new(core);
		if (!pj) {
			return;
		}
		pj_a(pj);
	}
	// TODO: honor mode
	list = rz_debug_modules_list(core->dbg);
	rz_list_foreach (list, iter, map) {
		switch (mode) {
		case 0:
			rz_cons_printf("0x%08" PFMT64x " 0x%08" PFMT64x "  %s\n", map->addr, map->addr_end, map->file);
			break;
		case '.':
			if (addr >= map->addr && addr < map->addr_end) {
				rz_cons_printf("0x%08" PFMT64x " 0x%08" PFMT64x "  %s\n", map->addr, map->addr_end, map->file);
				goto beach;
			}
			break;
		case 'j': {
			/* Escape backslashes (e.g. for Windows). */
			pj_o(pj);
			pj_kn(pj, "addr", map->addr);
			pj_kn(pj, "addr_end", map->addr_end);
			pj_ks(pj, "file", map->file);
			pj_ks(pj, "name", map->name);
			pj_end(pj);
		} break;
		case ':':
		case '*':
			if (mode == '*' || (mode == ':' && addr >= map->addr && addr < map->addr_end)) {
				/* Escape backslashes (e.g. for Windows). */
				char *escaped_path = rz_str_escape(map->file);
				char *filtered_name = strdup(map->name);
				rz_name_filter(filtered_name, 0);
				rz_cons_printf("f mod.%s = 0x%08" PFMT64x "\n",
					filtered_name, map->addr);
				rz_cons_printf("oba 0x%08" PFMT64x " %s\n", map->addr, escaped_path);
				// rz_cons_printf (".!rz-bin -rsB 0x%08"PFMT64x" \"%s\"\n", map->addr, escaped_path);
				free(escaped_path);
				free(filtered_name);
			}
			break;
		default:
			pj_free(pj);
			rz_list_free(list);
			goto show_help;
			/* not reached */
		}
	}
beach:
	if (mode == 'j') {
		pj_end(pj);
		rz_cons_println(pj_string(pj));
	}
	pj_free(pj);
	rz_list_free(list);
}

#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__

static int cmd_dbg_map_heap_glibc_32(RzCore *core, const char *input);
static int cmd_dbg_map_heap_glibc_64(RzCore *core, const char *input);
#endif // __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__
#if __WINDOWS__
static int cmd_debug_map_heap_win(RzCore *core, const char *input);
#endif // __WINDOWS__

static ut64 addroflib(RzCore *core, const char *libname) {
	RzListIter *iter;
	RzDebugMap *map;
	if (!core || !libname) {
		return UT64_MAX;
	}
	rz_debug_map_sync(core->dbg);
	// RzList *list = rz_debug_native_modules_get (core->dbg);
	RzList *list = rz_debug_modules_list(core->dbg);
	rz_list_foreach (list, iter, map) {
		if (strstr(rz_file_basename(map->name), libname)) {
			return map->addr;
		}
	}
	rz_list_foreach (core->dbg->maps, iter, map) {
		if (strstr(rz_file_basename(map->name), libname)) {
			return map->addr;
		}
	}
	return UT64_MAX;
}

static RzDebugMap *get_closest_map(RzCore *core, ut64 addr) {
	RzListIter *iter;
	RzDebugMap *map;

	rz_debug_map_sync(core->dbg);
	RzList *list = rz_debug_modules_list(core->dbg);
	rz_list_foreach (list, iter, map) {
		if (addr != UT64_MAX && (addr >= map->addr && addr < map->addr_end)) {
			return map;
		}
	}
	rz_list_foreach (core->dbg->maps, iter, map) {
		if (addr != UT64_MAX && (addr >= map->addr && addr < map->addr_end)) {
			return map;
		}
	}
	return NULL;
}

static int rz_debug_heap(RzCore *core, const char *input) {
	const char *m = rz_config_get(core->config, "dbg.malloc");
	if (m && !strcmp("glibc", m)) {
#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__
		if (core->rasm->bits == 64) {
			cmd_dbg_map_heap_glibc_64(core, input + 1);
		} else {
			cmd_dbg_map_heap_glibc_32(core, input + 1);
		}
#else
		eprintf("glibc not supported for this platform\n");
#endif
#if HAVE_JEMALLOC
	} else if (m && !strcmp("jemalloc", m)) {
		if (core->rasm->bits == 64) {
			cmd_dbg_map_jemalloc_64(core, input + 1);
		} else {
			cmd_dbg_map_jemalloc_32(core, input + 1);
		}
#endif
	} else {
#if __WINDOWS__
		cmd_debug_map_heap_win(core, input + 1);
#else
		eprintf("MALLOC algorithm not supported\n");
		return false;
#endif
	}
	return true;
}

static bool get_bin_info(RzCore *core, const char *file, ut64 baseaddr, PJ *pj, int mode, bool symbols_only, RzCoreBinFilter *filter) {
	int fd;
	if ((fd = rz_io_fd_open(core->io, file, RZ_PERM_R, 0)) == -1) {
		return false;
	}
	RzBinOptions opt = { 0 };
	opt.fd = fd;
	opt.sz = rz_io_fd_size(core->io, fd);
	opt.baseaddr = baseaddr;
	RzBinFile *obf = rz_bin_cur(core->bin);
	if (!rz_bin_open_io(core->bin, &opt)) {
		rz_io_fd_close(core->io, fd);
		return false;
	}
	int action = RZ_CORE_BIN_ACC_ALL & ~RZ_CORE_BIN_ACC_INFO;
	if (symbols_only || filter->name) {
		action = RZ_CORE_BIN_ACC_SYMBOLS;
	} else if (mode == RZ_MODE_SET || mode == RZ_MODE_RIZINCMD) {
		action &= ~RZ_CORE_BIN_ACC_ENTRIES & ~RZ_CORE_BIN_ACC_MAIN;
	}
	rz_core_bin_info(core, action, pj, mode, 1, filter, NULL);
	RzBinFile *bf = rz_bin_cur(core->bin);
	rz_bin_file_delete(core->bin, bf->id);
	rz_bin_file_set_cur_binfile(core->bin, obf);
	rz_io_fd_close(core->io, fd);
	return true;
}

static int cmd_debug_map(RzCore *core, const char *input) {
	RzListIter *iter;
	RzDebugMap *map;
	ut64 addr = core->offset;

	switch (input[0]) {
	case '.': // "dm."
		rz_debug_map_list(core->dbg, addr, input);
		break;
	case 'm': // "dmm"
		if (!strcmp(input + 1, ".*")) {
			cmd_debug_modules(core, ':');
		} else
			cmd_debug_modules(core, input[1]);
		break;
	case '?': // "dm?"
		rz_core_cmd_help(core, help_msg_dm);
		break;
	case 'p': // "dmp"
		if (input[1] == '?') {
			rz_core_cmd_help(core, help_msg_dmp);
		} else if (input[1] == ' ') {
			int perms;
			char *p, *q;
			ut64 size = 0, addr;
			p = strchr(input + 2, ' ');
			if (p) {
				*p++ = 0;
				q = strchr(p, ' ');
				if (q) {
					*q++ = 0;
					addr = rz_num_math(core->num, input + 2);
					size = rz_num_math(core->num, p);
					perms = rz_str_rwx(q);
					//	eprintf ("(%s)(%s)(%s)\n", input + 2, p, q);
					//	eprintf ("0x%08"PFMT64x" %d %o\n", addr, (int) size, perms);
					rz_debug_map_protect(core->dbg, addr, size, perms);
				} else
					eprintf("See dmp?\n");
			} else {
				rz_debug_map_sync(core->dbg); // update process memory maps
				addr = UT64_MAX;
				rz_list_foreach (core->dbg->maps, iter, map) {
					if (core->offset >= map->addr && core->offset < map->addr_end) {
						addr = map->addr;
						size = map->size;
						break;
					}
				}
				perms = rz_str_rwx(input + 2);
				if (addr != UT64_MAX && perms >= 0) {
					rz_debug_map_protect(core->dbg, addr, size, perms);
				} else {
					eprintf("See dmp?\n");
				}
			}
		} else {
			eprintf("See dmp?\n");
		}
		break;
	case 'd': // "dmd"
		switch (input[1]) {
		case 'a': return dump_maps(core, 0, NULL);
		case 'w': return dump_maps(core, RZ_PERM_RW, NULL);
		case ' ': return dump_maps(core, -1, input + 2);
		case 0: return dump_maps(core, -1, NULL);
		case '?':
		default:
			eprintf("Usage: dmd[aw]  - dump (all-or-writable) debug maps\n");
			break;
		}
		break;
	case 'l': // "dml"
		if (input[1] != ' ') {
			eprintf("Usage: dml [file]\n");
			return false;
		}
		rz_debug_map_sync(core->dbg); // update process memory maps
		rz_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				size_t sz;
				char *buf = rz_file_slurp(input + 2, &sz);
				//TODO: use mmap here. we need a portable implementation
				if (!buf) {
					eprintf("Cannot allocate 0x%08" PFMT64x " byte(s)\n", map->size);
					return false;
				}
				rz_io_write_at(core->io, map->addr, (const ut8 *)buf, sz);
				if (sz != map->size)
					eprintf("File size differs from region size (%" PFMT64u " vs %" PFMT64d ")\n",
						(ut64)sz, map->size);
				eprintf("Loaded %" PFMT64u " byte(s) into the map region at 0x%08" PFMT64x "\n",
					(ut64)sz, map->addr);
				free(buf);
				return true;
			}
		}
		eprintf("No debug region found here\n");
		return false;
	case 'i': // "dmi"
		switch (input[1]) {
		case '\0': // "dmi" alias of "dmm"
			rz_core_cmd(core, "dmm", 0);
			break;
		case ' ': // "dmi "
		case '*': // "dmi*"
		case 'v': // "dmiv"
		case 'j': // "dmij"
		case 'q': // "dmiq"
		case 'a': // "dmia"
		{
			const char *libname = NULL, *symname = NULL, *a0;
			int mode;
			ut64 baddr = 0LL;
			char *ptr;
			int i = 1;
			bool symbols_only = true;
			if (input[1] == 'a') {
				symbols_only = false;
				input++;
			}
			PJ *pj = NULL;
			switch (input[1]) {
			case 's':
				mode = RZ_MODE_SET;
				break;
			case '*':
				mode = RZ_MODE_RIZINCMD;
				break;
			case 'j':
				mode = RZ_MODE_JSON;
				pj = rz_core_pj_new(core);
				if (!pj) {
					return false;
				}
				break;
			case 'q':
				mode = input[2] == 'q' ? input++, RZ_MODE_SIMPLEST : RZ_MODE_SIMPLE;
				break;
			default:
				mode = RZ_MODE_PRINT;
				break;
			}
			ptr = strdup(rz_str_trim_head_ro(input + 2));
			if (!ptr || !*ptr) {
				rz_core_cmd(core, "dmm", 0);
				free(ptr);
				break;
			}
			if (symbols_only) {
				i = rz_str_word_set0(ptr);
			}
			switch (i) {
			case 2:
				symname = rz_str_word_get0(ptr, 1);
				// fall through
			case 1:
				a0 = rz_str_word_get0(ptr, 0);
				addr = rz_num_get(core->num, a0);
				if (!addr || addr == UT64_MAX) {
					libname = rz_str_word_get0(ptr, 0);
				}
				break;
			}
			if (libname && !addr) {
				addr = addroflib(core, rz_file_basename(libname));
				if (addr == UT64_MAX) {
					eprintf("Unknown library, or not found in dm\n");
				}
			}
			map = get_closest_map(core, addr);
			if (map) {
				RzCoreBinFilter filter;
				filter.offset = 0LL;
				filter.name = (char *)symname;
				baddr = map->addr;

				if (libname) {
					const char *file = map->file ? map->file : map->name;
					char *newfile = NULL;
					if (!rz_file_exists(file)) {
						newfile = rz_file_temp("memlib");
						if (newfile) {
							file = newfile;
							rz_core_cmdf(core, "wtf %s 0x%" PFMT64x " @ 0x%" PFMT64x " 2> %s",
								file, map->size, baddr, RZ_SYS_DEVNULL);
						}
					}
					get_bin_info(core, file, baddr, pj, mode, symbols_only, &filter);
					if (newfile) {
						if (!rz_file_rm(newfile)) {
							eprintf("Error when removing %s\n", newfile);
						}
						free(newfile);
					}
				} else {
					rz_bin_set_baddr(core->bin, map->addr);
					rz_core_bin_info(core, RZ_CORE_BIN_ACC_SYMBOLS, pj, (input[1] == '*'), true, &filter, NULL);
					rz_bin_set_baddr(core->bin, baddr);
				}
			}
			if (mode == RZ_MODE_JSON) {
				rz_cons_println(pj_string(pj));
				pj_free(pj);
			}
			free(ptr);
		} break;
		case '.': // "dmi."
		{
			map = get_closest_map(core, addr);
			if (map) {
				ut64 closest_addr = UT64_MAX;
				RzList *symbols = rz_bin_get_symbols(core->bin);
				RzBinSymbol *symbol, *closest_symbol = NULL;

				rz_list_foreach (symbols, iter, symbol) {
					if (symbol->vaddr > addr) {
						if (symbol->vaddr - addr < closest_addr) {
							closest_addr = symbol->vaddr - addr;
							closest_symbol = symbol;
						}
					} else {
						if (addr - symbol->vaddr < closest_addr) {
							closest_addr = addr - symbol->vaddr;
							closest_symbol = symbol;
						}
					}
				}
				if (closest_symbol) {
					RzCoreBinFilter filter;
					filter.offset = 0LL;
					filter.name = (char *)closest_symbol->name;

					rz_bin_set_baddr(core->bin, map->addr);
					rz_core_bin_info(core, RZ_CORE_BIN_ACC_SYMBOLS, NULL, false, true, &filter, NULL);
				}
			}
		} break;
		default:
			rz_core_cmd_help(core, help_msg_dmi);
			break;
		}
		break;
	case 'S': // "dmS"
	{ // Move to a separate function
		const char *libname = NULL, *sectname = NULL, *mode = "";
		ut64 baddr = 0LL;
		char *ptr;
		int i;

		if (input[1] == '*') {
			ptr = strdup(rz_str_trim_head_ro((char *)input + 2));
			mode = "-r ";
		} else {
			ptr = strdup(rz_str_trim_head_ro((char *)input + 1));
		}
		i = rz_str_word_set0(ptr);

		addr = UT64_MAX;
		switch (i) {
		case 2: // get section name
			sectname = rz_str_word_get0(ptr, 1);
			/* fallthrou */
		case 1: // get addr|libname
			if (IS_DIGIT(*ptr)) {
				const char *a0 = rz_str_word_get0(ptr, 0);
				addr = rz_num_math(core->num, a0);
			} else {
				addr = UT64_MAX;
			}
			if (!addr || addr == UT64_MAX) {
				libname = rz_str_word_get0(ptr, 0);
			}
			break;
		}
		rz_debug_map_sync(core->dbg); // update process memory maps
		RzList *list = rz_debug_modules_list(core->dbg);
		rz_list_foreach (list, iter, map) {
			if ((!libname ||
				    (addr != UT64_MAX && (addr >= map->addr && addr < map->addr_end)) ||
				    (libname != NULL && (strstr(map->name, libname))))) {
				baddr = map->addr;
				char *res;
				const char *file = map->file ? map->file : map->name;
				char *name = rz_str_escape((char *)rz_file_basename(file));
				char *filesc = rz_str_escape(file);
				/* TODO: do not spawn. use RzBin API */
				if (sectname) {
					char *sect = rz_str_escape(sectname);
					res = rz_sys_cmd_strf("env RZ_BIN_PREFIX=\"%s\" rz-bin %s-B 0x%08" PFMT64x " -S \"%s\" | grep \"%s\"", name, mode, baddr, filesc, sect);
					free(sect);
				} else {
					res = rz_sys_cmd_strf("env RZ_BIN_PREFIX=\"%s\" rz-bin %s-B 0x%08" PFMT64x " -S \"%s\"", name, mode, baddr, filesc);
				}
				free(filesc);
				rz_cons_println(res);
				free(name);
				free(res);
				if (libname || addr != UT64_MAX) { //only single match requested
					break;
				}
			}
		}
		free(ptr);
	} break;
	case ' ': // "dm "
	{
		int size;
		char *p = strchr(input + 2, ' ');
		if (p) {
			*p++ = 0;
			addr = rz_num_math(core->num, input + 1);
			size = rz_num_math(core->num, p);
			rz_debug_map_alloc(core->dbg, addr, size, false);
		} else {
			eprintf("Usage: dm addr size\n");
			return false;
		}
	} break;
	case '-': // "dm-"
		if (input[1] != ' ') {
			eprintf("|ERROR| Usage: dm- [addr]\n");
			break;
		}
		addr = rz_num_math(core->num, input + 2);
		rz_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				rz_debug_map_dealloc(core->dbg, map);
				rz_debug_map_sync(core->dbg);
				return true;
			}
		}
		eprintf("The address doesn't match with any map.\n");
		break;
	case 'L': // "dmL"
	{
		int size;
		char *p = strchr(input + 2, ' ');
		if (p) {
			*p++ = 0;
			addr = rz_num_math(core->num, input + 1);
			size = rz_num_math(core->num, p);
			rz_debug_map_alloc(core->dbg, addr, size, true);
		} else {
			eprintf("Usage: dmL addr size\n");
			return false;
		}
	} break;
	case '\0': // "dm"
	case '*': // "dm*"
	case 'j': // "dmj"
	case 'q': // "dmq"
		rz_debug_map_sync(core->dbg); // update process memory maps
		rz_debug_map_list(core->dbg, core->offset, input);
		break;
	case '=': // "dm="
		rz_debug_map_sync(core->dbg);
		rz_debug_map_list_visual(core->dbg, core->offset, input,
			rz_config_get_i(core->config, "scr.color"));
		break;
	case 'h': // "dmh"
		(void)rz_debug_heap(core, input);
		break;
	}
	return true;
}

#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__
#include "linux_heap_glibc.c"
#elif __WINDOWS__
#include "windows_heap.c"
#endif

static void foreach_reg_set_or_clear(RzCore *core, bool set) {
	RzReg *reg = rz_config_get_i(core->config, "cfg.debug")
		? core->dbg->reg
		: core->analysis->reg;
	const RzList *regs = rz_reg_get_list(reg, RZ_REG_TYPE_GPR);
	RzListIter *it;
	RzRegItem *reg_item;
	rz_list_foreach (regs, it, reg_item) {
		if (set) {
			const ut64 value = rz_reg_get_value(core->dbg->reg, reg_item);
			rz_flag_set(core->flags, reg_item->name, value, reg_item->size / 8);
		} else {
			rz_flag_unset_name(core->flags, reg_item->name);
		}
	}
}

RZ_API void rz_core_debug_set_register_flags(RzCore *core) {
	rz_flag_space_push(core->flags, RZ_FLAGS_FS_REGISTERS);
	foreach_reg_set_or_clear(core, true);
	rz_flag_space_pop(core->flags);
}

RZ_API void rz_core_debug_clear_register_flags(RzCore *core) {
	foreach_reg_set_or_clear(core, false);
}

RZ_API void rz_core_debug_rr(RzCore *core, RzReg *reg, int mode) {
	char *color = "";
	char *colorend = "";
	int had_colors = rz_config_get_i(core->config, "scr.color");
	bool use_colors = had_colors != 0;
	int delta = 0;
	ut64 diff, value;
	int bits = core->rasm->bits;
	//XXX: support other RzRegisterType
	const RzList *list = rz_reg_get_list(reg, RZ_REG_TYPE_GPR);
	RzListIter *iter;
	RzRegItem *r;
	RzTable *t = rz_core_table(core);

	if (mode == 'j') {
		rz_config_set_i(core->config, "scr.color", false);
		use_colors = 0;
	}

	if (use_colors) {
#undef ConsP
#define ConsP(x) (core->cons && core->cons->context->pal.x) ? core->cons->context->pal.x
		color = ConsP(creg)
		    : Color_BWHITE;
		colorend = Color_RESET;
	}

	rz_table_set_columnsf(t, "ssss", "role", "reg", "value", "refstr");
	rz_list_foreach (list, iter, r) {
		if (r->size != bits) {
			continue;
		}

		value = rz_reg_get_value(core->dbg->reg, r);
		delta = 0;
		int regSize = r->size;
		//XXX: support larger regSize
		if (regSize < 80) {
			rz_reg_arena_swap(core->dbg->reg, false);
			diff = rz_reg_get_value(core->dbg->reg, r);
			rz_reg_arena_swap(core->dbg->reg, false);
			delta = value - diff;
		}

		const char *role = "";
		int i;
		for (i = 0; i < RZ_REG_NAME_LAST; i++) {
			const char *t = rz_reg_get_name(reg, i);
			if (t && !strcmp(t, r->name)) {
				role = rz_reg_get_role(i);
			}
		}

		char *namestr = NULL;
		char *valuestr = NULL;
		if (delta && use_colors) {
			namestr = rz_str_newf("%s%s%s", color, r->name, colorend);
			valuestr = rz_str_newf("%s%" PFMT64x "%s", color, value, colorend);
		} else {
			namestr = rz_str_new(r->name);
			valuestr = rz_str_newf("%" PFMT64x, value);
		}

		char *rrstr = rz_core_analysis_hasrefs(core, value, true);
		if (!rrstr) {
			rrstr = strdup("");
		}

		rz_table_add_rowf(t, "ssss", role, namestr, valuestr, rrstr);
		free(namestr);
		free(valuestr);
		free(rrstr);
	}

	char *s = (mode == 'j') ? rz_table_tojson(t) : rz_table_tostring(t);
	rz_cons_print(s);
	free(s);
	rz_table_free(t);

	if (had_colors) {
		rz_config_set_i(core->config, "scr.color", had_colors);
	}
}

static void show_drpi(RzCore *core) {
	int i;
	RzListIter *iter;
	RzRegItem *ri;
	rz_cons_printf("Aliases (Reg->name)\n");
	for (i = 0; i < RZ_REG_NAME_LAST; i++) {
		rz_cons_printf("%d %s %s\n", i, rz_reg_get_role(i), core->analysis->reg->name[i]);
	}
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		const char *nmi = rz_reg_get_type(i);
		rz_cons_printf("regset %d (%s)\n", i, nmi);
		RzRegSet *rs = &core->analysis->reg->regset[i];
		rz_cons_printf("* arena %s size %d\n", rz_reg_get_type(i), rs->arena->size);
		rz_list_foreach (rs->regs, iter, ri) {
			const char *tpe = rz_reg_get_type(ri->type);
			const char *arn = rz_reg_get_type(ri->arena);
			rz_cons_printf("   %s %s @ %s (offset: %d  size: %d)", ri->name, tpe, arn, ri->offset / 8, ri->size / 8);
			if ((ri->offset / 8) + (ri->size / 8) > rs->arena->size) {
				rz_cons_printf(" *OVERFLOW*");
			}
			rz_cons_newline();
		}
	}
}

static void cmd_reg_profile(RzCore *core, char from, const char *str) { // "arp" and "drp"
	const char *ptr;
	RzReg *r = rz_config_get_i(core->config, "cfg.debug") ? core->dbg->reg : core->analysis->reg;
	switch (str[1]) {
	case '\0': // "drp" "arp"
		if (r->reg_profile_str) {
			rz_cons_println(r->reg_profile_str);
		} else {
			eprintf("No register profile defined. Try 'dr.'\n");
		}
		break;
	case 'c': // "drpc" "arpc"
		if (core->dbg->reg->reg_profile_cmt) {
			rz_cons_println(r->reg_profile_cmt);
		}
		break;
	case 'g': // "drpg" "arpg"
		ptr = rz_str_trim_head_ro(str + 2);
		if (!RZ_STR_ISEMPTY(ptr)) {
			char *r2profile = rz_reg_parse_gdb_profile(ptr);
			if (r2profile) {
				rz_cons_println(r2profile);
				core->num->value = 0;
				free(r2profile);
			} else {
				core->num->value = 1;
				eprintf("Warning: Cannot parse gdb profile.\n");
			}
		} else {
			eprintf("Usage: arpg [gdb-reg-profile]\n");
		}
		break;
	case ' ': // "drp " "arp "
		ptr = rz_str_trim_head_ro(str + 2);
		rz_reg_set_profile(r, ptr);
		rz_debug_plugin_set_reg_profile(core->dbg, ptr);
		break;
	case '.': { // "drp."
		RzRegSet *rs = rz_reg_regset_get(r, RZ_REG_TYPE_GPR);
		if (rs) {
			eprintf("size = %d\n", rs->arena->size);
		}
	} break;
	case 'i': // "drpi" "arpi"
		show_drpi(core);
		break;
	case 's': // "drps" "arps"
		if (str[2] == ' ') {
			ut64 n = rz_num_math(core->num, str + 2);
			// TODO: move this thing into the rz_reg API
			RzRegSet *rs = rz_reg_regset_get(core->dbg->reg, RZ_REG_TYPE_GPR);
			if (rs && n > 0) {
				RzListIter *iter;
				RzRegArena *arena;
				rz_list_foreach (rs->pool, iter, arena) {
					ut8 *newbytes = calloc(1, n);
					if (newbytes) {
						free(arena->bytes);
						arena->bytes = newbytes;
						arena->size = n;
					} else {
						eprintf("Cannot allocate %d\n", (int)n);
					}
				}
			} else {
				eprintf("Invalid arena size\n");
			}
		} else {
			RzRegSet *rs = rz_reg_regset_get(core->dbg->reg, RZ_REG_TYPE_GPR);
			if (rs) {
				rz_cons_printf("%d\n", rs->arena->size);
			} else
				eprintf("Cannot find GPR register arena.\n");
		}
		break;
	case 'j': // "drpj" "arpj"
	{
		// "drpj" .. dup from "arpj"
		RzListIter *iter;
		RzRegItem *r;
		int i;
		PJ *pj = rz_core_pj_new(core);
		if (!pj) {
			return;
		}
		pj_o(pj);
		pj_k(pj, "alias_info");
		pj_a(pj);
		for (i = 0; i < RZ_REG_NAME_LAST; i++) {
			if (core->dbg->reg->name[i]) {
				pj_o(pj);
				pj_kn(pj, "role", i);
				pj_ks(pj, "role_str", rz_reg_get_role(i));
				pj_ks(pj, "reg", core->dbg->reg->name[i]);
				pj_end(pj);
			}
		}
		pj_end(pj);
		pj_k(pj, "reg_info");
		pj_a(pj);
		for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
			rz_list_foreach (core->dbg->reg->regset[i].regs, iter, r) {
				pj_o(pj);
				pj_kn(pj, "type", r->type);
				pj_ks(pj, "type_str", rz_reg_get_type(r->type));
				pj_ks(pj, "name", r->name);
				pj_kn(pj, "size", r->size);
				pj_kn(pj, "offset", r->offset);
				pj_end(pj);
			}
		}
		pj_end(pj); // "]"
		pj_end(pj); // "}"
		rz_cons_printf("%s", pj_string(pj));
		pj_free(pj);
	} break;
	case '?': // "drp?" "arp?"
	default: {
		const char *from_a[] = { "arp", "arpi", "arpg", "arp.", "arpj", "arps" };
		// TODO #7967 help refactor
		const char **help_msg = help_msg_drp;
		if (from == 'a') {
			help_msg[1] = help_msg[3] = help_msg[6] = help_msg[9] = from_a[0];
			help_msg[12] = from_a[1];
			help_msg[15] = from_a[2];
			help_msg[18] = from_a[3];
			help_msg[21] = from_a[4];
		}
		rz_core_cmd_help(core, help_msg);
		break;
	}
	}
}

// helpers for packed registers
#define NUM_PACK_TYPES     6
#define NUM_INT_PACK_TYPES 4
int pack_sizes[NUM_PACK_TYPES] = { 8, 16, 32, 64, 32, 64 };
char *pack_format[NUM_PACK_TYPES] = { "%s0x%02" PFMT64x, "%s0x%04" PFMT64x, "%s0x%08" PFMT64x,
	"%s0x%016" PFMT64x, "%s%lf", "%s%lf" };
#define pack_print(i, reg, pack_type_index) rz_cons_printf(pack_format[pack_type_index], i != 0 ? " " : "", reg);

static void cmd_debug_reg_print_packed_reg(RzCore *core, RzRegItem *item, char explicit_size, char *pack_show) {
	int pi, i;
	for (pi = 0; pi < NUM_PACK_TYPES; pi++) {
		if (!explicit_size || pack_show[pi]) {
			for (i = 0; i < item->packed_size / pack_sizes[pi]; i++) {
				ut64 res = rz_reg_get_pack(core->dbg->reg, item, i, pack_sizes[pi]);
				if (pi > NUM_INT_PACK_TYPES - 1) { // are we printing int or double?
					if (pack_sizes[pi] == 64) {
						double dres;
						memcpy((void *)&dres, (void *)&res, 8);
						pack_print(i, dres, pi);
					} else if (pack_sizes[pi] == 32) {
						float fres;
						memcpy((void *)&fres, (void *)&res, 4);
						pack_print(i, fres, pi);
					}
				} else {
					pack_print(i, res, pi);
				}
			}
			rz_cons_newline();
		}
	}
}

static char *__table_format_string(RzTable *t, int fmt) {
	switch (fmt) {
	case 'j': return rz_table_tojson(t);
	case 's': return rz_table_tostring(t);
	}
	return rz_table_tofancystring(t);
}

static void __tableRegList(RzCore *core, RzReg *reg, const char *str) {
	int i;
	RzRegItem *e;
	RzTable *t = rz_core_table(core);
	RzTableColumnType *typeString = rz_table_type("string");
	RzTableColumnType *typeNumber = rz_table_type("number");
	RzTableColumnType *typeBoolean = rz_table_type("boolean");
	rz_table_add_column(t, typeNumber, "offset", 0);
	rz_table_add_column(t, typeNumber, "size", 0);
	rz_table_add_column(t, typeNumber, "psize", 0);
	rz_table_add_column(t, typeNumber, "index", 0);
	rz_table_add_column(t, typeNumber, "arena", 0);
	rz_table_add_column(t, typeBoolean, "float", 0);
	rz_table_add_column(t, typeString, "name", 0);
	rz_table_add_column(t, typeString, "flags", 0);
	rz_table_add_column(t, typeString, "comment", 0);
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		const RzList *list = rz_reg_get_list(reg, i);
		RzListIter *iter;
		rz_list_foreach (list, iter, e) {
			// sdb_fmt is not thread safe
			rz_table_add_row(t,
				sdb_fmt("%d", e->offset),
				sdb_fmt("%d", e->size),
				sdb_fmt("%d", e->packed_size),
				sdb_fmt("%d", e->index),
				sdb_fmt("%d", i),
				rz_str_bool(e->is_float),
				e->name ? e->name : "",
				e->flags ? e->flags : "",
				e->comment ? e->comment : "",
				NULL);
		}
	}
	const char fmt = *str++;
	const char *q = str;
	if (rz_table_query(t, q)) {
		char *s = __table_format_string(t, fmt);
		rz_cons_printf("%s\n", s);
		free(s);
	}
	rz_table_free(t);
}

static void cmd_debug_reg(RzCore *core, const char *str) {
	char *arg;
	struct rz_reg_item_t *r;
	const char *name, *use_color;
	size_t i;
	int size, type = RZ_REG_TYPE_GPR;
	int bits = (core->dbg->bits & RZ_SYS_BITS_64) ? 64 : 32;
	int use_colors = rz_config_get_i(core->config, "scr.color");
	int newbits = atoi((str && *str) ? str + 1 : "");
	if (newbits > 0) {
		bits = newbits;
	}
	if (use_colors) {
#undef ConsP
#define ConsP(x) (core->cons && core->cons->context->pal.x) ? core->cons->context->pal.x
		use_color = ConsP(creg)
		    : Color_BWHITE;
	} else {
		use_color = NULL;
	}
	if (!str) {
		str = "";
	}
	switch (str[0]) {
	case 'C': // "drC"
	{
		const bool json_out = str[1] == 'j';
		name = rz_str_trim_head_ro(json_out ? str + 3 : str + 2);
		if (name) {
			r = rz_reg_get(core->dbg->reg, name, -1);
			if (r) {
				if (json_out) {
					PJ *pj = rz_core_pj_new(core);
					if (!pj) {
						return;
					}
					pj_o(pj);
					if (r->comment) {
						pj_ks(pj, r->name, r->comment);
					} else {
						pj_knull(pj, r->name);
					}
					pj_end(pj);
					const char *s = pj_string(pj);
					rz_cons_println(s);
					pj_free(pj);
				} else {
					if (r->comment) {
						rz_cons_printf("%s\n", r->comment);
					} else {
						eprintf("Register %s doesn't have any comments\n", name);
					}
				}
			} else {
				eprintf("Register %s not found\n", name);
			}
		} else {
			eprintf("usage: drC [register]\n");
		}
	} break;
	case '-': // "dr-"
		rz_core_debug_reg_list(core, RZ_REG_TYPE_GPR, bits, NULL, '-', 0);
		break;
	case '?': // "dr?"
		if (str[1]) {
			RzListIter *iter;
			char *all = (char *)rz_str_trim_head_ro(str + 1);
			if (!strcmp(all, "?")) { // "dr??"
				all = rz_core_cmd_str(core, "drp~=[0]");
				all = rz_str_replace(all, "\n", " ", 1);
			} else {
				all = strdup(all);
			}
			char *arg;
			RzList *args = rz_str_split_list(all, " ", 0);
			rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_ALL, false); //RZ_REG_TYPE_GPR, false);
			int count = rz_list_length(args);
			rz_list_foreach (args, iter, arg) {
				ut64 off = rz_debug_reg_get(core->dbg, arg);
				if (count == 1) {
					rz_cons_printf("0x%08" PFMT64x "\n", off);
				} else {
					int type = rz_reg_get_name_idx(arg);
					const char *r = arg;
					if (type != -1) {
						r = rz_reg_get_name(core->dbg->reg, type);
					}
					rz_cons_printf("%3s %3s 0x%08" PFMT64x "\n", arg, r, off);
				}
				core->num->value = off;
			}
			free(all);
			rz_list_free(args);
		} else {
			rz_core_cmd_help(core, help_msg_dr);
		}
		break;
	case 'l': // "drl[j]"
	{
		const bool json_out = str[1] == 'j';
		RzRegSet *rs = rz_reg_regset_get(core->dbg->reg, RZ_REG_TYPE_GPR);
		if (rs) {
			RzRegItem *r;
			RzListIter *iter;
			i = 0;
			PJ *pj = NULL;
			if (json_out) {
				pj = rz_core_pj_new(core);
				if (!pj) {
					return;
				}
				pj_a(pj);
			}
			rz_list_foreach (rs->regs, iter, r) {
				if (json_out) {
					pj_s(pj, r->name);
					i++;
				} else {
					rz_cons_println(r->name);
				}
			}
			if (json_out) {
				pj_end(pj);
				const char *s = pj_string(pj);
				rz_cons_println(s);
				pj_free(pj);
			}
		}
	} break;
	case '8': // "dr8"
	case 'b': // "drb"
	{
		int len, type = RZ_REG_TYPE_GPR;
		arg = strchr(str, ' ');
		if (arg) {
			char *string = rz_str_trim_dup(arg + 1);
			if (string) {
				type = rz_reg_type_by_name(string);
				if (type == -1 && string[0] != 'a') {
					type = RZ_REG_TYPE_GPR;
				}
				free(string);
			}
		}
		ut8 *buf = rz_reg_get_bytes(core->dbg->reg, type, &len);
		if (str[0] == '8') {
			rz_print_bytes(core->print, buf, len, "%02x");
		} else {
			switch (str[1]) {
			case '1':
				rz_print_hexdump(core->print, 0ll, buf, len, 8, 1, 1);
				break;
			case '2':
				rz_print_hexdump(core->print, 0ll, buf, len, 16, 2, 1);
				break;
			case '4':
				rz_print_hexdump(core->print, 0ll, buf, len, 32, 4, 1);
				break;
			case '8':
				rz_print_hexdump(core->print, 0ll, buf, len, 64, 8, 1);
				break;
			default:
				if (core->rasm->bits == 64) {
					rz_print_hexdump(core->print, 0ll, buf, len, 64, 8, 1);
				} else {
					rz_print_hexdump(core->print, 0ll, buf, len, 32, 4, 1);
				}
				break;
			}
		}
		free(buf);
	} break;
	case 'c': // "drc"
		// todo: set flag values with drc zf=1
		if (str[1] == '=') {
			RzRegFlags *rf = rz_reg_cond_retrieve(core->dbg->reg, NULL);
			if (rf) {
				rz_cons_printf("s:%d z:%d c:%d o:%d p:%d\n",
					rf->s, rf->z, rf->c, rf->o, rf->p);
				free(rf);
			}
		} else if (strchr(str, '=')) {
			char *a = strdup(rz_str_trim_head_ro(str + 1));
			char *eq = strchr(a, '=');
			if (eq) {
				*eq++ = 0;
				char *k = a;
				rz_str_trim(a);
				bool v = !strcmp(eq, "true") || atoi(eq);
				int type = rz_reg_cond_from_string(k);
				if (type != -1) {
					RzRegFlags *rf = rz_reg_cond_retrieve(core->dbg->reg, NULL);
					if (rf) {
						rz_reg_cond_bits_set(core->dbg->reg, type, rf, v);
						rz_reg_cond_apply(core->dbg->reg, rf);
						rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_ALL, true);
						free(rf);
					}
				} else {
					eprintf("Unknown condition register\n");
				}
			}
			free(a);
		} else {
			RzRegItem *r;
			const char *name = rz_str_trim_head_ro(str + 1);
			if (*name && name[1]) {
				r = rz_reg_cond_get(core->dbg->reg, name);
				if (r) {
					rz_cons_println(r->name);
				} else {
					int id = rz_reg_cond_from_string(name);
					RzRegFlags *rf = rz_reg_cond_retrieve(core->dbg->reg, NULL);
					if (rf) {
						int o = rz_reg_cond_bits(core->dbg->reg, id, rf);
						core->num->value = o;
						// orly?
						rz_cons_printf("%d\n", o);
						free(rf);
					} else
						eprintf("unknown conditional or flag register\n");
				}
			} else {
				RzRegFlags *rf = rz_reg_cond_retrieve(core->dbg->reg, NULL);
				if (rf) {
					if (*name == '=') {
						for (i = 0; i < RZ_REG_COND_LAST; i++) {
							rz_cons_printf("%s:%d ",
								rz_reg_cond_to_string(i),
								rz_reg_cond_bits(core->dbg->reg, i, rf));
						}
						rz_cons_newline();
					} else {
						for (i = 0; i < RZ_REG_COND_LAST; i++) {
							rz_cons_printf("%d %s\n",
								rz_reg_cond_bits(core->dbg->reg, i, rf),
								rz_reg_cond_to_string(i));
						}
					}
					free(rf);
				}
			}
		}
		break;
	case 'x': // "drx"
		switch (str[1]) {
		case '\0':
			rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_DRX, false);
			rz_debug_drx_list(core->dbg);
			break;
		case '-':
			rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_DRX, false);
			rz_debug_drx_unset(core->dbg, atoi(str + 2));
			rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_DRX, true);
			break;
		case ' ': {
			char *s = strdup(str + 2);
			char sl, n, perm;
			int len;
			ut64 off;

			sl = rz_str_word_set0(s);
			if (sl == 4) {
#define arg(x) rz_str_word_get0(s, x)
				n = (char)rz_num_math(core->num, arg(0));
				off = rz_num_math(core->num, arg(1));
				len = (int)rz_num_math(core->num, arg(2));
				perm = (char)rz_str_rwx(arg(3));
				if (len == -1) {
					rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_DRX, false);
					rz_debug_drx_set(core->dbg, n, 0, 0, 0, 0);
					rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_DRX, true);
				} else {
					rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_DRX, false);
					rz_debug_drx_set(core->dbg, n, off, len, perm, 0);
					rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_DRX, true);
				}
			} else {
				eprintf("|usage: drx n [address] [length] [perm]\n");
			}
			free(s);
		} break;
		case '?':
		default:
			rz_core_cmd_help(core, help_msg_drx);
			break;
		}
		break;
	case 's': // "drs"
		switch (str[1]) {
		case '\0': // "drs"
			rz_cons_printf("%d\n", rz_list_length(core->dbg->reg->regset[0].pool));
			break;
		case '-': // "drs-"
			rz_reg_arena_pop(core->dbg->reg);
			// restore debug registers if in debugger mode
			rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, true);
			break;
		case '+': // "drs+"
			rz_reg_arena_push(core->dbg->reg);
			break;
		case '?': // "drs?"
		default:
			rz_core_cmd_help(core, help_msg_drs);
			break;
		}
		break;
	case 'm': // "drm"
		if (str[1] == '?') {
			rz_core_cmd_help(core, help_msg_drm);
		} else if (str[1] == ' ' || str[1] == 'b' || str[1] == 'd' || str[1] == 'w' || str[1] == 'q' || str[1] == 'l' || str[1] == 'f' || (str[1] == 'y' && str[2] != '\x00')) {
			char explicit_index = 0;
			char explicit_size = 0;
			char explicit_name = 0;
			char pack_show[NUM_PACK_TYPES] = { 0, 0, 0, 0, 0, 0 };
			int index = 0;
			int size = 0; // auto
			char *q, *p, *name;
			char *eq = NULL;
			RzRegisterType reg_type = RZ_REG_TYPE_XMM;
			if ((str[1] == ' ' && str[2] != '\x00') || (str[1] == 'y' && str[2] == ' ' && str[3] != '\x00')) {
				if (str[1] == 'y') { // support `drmy ymm0` and `drm ymm0`
					str = str + 1;
				}
				name = strdup(str + 2);
				explicit_name = 1;
				eq = strchr(name, '=');
				if (eq) {
					*eq++ = 0;
				}
				p = strchr(name, ' ');
				if (p) {
					*p++ = 0;
					q = strchr(p, ' ');
					if (p[0] != '*') {
						// do not show whole register
						explicit_index = 1;
						index = rz_num_math(core->num, p);
					}
					if (q) {
						*q++ = 0;
						size = rz_num_math(core->num, q);
						for (i = 0; i < NUM_PACK_TYPES; i++) {
							if (size == pack_sizes[i]) {
								explicit_size = 1;
								pack_show[i] = 1;
							}
						}
						if (!explicit_size) {
							eprintf("Unsupported wordsize %d\n", size);
							break;
						}
					}
				}
			} else {
				explicit_size = 1;
				if (str[1] == 'y') {
					reg_type = RZ_REG_TYPE_YMM;
					str = str + 1;
				}
				if (str[2] == ' ' && str[3] != '\x00') {
					name = strdup(str + 3);
					explicit_name = 1;
				}
				switch (str[1]) {
				case 'b': // "drmb"
					size = pack_sizes[0];
					pack_show[0] = 1;
					break;
				case 'w': // "drmw"
					size = pack_sizes[1];
					pack_show[1] = 1;
					break;
				case 'd': // "drmd"
					size = pack_sizes[2];
					pack_show[2] = 1;
					break;
				case 'q': // "drmq"
					size = pack_sizes[3];
					pack_show[3] = 1;
					break;
				case 'f': // "drmf"
					size = pack_sizes[4];
					pack_show[4] = 1;
					break;
				case 'l': // "drml"
					size = pack_sizes[5];
					pack_show[5] = 1;
					break;
				default:
					eprintf("Unkown comamnd");
					return;
				}
			}
			if (explicit_name) {
				RzRegItem *item = rz_reg_get(core->dbg->reg, name, -1);
				if (item) {
					if (eq) {
						// TODO: support setting YMM registers
						if (reg_type == RZ_REG_TYPE_YMM) {
							eprintf("Setting ymm registers not supported yet!\n");
						} else {
							ut64 val = rz_num_math(core->num, eq);
							rz_reg_set_pack(core->dbg->reg, item, index, size, val);
							rz_debug_reg_sync(core->dbg, reg_type, true);
						}
					} else {
						rz_debug_reg_sync(core->dbg, reg_type, false);
						if (!explicit_index) {
							cmd_debug_reg_print_packed_reg(core, item, explicit_size, pack_show);
						} else {
							ut64 res = rz_reg_get_pack(core->dbg->reg, item, index, size);
							// print selected index / wordsize
							rz_cons_printf("0x%08" PFMT64x "\n", res);
						}
					}
				} else {
					eprintf("cannot find multimedia register '%s'\n", name);
				}
				free(name);
			} else {
				// explicit size no name
				RzListIter *iter;
				RzRegItem *item;
				rz_debug_reg_sync(core->dbg, reg_type, false);
				const RzList *head = rz_reg_get_list(core->dbg->reg, reg_type);
				if (head) {
					rz_list_foreach (head, iter, item) {
						if (item->type != reg_type) {
							continue;
						}
						rz_cons_printf("%-5s = ", item->name);
						cmd_debug_reg_print_packed_reg(core, item, explicit_size, pack_show);
					}
				}
			}
		} else { // drm # no arg
			if (str[1] == 'y') { // drmy
				rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_YMM, false);
				rz_core_debug_reg_list(core, RZ_REG_TYPE_YMM, 256, NULL, 0, 0);
			} else { // drm
				rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_XMM, false);
				rz_core_debug_reg_list(core, RZ_REG_TYPE_XMM, 128, NULL, 0, 0);
			}
		}
		//rz_debug_drx_list (core->dbg);
		break;
	case 'f': // "drf"
		//rz_debug_drx_list (core->dbg);
		if (str[1] == '?') {
			eprintf("usage: drf [fpureg] [= value]\n");
		} else if (str[1] == ' ') {
			char *p, *name = strdup(str + 2);
			char *eq = strchr(name, '=');
			if (eq) {
				*eq++ = 0;
			}
			p = strchr(name, ' ');
			if (p) {
				*p++ = 0;
			}
			RzRegItem *item = rz_reg_get(core->dbg->reg, name, -1);
			if (item) {
				if (eq) {
					long double val = 0.0f;
#if __windows__
					double dval = 0.0f;
					sscanf(eq, "%lf", (double *)&dval);
					val = dval;
#else
					sscanf(eq, "%Lf", &val);
#endif
					rz_reg_set_double(core->dbg->reg, item, val);
					rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, true);
					rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_FPU, true);
				} else {
					rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false);
					rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_FPU, false);
					long double res = rz_reg_get_longdouble(core->dbg->reg, item);
					rz_cons_printf("%Lf\n", res);
				}
			} else {
				/* note, that negative type forces sync to print the regs from the backend */
				eprintf("cannot find multimedia register '%s'\n", name);
			}
			free(name);
		} else {
			//TODO: Do not use this hack to print fpu register
			rz_debug_reg_sync(core->dbg, -RZ_REG_TYPE_FPU, false);
		}
		break;
	case 'p': // "drp"
		cmd_reg_profile(core, 'd', str);
		break;
	case 't': { // "drt"
		char rad = 0;
		switch (str[1]) {
		case '\0': // "drt"
			for (i = 0; (name = rz_reg_get_type(i)); i++) {
				rz_cons_println(name);
			}
			break;
		case 'j': // "drtj"
		case '*': // "drt*"
			rad = str[1];
			str++;
			if (rad == 'j' && !str[1]) {
				PJ *pj = rz_core_pj_new(core);
				if (!pj) {
					break;
				}
				pj_a(pj);
				for (i = 0; (name = rz_reg_get_type(i)); i++) {
					pj_s(pj, name);
				}
				pj_end(pj);
				rz_cons_println(pj_string(pj));
				pj_free(pj);
				break;
			}
			// fallthrough
		case ' ': // "drt "
		{
			int role = rz_reg_get_name_idx(str + 2);
			const char *regname = rz_reg_get_name(core->dbg->reg, role);
			if (!regname) {
				regname = str + 2;
			}
			size = atoi(regname);
			if (size < 1) {
				char *arg = strchr(str + 2, ' ');
				size = 0;
				if (arg) {
					*arg++ = 0;
					size = atoi(arg);
				}
				type = rz_reg_type_by_name(str + 2);
				rz_debug_reg_sync(core->dbg, type, false);
				rz_core_debug_reg_list(core, type, size, NULL, rad, use_color);
			} else {
				if (type != RZ_REG_TYPE_LAST) {
					rz_debug_reg_sync(core->dbg, type, false);
					rz_core_debug_reg_list(core, type, size, NULL, rad, use_color);
				} else {
					eprintf("cmd_debug_reg: unknown type\n");
				}
			}
			break;
		}
		case '?': // "drt?"
		default:
			rz_core_cmd_help(core, help_msg_drt);
			break;
		}
	} break;
	case 'n': // "drn"
	{
		char *foo = strdup(str + 2);
		rz_str_case(foo, true);
		name = rz_reg_get_name(core->dbg->reg, rz_reg_get_name_idx(foo));
		if (name && *name) {
			rz_cons_println(name);
		} else
			eprintf("oops. try drn [pc|sp|bp|a0|a1|a2|a3|a4|r0|r1|zf|sf|nf|of]\n");
		free(foo);
	} break;
	case 'd': // "drd"
		rz_core_debug_reg_list(core, RZ_REG_TYPE_GPR, bits, NULL, 3, use_color); // xxx detect which one is current usage
		break;
	case 'o': // "dro"
		rz_reg_arena_swap(core->dbg->reg, false);
		rz_core_debug_reg_list(core, RZ_REG_TYPE_GPR, bits, NULL, 0, use_color); // xxx detect which one is current usage
		rz_reg_arena_swap(core->dbg->reg, false);
		break;
	case ',': // "dr,"
		if (rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false)) {
			__tableRegList(core, core->dbg->reg, str + 1);
		} else {
			eprintf("cannot retrieve registers from pid %d\n", core->dbg->pid);
		}
		break;
	case '=': // "dr="
	{
		int pcbits2, pcbits = grab_bits(core, str + 1, &pcbits2);
		if (rz_config_get_i(core->config, "cfg.debug")) {
			if (rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false)) {
				if (pcbits && pcbits != bits) {
					rz_core_debug_reg_list(core, RZ_REG_TYPE_GPR, pcbits, NULL, '=', use_color); // xxx detect which one is current usage
				}
				rz_core_debug_reg_list(core, RZ_REG_TYPE_GPR, bits, NULL, '=', use_color); // xxx detect which one is current usage
				if (pcbits2) {
					rz_core_debug_reg_list(core, RZ_REG_TYPE_GPR, pcbits2, NULL, '=', use_color); // xxx detect which one is current usage
				}
			} //else eprintf ("cannot retrieve registers from pid %d\n", core->dbg->pid);
		} else {
			RzReg *orig = core->dbg->reg;
			core->dbg->reg = core->analysis->reg;
			if (pcbits && pcbits != bits)
				rz_core_debug_reg_list(core, RZ_REG_TYPE_GPR, pcbits, NULL, '=', use_color); // xxx detect which one is current usage
			rz_core_debug_reg_list(core, RZ_REG_TYPE_GPR, bits, NULL, '=', use_color); // xxx detect which one is current usage
			core->dbg->reg = orig;
		}
	} break;
	case '.':
		if (rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false)) {
			int pcbits2, pcbits = grab_bits(core, str + 1, &pcbits2);
			rz_core_debug_reg_list(core, RZ_REG_TYPE_GPR, pcbits, NULL, '.', use_color);
			if (pcbits2) {
				rz_core_debug_reg_list(core, RZ_REG_TYPE_GPR, pcbits2, NULL, '.', use_color);
			}
		}
		break;
	case '*': // "dr*"
		if (rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false)) {
			int pcbits2, pcbits = grab_bits(core, str + 1, &pcbits2);
			rz_core_debug_reg_list(core, RZ_REG_TYPE_GPR, pcbits, NULL, '*', use_color);
			if (pcbits2) {
				rz_core_debug_reg_list(core, RZ_REG_TYPE_GPR, pcbits2, NULL, '*', use_color);
			}
			rz_flag_space_pop(core->flags);
		}
		break;
	case 'i': // "dri"
		rz_core_debug_ri(core, core->dbg->reg, 0);
		break;
	case 'r': // "drr"
		switch (str[1]) {
		case 'j': // "drrj"
			rz_core_debug_rr(core, core->dbg->reg, 'j');
			break;
		default:
			rz_core_debug_rr(core, core->dbg->reg, 0);
			break;
		}
		break;
	case 'j': // "drj"
	case '\0': // "dr"
		if (rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false)) {
			int pcbits = core->analysis->bits;
			const char *pcname = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_PC);
			RzRegItem *reg = rz_reg_get(core->analysis->reg, pcname, 0);
			if (reg) {
				if (core->rasm->bits != reg->size) {
					pcbits = reg->size;
				}
			}
			if (str[0] == 'j') {
				PJ *pj = rz_core_pj_new(core);
				if (!pj) {
					return;
				}
				rz_core_debug_reg_list(core, RZ_REG_TYPE_GPR, pcbits, pj, 'j', use_color);
			} else {
				rz_core_debug_reg_list(core, RZ_REG_TYPE_GPR, pcbits, NULL, 0, use_color);
			}
		} else {
			eprintf("cannot retrieve registers from pid %d\n", core->dbg->pid);
		}
		break;
	case ' ': // "dr"
		arg = strchr(str + 1, '=');
		if (arg) {
			*arg = 0;
			char *ostr = rz_str_trim_dup(str + 1);
			char *regname = rz_str_trim_nc(ostr);
			ut64 regval = rz_num_math(core->num, arg + 1);
			rz_core_debug_reg_set(core, regname, regval, ostr);
			free(ostr);
			return;
		}

		size = atoi(str + 1);
		if (size) {
			rz_core_debug_reg_list(core, RZ_REG_TYPE_GPR, size, NULL, str[0], use_color);
		} else {
			char *comma = strchr(str + 1, ',');
			if (comma) {
				char *args = strdup(str + 1);
				char argc = rz_str_split(args, ',');
				for (i = 0; i < argc; i++) {
					showreg(core, rz_str_word_get0(args, i));
				}
				free(args);
			} else {
				showreg(core, str + 1);
			}
		}
	}
}

static void backtrace_vars(RzCore *core, RzList *frames) {
	RzDebugFrame *f;
	RzListIter *iter;
	// analysis vs debug ?
	const char *sp = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SP);
	const char *bp = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_BP);
	if (!sp) {
		sp = "SP";
	}
	if (!bp) {
		bp = "BP";
	}
	RzReg *r = core->analysis->reg;
	ut64 dsp = rz_reg_getv(r, sp);
	ut64 dbp = rz_reg_getv(r, bp);
	int n = 0;
	rz_list_foreach (frames, iter, f) {
		ut64 s = f->sp ? f->sp : dsp;
		ut64 b = f->bp ? f->bp : dbp;
		rz_reg_setv(r, bp, s);
		rz_reg_setv(r, sp, b);
		//////////
		char flagdesc[1024], flagdesc2[1024];
		RzFlagItem *fi = rz_flag_get_at(core->flags, f->addr, true);
		flagdesc[0] = flagdesc2[0] = 0;
		if (fi) {
			if (fi->offset != f->addr) {
				int delta = (int)(f->addr - fi->offset);
				if (delta > 0) {
					snprintf(flagdesc, sizeof(flagdesc),
						"%s+%d", fi->name, delta);
				} else if (delta < 0) {
					snprintf(flagdesc, sizeof(flagdesc),
						"%s%d", fi->name, delta);
				} else {
					snprintf(flagdesc, sizeof(flagdesc),
						"%s", fi->name);
				}
			} else {
				snprintf(flagdesc, sizeof(flagdesc),
					"%s", fi->name);
			}
		}
		//////////
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, f->addr, 0);
		// char *str = rz_str_newf ("[frame %d]", n);
		rz_cons_printf("%d  0x%08" PFMT64x " sp: 0x%08" PFMT64x " %-5d"
			       "[%s]  %s %s\n",
			n, f->addr, f->sp, (int)f->size,
			fcn ? fcn->name : "??", flagdesc, flagdesc2);
		rz_cons_push();
		char *res = rz_core_analysis_all_vars_display(core, fcn, true);
		rz_cons_pop();
		rz_cons_printf("%s", res);
		free(res);
		n++;
	}
	rz_reg_setv(r, bp, dbp);
	rz_reg_setv(r, sp, dsp);
}

static void asciiart_backtrace(RzCore *core, RzList *frames) {
	// TODO: show local variables
	// TODO: show function/flags/symbols related
	// TODO: show contents of stack
	// TODO: honor scr.color
	RzDebugFrame *f;
	RzListIter *iter;
	bool mymap = false;
	// analysis vs debug ?
	const char *sp = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_SP);
	const char *bp = rz_reg_get_name(core->analysis->reg, RZ_REG_NAME_BP);
	if (!sp) {
		sp = "SP";
	}
	if (!bp) {
		bp = "BP";
	}
	ut64 dsp = rz_reg_getv(core->analysis->reg, sp);
	ut64 dbp = rz_reg_getv(core->analysis->reg, bp);
	RzDebugMap *map = rz_debug_map_get(core->dbg, dsp);
	if (!map) {
		mymap = true;
		map = RZ_NEW0(RzDebugMap);
		map->addr = UT64_MAX;
		map->addr_end = UT64_MAX;
	}

	rz_cons_printf("0x%016" PFMT64x "  STACK END  ^^^\n", map->addr);
	rz_cons_printf("0x%016" PFMT64x "  STACK POINTER: %s\n", dsp, sp);
	rz_cons_printf("                    .------------------------.\n");
	int n = 0;
	rz_list_foreach (frames, iter, f) {
		ut64 s = f->sp ? f->sp : dsp;
		ut64 b = f->bp ? f->bp : dbp;
		char *str = rz_str_newf("[frame %d]", n);
		rz_cons_printf("0x%016" PFMT64x "  |%4s    %10s      | ; size %" PFMTDPTR "\n", s, sp, str, (ptrdiff_t)(s - b));
		free(str);
		rz_cons_printf("                    |            ...         |\n");
		rz_cons_printf("0x%016" PFMT64x "  |%4s 0x%016" PFMT64x " | %s\n", b, bp, f->addr, "; return address");
		rz_cons_printf("                    )------------------------(\n");
		// eprintf ("0x%08llx 0x%08llx 0x%08llx\n", f->addr, s, b);
		n++;
	}
	rz_cons_printf("                    |           ...          |\n");
	rz_cons_printf("                    `------------------------'\n");
	rz_cons_printf("0x%016" PFMT64x "  STACK BOTTOM\n", map->addr_end);
	if (mymap) {
		rz_debug_map_free(map);
	}
}

static void get_backtrace_info(RzCore *core, RzDebugFrame *frame, ut64 addr, char **flagdesc, char **flagdesc2, char **pcstr, char **spstr) {
	RzFlagItem *f = rz_flag_get_at(core->flags, frame->addr, true);
	*flagdesc = NULL;
	*flagdesc2 = NULL;
	if (f) {
		if (f->offset != addr) {
			int delta = (int)(frame->addr - f->offset);
			if (delta > 0) {
				*flagdesc = rz_str_newf("%s+%d", f->name, delta);
			} else if (delta < 0) {
				*flagdesc = rz_str_newf("%s%d", f->name, delta);
			} else {
				*flagdesc = rz_str_newf("%s", f->name);
			}
		} else {
			*flagdesc = rz_str_newf("%s", f->name);
		}
	}
	f = rz_flag_get_at(core->flags, frame->addr, true);
	if (f && !strchr(f->name, '.')) {
		f = rz_flag_get_at(core->flags, frame->addr - 1, true);
	}
	if (f) {
		if (f->offset != addr) {
			int delta = (int)(frame->addr - 1 - f->offset);
			if (delta > 0) {
				*flagdesc2 = rz_str_newf("%s+%d", f->name, delta + 1);
			} else if (delta < 0) {
				*flagdesc2 = rz_str_newf("%s%d", f->name, delta + 1);
			} else {
				*flagdesc2 = rz_str_newf("%s+1", f->name);
			}
		} else {
			*flagdesc2 = rz_str_newf("%s", f->name);
		}
	}
	if (!rz_str_cmp(*flagdesc, *flagdesc2, -1)) {
		free(*flagdesc2);
		*flagdesc2 = NULL;
	}
	if (pcstr && spstr) {
		if (core->dbg->bits & RZ_SYS_BITS_64) {
			*pcstr = rz_str_newf("0x%-16" PFMT64x, frame->addr);
			*spstr = rz_str_newf("0x%-16" PFMT64x, frame->sp);
		} else if (core->dbg->bits & RZ_SYS_BITS_32) {
			*pcstr = rz_str_newf("0x%-8" PFMT64x, frame->addr);
			*spstr = rz_str_newf("0x%-8" PFMT64x, frame->sp);
		} else {
			*pcstr = rz_str_newf("0x%" PFMT64x, frame->addr);
			*spstr = rz_str_newf("0x%" PFMT64x, frame->sp);
		}
	}
}

static void static_debug_stop(void *u) {
	RzDebug *dbg = (RzDebug *)u;
	rz_debug_stop(dbg);
}

static void core_cmd_dbi(RzCore *core, const char *input, const ut64 idx) {
	int i;
	char *p;
	RzBreakpointItem *bpi;
	switch (input[2]) {
	case ' ': // "dbi."
	{
		const int index = rz_bp_get_index_at(core->dbg->bp, idx);
		if (index != -1) {
			rz_cons_printf("%d\n", index);
		}
	} break;
	case '-': // "dbi-"
	{
		if (!rz_bp_del_index(core->dbg->bp, idx)) {
			eprintf("Breakpoint with index %d not found\n", (int)idx);
		}
	} break;
	case '.': // "dbi."
	{
		const int index = rz_bp_get_index_at(core->dbg->bp, core->offset);
		if (index != -1) {
			rz_cons_printf("%d\n", index);
		}
	} break;
	case 0: // "dbi"
		for (i = 0; i < core->dbg->bp->bps_idx_count; i++) {
			if ((bpi = core->dbg->bp->bps_idx[i])) {
				rz_cons_printf("%d 0x%08" PFMT64x " E:%d T:%d\n",
					i, bpi->addr, bpi->enabled, bpi->trace);
			}
		}
		break;
	case 'x': // "dbix"
		if (input[3] == ' ') {
			if ((bpi = rz_bp_get_index(core->dbg->bp, idx))) {
				char *expr = strchr(input + 4, ' ');
				if (expr) {
					free(bpi->expr);
					bpi->expr = strdup(expr);
				}
			}
			rz_cons_printf("%d\n", (int)idx);
		} else {
			for (i = 0; i < core->dbg->bp->bps_idx_count; i++) {
				RzBreakpointItem *bp = core->dbg->bp->bps_idx[i];
				if (bp) {
					rz_cons_printf("%d 0x%08" PFMT64x " %s\n", i, bp->addr, bp->expr);
				}
			}
		}
		break;
	case 'c': // "dbic"
		p = strchr(input + 3, ' ');
		if (p) {
			char *q = strchr(p + 1, ' ');
			if (q) {
				*q++ = 0;
				ut64 addr = rz_num_math(core->num, p);
				bpi = rz_bp_get_index(core->dbg->bp, addr);
				if (bpi) {
					bpi->data = strdup(q);
				} else {
					eprintf("Cannot set command\n");
				}
			} else {
				eprintf("|Usage: dbic # cmd\n");
			}
		} else {
			eprintf("|Usage: dbic # cmd\n");
		}
		break;
	case 'e': // "dbie"
		if ((bpi = rz_bp_get_index(core->dbg->bp, idx))) {
			bpi->enabled = true;
		} else {
			eprintf("Cannot unset tracepoint\n");
		}
		break;
	case 'd': // "dbid"
		if ((bpi = rz_bp_get_index(core->dbg->bp, idx))) {
			bpi->enabled = false;
		} else {
			eprintf("Cannot unset tracepoint\n");
		}
		break;
	case 's': // "dbis"
		if ((bpi = rz_bp_get_index(core->dbg->bp, idx))) {
			bpi->enabled = !!!bpi->enabled;
		} else {
			eprintf("Cannot unset tracepoint\n");
		}
		break;
	case 't': // "dbite" "dbitd" ...
		switch (input[3]) {
		case 'e':
			if ((bpi = rz_bp_get_index(core->dbg->bp, idx))) {
				bpi->trace = true;
			} else {
				eprintf("Cannot unset tracepoint\n");
			}
			break;
		case 'd':
			if ((bpi = rz_bp_get_index(core->dbg->bp, idx))) {
				bpi->trace = false;
			} else
				eprintf("Cannot unset tracepoint\n");
			break;
		case 's':
			if ((bpi = rz_bp_get_index(core->dbg->bp, idx))) {
				bpi->trace = !!!bpi->trace;
			} else {
				eprintf("Cannot unset tracepoint\n");
			}
			break;
		}
		break;
	}
}

#if __WINDOWS__
#include "..\debug\p\native\windows\windows_message.h"
#endif

#define DB_ARG(x) rz_str_word_get0(str, x)
static void add_breakpoint(RzCore *core, const char *input, bool hwbp, bool watch) {
	RzBreakpointItem *bpi;
	ut64 addr;
	int i = 0;

	char *str = strdup(rz_str_trim_head_ro(input + 1));
	int sl = rz_str_word_set0(str);
	// For dbw every second argument is 'rw', so we need to skip it.
	for (; i < sl; i += 1 + (watch ? 1 : 0)) {
		if (*DB_ARG(i) == '-') {
			rz_bp_del(core->dbg->bp, rz_num_math(core->num, DB_ARG(i) + 1));
		} else {
			int rw = 0;
			if (watch) {
				if (sl % 2 == 0) {
					if (!strcmp(DB_ARG(i + 1), "r")) {
						rw = RZ_BP_PROT_READ;
					} else if (!strcmp(DB_ARG(i + 1), "w")) {
						rw = RZ_BP_PROT_WRITE;
					} else if (!strcmp(DB_ARG(i + 1), "rw")) {
						rw = RZ_BP_PROT_ACCESS;
					} else {
						rz_core_cmd_help(core, help_msg_dbw);
						break;
					}
				} else {
					rz_core_cmd_help(core, help_msg_dbw);
					break;
				}
			}
			addr = rz_num_math(core->num, DB_ARG(i));
			bpi = rz_debug_bp_add(core->dbg, addr, hwbp, watch, rw, NULL, 0);
			if (bpi) {
				free(bpi->name);
				if (!strcmp(DB_ARG(i), "$$")) {
					RzFlagItem *f = rz_core_flag_get_by_spaces(core->flags, addr);
					if (f) {
						if (addr > f->offset) {
							bpi->name = rz_str_newf("%s+0x%" PFMT64x, f->name, addr - f->offset);
						} else {
							bpi->name = strdup(f->name);
						}
					} else {
						bpi->name = rz_str_newf("0x%08" PFMT64x, addr);
					}
				} else {
					bpi->name = strdup(DB_ARG(i));
				}
			} else {
				eprintf("Cannot set breakpoint at '%s'\n", DB_ARG(i));
			}
		}
	}

	free(str);
}

static void rz_core_cmd_bp(RzCore *core, const char *input) {
	RzBreakpointItem *bpi;
	int i, hwbp = rz_config_get_i(core->config, "dbg.hwbp");
	RzDebugFrame *frame;
	RzListIter *iter;
	const char *p;
	bool watch = false;
	RzList *list;
	ut64 addr, idx;
	p = strchr(input, ' ');
	addr = p ? rz_num_math(core->num, p + 1) : UT64_MAX;
	idx = addr; // 0 is valid index
	if (!addr) {
		addr = UT64_MAX;
	}
	char *str = NULL;

	switch (input[1]) {
	case '.':
		if (input[2]) {
			ut64 addr = rz_num_tail(core->num, core->offset, input + 2);
			bpi = rz_debug_bp_add(core->dbg, addr, hwbp, false, 0, NULL, 0);
			if (!bpi) {
				eprintf("Unable to add breakpoint (%s)\n", input + 2);
			}
		} else {
			bpi = rz_bp_get_at(core->dbg->bp, core->offset);
			if (bpi) {
				rz_cons_printf("breakpoint %s %s %s\n",
					rz_str_rwx_i(bpi->perm),
					bpi->enabled ? "enabled" : "disabled",
					bpi->name ? bpi->name : "");
			}
		}
		break;
	case 'f': {
		RzList *symbols = rz_bin_get_symbols(core->bin);
		RzBinSymbol *symbol;
		rz_list_foreach (symbols, iter, symbol) {
			if (symbol->type && !strcmp(symbol->type, RZ_BIN_TYPE_FUNC_STR)) {
				if (rz_analysis_noreturn_at(core->analysis, symbol->vaddr)) {
					bpi = rz_debug_bp_add(core->dbg, symbol->vaddr, hwbp, false, 0, NULL, 0);
					if (bpi) {
						bpi->name = rz_str_newf("%s.%s", "sym", symbol->name);
					} else {
						eprintf("Unable to add a breakpoint"
							"into a noreturn function %s at addr 0x%" PFMT64x "\n",
							symbol->name, symbol->vaddr);
					}
				}
			}
		}
	} break;
	case 'x': // "dbx"
		if (input[2] == ' ') {
			if (addr == UT64_MAX) {
				addr = core->offset;
			}
			bpi = rz_bp_get_at(core->dbg->bp, addr);
			if (bpi) {
				free(bpi->expr);
				bpi->expr = strdup(input + 3);
			}
		} else {
			RzBreakpointItem *bp;
			rz_list_foreach (core->dbg->bp->bps, iter, bp) {
				rz_cons_printf("0x%08" PFMT64x " %s\n", bp->addr, rz_str_get(bp->expr));
			}
		}
		break;
	case 't': // "dbt"
		switch (input[2]) {
		case 'v': // "dbtv"
			list = rz_debug_frames(core->dbg, addr);
			backtrace_vars(core, list);
			rz_list_free(list);
			break;
		case 'a': // "dbta"
			list = rz_debug_frames(core->dbg, addr);
			asciiart_backtrace(core, list);
			rz_list_free(list);
			break;
		case 'e': // "dbte"
			for (p = input + 3; *p == ' '; p++) {
				/* nothing to do here */
			}
			if (*p == '*') {
				rz_bp_set_trace_all(core->dbg->bp, true);
			} else if (!rz_bp_set_trace(core->dbg->bp, addr, true)) {
				eprintf("Cannot set tracepoint\n");
			}
			break;
		case 'd': // "dbtd"
			for (p = input + 3; *p == ' '; p++) {
				//nothing to see here
			}
			if (*p == '*') {
				rz_bp_set_trace_all(core->dbg->bp, false);
			} else if (!rz_bp_set_trace(core->dbg->bp, addr, false)) {
				eprintf("Cannot unset tracepoint\n");
			}
			break;
		case 's': // "dbts"
			bpi = rz_bp_get_at(core->dbg->bp, addr);
			if (bpi) {
				bpi->trace = !!!bpi->trace;
			} else {
				eprintf("Cannot unset tracepoint\n");
			}
			break;
		case 'j': { // "dbtj"
			PJ *pj = rz_core_pj_new(core);
			if (!pj) {
				return;
			}
			addr = UT64_MAX;
			if (input[2] == ' ' && input[3]) {
				addr = rz_num_math(core->num, input + 2);
			}
			i = 0;
			list = rz_debug_frames(core->dbg, addr);
			pj_a(pj);
			rz_list_foreach (list, iter, frame) {
				char *flagdesc, *flagdesc2, *desc;
				get_backtrace_info(core, frame, addr, &flagdesc, &flagdesc2, NULL, NULL);
				RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, frame->addr, 0);
				desc = rz_str_newf("%s%s", rz_str_get_null(flagdesc), rz_str_get_null(flagdesc2));
				pj_o(pj);
				pj_ki(pj, "idx", i);
				pj_kn(pj, "pc", frame->addr);
				pj_kn(pj, "sp", frame->sp);
				pj_ki(pj, "frame_size", frame->size);
				pj_ks(pj, "fname", fcn ? fcn->name : "");
				pj_ks(pj, "desc", desc);
				pj_end(pj);
				i++;
				free(flagdesc);
				free(flagdesc2);
				free(desc);
			}
			pj_end(pj);
			rz_cons_println(pj_string(pj));
			pj_free(pj);
			rz_list_free(list);
			break;
		}
		case '=': // dbt=
			addr = UT64_MAX;
			if (input[2] == ' ' && input[3]) {
				addr = rz_num_math(core->num, input + 2);
			}
			i = 0;
			list = rz_debug_frames(core->dbg, addr);
			rz_list_reverse(list);
			rz_list_foreach (list, iter, frame) {
				switch (input[3]) {
				case 0:
					rz_cons_printf("%s0x%08" PFMT64x,
						(i ? " " : ""), frame->addr);
					break;
				case 's':
					rz_cons_printf("%s0x%08" PFMT64x,
						(i ? " " : ""), frame->sp);
					break;
				case 'b':
					rz_cons_printf("%s0x%08" PFMT64x,
						(i ? " " : ""), frame->bp);
					break;
				case '?':
				default:
					rz_core_cmd0(core, "db?~dbt");
					break;
				}
				i++;
			}
			rz_cons_newline();
			rz_list_free(list);
			break;
		case '*': // dbt*
			addr = UT64_MAX;
			if (input[2] == ' ' && input[3]) {
				addr = rz_num_math(core->num, input + 2);
			}
			i = 0;
			list = rz_debug_frames(core->dbg, addr);
			rz_list_reverse(list);
			rz_cons_printf("f-bt.*\n");
			rz_list_foreach (list, iter, frame) {
				rz_cons_printf("f bt.frame%d = 0x%08" PFMT64x "\n", i, frame->addr);
				rz_cons_printf("f bt.frame%d.stack %d 0x%08" PFMT64x "\n", i, frame->size, frame->sp);
				i++;
			}
			rz_list_free(list);
			break;
		case 0: // "dbt" -- backtrace
			addr = UT64_MAX;
			if (input[2] == ' ' && input[3]) {
				addr = rz_num_math(core->num, input + 2);
			}
			i = 0;
			list = rz_debug_frames(core->dbg, addr);
			rz_list_foreach (list, iter, frame) {
				char *flagdesc, *flagdesc2, *pcstr, *spstr;
				get_backtrace_info(core, frame, addr, &flagdesc, &flagdesc2, &pcstr, &spstr);
				RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, frame->addr, 0);
				rz_cons_printf("%d  %s sp: %s  %-5d"
					       "[%s]  %s %s\n",
					i++,
					pcstr, spstr,
					(int)frame->size,
					fcn ? fcn->name : "??",
					flagdesc ? flagdesc : "",
					flagdesc2 ? flagdesc2 : "");
				free(flagdesc);
				free(flagdesc2);
				free(pcstr);
				free(spstr);
			}
			rz_list_free(list);
			break;
		case '?':
		default:
			rz_core_cmd_help(core, help_msg_dbt);
			break;
		}
		break;
	case 'b': // "dbb"
		if (input[2]) {
			core->dbg->bp->delta = (st64)rz_num_math(core->num, input + 2);
		} else {
			rz_cons_printf("%" PFMT64d "\n", core->dbg->bp->delta);
		}
		break;
	case 'm': // "dbm"
		if (input[2] && input[3]) {
			char *string = strdup(input + 3);
			char *module = NULL;
			st64 delta = 0;

			module = strtok(string, " ");
			delta = (ut64)rz_num_math(core->num, strtok(NULL, ""));
			bpi = rz_debug_bp_add(core->dbg, 0, hwbp, false, 0, module, delta);
			if (!bpi) {
				eprintf("Cannot set breakpoint.\n");
			}
			free(string);
		}
		break;
	case 'j': rz_bp_list(core->dbg->bp, 'j'); break;
	case '*': rz_bp_list(core->dbg->bp, 1); break;
	case '\0': rz_bp_list(core->dbg->bp, 0); break;
	case '-': // "db-"
		if (input[2] == '*') {
			rz_bp_del_all(core->dbg->bp);
		} else {
#define DB_ARG(x) rz_str_word_get0(str, x)
			char *str = strdup(rz_str_trim_head_ro(input + 2));
			int i = 0;
			int sl = rz_str_word_set0(str);
			for (; i < sl; i++) {
				const ut64 addr = rz_num_math(core->num, DB_ARG(i));
				rz_bp_del(core->dbg->bp, addr);
			}
			free(str);
		}
		break;
	case 'c': // "dbc"
		if (input[2] == ' ') {
			char *inp = strdup(input + 3);
			if (inp) {
				char *arg = strchr(inp, ' ');
				if (arg) {
					*arg++ = 0;
					addr = rz_num_math(core->num, inp);
					bpi = rz_bp_get_at(core->dbg->bp, addr);
					if (bpi) {
						free(bpi->data);
						bpi->data = strdup(arg);
					} else {
						eprintf("No breakpoint defined at 0x%08" PFMT64x "\n", addr);
					}
				} else {
					eprintf("- Missing argument\n");
				}
				free(inp);
			} else {
				eprintf("Cannot strdup. Your heap is a mess\n");
			}
		} else {
			eprintf("Use: dbc [addr] [command]\n");
		}
		break;
	case 'C': // "dbC"
		if (input[2] == ' ') {
			char *inp = strdup(input + 3);
			if (inp) {
				char *arg = strchr(inp, ' ');
				if (arg) {
					*arg++ = 0;
					addr = rz_num_math(core->num, inp);
					bpi = rz_bp_get_at(core->dbg->bp, addr);
					if (bpi) {
						free(bpi->cond);
						bpi->cond = strdup(arg);
					} else {
						eprintf("No breakpoint defined at 0x%08" PFMT64x "\n", addr);
					}
				} else {
					eprintf("1 Missing argument\n");
				}
				free(inp);
			} else {
				eprintf("Cannot strdup. Your heap is a mess\n");
			}
		} else {
			eprintf("Use: dbC [addr] [command]\n");
		}
		break;
	case 's': // "dbs"
		addr = rz_num_math(core->num, input + 2);
		rz_core_debug_breakpoint_toggle(core, addr);
		break;
	case 'n': // "dbn"
		bpi = rz_bp_get_at(core->dbg->bp, core->offset);
		if (input[2] == ' ') {
			if (bpi) {
				free(bpi->name);
				bpi->name = strdup(input + 3);
			} else {
				eprintf("Cannot find breakpoint at "
					"0x%08" PFMT64x "\n",
					core->offset);
			}
		} else {
			if (bpi && bpi->name) {
				rz_cons_println(bpi->name);
			}
		}
		break;
	case 'e': // "dbe"
		for (p = input + 2; *p == ' '; p++)
			;
		if (*p == '*')
			rz_bp_enable_all(core->dbg->bp, true);
		else {
			for (; *p && *p != ' '; p++)
				;
			rz_bp_enable(core->dbg->bp, rz_num_math(core->num, input + 2), true, rz_num_math(core->num, p));
		}
		break;
	case 'd': // "dbd"
		for (p = input + 2; *p == ' '; p++)
			;
		if (*p == '*')
			rz_bp_enable_all(core->dbg->bp, false);
		else {
			for (; *p && *p != ' '; p++)
				;
			rz_bp_enable(core->dbg->bp, rz_num_math(core->num, input + 2), false, rz_num_math(core->num, p));
		}
		break;
	case 'h': // "dbh"
		switch (input[2]) {
		case 0:
			rz_bp_plugin_list(core->dbg->bp);
			break;
		case ' ':
			if (input[3]) {
				if (!rz_bp_use(core->dbg->bp, input + 3, core->analysis->bits)) {
					eprintf("Invalid name: '%s'.\n", input + 3);
				}
			}
			break;
		case '-':
			if (input[3]) {
				if (!rz_bp_plugin_del(core->dbg->bp, input + 3)) {
					eprintf("Invalid name: '%s'.\n", input + 3);
				}
			}
			break;
		case '?':
		default:
			eprintf("Usage: dh [plugin-name]  # select a debug handler plugin\n");
			break;
		}
		break;
#if __WINDOWS__
	case 'W': // "dbW"
		if (input[2] == ' ') {
			if (rz_w32_add_winmsg_breakpoint(core->dbg, input + 3)) {
				rz_cons_print("Breakpoint set.\n");
			} else {
				rz_cons_print("Breakpoint not set.\n");
			}
		}
		break;
#endif
	case 'w': // "dbw"
		add_breakpoint(core, input + 1, hwbp, true);
		break;
	case 'H': // "dbH"
		add_breakpoint(core, input + 1, true, watch);
		break;
	case ' ': // "db"
		add_breakpoint(core, input + 1, hwbp, watch);
		break;
	case 'i':
		core_cmd_dbi(core, input, idx);
		break;
	case '?':
	default:
		rz_core_cmd_help(core, help_msg_db);
		break;
	}
	free(str);
}

static RTreeNode *add_trace_tree_child(HtUP *ht, RTree *t, RTreeNode *cur, ut64 addr) {
	struct trace_node *t_node = ht_up_find(ht, addr, NULL);
	if (!t_node) {
		t_node = RZ_NEW0(struct trace_node);
		if (t_node) {
			t_node->addr = addr;
			t_node->refs = 1;
			ht_up_insert(ht, addr, t_node);
		}
	} else {
		t_node->refs++;
	}
	return rz_tree_add_node(t, cur, t_node);
}

static RzCore *_core = NULL;

static void trace_traverse_pre(RTreeNode *n, RTreeVisitor *vis) {
	const char *name = "";
	struct trace_node *tn = n->data;
	unsigned int i;
	if (!tn)
		return;
	for (i = 0; i < n->depth - 1; i++) {
		rz_cons_printf("  ");
	}
	if (_core) {
		RzFlagItem *f = rz_flag_get_at(_core->flags, tn->addr, true);
		if (f) {
			name = f->name;
		}
	}
	rz_cons_printf(" 0x%08" PFMT64x " refs %d %s\n", tn->addr, tn->refs, name);
}

static void trace_traverse(RTree *t) {
	RTreeVisitor vis = { 0 };

	/* clear the line on stderr, because somebody has written there */
	fprintf(stderr, "\x1b[2K\r");
	fflush(stderr);
	vis.pre_visit = (RTreeNodeVisitCb)trace_traverse_pre;
	rz_tree_dfs(t, &vis);
}

static void do_debug_trace_calls(RzCore *core, ut64 from, ut64 to, ut64 final_addr) {
	bool trace_libs = rz_config_get_i(core->config, "dbg.trace.libs");
	bool shallow_trace = rz_config_get_i(core->config, "dbg.trace.inrange");
	HtUP *tracenodes = core->dbg->tracenodes;
	RTree *tr = core->dbg->tree;
	RzDebug *dbg = core->dbg;
	ut64 debug_to = UT64_MAX;
	RTreeNode *cur;
	ut64 addr = 0;
	int n = 0;

	if (!trace_libs) {
#if NOOP
		RzList *bounds = rz_core_get_boundaries_prot(core, -1, "dbg.program", "search");
		rz_list_free(bounds);
#endif
	}

	/* set root if not already present */
	rz_tree_add_node(tr, NULL, NULL);
	cur = tr->root;

	while (true) {
		ut8 buf[32];
		RzAnalysisOp aop;
		int addr_in_range;

		if (rz_cons_is_breaked()) {
			break;
		}
		if (rz_debug_is_dead(dbg)) {
			break;
		}
		if (debug_to != UT64_MAX && !rz_debug_continue_until(dbg, debug_to)) {
			break;
		}
		if (!rz_debug_step(dbg, 1)) {
			break;
		}
		debug_to = UT64_MAX;
		if (!rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false)) {
			break;
		}
		addr = rz_debug_reg_get(dbg, "PC");
		if (addr == final_addr) {
			//we finished the tracing so break the loop
			break;
		}
		addr_in_range = addr >= from && addr < to;

		rz_io_read_at(core->io, addr, buf, sizeof(buf));
		rz_analysis_op(core->analysis, &aop, addr, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC);
		eprintf("%d %" PFMT64x "\r", n++, addr);
		switch (aop.type) {
		case RZ_ANALYSIS_OP_TYPE_UCALL:
		case RZ_ANALYSIS_OP_TYPE_ICALL:
		case RZ_ANALYSIS_OP_TYPE_RCALL:
		case RZ_ANALYSIS_OP_TYPE_IRCALL: {
			ut64 called_addr;
			int called_in_range;
			// store regs
			// step into
			// get pc
			rz_debug_step(dbg, 1);
			rz_debug_reg_sync(dbg, RZ_REG_TYPE_GPR, false);
			called_addr = rz_debug_reg_get(dbg, "PC");
			called_in_range = called_addr >= from && called_addr < to;
			if (!called_in_range && addr_in_range && !shallow_trace) {
				debug_to = addr + aop.size;
			}
			if (addr_in_range || shallow_trace) {
				cur = add_trace_tree_child(tracenodes, tr, cur, addr);
				if (debug_to != UT64_MAX) {
					cur = cur->parent;
				}
			}
			// TODO: push pc+aop.length into the call path stack
			break;
		}
		case RZ_ANALYSIS_OP_TYPE_CALL: {
			int called_in_range = aop.jump >= from && aop.jump < to;
			if (!called_in_range && addr_in_range && !shallow_trace) {
				debug_to = aop.addr + aop.size;
			}
			if (addr_in_range || shallow_trace) {
				cur = add_trace_tree_child(tracenodes, tr, cur, addr);
				if (debug_to != UT64_MAX) {
					cur = cur->parent;
				}
			}
			break;
		}
		case RZ_ANALYSIS_OP_TYPE_RET:
#if 0
			// TODO: we must store ret value for each call in the graph path to do this check
			rz_debug_step (dbg, 1);
			rz_debug_reg_sync (dbg, RZ_REG_TYPE_GPR, false);
			addr = rz_debug_reg_get (dbg, "PC");
			// TODO: step into and check return address if correct
			// if not correct we are hijacking the control flow (exploit!)
#endif
			if (cur != tr->root) {
				cur = cur->parent;
			}
#if 0
			if (addr != gn->addr) {
				eprintf ("Oops. invalid return address 0x%08"PFMT64x
						"\n0x%08"PFMT64x"\n", addr, gn->addr);
			}
#endif
			break;
		}
	}
}

static void debug_trace_calls(RzCore *core, const char *input) {
	RzBreakpointItem *bp_final = NULL;
	int t = core->dbg->trace->enabled;
	ut64 from = 0, to = UT64_MAX, final_addr = UT64_MAX;

	if (rz_debug_is_dead(core->dbg)) {
		eprintf("No process to debug.");
		return;
	}
	if (*input == ' ') {
		input = rz_str_trim_head_ro(input);
		ut64 first_n = rz_num_math(core->num, input);
		input = strchr(input, ' ');
		if (input) {
			input = rz_str_trim_head_ro(input);
			from = first_n;
			to = rz_num_math(core->num, input);
			input = strchr(input, ' ');
			if (input) {
				input = rz_str_trim_head_ro(input);
				final_addr = rz_num_math(core->num, input);
			}
		} else {
			final_addr = first_n;
		}
	}
	core->dbg->trace->enabled = 0;
	rz_cons_break_push(static_debug_stop, core->dbg);
	rz_reg_arena_swap(core->dbg->reg, true);
	if (final_addr != UT64_MAX) {
		int hwbp = rz_config_get_i(core->config, "dbg.hwbp");
		bp_final = rz_debug_bp_add(core->dbg, final_addr, hwbp, false, 0, NULL, 0);
		if (!bp_final) {
			eprintf("Cannot set breakpoint at final address (%" PFMT64x ")\n", final_addr);
		}
	}
	do_debug_trace_calls(core, from, to, final_addr);
	if (bp_final) {
		rz_bp_del(core->dbg->bp, final_addr);
	}
	_core = core;
	trace_traverse(core->dbg->tree);
	core->dbg->trace->enabled = t;
	rz_cons_break_pop();
}

static void rz_core_debug_esil(RzCore *core, const char *input) {
	switch (input[0]) {
	case '\0': // "de"
		// list
		rz_debug_esil_watch_list(core->dbg);
		break;
	case ' ': // "de "
	{
		char *line = strdup(input + 1);
		char *p, *q;
		int done = 0;
		int perm = 0, dev = 0;
		p = strchr(line, ' ');
		if (p) {
			*p++ = 0;
			if (strchr(line, 'r'))
				perm |= RZ_PERM_R;
			if (strchr(line, 'w'))
				perm |= RZ_PERM_W;
			if (strchr(line, 'x'))
				perm |= RZ_PERM_X;
			q = strchr(p, ' ');
			if (q) {
				*q++ = 0;
				dev = p[0];
				if (q) {
					rz_debug_esil_watch(core->dbg, perm, dev, q);
					done = 1;
				}
			}
		}
		if (!done) {
			const char *help_de_msg[] = {
				"Usage:", "de", " [perm] [reg|mem] [expr]",
				NULL
			};
			rz_core_cmd_help(core, help_de_msg);
		}
		free(line);
	} break;
	case '-': // "de-"
		rz_debug_esil_watch_reset(core->dbg);
		break;
	case 'c': // "dec"
		if (rz_debug_esil_watch_empty(core->dbg)) {
			eprintf("Error: no esil watchpoints defined\n");
		} else {
			rz_core_analysis_esil_reinit(core);
			rz_debug_esil_prestep(core->dbg, rz_config_get_i(core->config, "esil.prestep"));
			rz_debug_esil_continue(core->dbg);
		}
		break;
	case 's': // "des"
		if (input[1] == 'u' && input[2] == ' ') { // "desu"
			ut64 addr, naddr, fin = rz_num_math(core->num, input + 2);
			rz_core_analysis_esil_reinit(core);
			addr = rz_debug_reg_get(core->dbg, "PC");
			while (addr != fin) {
				rz_debug_esil_prestep(core->dbg, rz_config_get_i(core->config, "esil.prestep"));
				rz_debug_esil_step(core->dbg, 1);
				naddr = rz_debug_reg_get(core->dbg, "PC");
				if (naddr == addr) {
					eprintf("Detected loophole\n");
					break;
				}
				addr = naddr;
			}
		} else if (input[1] == '?' || !input[1]) {
			rz_core_cmd_help(core, help_msg_des);
		} else {
			rz_core_analysis_esil_reinit(core);
			rz_debug_esil_prestep(core->dbg, rz_config_get_i(core->config, "esil.prestep"));
			// continue
			rz_debug_esil_step(core->dbg, rz_num_math(core->num, input + 1));
		}
		break;
	case '?': // "de?"
	default: {
		rz_core_cmd_help(core, help_msg_de);
		// TODO #7967 help refactor: move to detail
		rz_cons_printf("Examples:\n"
			       " de r r rip       # stop when reads rip\n"
			       " de rw m ADDR     # stop when read or write in ADDR\n"
			       " de w r rdx       # stop when rdx register is modified\n"
			       " de x m FROM..TO  # stop when rip in range\n");
	} break;
	}
}

static void rz_core_debug_kill(RzCore *core, const char *input) {
	if (!input || *input == '?') {
		if (input && input[1]) {
			const char *signame, *arg = input + 1;
			int signum = atoi(arg);
			if (signum > 0) {
				signame = rz_signal_to_string(signum);
				if (signame)
					rz_cons_println(signame);
			} else {
				signum = rz_signal_from_string(arg);
				if (signum > 0) {
					rz_cons_printf("%d\n", signum);
				}
			}
		} else {
			rz_core_cmd_help(core, help_msg_dk);
		}
	} else if (*input == 'o') {
		switch (input[1]) {
		case 0: // "dko" - list signal skip/conts
			rz_debug_signal_list(core->dbg, RZ_OUTPUT_MODE_STANDARD);
			break;
		case ' ': // dko SIGNAL
			if (input[2]) {
				char *p, *name = strdup(input + 2);
				int signum = atoi(name);
				p = strchr(name, ' ');
				if (p)
					*p++ = 0; /* got SIGNAL and an action */
				// Actions:
				//  - pass
				//  - trace
				//  - stop
				if (signum < 1)
					signum = rz_signal_from_string(name);
				if (signum > 0) {
					if (!p || !p[0]) { // stop (the usual)
						rz_debug_signal_setup(core->dbg, signum, 0);
					} else if (*p == 's') { // skip
						rz_debug_signal_setup(core->dbg, signum, RZ_DBG_SIGNAL_SKIP);
					} else if (*p == 'c') { // cont
						rz_debug_signal_setup(core->dbg, signum, RZ_DBG_SIGNAL_CONT);
					} else {
						eprintf("Invalid option: %s\n", p);
					}
				} else {
					eprintf("Invalid signal: %s\n", input + 2);
				}
				free(name);
				break;
			}
			/* fall through */
		case '?':
		default: {
			rz_core_cmd_help(core, help_msg_dko);
			// TODO #7967 help refactor: move to detail
			rz_cons_println("NOTE: [signal] can be a number or a string that resolves with dk?\n"
					"  skip means do not enter into the signal handler\n"
					"  continue means enter into the signal handler");
		}
		}
	} else if (*input == 'j') {
		rz_debug_signal_list(core->dbg, RZ_OUTPUT_MODE_JSON);
	} else if (!*input) {
		rz_debug_signal_list(core->dbg, RZ_OUTPUT_MODE_STANDARD);
#if 0
		RzListIter *iter;
		RzDebugSignal *ds;
		eprintf ("TODO: list signal handlers of child\n");
		RzList *list = rz_debug_kill_list (core->dbg);
		rz_list_foreach (list, iter, ds) {
			// TODO: resolve signal name by number and show handler offset
			eprintf ("--> %d\n", ds->num);
		}
		rz_list_free (list);
#endif
	} else {
		int sig = atoi(input);
		char *p = strchr(input, '=');
		if (p) {
			rz_debug_kill_setup(core->dbg, sig, rz_num_math(core->num, p + 1));
		} else {
			rz_debug_kill(core->dbg, core->dbg->pid, core->dbg->tid, sig);
		}
	}
}

static bool cmd_dcu(RzCore *core, const char *input) {
	const char *ptr = NULL;
	ut64 from, to, pc;
	bool dcu_range = false;
	bool invalid = (!input[0] || !input[1] || !input[2]);
	if (invalid || (input[2] != ' ' && input[2] != '.')) {
		rz_core_cmd_help(core, help_msg_dcu);
		return false;
	}
	to = UT64_MAX;
	if (input[2] == '.') {
		ptr = strchr(input + 3, ' ');
		if (ptr) { // TODO: put '\0' in *ptr to avoid
			from = rz_num_tail(core->num, core->offset, input + 2);
			if (ptr[1] == '.') {
				to = rz_num_tail(core->num, core->offset, ptr + 2);
			} else {
				to = rz_num_math(core->num, ptr + 1);
			}
			dcu_range = true;
		} else {
			from = rz_num_tail(core->num, core->offset, input + 2);
		}
	} else {
		ptr = strchr(input + 3, ' ');
		if (ptr) { // TODO: put '\0' in *ptr to avoid
			from = rz_num_math(core->num, input + 3);
			if (ptr[1] == '.') {
				to = rz_num_tail(core->num, core->offset, ptr + 2);
			} else {
				to = rz_num_math(core->num, ptr + 1);
			}
			dcu_range = true;
		} else {
			from = rz_num_math(core->num, input + 3);
		}
	}
	if (core->num->nc.errors && rz_cons_is_interactive()) {
		eprintf("Cannot continue until unknown address '%s'\n", core->num->nc.calc_buf);
		return false;
	}
	if (to == UT64_MAX) {
		to = from;
	}
	if (dcu_range) {
		rz_cons_break_push(NULL, NULL);
		do {
			if (rz_cons_is_breaked()) {
				break;
			}
			rz_debug_step(core->dbg, 1);
			rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false);
			pc = rz_debug_reg_get(core->dbg, "PC");
			eprintf("Continue 0x%08" PFMT64x " > 0x%08" PFMT64x " < 0x%08" PFMT64x "\n",
				from, pc, to);
		} while (pc < from || pc > to);
		rz_cons_break_pop();
	} else {
		return rz_core_debug_continue_until(core, from, to);
	}
	return true;
}

RZ_IPI int rz_debug_continue_oldhandler(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	int pid, old_pid, signum;
	char *ptr;
	rz_cons_break_push(static_debug_stop, core->dbg);
	// TODO: we must use this for step 'ds' too maybe...
	switch (input[0]) {
	case 0: // "dc"
		rz_reg_arena_swap(core->dbg->reg, true);
#if __linux__
		core->dbg->continue_all_threads = true;
#endif
		if (rz_debug_is_dead(core->dbg)) {
			eprintf("Cannot continue, run ood?\n");
			break;
		}
		rz_debug_continue(core->dbg);
		break;
	case 'a': // "dca"
		eprintf("TODO: dca\n");
		break;
	case 'b': // "dcb"
	{
		if (!core->dbg->session) {
			eprintf("Error: Session has not started\n");
			break;
		}
		if (!rz_debug_continue_back(core->dbg)) {
			eprintf("cannot continue back\n");
		}
		break;
	}
#if __WINDOWS__
	case 'e': // "dce"
		rz_reg_arena_swap(core->dbg->reg, true);
		rz_debug_continue_pass_exception(core->dbg);
		break;
#endif
	case 'f': // "dcf"
		eprintf("[+] Running 'dcs vfork fork clone' behind the scenes...\n");
		// we should stop in fork, vfork, and clone syscalls
		cmd_debug_cont_syscall(core, "vfork fork clone");
		break;
	case 'c': // "dcc"
		rz_reg_arena_swap(core->dbg->reg, true);
		if (input[1] == 'u') {
			rz_debug_continue_until_optype(core->dbg, RZ_ANALYSIS_OP_TYPE_UCALL, 0);
		} else {
			rz_debug_continue_until_optype(core->dbg, RZ_ANALYSIS_OP_TYPE_CALL, 0);
		}
		break;
	case 'r':
		rz_reg_arena_swap(core->dbg->reg, true);
		rz_debug_continue_until_optype(core->dbg, RZ_ANALYSIS_OP_TYPE_RET, 1);
		break;
	case 'k':
		// select pid and rz_debug_continue_kill (core->dbg,
		rz_reg_arena_swap(core->dbg->reg, true);
		signum = rz_num_math(core->num, input + 1);
		ptr = strchr(input + 2, ' ');
		if (ptr) {
			int old_pid = core->dbg->pid;
			int old_tid = core->dbg->tid;
			int pid = atoi(ptr + 1);
			int tid = pid; // XXX
			*ptr = 0;
			rz_debug_select(core->dbg, pid, tid);
			rz_debug_continue_kill(core->dbg, signum);
			rz_debug_select(core->dbg, old_pid, old_tid);
		} else {
			rz_debug_continue_kill(core->dbg, signum);
		}
		break;
	case 's': // "dcs"
		switch (input[1]) {
		case '*':
			cmd_debug_cont_syscall(core, "-1");
			break;
		case ' ':
			cmd_debug_cont_syscall(core, input + 2);
			break;
		case '\0':
			cmd_debug_cont_syscall(core, NULL);
			break;
		default:
		case '?':
			rz_core_cmd_help(core, help_msg_dcs);
			break;
		}
		break;
	case 'p': // "dcp"
	{ // XXX: this is very slow
		RzIOMap *s;
		ut64 pc;
		int n = 0;
		bool t = core->dbg->trace->enabled;
		core->dbg->trace->enabled = false;
		rz_cons_break_push(static_debug_stop, core->dbg);
		do {
			rz_debug_step(core->dbg, 1);
			rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false);
			pc = rz_debug_reg_get(core->dbg, "PC");
			eprintf(" %d %" PFMT64x "\r", n++, pc);
			s = rz_io_map_get(core->io, pc);
			if (rz_cons_is_breaked()) {
				break;
			}
		} while (!s);
		eprintf("\n");
		core->dbg->trace->enabled = t;
		rz_cons_break_pop();
		return 1;
	}
	case 'u': // "dcu"
		if (input[1] == '?') {
			rz_core_cmd_help(core, help_msg_dcu);
		} else if (input[1] == '.' || input[1] == '\0') {
			cmd_dcu(core, "cu $$");
		} else {
			char *tmpinp = rz_str_newf("cu %s", input + 2);
			cmd_dcu(core, tmpinp);
			free(tmpinp);
		}
		break;
	case ' ':
		old_pid = core->dbg->pid;
		pid = atoi(input + 1);
		rz_reg_arena_swap(core->dbg->reg, true);
		rz_debug_select(core->dbg, pid, core->dbg->tid);
		rz_debug_continue(core->dbg);
		rz_debug_select(core->dbg, old_pid, core->dbg->tid);
		break;
	case 't':
		cmd_debug_backtrace(core, input + 1);
		break;
	case '?': // "dc?"
	default:
		rz_core_cmd_help(core, help_msg_dc);
		return 0;
	}
	rz_cons_break_pop();
	dbg_follow_seek_register(core);
	return 1;
}

RZ_IPI RzCmdStatus rz_cmd_debug_step_until_handler(RzCore *core, int argc, const char **argv) {
	rz_reg_arena_swap(core->dbg->reg, true);
	step_until(core, rz_num_math(core->num, argv[1]));
	dbg_follow_seek_register(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_debug_step_until_instr_handler(RzCore *core, int argc, const char **argv) {
	step_until_inst(core, argv[1], false);
	dbg_follow_seek_register(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_debug_step_until_instr_regex_handler(RzCore *core, int argc, const char **argv) {
	step_until_inst(core, argv[1], true);
	dbg_follow_seek_register(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_debug_step_until_optype_handler(RzCore *core, int argc, const char **argv) {
	RzList *optypes_list = rz_list_new_from_array((const void **)argv + 1, argc - 1);
	step_until_optype(core, optypes_list);
	dbg_follow_seek_register(core);
	rz_list_free(optypes_list);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_debug_step_until_esil_handler(RzCore *core, int argc, const char **argv) {
	step_until_esil(core, argv[1]);
	dbg_follow_seek_register(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_debug_step_until_flag_handler(RzCore *core, int argc, const char **argv) {
	step_until_flag(core, argv[1]);
	dbg_follow_seek_register(core);
	return RZ_CMD_STATUS_OK;
}

static char *get_corefile_name(const char *raw_name, int pid) {
	return (!*raw_name) ? rz_str_newf("core.%u", pid) : rz_str_trim_dup(raw_name);
}

RZ_IPI int rz_cmd_debug_step(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	ut64 addr = core->offset;
	ut8 buf[64];
	RzAnalysisOp aop;
	int i, times = 1;
	char *ptr = strchr(input, ' ');
	if (ptr) {
		times = rz_num_math(core->num, ptr + 1);
	}
	if (times < 1) {
		times = 1;
	}
	switch (input[0]) {
	case 0: // "ds"
	case ' ':
		rz_core_debug_step_one(core, times);
		break;
	case 'i': // "dsi"
		if (input[1] == ' ') {
			int n = 0;
			rz_cons_break_push(static_debug_stop, core->dbg);
			do {
				if (rz_cons_is_breaked()) {
					break;
				}
				rz_debug_step(core->dbg, 1);
				if (rz_debug_is_dead(core->dbg)) {
					core->break_loop = true;
					break;
				}
				rz_core_debug_regs2flags(core, 0);
				n++;
			} while (!rz_num_conditional(core->num, input + 2));
			rz_cons_break_pop();
			eprintf("Stopped after %d instructions\n", n);
		} else {
			eprintf("3 Missing argument\n");
		}
		break;
	case 'f': // "dsf"
		step_until_eof(core);
		break;
	case 'u': // "dsu"
		switch (input[1]) {
		case 'f': // dsuf
			step_until_flag(core, input + 2);
			break;
		case 'i': // dsui
			if (input[2] == 'r') {
				step_until_inst(core, input + 3, true);
			} else {
				step_until_inst(core, input + 2, false);
			}
			break;
		case 'e': // dsue
			step_until_esil(core, input + 2);
			break;
		case 'o': { // dsuo
			char *optypes = strdup(rz_str_trim_head_ro((char *)input + 2));
			RzList *optypes_list = rz_str_split_list(optypes, " ", 0);
			step_until_optype(core, optypes_list);
			free(optypes);
			rz_list_free(optypes_list);
			break;
		}
		case ' ': // dsu <address>
			rz_reg_arena_swap(core->dbg->reg, true);
			step_until(core, rz_num_math(core->num, input + 1)); // XXX dupped by times
			break;
		default:
			rz_core_cmd_help(core, help_msg_dsu);
			return 0;
		}
		break;
	case 'p': // "dsp"
		rz_reg_arena_swap(core->dbg->reg, true);
		for (i = 0; i < times; i++) {
			ut8 buf[64];
			ut64 addr;
			RzAnalysisOp aop;
			rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false);
			addr = rz_debug_reg_get(core->dbg, "PC");
			rz_io_read_at(core->io, addr, buf, sizeof(buf));
			rz_analysis_op(core->analysis, &aop, addr, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC);
			if (aop.type == RZ_ANALYSIS_OP_TYPE_CALL) {
				RzBinObject *o = rz_bin_cur_object(core->bin);
				RzBinSection *s = rz_bin_get_section_at(o, aop.jump, true);
				if (!s) {
					rz_debug_step_over(core->dbg, times);
					continue;
				}
			}
			rz_debug_step(core->dbg, 1);
		}
		break;
	case 's': // "dss"
	{
		int hwbp = rz_config_get_i(core->config, "dbg.hwbp");
		addr = rz_debug_reg_get(core->dbg, "PC");
		RzBreakpointItem *bpi = rz_bp_get_at(core->dbg->bp, addr);
		rz_reg_arena_swap(core->dbg->reg, true);
		for (i = 0; i < times; i++) {
			rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false);
			rz_io_read_at(core->io, addr, buf, sizeof(buf));
			rz_analysis_op(core->analysis, &aop, addr, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC);
#if 0
				if (aop.jump != UT64_MAX && aop.fail != UT64_MAX) {
					eprintf ("Don't know how to skip this instruction\n");
					if (bpi) rz_core_cmd0 (core, delb);
					break;
				}
#endif
			addr += aop.size;
		}
		rz_debug_reg_set(core->dbg, "PC", addr);
		rz_reg_setv(core->analysis->reg, "PC", addr);
		rz_core_debug_regs2flags(core, 0);
		if (bpi) {
			(void)rz_debug_bp_add(core->dbg, addr, hwbp, false, 0, NULL, 0);
		}
		break;
	}
	case 'o': // "dso"
		if (rz_config_get_i(core->config, "dbg.skipover")) {
			rz_core_cmdf(core, "dss%s", input + 1);
		} else {
			if (rz_config_get_i(core->config, "cfg.debug")) {
				int hwbp = rz_config_get_i(core->config, "dbg.hwbp");
				addr = rz_debug_reg_get(core->dbg, "PC");
				RzBreakpointItem *bpi = rz_bp_get_at(core->dbg->bp, addr);
				rz_bp_del(core->dbg->bp, addr);
				rz_reg_arena_swap(core->dbg->reg, true);
				rz_debug_step_over(core->dbg, times);
				if (bpi) {
					(void)rz_debug_bp_add(core->dbg, addr, hwbp, false, 0, NULL, 0);
				}
			} else {
				for (i = 0; i < times; i++) {
					rz_core_analysis_esil_step_over(core);
				}
			}
		}
		break;
	case 'b': // "dsb"
		if (rz_config_get_i(core->config, "cfg.debug")) {
			if (!core->dbg->session) {
				eprintf("Session has not started\n");
			} else if (rz_debug_step_back(core->dbg, times) < 0) {
				eprintf("Error: stepping back failed\n");
			}
		} else {
			if (rz_core_esil_step_back(core)) {
				rz_core_debug_regs2flags(core, 0);
			} else {
				eprintf("cannot step back\n");
			}
		}
		break;
	case 'l': // "dsl"
		rz_reg_arena_swap(core->dbg->reg, true);
		step_line(core, times);
		break;
	case '?': // "ds?"
	default:
		rz_core_cmd_help(core, help_msg_ds);
		return 0;
	}
	dbg_follow_seek_register(core);
	return 1;
}

static ut8 *getFileData(RzCore *core, const char *arg) {
	if (*arg == '$') {
		return (ut8 *)rz_cmd_alias_get(core->rcmd, arg, 1);
	}
	return (ut8 *)rz_file_slurp(arg, NULL);
}

static void consumeBuffer(RzBuffer *buf, const char *cmd, const char *errmsg) {
	if (!buf) {
		if (errmsg) {
			rz_cons_printf("%s\n", errmsg);
		}
		return;
	}
	if (cmd) {
		rz_cons_printf("%s", cmd);
	}
	int i;
	rz_buf_seek(buf, 0, RZ_BUF_SET);
	for (i = 0; i < rz_buf_size(buf); i++) {
		rz_cons_printf("%02x", rz_buf_read8(buf));
	}
	rz_cons_printf("\n");
}

RZ_IPI int rz_cmd_debug(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	RzDebugTracepoint *t;
	const char *ptr;
	int follow = 0;
	ut64 addr;
	int min;
	RzListIter *iter;
	RzList *list;
	RzDebugPid *p;
	RzDebugTracepoint *trace;
	RzAnalysisOp *op;

	if (!strncmp(input, "ate", 3)) {
		char str[128];
		str[0] = 0;
		rz_print_date_get_now(core->print, str);
		rz_cons_println(str);
		return 0;
	}

	switch (input[0]) {
	case 't':
		// TODO: define ranges? to display only some traces, allow to scroll on this disasm? ~.. ?
		switch (input[1]) {
		case '\0': // "dt"
			rz_debug_trace_list(core->dbg, 0, core->offset);
			break;
		case '=': // "dt="
			rz_debug_trace_list(core->dbg, '=', core->offset);
			break;
		case 'q': // "dtq"
			rz_debug_trace_list(core->dbg, 'q', core->offset);
			break;
		case '*': // "dt*"
			rz_debug_trace_list(core->dbg, 1, core->offset);
			break;
		case ' ': // "dt [addr]"
			if ((t = rz_debug_trace_get(core->dbg,
				     rz_num_math(core->num, input + 3)))) {
				rz_cons_printf("offset = 0x%" PFMT64x "\n", t->addr);
				rz_cons_printf("opsize = %d\n", t->size);
				rz_cons_printf("times = %d\n", t->times);
				rz_cons_printf("count = %d\n", t->count);
				//TODO cons_printf("time = %d\n", t->tm);
			}
			break;
		case 'a': // "dta"
			rz_debug_trace_at(core->dbg, input + 3);
			break;
		case 't': // "dtt"
			rz_debug_trace_tag(core->dbg, atoi(input + 3));
			break;
		case 'c': // "dtc"
			if (input[2] == '?') {
				rz_cons_println("Usage: dtc [addr] ([from] [to] [addr]) - trace calls in debugger");
			} else {
				debug_trace_calls(core, input + 2);
			}
			break;
		case 'd': // "dtd"
			min = rz_num_math(core->num, input + 3);
			if (input[2] == 'q') { // "dtdq"
				int n = 0;
				rz_list_foreach (core->dbg->trace->traces, iter, trace) {
					if (n >= min) {
						rz_cons_printf("%d  ", trace->count);
						rz_cons_printf("0x%08" PFMT64x "\n", trace->addr);
						break;
					}
					n++;
				}
			} else if (input[2] == 'i') {
				int n = 0;
				rz_list_foreach (core->dbg->trace->traces, iter, trace) {
					op = rz_core_analysis_op(core, trace->addr, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_DISASM);
					if (n >= min) {
						rz_cons_printf("%d %s\n", trace->count, op->mnemonic);
					}
					n++;
					rz_analysis_op_free(op);
				}
			} else if (input[2] == ' ') {
				int n = 0;
				rz_list_foreach (core->dbg->trace->traces, iter, trace) {
					op = rz_core_analysis_op(core, trace->addr, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_DISASM);
					if (n >= min) {
						rz_cons_printf("0x%08" PFMT64x " %s\n", trace->addr, op->mnemonic);
					}
					n++;
					rz_analysis_op_free(op);
				}
			} else {
				rz_list_foreach (core->dbg->trace->traces, iter, trace) {
					op = rz_core_analysis_op(core, trace->addr, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_DISASM);
					rz_cons_printf("0x%08" PFMT64x " %s\n", trace->addr, op->mnemonic);
					rz_analysis_op_free(op);
				}
			}
			break;
		case 'g': // "dtg"
			dot_trace_traverse(core, core->dbg->tree, input[2]);
			break;
		case '-': // "dt-"
			rz_tree_reset(core->dbg->tree);
			rz_debug_trace_free(core->dbg->trace);
			rz_debug_tracenodes_reset(core->dbg);
			core->dbg->trace = rz_debug_trace_new();
			break;
		case '+': // "dt+"
			if (input[2] == '+') { // "dt++"
				char *a, *s = rz_str_trim_dup(input + 3);
				RzList *args = rz_str_split_list(s, " ", 0);
				RzListIter *iter;
				rz_list_foreach (args, iter, a) {
					ut64 addr = rz_num_get(NULL, a);
					(void)rz_debug_trace_add(core->dbg, addr, 1);
				}
				rz_list_free(args);
				free(s);
			} else {
				ptr = input + 2;
				addr = rz_num_math(core->num, ptr);
				ptr = strchr(ptr, ' ');
				int count = 1;
				if (ptr) {
					count = rz_num_math(core->num, ptr + 1);
				}
				RzAnalysisOp *op = rz_core_op_analysis(core, addr, RZ_ANALYSIS_OP_MASK_HINT);
				if (op) {
					RzDebugTracepoint *tp = rz_debug_trace_add(core->dbg, addr, op->size);
					if (!tp) {
						rz_analysis_op_free(op);
						break;
					}
					tp->count = count;
					rz_analysis_trace_bb(core->analysis, addr);
					rz_analysis_op_free(op);
				} else {
					eprintf("Cannot analyze opcode at 0x%08" PFMT64x "\n", addr);
				}
			}
			break;
		case 'e': // "dte"
			rz_core_analysis_esil_init(core);
			switch (input[2]) {
			case 0: // "dte"
				rz_analysis_esil_trace_list(core->analysis->esil);
				break;
			case 'i': { // "dtei"
				ut64 addr = rz_num_math(core->num, input + 3);
				if (!addr) {
					addr = core->offset;
				}
				RzAnalysisOp *op = rz_core_analysis_op(core, addr, RZ_ANALYSIS_OP_MASK_ESIL);
				if (op) {
					rz_analysis_esil_trace_op(core->analysis->esil, op);
				}
				rz_analysis_op_free(op);
			} break;
			case '-': // "dte-"
				if (!strcmp(input + 3, "*")) {
					if (core->analysis->esil) {
						sdb_free(core->analysis->esil->trace->db);
						core->analysis->esil->trace->db = sdb_new0();
					}
				} else {
					eprintf("TODO: dte- cannot delete specific logs. Use dte-*\n");
				}
				break;
			case ' ': { // "dte "
				int idx = atoi(input + 3);
				rz_analysis_esil_trace_show(
					core->analysis->esil, idx);
			} break;
			case 'k': // "dtek"
				if (input[3] == ' ') {
					char *s = sdb_querys(core->analysis->esil->trace->db,
						NULL, 0, input + 4);
					rz_cons_println(s);
					free(s);
				} else {
					eprintf("Usage: dtek [query]\n");
				}
				break;
			default:
				rz_core_cmd_help(core, help_msg_dte);
			}
			break;
		case 's': // "dts"
			switch (input[2]) {
			case '+': // "dts+"
				if (rz_debug_is_dead(core->dbg)) {
					eprintf("Cannot start session outside of debug mode, run ood?\n");
					break;
				}
				if (core->dbg->session) {
					eprintf("Session already started\n");
					break;
				}
				core->dbg->session = rz_debug_session_new();
				rz_debug_add_checkpoint(core->dbg);
				break;
			case '-': // "dts-"
				if (!core->dbg->session) {
					eprintf("No session started\n");
					break;
				}
				rz_debug_session_free(core->dbg->session);
				core->dbg->session = NULL;
				break;
			case 't': // "dtst"
				if (!core->dbg->session) {
					eprintf("No session started\n");
					break;
				}
				rz_debug_session_save(core->dbg->session, input + 4);
				break;
			case 'f': // "dtsf"
				if (core->dbg->session) {
					rz_debug_session_free(core->dbg->session);
					core->dbg->session = NULL;
				}
				core->dbg->session = rz_debug_session_new();
				rz_debug_session_load(core->dbg, input + 4);
				break;
			case 'm': // "dtsm"
				if (core->dbg->session) {
					rz_debug_session_list_memory(core->dbg);
				}
				break;
			default:
				rz_core_cmd_help(core, help_msg_dts);
			}
			break;
		case '?':
		default: {
			rz_core_cmd_help(core, help_msg_dt);
			rz_cons_printf("Current Tag: %d\n", core->dbg->trace->tag);
		} break;
		}
		break;
	case 'd': // "ddd"
		switch (input[1]) {
		case '\0': // "ddd"
			rz_debug_desc_list(core->dbg, 0);
			break;
		case '*': // "dtd*"
			rz_debug_desc_list(core->dbg, 1);
			break;
		case 's': // "dtds"
		{
			ut64 off = UT64_MAX;
			int fd = atoi(input + 2);
			char *str = strchr(input + 2, ' ');
			if (str)
				off = rz_num_math(core->num, str + 1);
			if (off == UT64_MAX || !rz_debug_desc_seek(core->dbg, fd, off)) {
				RzBuffer *buf = rz_core_syscallf(core, "lseek", "%d, 0x%" PFMT64x ", %d", fd, off, 0);
				consumeBuffer(buf, "dx ", "Cannot seek");
			}
		} break;
		case 't': { // "ddt" <ttypath>
			RzBuffer *buf = rz_core_syscall(core, "close", 0);
			consumeBuffer(buf, "dx ", "Cannot close");
			break;
		}
		case 'd': // "ddd"
		{
			ut64 newfd = UT64_MAX;
			int fd = atoi(input + 2);
			char *str = strchr(input + 3, ' ');
			if (str)
				newfd = rz_num_math(core->num, str + 1);
			if (newfd == UT64_MAX || !rz_debug_desc_dup(core->dbg, fd, newfd)) {
				RzBuffer *buf = rz_core_syscallf(core, "dup2", "%d, %d", fd, (int)newfd);
				if (buf) {
					consumeBuffer(buf, "dx ", NULL);
				} else {
					eprintf("Cannot dup %d %d\n", fd, (int)newfd);
				}
			}
		} break;
		case 'r': {
			ut64 off = UT64_MAX;
			ut64 len = UT64_MAX;
			int fd = atoi(input + 2);
			char *str = strchr(input + 2, ' ');
			if (str)
				off = rz_num_math(core->num, str + 1);
			if (str)
				str = strchr(str + 1, ' ');
			if (str)
				len = rz_num_math(core->num, str + 1);
			if (len == UT64_MAX || off == UT64_MAX ||
				!rz_debug_desc_read(core->dbg, fd, off, len)) {
				consumeBuffer(rz_core_syscallf(core, "read", "%d, 0x%" PFMT64x ", %d",
						      fd, off, (int)len),
					"dx ", "Cannot read");
			}
		} break;
		case 'w': {
			ut64 off = UT64_MAX;
			ut64 len = UT64_MAX;
			int fd = atoi(input + 2);
			char *str = strchr(input + 2, ' ');
			if (str)
				off = rz_num_math(core->num, str + 1);
			if (str)
				str = strchr(str + 1, ' ');
			if (str)
				len = rz_num_math(core->num, str + 1);
			if (len == UT64_MAX || off == UT64_MAX ||
				!rz_debug_desc_write(core->dbg, fd, off, len)) {
				RzBuffer *buf = rz_core_syscallf(core, "write", "%d, 0x%" PFMT64x ", %d", fd, off, (int)len);
				consumeBuffer(buf, "dx ", "Cannot write");
			}
		} break;
		case '-': // "dd-"
			// close file
			{
				int fd = atoi(input + 2);
				//rz_core_cmdf (core, "dxs close %d", (int)rz_num_math ( core->num, input + 2));
				RzBuffer *buf = rz_core_syscallf(core, "close", "%d", fd);
				consumeBuffer(buf, "dx ", "Cannot close");
			}
			break;
		case ' ': // "dd"
			// TODO: handle read, readwrite, append
			{
				RzBuffer *buf = rz_core_syscallf(core, "open", "%s, %d, %d", input + 2, 2, 0644);
				consumeBuffer(buf, "dx ", "Cannot open");
			}
			// open file
			break;
		case '?':
		default:
			rz_core_cmd_help(core, help_msg_dd);
			break;
		}
		break;
	case 's': // "ds"
		if (rz_cmd_debug_step(core, input + 1)) {
			follow = rz_config_get_i(core->config, "dbg.follow");
		}
		break;
	case 'b': // "db"
		rz_core_cmd_bp(core, input);
		break;
	case 'H': // "dH"
		eprintf("TODO: transplant process\n");
		break;
	case 'c': // "dc"
		(void)rz_debug_continue_oldhandler(core, input + 1);
		break;
	case 'm': // "dm"
		cmd_debug_map(core, input + 1);
		break;
	case 'r': // "dr"
		if (core->bin->is_debugger || input[1] == '?') {
			cmd_debug_reg(core, input + 1);
		} else {
			cmd_analysis_reg(core, input + 1);
		}
		//rz_core_cmd (core, "|reg", 0);
		break;
	case 'p': // "dp"
		cmd_debug_pid(core, input);
		break;
	case 'L': // "dL"
		switch (input[1]) {
		case 'q':
		case 'j':
			rz_debug_plugin_list(core->dbg, input[1]);
			break;
		case '?':
			rz_core_cmd_help(core, help_msg_dL);
			break;
		case ' ': {
			char *str = rz_str_trim_dup(input + 2);
			rz_config_set(core->config, "dbg.backend", str);
			// implicit by config.set rz_debug_use (core->dbg, str);
			free(str);
		} break;
		default:
			rz_debug_plugin_list(core->dbg, 0);
			break;
		}
		break;
	case 'i': // "di"
	{
		RzDebugInfo *rdi = rz_debug_info(core->dbg, input + 2);
		RzDebugReasonType stop = rz_debug_stop_reason(core->dbg);
		char *escaped_str;
		switch (input[1]) {
		case '\0': // "di"
#define P rz_cons_printf
#define PS(X, Y) \
	{ \
		escaped_str = rz_str_escape(Y); \
		rz_cons_printf(X, escaped_str); \
		free(escaped_str); \
	}
			if (rdi) {
				const char *s = rz_signal_to_string(core->dbg->reason.signum);
				P("type=%s\n", rz_debug_reason_to_string(core->dbg->reason.type));
				P("signal=%s\n", s ? s : "none");
				P("signum=%d\n", core->dbg->reason.signum);
				P("sigpid=%d\n", core->dbg->reason.tid);
				P("addr=0x%" PFMT64x "\n", core->dbg->reason.addr);
				P("bp_addr=0x%" PFMT64x "\n", core->dbg->reason.bp_addr);
				P("inbp=%s\n", rz_str_bool(core->dbg->reason.bp_addr));
				P("baddr=0x%" PFMT64x "\n", rz_debug_get_baddr(core->dbg, NULL));
				P("pid=%d\n", rdi->pid);
				P("tid=%d\n", rdi->tid);
				P("stopaddr=0x%" PFMT64x "\n", core->dbg->stopaddr);
				if (rdi->uid != -1) {
					P("uid=%d\n", rdi->uid);
				}
				if (rdi->gid != -1) {
					P("gid=%d\n", rdi->gid);
				}
				if (rdi->usr) {
					P("usr=%s\n", rdi->usr);
				}
				if (rdi->exe && *rdi->exe) {
					P("exe=%s\n", rdi->exe);
				}
				if (rdi->cmdline && *rdi->cmdline) {
					P("cmdline=%s\n", rdi->cmdline);
				}
				if (rdi->cwd && *rdi->cwd) {
					P("cwd=%s\n", rdi->cwd);
				}
				if (rdi->kernel_stack && *rdi->kernel_stack) {
					P("kernel_stack=\n%s\n", rdi->kernel_stack);
				}
			}
			if (stop != -1) {
				P("stopreason=%d\n", stop);
			}
			break;
		case 'f': // "dif" "diff"
			if (input[1] == '?') {
				eprintf("Usage: dif $a $b  # diff two alias files\n");
			} else {
				char *arg = strchr(input, ' ');
				if (arg) {
					arg = strdup(rz_str_trim_head_ro(arg + 1));
					char *arg2 = strchr(arg, ' ');
					if (arg2) {
						*arg2++ = 0;
						ut8 *a = getFileData(core, arg);
						ut8 *b = getFileData(core, arg2);
						if (a && b) {
							int al = strlen((const char *)a);
							int bl = strlen((const char *)b);
							RzDiff *d = rz_diff_new();
							char *uni = rz_diff_buffers_to_string(d, a, al, b, bl);
							rz_cons_printf("%s\n", uni);
							rz_diff_free(d);
							free(uni);
						} else {
							eprintf("Cannot open those alias files\n");
						}
					}
					free(arg);
				} else {
					eprintf("Usage: dif $a $b  # diff two alias files\n");
				}
			}
			break;
		case '*': // "di*"
			if (rdi) {
				rz_cons_printf("f dbg.signal = %d\n", core->dbg->reason.signum);
				rz_cons_printf("f dbg.sigpid = %d\n", core->dbg->reason.tid);
				rz_cons_printf("f dbg.inbp = %d\n", core->dbg->reason.bp_addr ? 1 : 0);
				rz_cons_printf("f dbg.sigaddr = 0x%" PFMT64x "\n", core->dbg->reason.addr);
				rz_cons_printf("f dbg.baddr = 0x%" PFMT64x "\n", rz_debug_get_baddr(core->dbg, NULL));
				rz_cons_printf("f dbg.pid = %d\n", rdi->pid);
				rz_cons_printf("f dbg.tid = %d\n", rdi->tid);
				rz_cons_printf("f dbg.uid = %d\n", rdi->uid);
				rz_cons_printf("f dbg.gid = %d\n", rdi->gid);
			}
			break;
		case 'j': // "dij"
			P("{");
			if (rdi) {
				const char *s = rz_signal_to_string(core->dbg->reason.signum);
				P("\"type\":\"%s\",", rz_debug_reason_to_string(core->dbg->reason.type));
				P("\"signal\":\"%s\",", s ? s : "none");
				P("\"signum\":%d,", core->dbg->reason.signum);
				P("\"sigpid\":%d,", core->dbg->reason.tid);
				P("\"addr\":%" PFMT64d ",", core->dbg->reason.addr);
				P("\"inbp\":%s,", rz_str_bool(core->dbg->reason.bp_addr));
				P("\"baddr\":%" PFMT64d ",", rz_debug_get_baddr(core->dbg, NULL));
				P("\"stopaddr\":%" PFMT64d ",", core->dbg->stopaddr);
				P("\"pid\":%d,", rdi->pid);
				P("\"tid\":%d,", rdi->tid);
				P("\"uid\":%d,", rdi->uid);
				P("\"gid\":%d,", rdi->gid);
				if (rdi->usr) {
					PS("\"usr\":\"%s\",", rdi->usr);
				}
				if (rdi->exe) {
					PS("\"exe\":\"%s\",", rdi->exe);
				}
				if (rdi->cmdline) {
					PS("\"cmdline\":\"%s\",", rdi->cmdline);
				}
				if (rdi->cwd) {
					PS("\"cwd\":\"%s\",", rdi->cwd);
				}
			}
			P("\"stopreason\":%d}\n", stop);
			break;
#undef P
#undef PS
		case 'q': {
			const char *r = rz_debug_reason_to_string(core->dbg->reason.type);
			if (!r) {
				r = "none";
			}
			rz_cons_printf("%s at 0x%08" PFMT64x "\n", r, core->dbg->stopaddr);
		} break;
		case '?': // "di?"
		default:
			rz_core_cmd_help(core, help_msg_di);
			break;
		}
		rz_debug_info_free(rdi);
	} break;
	case 'e': // "de"
		rz_core_debug_esil(core, input + 1);
		break;
	case 'g': // "dg"
		if (core->dbg->h && core->dbg->h->gcore) {
			if (core->dbg->pid == -1) {
				eprintf("Not debugging, can't write core.\n");
				break;
			}
			char *corefile = get_corefile_name(input + 1, core->dbg->pid);
			eprintf("Writing to file '%s'\n", corefile);
			rz_file_rm(corefile);
			RzBuffer *dst = rz_buf_new_file(corefile, O_RDWR | O_CREAT, 0644);
			if (dst) {
				if (!core->dbg->h->gcore(core->dbg, dst)) {
					eprintf("dg: coredump failed\n");
				}
				rz_buf_free(dst);
			} else {
				perror("rz_buf_new_file");
			}
			free(corefile);
		}
		break;
	case 'k': // "dk"
		rz_core_debug_kill(core, input + 1);
		break;
	case 'o': // "do"
		switch (input[1]) {
		case '\0': // "do"
			rz_core_file_reopen(core, input[1] ? input + 2 : NULL, 0, 1);
			break;
		case 'e': // "doe"
			switch (input[2]) {
			case '\0': // "doe"
				if (core->io->envprofile) {
					rz_cons_println(core->io->envprofile);
				}
				break;
			case '!': // "doe!"
			{
				char *out = rz_core_editor(core, NULL, core->io->envprofile);
				if (out) {
					free(core->io->envprofile);
					core->io->envprofile = out;
					eprintf("%s\n", core->io->envprofile);
				}
			} break;
			default:
				break;
			}
			break;
		case 'r': // "dor" : rarun profile
			if (input[2] == ' ') {
				setRarunProfileString(core, input + 3);
			} else {
				// TODO use the api
				rz_sys_xsystem("rz_run -h");
			}
			break;
		case 'o': // "doo" : reopen in debug mode
			if (input[2] == 'f') { // "doof" : reopen in debug mode from the given file
				rz_config_set_i(core->config, "cfg.debug", true);
				rz_core_cmd0(core, sdb_fmt("oodf %s", input + 3));
			} else {
				rz_core_file_reopen_debug(core, input + 2);
			}
			break;
		case 'c': // "doc" : close current debug session
			if (!core || !core->io || !core->io->desc || !rz_config_get_i(core->config, "cfg.debug")) {
				eprintf("No open debug session\n");
				break;
			}
			// Stop trace session
			if (core->dbg->session) {
				rz_debug_session_free(core->dbg->session);
				core->dbg->session = NULL;
			}
			// Kill debugee and all child processes
			if (core->dbg && core->dbg->h && core->dbg->h->pids && core->dbg->pid != -1) {
				list = core->dbg->h->pids(core->dbg, core->dbg->pid);
				if (list) {
					rz_list_foreach (list, iter, p) {
						rz_debug_kill(core->dbg, p->pid, p->pid, SIGKILL);
						rz_debug_detach(core->dbg, p->pid);
					}
				} else {
					rz_debug_kill(core->dbg, core->dbg->pid, core->dbg->pid, SIGKILL);
					rz_debug_detach(core->dbg, core->dbg->pid);
				}
			}
			// Remove the target's registers from the flag list
			rz_core_cmd0(core, ".dr-");
			// Reopen and rebase the original file
			rz_core_io_file_open(core, core->io->desc->fd);
			break;
		case '?': // "do?"
		default:
			rz_core_cmd_help(core, help_msg_do);
			break;
		}
		break;
#if __WINDOWS__
	case 'W': // "dW"
		if (input[1] == 'i') {
			rz_w32_identify_window();
		} else {
			rz_w32_print_windows(core->dbg);
		}
		break;
#endif
	case 'w': // "dw"
		rz_cons_break_push(static_debug_stop, core->dbg);
		for (; !rz_cons_is_breaked();) {
			int pid = atoi(input + 1);
			//int opid = core->dbg->pid = pid;
			int res = rz_debug_kill(core->dbg, pid, 0, 0);
			if (!res) {
				break;
			}
			rz_sys_usleep(200);
		}
		rz_cons_break_pop();
		break;
	case 'x': // "dx"
		switch (input[1]) {
		case ' ': { // "dx "
			ut8 bytes[4096];
			if (strlen(input + 2) < 4096) {
				int bytes_len = rz_hex_str2bin(input + 2, bytes);
				if (bytes_len > 0)
					rz_debug_execute(core->dbg,
						bytes, bytes_len, 0);
				else
					eprintf("Invalid hexpairs\n");
			} else
				eprintf("Injection opcodes so long\n");
			break;
		}
		case 'a': { // "dxa"
			RzAsmCode *acode;
			rz_asm_set_pc(core->rasm, core->offset);
			acode = rz_asm_massemble(core->rasm, input + 2);
			if (acode) {
				rz_reg_arena_push(core->dbg->reg);
				rz_debug_execute(core->dbg, acode->bytes, acode->len, 0);
				rz_reg_arena_pop(core->dbg->reg);
			}
			rz_asm_code_free(acode);
			break;
		}
		case 'e': { // "dxe"
			RzEgg *egg = core->egg;
			RzBuffer *b;
			const char *asm_arch = rz_config_get(core->config, "asm.arch");
			int asm_bits = rz_config_get_i(core->config, "asm.bits");
			const char *asm_os = rz_config_get(core->config, "asm.os");
			rz_egg_setup(egg, asm_arch, asm_bits, 0, asm_os);
			rz_egg_reset(egg);
			rz_egg_load(egg, input + 1, 0);
			rz_egg_compile(egg);
			b = rz_egg_get_bin(egg);
			rz_asm_set_pc(core->rasm, core->offset);
			rz_reg_arena_push(core->dbg->reg);
			ut64 tmpsz;
			const ut8 *tmp = rz_buf_data(b, &tmpsz);
			rz_debug_execute(core->dbg, tmp, tmpsz, 0);
			rz_reg_arena_pop(core->dbg->reg);
			break;
		}
		case 'r': // "dxr"
			rz_reg_arena_push(core->dbg->reg);
			if (input[2] == ' ') {
				ut8 bytes[4096];
				if (strlen(input + 2) < 4096) {
					int bytes_len = rz_hex_str2bin(input + 2,
						bytes);
					if (bytes_len > 0) {
						rz_debug_execute(core->dbg,
							bytes, bytes_len,
							0);
					} else {
						eprintf("Invalid hexpairs\n");
					}
				} else
					eprintf("Injection opcodes so long\n");
			}
			rz_reg_arena_pop(core->dbg->reg);
			break;
		case 's': // "dxs"
			if (input[2]) {
				char *str;
				str = rz_core_cmd_str(core, sdb_fmt("gs %s", input + 2));
				rz_core_cmdf(core, "dx %s", str); //`gs %s`", input + 2);
				free(str);
			} else {
				eprintf("Missing parameter used in gs by dxs\n");
			}
			break;
		case '?': // "dx?"
		default:
			rz_core_cmd_help(core, help_msg_dx);
			break;
		}
		break;
	case '?': // "d?"
	default:
		rz_core_cmd_help(core, help_msg_d);
		break;
	}
	if (follow > 0) {
		dbg_follow_seek_register(core);
	}
	return 0;
}
