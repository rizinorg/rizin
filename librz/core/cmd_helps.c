#include "cmd_helps.h"

// root helps

const RzCmdDescDetailEntry tmp_modifier_detail_entries[] = {
	{ .text = "<cmd> @", .arg_str = " <addr>", .comment = "temporary seek to <addr>" },
	{ .text = "<cmd> @", .arg_str = " <addr>!<blocksize>", .comment = "temporary seek to <addr> and set blocksize to <blocksize>" },
	{ .text = "<cmd> @..", .arg_str = "<addr>", .comment = "temporary partial address seek (see s..)" },
	{ .text = "<cmd> @!", .arg_str = "<blocksize>", .comment = "temporary change the block size" },
	{ .text = "<cmd> @{", .arg_str = "<from> <to>}", .comment = "temporary set from and to for commands supporting ranges" },
	{ .text = "<cmd> @a:", .arg_str = "<arch>[:<bits>]", .comment = "temporary set arch and bits, if specified" },
	{ .text = "<cmd> @b:", .arg_str = "<bits>", .comment = "temporary set asm.bits" },
	{ .text = "<cmd> @B:", .arg_str = "<nth>", .comment = "temporary seek to nth instruction in current basic block (negative numbers too)" },
	{ .text = "<cmd> @e:", .arg_str = "<k>=<v>[,<k>=<v>]", .comment = "temporary change eval vars (multiple vars separated by comma)" },
	{ .text = "<cmd> @f:", .arg_str = "<file>", .comment = "temporary replace block with file contents" },
	{ .text = "<cmd> @F:", .arg_str = "<flagspace>", .comment = "temporary change flag space" },
	{ .text = "<cmd> @i:", .arg_str = "<nth.op>", .comment = "temporary seek to the Nth relative instruction" },
	{ .text = "<cmd> @k:", .arg_str = "<key>", .comment = "temporary seek at value of sdb key `key`" },
	{ .text = "<cmd> @o:", .arg_str = "<fd>", .comment = "temporary switch to another fd" },
	{ .text = "<cmd> @r:", .arg_str = "<reg>", .comment = "temporary seek to register value" },
	{ .text = "<cmd> @s:", .arg_str = "<string>", .comment = "temporary replace block with string" },
	{ .text = "<cmd> @x:", .arg_str = "<hexstring>", .comment = "temporary replace block with hexstring" },
	{ 0 },
};

const RzCmdDescDetail tmp_modifier_detail[] = {
	{ .name = "", .entries = tmp_modifier_detail_entries },
	{ 0 },
};

const RzCmdDescHelp tmp_modifier_help = {
	.summary = "'@' help",
	.options = "?",
	.details = tmp_modifier_detail,
	.usage = "<cmd> <@> <args>",
};

const RzCmdDescDetailEntry iterator_detail_entries[] = {
	{ .text = "<cmd> @@", .arg_str = " <glob>", .comment = "run <cmd> over all flags matching <glob> in current flagspace. <glob> may contain `*` to indicate multiple chars" },
	{ .text = "<cmd> @@dbt[abs]", .arg_str = "", .comment = "run <cmd> on every backtrace address, bp or sp" },
	{ .text = "<cmd> @@.", .arg_str = "<file>", .comment = "run <cmd> over the offsets specified in <file>, one per line" },
	{ .text = "<cmd> @@=", .arg_str = "<addr1> [<addr2> ...]", .comment = "run <cmd> over the listed addresses" },
	{ .text = "<cmd> @@/", .arg_str = "<search-cmd>", .comment = "run <cmd> over the search results of /<search-cmd>" },
	{ .text = "<cmd> @@k", .arg_str = " <sdbquery>", .comment = "run <cmd> over all offsets return by the sdb query <sdbquery>" },
	{ .text = "<cmd> @@t", .arg_str = "", .comment = "run <cmd> over all threads" },
	{ .text = "<cmd> @@b", .arg_str = "", .comment = "run <cmd> over all basic blocks of the current function" },
	{ .text = "<cmd> @@i", .arg_str = "", .comment = "run <cmd> over all instructions of the current function" },
	{ .text = "<cmd> @@iS", .arg_str = "", .comment = "run <cmd> over all sections" },
	{ .text = "<cmd> @@f", .arg_str = "", .comment = "run <cmd> over all functions" },
	{ .text = "<cmd> @@f:", .arg_str = "<glob>", .comment = "run <cmd> over all function matching <glob>. <glob> may contain `*` to indicate multiple chars" },
	{ .text = "<cmd> @@s:", .arg_str = "<from> <to> <step>", .comment = "run <cmd> on all addresses starting from <from> and going up to <to> (included), with a step <step>." },
	{ .text = "<cmd> @@c:", .arg_str = "<cmd2>", .comment = "run <cmd> on all addresses in the output of <cmd2>" },
	{ 0 },
};

const RzCmdDescDetail iterator_detail[] = {
	{ .name = "", .entries = iterator_detail_entries },
	{ 0 },
};

const RzCmdDescHelp iterator_help = {
	.summary = "'@@' help",
	.options = "?",
	.details = iterator_detail,
	.usage = "<cmd> <@@> <args>",
};

const RzCmdDescDetailEntry foreach_detail_entries[] = {
	{ .text = "<cmd> @@@=", .arg_str = "<addr> <size> (<addr> <size> ...)", .comment = "run <cmd> on each <addr> and set blocksize to <size>" },
	{ .text = "<cmd> @@@b", .arg_str = "", .comment = "run <cmd> on each basic block of current function" },
	{ .text = "<cmd> @@@c:", .arg_str = "<cmd2>", .comment = "same as <cmd>@@@=`<cmd2>`" },
	{ .text = "<cmd> @@@C:", .arg_str = "<string>", .comment = "run <cmd> on each comment matching <string>" },
	{ .text = "<cmd> @@@i", .arg_str = "", .comment = "run <cmd> on each import" },
	{ .text = "<cmd> @@@r", .arg_str = "", .comment = "run <cmd> on each register" },
	{ .text = "<cmd> @@@s", .arg_str = "", .comment = "run <cmd> on each symbol" },
	{ .text = "<cmd> @@@st", .arg_str = "", .comment = "run <cmd> on each string" },
	{ .text = "<cmd> @@@S", .arg_str = "", .comment = "run <cmd> on each section" },
	{ .text = "<cmd> @@@m", .arg_str = "", .comment = "run <cmd> on each io.maps" },
	{ .text = "<cmd> @@@M", .arg_str = "", .comment = "run <cmd> on each dbg.maps" },
	{ .text = "<cmd> @@@f", .arg_str = "", .comment = "run <cmd> on each flag" },
	{ .text = "<cmd> @@@f:", .arg_str = "<glob-string>", .comment = "run <cmd> on each flag matching <glob-string>. <glob-string> may contain `*` to indicate multiple chars" },
	{ .text = "<cmd> @@@F", .arg_str = "", .comment = "run <cmd> on each function" },
	{ .text = "<cmd> @@@F:", .arg_str = "<glob-string>", .comment = "run <cmd> on each function whose name matches <glob-string>. <glob-string> may contain `*` to indicate multiple chars" },
	{ .text = "<cmd> @@@t", .arg_str = "", .comment = "run <cmd> on each thread" },
	{ 0 },
};

const RzCmdDescDetail foreach_detail[] = {
	{ .name = "", .entries = foreach_detail_entries },
	{ 0 },
};

const RzCmdDescHelp foreach_help = {
	.summary = "'@@@' help",
	.options = "?",
	.details = foreach_detail,
	.usage = "<cmd> <@@@>",
};

const RzCmdDescDetailEntry redirection_detail_entries[] = {
	{ .text = "<cmd> >", .arg_str = " <file>|<$alias>", .comment = "redirect STDOUT of <cmd> to <file> or save it to an alias (see $?)" },
	{ .text = "<cmd> 2>", .arg_str = " <file>|<$alias>", .comment = "redirect STDERR of <cmd> to <file> or save it to an alias (see $?)" },
	{ .text = "<cmd> H>", .arg_str = " <file>|<$alias>", .comment = "redirect HTML output of <cmd> to <file> or save it to an alias (see $?)" },
	{ 0 },
};

const RzCmdDescDetail redirection_detail[] = {
	{ .name = "", .entries = redirection_detail_entries },
	{ 0 },
};

const RzCmdDescHelp redirection_help = {
	.summary = "redirection help ('>')",
	.options = "?",
	.details = redirection_detail,
	.usage = "<cmd> > <arg>",
};

const RzCmdDescDetailEntry pipe_detail_entries[] = {
	{ .text = "<cmd> |", .arg_str = NULL, .comment = "disable scr.html and scr.color" },
	{ .text = "<cmd> |H", .arg_str = NULL, .comment = "enable scr.html, respect scr.color" },
	{ .text = "<cmd> |T", .arg_str = NULL, .comment = "use scr.tts to speak out the stdout" },
	{ .text = "<cmd> |", .arg_str = " <program>", .comment = "pipe output of command to program" },
	{ .text = "<cmd> |.", .arg_str = NULL, .comment = "alias for .<cmd>" },
	{ 0 },
};

const RzCmdDescDetail pipe_detail[] = {
	{ .name = "", .entries = pipe_detail_entries },
	{ 0 },
};

const RzCmdDescHelp pipe_help = {
	.summary = "pipe help ('|')",
	.options = "?",
	.details = pipe_detail,
	.usage = "<cmd> |[<program>|H|T|.|]",
};

const RzCmdDescDetailEntry grep_modifiers[] = {
	{ .text = "&", .arg_str = NULL, .comment = "all words must match to grep the line" },
	{ .text = "$[n]", .arg_str = NULL, .comment = "sort numerically / alphabetically the Nth column" },
	{ .text = "$!", .arg_str = NULL, .comment = "sort in inverse order" },
	{ .text = ",", .arg_str = NULL, .comment = "token to define another keyword" },
	{ .text = "+", .arg_str = NULL, .comment = "case insensitive grep (grep -i)" },
	{ .text = "^", .arg_str = NULL, .comment = "words must be placed at the beginning of line" },
	{ .text = "<", .arg_str = NULL, .comment = "perform zoom operation on the buffer" },
	{ .text = "!", .arg_str = NULL, .comment = "negate grep" },
	{ .text = "?", .arg_str = NULL, .comment = "count number of matching lines" },
	{ .text = "?.", .arg_str = NULL, .comment = "count number chars" },
	{ .text = ":s..e", .arg_str = NULL, .comment = "show lines s-e" },
	{ .text = "..", .arg_str = NULL, .comment = "internal 'less'" },
	{ .text = "...", .arg_str = NULL, .comment = "internal 'hud' (like V_)" },
	{ .text = "{:", .arg_str = NULL, .comment = "human friendly indentation (yes, it's a smiley)" },
	{ .text = "{:..", .arg_str = NULL, .comment = "less the output of {:" },
	{ .text = "{:...", .arg_str = NULL, .comment = "hud the output of {:" },
	{ .text = "{}", .arg_str = NULL, .comment = "json indentation" },
	{ .text = "{}..", .arg_str = NULL, .comment = "less json indentation" },
	{ .text = "{}...", .arg_str = NULL, .comment = "hud json indentation" },
	{ .text = "{path}", .arg_str = NULL, .comment = "json path grep" },
	{ 0 },
};

const RzCmdDescDetailEntry grep_endmodifiers[] = {
	{ .text = "$", .arg_str = NULL, .comment = "words must be placed at the end of line" },
	{ 0 },
};

const RzCmdDescDetailEntry grep_columns[] = {
	{ .text = "[n]", .arg_str = NULL, .comment = "show only column n" },
	{ .text = "[n-m]", .arg_str = NULL, .comment = "show column n to m" },
	{ .text = "[n-]", .arg_str = NULL, .comment = "show all columns starting from column n" },
	{ .text = "[i,j,k]", .arg_str = NULL, .comment = "show the columns i, j and k" },
	{ 0 },
};

const RzCmdDescDetailEntry grep_examples[] = {
	{ .text = "i", .arg_str = "~:0", .comment = "show first line of 'i' output" },
	{ .text = "i", .arg_str = "~:-2", .comment = "show the second to last line of 'i' output" },
	{ .text = "i", .arg_str = "~:0..3", .comment = "show first three lines of 'i' output" },
	{ .text = "pd", .arg_str = "~mov", .comment = "disasm and grep for mov" },
	{ .text = "pi", .arg_str = "~[0]", .comment = "show only opcode" },
	{ .text = "i", .arg_str = "~0x400$", .comment = "show lines ending with 0x400" },
	{ 0 },
};

const RzCmdDescDetail grep_detail[] = {
	{ .name = "Modifiers", .entries = grep_modifiers },
	{ .name = "EndModifiers", .entries = grep_endmodifiers },
	{ .name = "Columns", .entries = grep_columns },
	{ .name = "Examples", .entries = grep_examples },
	{ 0 },
};

const RzCmdDescHelp grep_help = {
	.summary = "grep help ('~')",
	.options = "?",
	.details = grep_detail,
	.usage = "<command>~[modifier][word,word][endmodifier][[column]][:line]",
};

const RzCmdDescHelp system_help = {
	.summary = "run given command as in system(3)",
};
const RzCmdDescHelp underscore_help = {
	.summary = "Print last output",
};

const RzCmdDescHelp hash_help = {
	.summary = "Hashbang to run an rlang script",
};

const RzCmdDescHelp alias_help = {
	.summary = "Alias commands and strings",
};

const RzCmdDescDetailEntry env_help_examples[] = {
	{ .text = "%", .comment = "list all environment variables" },
	{ .text = "%", .arg_str = "SHELL", .comment = "print value of SHELL variable" },
	{ .text = "%", .arg_str = "TMPDIR=/tmp", .comment = "set TMPDIR to \"/tmp\"" },
	{ .text = "env", .arg_str = "SHELL", .comment = "same as `%SHELL`" },
	{ 0 },
};

const RzCmdDescDetailEntry env_help_environments[] = {
	{ .text = "RZ_FILE", .comment = "currently opened file name" },
	{ .text = "RZ_OFFSET", .comment = "10base offset 64bit value" },
	{ .text = "RZ_BYTES", .comment = "TODO: variable with bytes in curblock" },
	{ .text = "RZ_XOFFSET", .comment = "same as above, but in 16 base" },
	{ .text = "RZ_BSIZE", .comment = "block size" },
	{ .text = "RZ_ENDIAN", .comment = "'big' or 'little'" },
	{ .text = "RZ_IOVA", .comment = "is io.va true? virtual addressing (1,0)" },
	{ .text = "RZ_DEBUG", .comment = "debug mode enabled? (1,0)" },
	{ .text = "RZ_BLOCK", .comment = "TODO: dump current block to tmp file" },
	{ .text = "RZ_SIZE", .comment = "file size" },
	{ .text = "RZ_ARCH", .comment = "value of asm.arch" },
	{ .text = "RZ_BITS", .comment = "arch reg size (8, 16, 32, 64)" },
	{ .text = "RZ_BIN_LANG", .comment = "assume this lang to demangle" },
	{ .text = "RZ_BIN_DEMANGLE", .comment = "demangle or not" },
	{ .text = "RZ_BIN_PDBSERVER", .comment = "e pdb.server" },
	{ 0 },
};

const RzCmdDescDetail env_help_details[] = {
	{ .name = "Examples", .entries = env_help_examples },
	{ .name = "Environment", .entries = env_help_environments },
	{ 0 },
};

const RzCmdDescHelp env_help = {
	.summary = "get/set environment variables",
	.args_str = " [varname[=varvalue]]",
	.details = env_help_details,
};

const RzCmdDescHelp percentage_help = {
	.summary = "get/set environment variables",
	.args_str = "[varname[=varvalue]]",
	.details = env_help_details,
};

const RzCmdDescHelp tasks_help = {
	.summary = "Manage tasks (WARNING: Experimental. Use with caution!)",
};

const RzCmdDescHelp macro_help = {
	.summary = "manage scripting macros",
};

const RzCmdDescDetailEntry pointer_help_examples[] = {
	{ .text = "*", .arg_str = "entry0=cc", .comment = "write trap in entrypoint" },
	{ .text = "*", .arg_str = "entry0+10=0x804800", .comment = "write 0x804800 as a 4-byte value at 10 bytes from the entrypoint" },
	{ .text = "*", .arg_str = "entry0", .comment = "read the value contained at the entrypoint" },
	{ 0 },
};

const RzCmdDescDetail pointer_help_details[] = {
	{ .name = "Examples", .entries = pointer_help_examples },
	{ 0 },
};

const RzCmdDescHelp pointer_help = {
	.summary = "pointer read/write data/values",
	.args_str = "<addr>[=<0xvalue>|<hexstring>]",
	.description = "Read or write values at a given address. When the value starts with `0x`, a 4-bytes value or 8-bytes value is written in the memory at address, depending on the size of the value. When value does not start with `0x` an hexstring with arbitrary length is expected and it is written starting from the specified address.",
	.details = pointer_help_details,
};

const RzCmdDescHelp stdin_help = {
	.summary = "",
};

const RzCmdDescHelp interpret_help = {
	.summary = "Define macro or load rizin, cparse or rlang file",
};

const RzCmdDescHelp search_help = {
	.summary = "search for bytes, regexps, patterns, ..",
};

const RzCmdDescHelp rap_help = {
	.summary = "connect with other instances of rizin",
};

const RzCmdDescHelp help_help = {
	.summary = "Help or evaluate math expression",
	.options = "[??]",
};

const RzCmdDescHelp rap_run_help = {
	.summary = "alias for =!",
};

const RzCmdDescHelp zero_help = {
	.summary = "alias for `s 0x...`",
};

const RzCmdDescHelp anal_help = {
	.summary = "analysis commands",
};

const RzCmdDescHelp b_help = {
	.summary = "display or change the block size",
};

const RzCmdDescHelp c_help = {
	.summary = "compare block with given data",
};

const RzCmdDescHelp C_help = {
	.summary = "code metadata (comments, format, hints, ..)",
};

const RzCmdDescHelp d_help = {
	.summary = "debugger commands",
};

const RzCmdDescHelp e_help = {
	.summary = "list/get/set config evaluable vars",
};

const RzCmdDescHelp f_help = {
	.summary = "add flag at current address",
};

const RzCmdDescHelp g_help = {
	.summary = "generate shellcodes with rz_egg",
};

const RzCmdDescHelp i_help = {
	.summary = "get info about opened file from rz_bin",
};

const RzCmdDescHelp k_help = {
	.summary = "run sdb-query",
};

const RzCmdDescHelp l_help = {
	.summary = "list files and directories",
};

const RzCmdDescHelp m_help = {
	.summary = "make directories and move files",
};

const RzCmdDescHelp j_help = {
	.summary = "join the contents of the two files",
};

const RzCmdDescHelp h_help = {
	.summary = "show the top n number of line in file",
};

const RzCmdDescHelp L_help = {
	.summary = "list, unload, load rizin plugins",
};

const RzCmdDescHelp o_help = {
	.summary = "open file at optional address",
};

const RzCmdDescHelp p_help = {
	.summary = "print commands",
};

const RzCmdDescHelp P_help = {
	.summary = "project management utilities",
};

const RzCmdDescHelp q_help = {
	.summary = "quit program with a return value",
};

const RzCmdDescHelp Q_help = {
	.summary = "quick quit",
};

const RzCmdDescHelp colon_help = {
	.summary = "long commands (experimental)",
};

const RzCmdDescHelp rz_help = {
	.summary = "resize file",
};

const RzCmdDescHelp s_help = {
	.summary = "seek to address",
};

const RzCmdDescHelp t_help = {
	.summary = "types, noreturn, signatures, C parser and more",
};

const RzCmdDescHelp T_help = {
	.summary = "Text log utility (used to chat, sync, log, ...)",
};

const RzCmdDescHelp u_help = {
	.summary = "uname/undo seek/write",
};

const RzCmdDescHelp pipein_help = {
	.summary = "push escaped string into the RzCons.readChar buffer",
};

const RzCmdDescHelp V_help = {
	.summary = "enter visual mode",
};

const RzCmdDescHelp v_help = {
	.summary = "enter visual panels mode",
};

const RzCmdDescHelp w_group_help = {
	.summary = "write commands",
};

const RzCmdDescHelp w_help = {
	.args_str = " <string>",
	.summary = "write string",
};

const RzCmdDescHelp x_help = {
	.summary = "alias for 'px' (print hexadecimal)",
};

const RzCmdDescHelp y_help = {
	.summary = "Yank/paste bytes from/to memory",
};

const RzCmdDescHelp z_help = {
	.summary = "zignatures management",
};

// w0 helps

const RzCmdDescHelp w0_help = {
	.summary = "Write 'len' bytes with value 0x00",
	.args_str = " [len]",
	.description = "Fill len bytes starting from the current offset with the value 0.",
};

// w[1248][+-] helps

const RzCmdDescDetailEntry w_incdec_help_examples[] = {
	{ .text = "w1+", .comment = "Add 1 to the byte at the current offset." },
	{ .text = "w2-", .comment = "Subtract 1 to the word at the current offset." },
	{ .text = "w4+", .arg_str = " 0xdeadbeef", .comment = "Add 0xdeadbeef to the dword at the current offset." },
	{ .text = "w8-", .arg_str = " 10", .comment = "Subtract 10 to the qword at the current offset." },
	{ 0 },
};

const RzCmdDescDetail w_incdec_help_details[] = {
	{ .name = "Examples", .entries = w_incdec_help_examples },
	{ 0 },
};

const RzCmdDescHelp w_incdec_help = {
	.summary = "increment/decrement byte,word..",
	.args_str = " [n]",
	.options = "<1248><+->",
};

const RzCmdDescHelp w1_incdec_group_help = {
	.summary = "Increment/decrement a byte",
	.options = "<+->",
	.args_str = " [n]",
	.description = "Increment/decrement a byte at the current offset by 1 or n, if specified",
	.details = w_incdec_help_details,
};

const RzCmdDescHelp w1_inc_help = {
	.summary = "Increment a byte",
	.args_str = " [n]",
	.description = "Increment a byte at the current offset by 1 or n, if specified",
	.details = w_incdec_help_details,
};

const RzCmdDescHelp w1_dec_help = {
	.summary = "Decrement a byte",
	.args_str = " [n]",
	.description = "Decrement a byte at the current offset by 1 or n, if specified",
	.details = w_incdec_help_details,
};

const RzCmdDescHelp w2_incdec_group_help = {
	.summary = "Increment/decrement a word",
	.options = "<+->",
	.args_str = " [n]",
	.description = "Increment/decrement a word at the current offset by 1 or n, if specified",
	.details = w_incdec_help_details,
};

const RzCmdDescHelp w2_inc_help = {
	.summary = "Increment a word",
	.args_str = " [n]",
	.description = "Increment a word at the current offset by 1 or n, if specified",
	.details = w_incdec_help_details,
};

const RzCmdDescHelp w2_dec_help = {
	.summary = "Decrement a word",
	.args_str = " [n]",
	.description = "Decrement a word at the current offset by 1 or n, if specified",
	.details = w_incdec_help_details,
};

const RzCmdDescHelp w4_incdec_group_help = {
	.summary = "Increment/decrement a dword",
	.options = "<+->",
	.args_str = " [n]",
	.description = "Increment/decrement a dword at the current offset by 1 or n, if specified",
	.details = w_incdec_help_details,
};

const RzCmdDescHelp w4_inc_help = {
	.summary = "Increment a dword",
	.args_str = " [n]",
	.description = "Increment a dword at the current offset by 1 or n, if specified",
	.details = w_incdec_help_details,
};

const RzCmdDescHelp w4_dec_help = {
	.summary = "Decrement a dword",
	.args_str = " [n]",
	.description = "Decrement a dword at the current offset by 1 or n, if specified",
	.details = w_incdec_help_details,
};

const RzCmdDescHelp w8_incdec_group_help = {
	.summary = "Increment/decrement a qword",
	.options = "<+->",
	.args_str = " [n]",
	.description = "Increment/decrement a qword at the current offset by 1 or n, if specified",
	.details = w_incdec_help_details,
};

const RzCmdDescHelp w8_inc_help = {
	.summary = "Increment a qword",
	.args_str = " [n]",
	.description = "Increment a qword at the current offset by 1 or n, if specified",
	.details = w_incdec_help_details,
};

const RzCmdDescHelp w8_dec_help = {
	.summary = "Decrement a qword",
	.args_str = " [n]",
	.description = "Decrement a qword at the current offset by 1 or n, if specified",
	.details = w_incdec_help_details,
};

// wB helps

const RzCmdDescDetailEntry wB_help_examples[] = {
	{ .text = "wB", .arg_str = " 0x20", .comment = "Sets the 5th bit at current offset, leaving all other bits intact." },
	{ 0 },
};

const RzCmdDescDetail wB_help_details[] = {
	{ .name = "Examples", .entries = wB_help_examples },
	{ 0 },
};

const RzCmdDescHelp wB_group_help = {
	.args_str = " [value]",
	.summary = "Set or unset bits with given value",
};

const RzCmdDescHelp wB_help = {
	.summary = "Set bits with given value",
	.args_str = " [value]",
	.description = "Set the bits that are set in the value passed as arguments. 0 bits in the value argument are ignored, while the others are set at the current offset",
	.details = wB_help_details,
};

const RzCmdDescHelp wB_minus_help = {
	.summary = "Unset bits with given value",
	.args_str = " [value]",
	.description = "Unset the bits that are set in the value passed as arguments. 0 bits in the value argument are ignored, while the others are unset at the current offset"
};

// wv helps

const RzCmdDescDetailEntry wv_help_examples[] = {
	{ .text = "wv", .arg_str = " 0xdeadbeef", .comment = "Write the value 0xdeadbeef at current offset" },
	{ 0 },
};

const RzCmdDescDetail wv_help_details[] = {
	{ .name = "Examples", .entries = wv_help_examples },
	{ 0 },
};

const RzCmdDescHelp wv_group_help = {
	.args_str = " [value]",
	.summary = "Write value of given size",
};

const RzCmdDescHelp wv_help = {
	.summary = "Write value as 4 - bytes / 8 - bytes based on value",
	.args_str = " [value]",
	.description = "Write the number passed as argument at the current offset as a 4 - bytes value or 8 - bytes value if the input is bigger than UT32_MAX, respecting the cfg.bigendian variable",
	.details = wv_help_details,
};

const RzCmdDescHelp wv1_help = {
	.summary = "Write value of 1 byte",
	.args_str = " [value]",
	.description = "Write the number passed as argument at the current offset as 1 - byte, respecting the cfg.bigendian variable",
};
const RzCmdDescHelp wv2_help = {
	.summary = "Write value of 2 bytes",
	.args_str = " [value]",
	.description = "Write the number passed as argument at the current offset as 2 - bytes, respecting the cfg.bigendian variable",
};
const RzCmdDescHelp wv4_help = {
	.summary = "Write value of 4 bytes",
	.args_str = " [value]",
	.description = "Write the number passed as argument at the current offset as 4 - bytes, respecting the cfg.bigendian variable",
};
const RzCmdDescHelp wv8_help = {
	.summary = "Write value of 8 byte",
	.args_str = " [value]",
	.description = "Write the number passed as argument at the current offset as 8 - bytes, respecting the cfg.bigendian variable",
};

const RzCmdDescDetailEntry w6_help_examples[] = {
	{ .text = "w6d", .arg_str = " SGVsbG9Xb3JsZAo=", .comment = "Write the string \"HelloWorld\" (without quotes) at current offset." },
	{ .text = "w6e", .arg_str = " 48656c6c6f576f726c64", .comment = "Write the string \"SGVsbG9Xb3JsZAo=\" (without quotes) at current offset." },
	{ 0 },
};

const RzCmdDescDetail w6_help_details[] = {
	{ .name = "Examples", .entries = w6_help_examples },
	{ 0 },
};

const RzCmdDescHelp w6_group_help = {
	.args_str = " <base64>|<hexstring>",
	.summary = "write base64 [d]ecoded or [e]ncoded string",
	.details = w6_help_details,
};

const RzCmdDescHelp w6d_help = {
	.args_str = " <base64>",
	.summary = "write the base64-decoded bytes",
	.description = "Base64-Decode the string passed as argument and write it at the current offset.",
	.details = w6_help_details,
};

const RzCmdDescHelp w6e_help = {
	.args_str = " <hexstring>",
	.summary = "write the base64-encoded bytes",
	.description = "Base64-Encode the hex string passed as argument and write it at the current offset.",
	.details = w6_help_details,
};

const RzCmdDescHelp wh_help = {
	.args_str = " <command>",
	.summary = "whereis/which shell command",
};

const RzCmdDescHelp we_help = {
	.summary = "extend write operations (insert bytes instead of replacing)",
};

const RzCmdDescHelp wp_help = {
	.args_str = " -|<file>",
	.summary = "apply radare patch file. See wp? fmi",
};

const RzCmdDescHelp wu_help = {
	.summary = "Apply unified hex patch (see output of cu)",
};

const RzCmdDescHelp wr_help = {
	.args_str = " <num>",
	.summary = "write <num> random bytes",
};

const RzCmdDescHelp wA_help = {
	.args_str = " <type> <value>",
	.summary = "alter/modify opcode at current seek (see wA?)",
};

const RzCmdDescHelp wc_help = {
	.summary = "write cache commands",
};

const RzCmdDescHelp wz_help = {
	.args_str = " <string>",
	.summary = "write zero terminated string (like w + \x00)",
};

const RzCmdDescHelp wt_help = {
	.summary = "write to file (from current seek, blocksize or sz bytes)",
};

const RzCmdDescHelp wf_help = {
	.summary = "write data from file, socket, offset",
};

const RzCmdDescHelp ww_help = {
	.args_str = " <string>",
	.summary = "write wide string",
};

const RzCmdDescHelp wx_help = {
	.args_str = " <hexstring>",
	.summary = "write two intel nops (from wxfile or wxseek)",
};

const RzCmdDescHelp wa_help = {
	.summary = "write opcode, separated by ';' (use '\"' around the command)",
};

const RzCmdDescHelp wb_help = {
	.args_str = " <hexstring>",
	.summary = "fill current block with cyclic hexstring",
};

const RzCmdDescHelp wm_help = {
	.args_str = " <hexstring>",
	.summary = "set binary mask hexpair to be used as cyclic write mask",
};

const RzCmdDescHelp wo_help = {
	.summary = "write in block with operation. 'wo?' fmi",
};

const RzCmdDescHelp wd_help = {
	.summary = "duplicate N bytes from offset at current seek (memcpy) (see y?)",
};

const RzCmdDescHelp ws_help = {
	.summary = "write 1 byte for length and then the string",
};
