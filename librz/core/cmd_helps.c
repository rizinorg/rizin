#include "cmd_helps.h"

// root helps

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
	{ .text = "%SHELL", .comment = "print value of SHELL variable" },
	{ .text = "%TMPDIR=/tmp", .comment = "set TMPDIR to \"/tmp\"" },
	{ .text = "env SHELL", .comment = "same as `%SHELL`" },
	{ 0 },
};

const RzCmdDescDetail env_help_details[] = {
	{ .name = "Examples", .entries = env_help_examples },
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
	{ .text = "*entry0=cc", .comment = "write trap in entrypoint" },
	{ .text = "*entry0+10=0x804800", .comment = "write 0x804800 as a 4-byte value at 10 bytes from the entrypoint" },
	{ .text = "*entry0", .comment = "read the value contained at the entrypoint" },
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
	.summary = "Define macro or load r2, cparse or rlang file",
};

const RzCmdDescHelp search_help = {
	.summary = "search for bytes, regexps, patterns, ..",
};

const RzCmdDescHelp rap_help = {
	.summary = "connect with other instances of r2",
};

const RzCmdDescHelp help_help = {
	.summary = "Help or evaluate math expression",
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
	.summary = "list, unload, load r2 plugins",
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
	{ .text = "w4+ 0xdeadbeef", .comment = "Add 0xdeadbeef to the dword at the current offset." },
	{ .text = "w8- 10", .comment = "Subtract 10 to the qword at the current offset." },
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

const RzCmdDescHelp w1_incdec_help = {
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

const RzCmdDescHelp w2_incdec_help = {
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

const RzCmdDescHelp w4_incdec_help = {
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

const RzCmdDescHelp w8_incdec_help = {
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
	{ .text = "wB 0x20", .comment = "Sets the 5th bit at current offset, leaving all other bits intact." },
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
	{ .text = "wv 0xdeadbeef", .comment = "Write the value 0xdeadbeef at current offset" },
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
	{ .text = "w6d SGVsbG9Xb3JsZAo=", .comment = "Write the string \"HelloWorld\" (without quotes) at current offset." },
	{ .text = "w6e 48656c6c6f576f726c64", .comment = "Write the string \"SGVsbG9Xb3JsZAo=\" (without quotes) at current offset." },
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
