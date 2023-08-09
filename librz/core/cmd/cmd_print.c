// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_core.h>
#include <rz_config.h>
#include <rz_util.h>
#include <rz_type.h>
#include <rz_types.h>
#include <limits.h>

#include "../core_private.h"
#include "rz_util/rz_strbuf.h"

#define PF_USAGE_STR "pf[.k[.f[=v]]|[v]]|[n]|[0|cnt][fmt] [a0 a1 ...]"

static const char *help_msg_at[] = {
	"Usage: [.][#]<cmd>[*] [`cmd`] [@ addr] [~grep] [|syscmd] [>[>]file]", "", "",
	"0", "", "alias for 's 0'",
	"0x", "addr", "alias for 's 0x..'",
	"#", "cmd", "if # is a number repeat the command # times",
	"/*", "", "start multiline comment",
	"*/", "", "end multiline comment",
	".", "cmd", "execute output of command as rizin script",
	".:", "8080", "wait for commands on port 8080",
	".!", "rz-bin -re $FILE", "run command output as rizin script",
	"*", "", "output of command in rizin script format (CC*)",
	"j", "", "output of command in JSON format (pdj)",
	"~", "?", "count number of lines (like wc -l)",
	"~", "??", "show internal grep help",
	"~", "..", "internal less",
	"~", "{}", "json indent",
	"~", "{}..", "json indent and less",
	"~", "word", "grep for lines matching word",
	"~", "!word", "grep for lines NOT matching word",
	"~", "word[2]", "grep 3rd column of lines matching word",
	"~", "word:3[0]", "grep 1st column from the 4th line matching word",
	"@", " 0x1024", "temporary seek to this address (sym.main+3)",
	"@", " [addr]!blocksize", "temporary set a new blocksize",
	"@..", "addr", "temporary partial address seek (see s..)",
	"@!", "blocksize", "temporary change the block size (p8@3!3)",
	"@{", "from to}", "temporary set from and to for commands supporting ranges",
	"@a:", "arch[:bits]", "temporary set arch and bits",
	"@b:", "bits", "temporary set asm.bits",
	"@B:", "nth", "temporary seek to nth instruction in current bb (negative numbers too)",
	"@e:", "k=v,k=v", "temporary change eval vars",
	"@f:", "file", "temporary replace block with file contents",
	"@F:", "flagspace", "temporary change flag space",
	"@i:", "nth.op", "temporary seek to the Nth relative instruction",
	"@k:", "k", "temporary seek at value of sdb key `k`",
	"@o:", "fd", "temporary switch to another fd",
	"@r:", "reg", "tmp seek to reg value (f.ex pd@r:PC)",
	"@s:", "string", "same as above but from a string",
	"@v:", "value", "modify the current offset to a custom value",
	"@x:", "909192", "from hex pairs string",
	"@@=", "1 2 3", "run the previous command at offsets 1, 2 and 3",
	"@@", " hit*", "run the command on every flag matching 'hit*'",
	"@@?", "[ktfb..]", "show help for the iterator operator",
	"@@@", " [type]", "run a command on every [type] (see @@@? for help)",
	">", "file", "pipe output of command to file",
	">>", "file", "append to file",
	"H>", "file", "pipe output of command to file in HTML",
	"H>>", "file", "append to file with the output of command in HTML",
	"`", "pdq~push:0[0]`", "replace output of command inside the line",
	"|", "cmd", "pipe output to command (pd|less) (.dr*)",
	NULL
};

static const char *help_msg_at_at[] = {
	"@@", "", " # foreach iterator command:",
	"x", " @@ sym.*", "run 'x' over all flags matching 'sym.' in current flagspace",
	"x", " @@dbt[abs]", "run 'x' command on every backtrace address, bp or sp",
	"x", " @@.file", "run 'x' over the offsets specified in the file (one offset per line)",
	"x", " @@=off1 off2 ..", "manual list of offsets",
	"x", " @@/x 9090", "temporary set cmd.hit to run a command on each search result",
	"x", " @@k sdbquery", "run 'x' on all offsets returned by that sdbquery",
	"x", " @@t", "run 'x' on all threads (see dp)",
	"x", " @@b", "run 'x' on all basic blocks of current function (see afb)",
	"x", " @@i", "run 'x' on all instructions of the current function (see pdr)",
	"x", " @@iS", "run 'x' on all sections adjusting blocksize",
	"x", " @@f", "run 'x' on all functions (see aflq)",
	"x", " @@f:write", "run 'x' on all functions matching write in the name",
	"x", " @@s:from to step", "run 'x' on all offsets from, to incrementing by step",
	"x", " @@c:cmd", "the same as @@=`` without the backticks",
	"x", " @@=`pdf~call[0]`", "run 'x' at every call offset of the current function",
	// TODO: Add @@k sdb-query-expression-here
	NULL
};

static const char *help_msg_at_at_at[] = {
	"@@@", "", " # foreach offset+size iterator command:",
	"x", " @@@=", "[addr] [size] ([addr] [size] ...)",
	"x", " @@@b", "basic blocks of current function",
	"x", " @@@c:cmd", "Same as @@@=`cmd`, without the backticks",
	"x", " @@@C:cmd", "comments matching",
	"x", " @@@i", "imports",
	"x", " @@@r", "registers",
	"x", " @@@s", "symbols",
	"x", " @@@st", "strings",
	"x", " @@@S", "sections",
	"x", " @@@m", "io.maps",
	"x", " @@@M", "dbg.maps (See ?$?~size)",
	"x", " @@@f", "flags",
	"x", " @@@f:hit*", "flags matching glob expression",
	"x", " @@@F", "functions (set fcn size which may be incorrect if not linear)",
	"x", " @@@F:glob", "functions matching glob expression",
	"x", " @@@t", "threads",
	"x", " @@@r", "regs",
	// TODO: Add @@k sdb-query-expression-here
	NULL
};

static const char *help_msg_p[] = {
	"Usage:", "p[=68abcdDfiImrstuxz] [arg|len] [@addr]", "",
	"p", "[b|B|xb] [len] ([S])", "bindump N bits skipping S bytes",
	"p", "[iI][df] [len]", "print N ops/bytes (f=func) (see pi? and pdq)",
	"p", "[kK] [len]", "print key in randomart (K is for mosaic)",
	"p-", "[?][jh] [mode]", "bar|json|histogram blocks (mode: e?search.in)",
	"p2", " [len]", "8x8 2bpp-tiles",
	"p6", "[de] [len]", "base64 decode/encode",
	"p8", "[?][j] [len]", "8bit hexpair list of bytes",
	"p=", "[?][bep] [N] [L] [b]", "show entropy/printable chars/chars bars",
	"pa", "[edD] [arg]", "pa:assemble  pa[dD]:disasm or pae: esil from hex",
	"pb", "[?] [n]", "bitstream of N bits",
	"pB", "[?] [n]", "bitstream of N bytes",
	"pc", "[?][p] [len]", "output C (or python) format",
	"pC", "[aAcdDxw] [rows]", "print disassembly in columns (see hex.cols and pdq)",
	"pd", "[?] [sz] [a] [b]", "disassemble N opcodes (pd) or N bytes (pD)",
	"pf", "[?][.nam] [fmt]", "print formatted data (pf.name, pf.name $<expr>)",
	"pF", "[?][apx]", "print asn1, pkcs7 or x509",
	"pg", "[?][x y w h] [cmd]", "create new visual gadget or print it (see pg? for details)",
	"ph", "[?][=|hash] ([len])", "calculate hash for a block",
	"pi", "[?][bdefrj] [num]", "print instructions",
	"pI", "[?][iI][df] [len]", "print N instructions/bytes (f=func)",
	"pj", "[?] [len]", "print as indented JSON",
	"pm", "[?] [magic]", "print libmagic data (see pm? and /m?)",
	"po", "[?] hex", "print operation applied to block (see po?)",
	"pp", "[?][sz] [len]", "print patterns, see pp? for more help",
	"pr", "[?][glx] [len]", "print N raw bytes (in lines or hexblocks, 'g'unzip)",
	"ps", "[?][pwz] [len]", "print pascal/wide/zero-terminated strings",
	"pt", "[?][dn] [len]", "print different timestamps",
	"pu", "[?][w] [len]", "print N url encoded bytes (w=wide)",
	"pv", "[?][jh] [mode]", "show variable/pointer/value in memory",
	"px", "[?][owq] [len]", "hexdump of N bytes (o=octal, w=32bit, q=64bit)",
	"plf", "", "print the RzIL output of the function",
	NULL
};

static const char *help_msg_pj[] = {
	"Usage:", "pj[..] [size]", "",
	"pj", "", "print current block as indented JSON",
	"pj.", "", "print as indented JSON from 0 to the current offset",
	"pj..", "", "print JSON path from 0 to the current offset",
	NULL
};

static const char *help_msg_pf[] = {
	"pf:", PF_USAGE_STR, "",
	"Commands:", "", "",
	"pf", " fmt", "Show data using the given format-string. See 'pf\?\?' and 'pf\?\?\?'.",
	"pf", "?", "Show this help",
	"pf", "??", "Format characters",
	"pf", "???", "pf usage examples",
	"pf* ", "fmt_name|fmt", "Show data using (named) format as rizin flag create commands",
	"pf.", "", "List all format definitions",
	"pf.", "fmt_name", "Show data using named format",
	"pf.", "fmt_name.field_name", "Show specific data field using named format",
	"pf.", "fmt_name.field_name=33", "Set new value for the specified field in named format",
	"pf.", "fmt_name.field_name[i]", "Show element i of array field_name",
	"pf.", "name [0|cnt]fmt", "Define a new named format",
	"pf?", "fmt_name", "Show the definition of a named format",
	"pfc ", "fmt_name|fmt", "Show data using (named) format as C string",
	"pfd.", "fmt_name", "Show data using named format as graphviz commands",
	"pfj ", "fmt_name|fmt", "Show data using (named) format in JSON",
	"pfo", " fdf_name", "Load a Format Definition File (fdf)",
	"pfo", "", "List all format definition files (fdf)",
	"pfq", " fmt ...", "Quiet print format (do now show address)",
	"pfs", "[.fmt_name| fmt]", "Print the size of (named) format in bytes",
	"pfv.", "fmt_name[.field]", "Print value(s) only for named format. Useful for one-liners",
	NULL
};

static const char *help_detail_pf[] = {
	"pf:", PF_USAGE_STR, "",
	"Format:", "", "",
	" ", "b", "byte (unsigned)",
	" ", "B", "resolve enum bitfield (see t?)",
	" ", "c", "char (signed byte)",
	" ", "C", "byte in decimal",
	" ", "d", "0xHEX value (4 bytes) (see 'i' and 'x')",
	" ", "D", "disassemble one opcode",
	" ", "e", "temporally swap endian",
	" ", "E", "resolve enum name (see t?)",
	" ", "f", "float value (4 bytes)",
	" ", "F", "double value (8 bytes)",
	" ", "i", "signed integer value (4 bytes) (see 'd' and 'x')",
	" ", "n", "next char specifies size of signed value (1, 2, 4 or 8 byte(s))",
	" ", "N", "next char specifies size of unsigned value (1, 2, 4 or 8 byte(s))",
	" ", "o", "octal value (4 byte)",
	" ", "p", "pointer reference (2, 4 or 8 bytes)",
	" ", "q", "quadword (8 bytes)",
	" ", "Q", "uint128_t (16 bytes)",
	" ", "r", "CPU register `pf r (eax)plop`",
	" ", "s", "32bit pointer to string (4 bytes)",
	" ", "S", "64bit pointer to string (8 bytes)",
	" ", "t", "UNIX timestamp (4 bytes)",
	" ", "T", "show Ten first bytes of buffer",
	" ", "u", "uleb128 (variable length)",
	" ", "w", "word (2 bytes unsigned short in hex)",
	" ", "x", "0xHEX value and flag (fd @ addr) (see 'd' and 'i')",
	" ", "X", "show formatted hexpairs",
	" ", "z", "null terminated string",
	" ", "Z", "null terminated wide string",
	" ", "?", "data structure `pf ? (struct_name)example_name`",
	" ", "*", "next char is pointer (honors asm.bits)",
	" ", "+", "toggle show flags for each offset",
	" ", ":", "skip 4 bytes",
	" ", ".", "skip 1 byte",
	" ", ";", "rewind 4 bytes",
	" ", ",", "rewind 1 byte",
	NULL
};

static const char *help_detail2_pf[] = {
	"pf:", PF_USAGE_STR, "",
	"Examples:", "", "",
	"pf", " 3xi foo bar", "3-array of struct, each with named fields: 'foo' as hex, and 'bar' as int",
	"pf", " B (BitFldType)arg_name`", "bitfield type",
	"pf", " E (EnumType)arg_name`", "enum type",
	"pf", " obj=xxdz prev next size name", "Same as above",
	"pf", " *z*i*w nb name blob", "Print the pointers with given labels",
	"pf", " iwq foo bar troll", "Print the iwq format with foo, bar, troll as the respective names for the fields",
	"pf", " 0iwq foo bar troll", "Same as above, but considered as a union (all fields at offset 0)",
	"pf.", "obj xxdz prev next size name", "Define the obj format as xxdz",
	"pf.", "plop ? (troll)mystruct", "Use structure troll previously defined",
	"pfj.", "plop @ 0x14", "Apply format object at the given offset",
	"pf", " 10xiz pointer length string", "Print a size 10 array of the xiz struct with its field names",
	"pf", " 5sqw string quad word", "Print an array with sqw struct along with its field names",
	"pf", " {integer}? (bifc)", "Print integer times the following format (bifc)",
	"pf", " [4]w[7]i", "Print an array of 4 words and then an array of 7 integers",
	"pf", " ic...?i foo bar \"(pf xw yo foo)troll\" yo", "Print nested anonymous structures",
	"pf", " ;..x", "Print value located 6 bytes from current offset",
	"pf", " [10]z[3]i[10]Zb", "Print an fixed size str, widechar, and var",
	"pfj", " +F @ 0x14", "Print the content at given offset with flag",
	"pf", " n2", "print signed short (2 bytes) value. Use N instead of n for printing unsigned values",
	"pf", " [2]? (plop)structname @ 0", "Prints an array of structs",
	"pf", " eqew bigWord beef", "Swap endianness and print with given labels",
	"pf", ".foo rr (eax)reg1 (eip)reg2", "Create object referencing to register values ",
	"pf", " tt troll plop", "print time stamps with labels troll and plop",
	NULL
};

static const char *help_msg_px[] = {
	"Usage:", "px[0afoswqWqQ][f]", " # Print heXadecimal",
	"px", "", "show hexdump",
	"px/", "", "same as x/ in gdb (help x)",
	"px0", "", "8bit hexpair list of bytes until zero byte",
	"pxa", "", "show annotated hexdump",
	"pxA", "[?]", "show op analysis color map",
	"pxb", "", "dump bits in hexdump form", // should be px1?
	"pxc", "", "show hexdump with comments",
	"pxd", "[?1248]", "signed integer dump (1 byte, 2 and 4)",
	"pxe", "", "emoji hexdump! :)",
	"pxf", "", "show hexdump of current function",
	"pxh", "", "show hexadecimal half-words dump (16bit)",
	"pxH", "", "same as above, but one per line",
	"pxi", "", "HexII compact binary representation",
	"pxl", "", "display N lines (rows) of hexdump",
	"pxo", "", "show octal dump",
	"pxq", "", "show hexadecimal quad-words dump (64bit)",
	"pxQ", "[q]", "same as above, but one per line",
	"pxr", "[1248][qj]", "show hexword references (q=quiet, j=json)",
	"pxs", "", "show hexadecimal in sparse mode",
	"pxt", "[*.] [origin]", "show delta pointer table in rizin commands",
	"pxw", "", "show hexadecimal words dump (32bit)",
	"pxW", "[q]", "same as above, but one per line (q=quiet)",
	"pxx", "", "show N bytes of hex-less hexdump",
	"pxX", "", "show N words of hex-less hexdump",
	NULL
};

const char *help_msg_pxA[] = {
	"Usage: pxA [len]", "", "show op analysis color map",
	"$$", "", "int/swi/trap/new\n",
	"+-*/", "", "math ops\n",
	"->", "", "push\n",
	"..", "", "nop\n",
	"<-", "", "pop\n",
	"<<>>", "", "shift ops\n",
	"==", "", "cmp/test\n",
	"XX", "", "invalid\n",
	"_C", "", "call\n",
	"_J", "", "jump\n",
	"_R", "", "ret\n",
	"cJ", "", "conditional jump\n",
	"io", "", "in/out ops\n",
	"mv", "", "move,lea,li\n",
	"|&^", "", "bin ops\n",
	NULL
};

static const ut32 colormap[256] = {
	0x000000,
	0x560000,
	0x640000,
	0x750000,
	0x870000,
	0x9b0000,
	0xb00000,
	0xc60000,
	0xdd0000,
	0xf50000,
	0xff0f0f,
	0xff2828,
	0xff4343,
	0xff5e5e,
	0xff7979,
	0xfe9595,
	0x4c1600,
	0x561900,
	0x641e00,
	0x752300,
	0x872800,
	0x9b2e00,
	0xb03400,
	0xc63b00,
	0xdd4200,
	0xf54900,
	0xff570f,
	0xff6928,
	0xff7b43,
	0xff8e5e,
	0xffa179,
	0xfeb595,
	0x4c3900,
	0x564000,
	0x644b00,
	0x755700,
	0x876500,
	0x9b7400,
	0xb08400,
	0xc69400,
	0xdda600,
	0xf5b800,
	0xffc30f,
	0xffc928,
	0xffd043,
	0xffd65e,
	0xffdd79,
	0xfee495,
	0x4c4c00,
	0x565600,
	0x646400,
	0x757500,
	0x878700,
	0x9b9b00,
	0xb0b000,
	0xc6c600,
	0xdddd00,
	0xf5f500,
	0xffff0f,
	0xffff28,
	0xffff43,
	0xffff5e,
	0xffff79,
	0xfffe95,
	0x324c00,
	0x395600,
	0x426400,
	0x4e7500,
	0x5a8700,
	0x679b00,
	0x75b000,
	0x84c600,
	0x93dd00,
	0xa3f500,
	0xafff0f,
	0xb7ff28,
	0xc0ff43,
	0xc9ff5e,
	0xd2ff79,
	0xdbfe95,
	0x1f4c00,
	0x235600,
	0x296400,
	0x307500,
	0x388700,
	0x409b00,
	0x49b000,
	0x52c600,
	0x5cdd00,
	0x66f500,
	0x73ff0f,
	0x82ff28,
	0x91ff43,
	0xa1ff5e,
	0xb1ff79,
	0xc1fe95,
	0x004c00,
	0x005600,
	0x006400,
	0x007500,
	0x008700,
	0x009b00,
	0x00b000,
	0x00c600,
	0x00dd00,
	0x00f500,
	0x0fff0f,
	0x28ff28,
	0x43ff43,
	0x5eff5e,
	0x79ff79,
	0x95fe95,
	0x004c19,
	0x00561c,
	0x006421,
	0x007527,
	0x00872d,
	0x009b33,
	0x00b03a,
	0x00c642,
	0x00dd49,
	0x00f551,
	0x0fff5f,
	0x28ff70,
	0x43ff81,
	0x5eff93,
	0x79ffa6,
	0x95feb8,
	0x004c4c,
	0x005656,
	0x006464,
	0x007575,
	0x008787,
	0x009b9b,
	0x00b0b0,
	0x00c6c6,
	0x00dddd,
	0x00f5f5,
	0x0ffffe,
	0x28fffe,
	0x43fffe,
	0x5efffe,
	0x79ffff,
	0x95fffe,
	0x00394c,
	0x004056,
	0x004b64,
	0x005775,
	0x006587,
	0x00749b,
	0x0084b0,
	0x0094c6,
	0x00a6dd,
	0x00b8f5,
	0x0fc3ff,
	0x28c9ff,
	0x43d0ff,
	0x5ed6ff,
	0x79ddff,
	0x95e4fe,
	0x00264c,
	0x002b56,
	0x003264,
	0x003a75,
	0x004387,
	0x004d9b,
	0x0058b0,
	0x0063c6,
	0x006edd,
	0x007af5,
	0x0f87ff,
	0x2893ff,
	0x43a1ff,
	0x5eaeff,
	0x79bcff,
	0x95cafe,
	0x00134c,
	0x001556,
	0x001964,
	0x001d75,
	0x002187,
	0x00269b,
	0x002cb0,
	0x0031c6,
	0x0037dd,
	0x003df5,
	0x0f4bff,
	0x285eff,
	0x4372ff,
	0x5e86ff,
	0x799aff,
	0x95b0fe,
	0x19004c,
	0x1c0056,
	0x210064,
	0x270075,
	0x2d0087,
	0x33009b,
	0x3a00b0,
	0x4200c6,
	0x4900dd,
	0x5100f5,
	0x5f0fff,
	0x7028ff,
	0x8143ff,
	0x935eff,
	0xa679ff,
	0xb895fe,
	0x33004c,
	0x390056,
	0x420064,
	0x4e0075,
	0x5a0087,
	0x67009b,
	0x7500b0,
	0x8400c6,
	0x9300dd,
	0xa300f5,
	0xaf0fff,
	0xb728ff,
	0xc043ff,
	0xc95eff,
	0xd279ff,
	0xdb95fe,
	0x4c004c,
	0x560056,
	0x640064,
	0x750075,
	0x870087,
	0x9b009b,
	0xb000b0,
	0xc600c6,
	0xdd00dd,
	0xf500f5,
	0xfe0fff,
	0xfe28ff,
	0xfe43ff,
	0xfe5eff,
	0xfe79ff,
	0xfe95fe,
	0x4c0032,
	0x560039,
	0x640042,
	0x75004e,
	0x87005a,
	0x9b0067,
	0xb00075,
	0xc60084,
	0xdd0093,
	0xf500a3,
	0xff0faf,
	0xff28b7,
	0xff43c0,
	0xff5ec9,
	0xff79d2,
	0xffffff,
};

static void colordump(RzCore *core, const ut8 *block, int len) {
	const char *chars = " .,:;!O@#";
	bool square = rz_config_get_i(core->config, "scr.square");
	int i, j;
	char ch, ch2, *color;
	int cols = rz_config_get_i(core->config, "hex.cols");
	bool show_color = rz_config_get_i(core->config, "scr.color");
	bool show_flags = rz_config_get_i(core->config, "asm.flags");
	bool show_section = rz_config_get_i(core->config, "hex.section");
	bool show_offset = rz_config_get_i(core->config, "hex.offset");
	bool show_cursor = core->print->cur_enabled;
	bool show_unalloc = core->print->flags & RZ_PRINT_FLAGS_UNALLOC;
	if (cols < 1 || cols > 0xfffff) {
		cols = 32;
	}
	for (i = 0; i < len; i += cols) {
		if (show_section) {
			const char *name = rz_core_get_section_name(core, core->offset + i);
			rz_cons_printf("%20s ", name ? name : "");
		}
		if (show_offset) {
			rz_print_addr(core->print, core->offset + i);
		}
		for (j = i; j < i + cols; j++) {
			if (j >= len) {
				break;
			}
			if (show_color) {
				ut32 color_val = colormap[block[j]];
				// Brightness weights are based on
				// https://twitter.com/DanHollick/status/1417895189239123968
				// (normalized to red). I'm aware that max
				// brightness is greater than 255 * 3.
				int brightness = ((color_val & 0xff0000) >> 16) + 2 * ((color_val & 0xff00) >> 8) + (color_val & 0xff) / 3;
				char *str = rz_str_newf("rgb:%s rgb:%06x",
					brightness <= 0x7f * 3 ? "fff" : "000", color_val);
				color = rz_cons_pal_parse(str, NULL);
				free(str);
				if (show_cursor && core->print->cur == j) {
					ch = '_';
				} else {
					ch = ' ';
				}
			} else {
				color = strdup("");
				if (show_cursor && core->print->cur == j) {
					ch = '_';
				} else {
					const int idx = ((float)block[j] / 255) * (strlen(chars) - 1);
					ch = chars[idx];
				}
			}
			if (show_unalloc &&
				!core->print->iob.is_valid_offset(core->print->iob.io, core->offset + j, false)) {
				ch = core->print->io_unalloc_ch;
				if (show_color) {
					free(color);
					color = strdup(Color_RESET);
					if (ch == ' ') {
						ch = '.';
					}
				} else {
					ch = strchr(chars, ch) ? '?' : ch;
				}
			}
			if (square) {
				if (show_flags) {
					RzFlagItem *fi = rz_flag_get_i(core->flags, core->offset + j);
					if (fi) {
						if (fi->name[1]) {
							ch = fi->name[0];
							ch2 = fi->name[1];
						} else {
							ch = ' ';
							ch2 = fi->name[0];
						}
					} else {
						ch2 = ch;
					}
				} else {
					ch2 = ch;
				}
				rz_cons_printf("%s%c%c", color, ch, ch2);
			} else {
				rz_cons_printf("%s%c", color, ch);
			}
			free(color);
		}
		if (show_color) {
			rz_cons_printf(Color_RESET);
		}
		rz_cons_newline();
	}
}

static void findMethodBounds(RzList /*<RzBinSymbol *>*/ *methods, ut64 *min, ut64 *max) {
	RzBinSymbol *sym;
	RzListIter *iter;
	ut64 at_min = UT64_MAX;
	ut64 at_max = 0LL;

	rz_list_foreach (methods, iter, sym) {
		if (sym->vaddr) {
			if (sym->vaddr < at_min) {
				at_min = sym->vaddr;
			}
			if (sym->vaddr + sym->size > at_max) {
				at_max = sym->vaddr + sym->size;
			}
		}
	}
	*min = at_min;
	*max = at_max;
}

static ut64 findClassBounds(RzCore *core, int *len) {
	ut64 min = 0, max = 0;
	RzListIter *iter;
	RzBinClass *c;
	RzList *cs = rz_bin_get_classes(core->bin);
	rz_list_foreach (cs, iter, c) {
		if (!c || !c->name || !c->name[0]) {
			continue;
		}
		findMethodBounds(c->methods, &min, &max);
		if (len) {
			*len = (max - min);
		}
		return min;
	}
	return 0;
}

RZ_API void rz_core_set_asm_configs(RzCore *core, char *arch, ut32 bits, int segoff) {
	rz_config_set(core->config, "asm.arch", arch);
	rz_config_set_i(core->config, "asm.bits", bits);
	// XXX - this needs to be done here, because
	// if arch == x86 and bits == 16, segoff automatically changes
	rz_config_set_i(core->config, "asm.segoff", segoff);
}

static void print_format_help_help_help_help(RzCore *core) {
	const char *help_msg[] = {
		"    STAHP IT!!!", "", "",
		NULL
	};
	rz_core_cmd_help(core, help_msg);
}

/**
 * \brief Frees a visual print gadget
 *
 * \param g reference to RzCoreGadget
 */
RZ_API void rz_core_gadget_free(RzCoreGadget *g) {
	free(g->cmd);
	free(g);
}

/**
 * \brief Prints or displays the print gadgets while in
 * visual mode
 *
 * \param core reference to RzCore
 */
RZ_API void rz_core_gadget_print(RzCore *core) {
	RzCoreGadget *g;
	RzListIter *iter;
	rz_list_foreach (core->gadgets, iter, g) {
		char *res = rz_core_cmd_str(core, g->cmd);
		if (res) {
			rz_cons_strcat_at(res, g->x, g->y, g->w, g->h);
			free(res);
		}
	}
}

static const char *help_msg_pg[] = {
	"Usage: pg[-]", "[asm|hex]", "print (dis)assembled",
	"pg", " [x y w h cmd]", "add a new gadget",
	"pg", "", "print them all",
	"pg", "*", "print the gadgets as rizin commands",
	"pg-", "*", "remove all the gadgets",
	NULL
};

RZ_IPI RzCmdStatus rz_cmd_print_gadget_print_as_rizin_handler(RzCore *core, int argc, const char **argv) {
	RzCoreGadget *g;
	RzListIter *iter;
	rz_list_foreach (core->gadgets, iter, g) {
		rz_cons_printf("\"pg %d %d %d %d %s\"\n", g->x, g->y, g->w, g->h, g->cmd);
	}
	return RZ_CMD_STATUS_OK;
}
RZ_IPI RzCmdStatus rz_cmd_print_gadget_remove_handler(RzCore *core, int argc, const char **argv) {
	rz_list_free(core->gadgets);
	core->gadgets = rz_list_newf((RzListFree)rz_core_gadget_free);
	return RZ_CMD_STATUS_OK;
}
RZ_IPI RzCmdStatus rz_cmd_print_gadget_move_handler(RzCore *core, int argc, const char **argv) {
	int n = rz_num_math(core->num, argv[1]);
	int x = rz_num_math(core->num, argv[2]);
	int y = rz_num_math(core->num, argv[3]);
	int w = rz_num_math(core->num, argv[4]);
	int h = rz_num_math(core->num, argv[5]);
	RzCoreGadget *g = rz_list_get_n(core->gadgets, n);
	if (x && y && w && h) {
		g->x = x;
		g->y = y;
		g->w = w;
		g->h = h;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_print_gadget_add_handler(RzCore *core, int argc, const char **argv) {
	char *cmd = NULL;
	if (argc == 1) {
		rz_core_gadget_print(core);
	} else {
		int x = argc > 2 ? rz_num_math(core->num, argv[1]) : 1;
		int y = argc > 3 ? rz_num_math(core->num, argv[2]) : 1;
		int w = argc > 4 ? rz_num_math(core->num, argv[3]) : 1;
		int h = argc > 5 ? rz_num_math(core->num, argv[4]) : 1;
		if (x && y && w && h) {
			cmd = rz_str_dup(cmd, argv[argc - 1]);
			if (cmd) {
				RzCoreGadget *g = RZ_NEW0(RzCoreGadget);
				g->x = x;
				g->y = y;
				g->w = w;
				g->h = h;
				g->cmd = cmd;
				rz_list_append(core->gadgets, g);
			}
		}
	}
	return RZ_CMD_STATUS_OK;
}

static void cmd_print_gadget(RzCore *core, const char *_input) {
	if (*_input == '?') { // "pg?"
		rz_core_cmd_help(core, help_msg_pg);
		return;
	}
	if (*_input == '-') { // "pg-"
		// TODO support selecting one
		rz_list_free(core->gadgets);
		core->gadgets = rz_list_newf((RzListFree)rz_core_gadget_free);
	} else if (*_input == '*') { // "pg*"
		RzCoreGadget *g;
		RzListIter *iter;
		rz_list_foreach (core->gadgets, iter, g) {
			rz_cons_printf("\"pg %d %d %d %d %s\"\n", g->x, g->y, g->w, g->h, g->cmd);
		}
	} else if (*_input == 'b') { // "pgb"
		RZ_LOG_WARN("core: change gadget background color has not been implemented\n");
	} else if (*_input == 'm') { // "pgm"
		int nth = atoi(_input + 1);
		RzCoreGadget *g = rz_list_get_n(core->gadgets, nth);
		if (g) {
			char *input = strdup(_input);
			char *space = strchr(input, ' ');
			if (space) {
				space++;
			} else {
				space = "";
			}
			RzList *args = rz_str_split_list(space, " ", 0);
			char *x = rz_list_pop_head(args);
			char *y = rz_list_pop_head(args);
			char *w = rz_list_pop_head(args);
			char *h = rz_list_pop_head(args);
			if (x && y && w && h) {
				g->x = rz_num_math(core->num, x);
				g->y = rz_num_math(core->num, y);
				g->w = rz_num_math(core->num, w);
				g->h = rz_num_math(core->num, h);
			}
			rz_list_free(args);
			free(input);
		}
	} else if (*_input == ' ') { // "pg "
		char *input = strdup(_input);
		RzList *args = rz_str_split_list(input, " ", 0);
		char *x = rz_list_pop_head(args);
		char *y = rz_list_pop_head(args);
		char *w = rz_list_pop_head(args);
		char *h = rz_list_pop_head(args);
		if (x && y && w && h) {
			int X = rz_num_math(core->num, x);
			int Y = rz_num_math(core->num, y);
			int W = rz_num_math(core->num, w);
			int H = rz_num_math(core->num, h);
			char *cmd = rz_str_list_join(args, " ");
			if (cmd) {
				//		eprintf ("%d %d %d %d (%s)\n", X, Y, W, H, cmd);
				RzCoreGadget *g = RZ_NEW0(RzCoreGadget);
				g->x = X;
				g->y = Y;
				g->w = W;
				g->h = H;
				g->cmd = cmd;
				rz_list_append(core->gadgets, g);
			}
		}
		rz_list_free(args);
		free(input);
	} else if (!*_input) { // "pg"
		rz_core_gadget_print(core);
	} else {
		rz_core_cmd_help(core, help_msg_pg);
	}
}

RZ_IPI RzCmdStatus rz_cmd_print_timestamp_unix_handler(RzCore *core, int argc, const char **argv) {
	char *date = NULL;
	const ut8 *block = core->block;
	ut32 len = core->blocksize;
	bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");
	int timezone = (int)rz_config_get_i(core->config, "time.zone");
	if (len < sizeof(ut32)) {
		RZ_LOG_ERROR("The block size is less than 4.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	for (ut64 i = 0; i < len; i += sizeof(ut32)) {
		ut32 dt = rz_read_ble32(block + i, big_endian);
		// add timezone
		dt += timezone * (60 * 60);
		date = rz_time_date_unix_to_string(dt);
		rz_cons_printf("%s\n", date);
		free(date);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_print_timestamp_current_handler(RzCore *core, int argc, const char **argv) {
	char *now = rz_time_date_now_to_string();
	rz_cons_printf("%s\n", now);
	free(now);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_print_timestamp_dos_handler(RzCore *core, int argc, const char **argv) {
	char *date = NULL;
	const ut8 *block = core->block;
	ut32 len = core->blocksize;
	if (len < sizeof(ut32)) {
		RZ_LOG_ERROR("The block size is less than 4.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	for (ut64 i = 0; i < len; i += sizeof(ut32)) {
		ut32 dt = rz_read_le32(block + i);
		date = rz_time_date_dos_to_string(dt);
		rz_cons_printf("%s\n", date);
		free(date);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_print_timestamp_hfs_handler(RzCore *core, int argc, const char **argv) {
	char *date = NULL;
	const ut8 *block = core->block;
	ut32 len = core->blocksize;
	bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");
	int timezone = (int)rz_config_get_i(core->config, "time.zone");
	if (len < sizeof(ut32)) {
		RZ_LOG_ERROR("The block size is less than 4.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	for (ut64 i = 0; i < len; i += sizeof(ut32)) {
		ut32 dt = rz_read_ble32(block + i, big_endian);
		// add timezone
		dt += timezone * (60 * 60);
		date = rz_time_date_hfs_to_string(dt);
		rz_cons_printf("%s\n", date);
		free(date);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_print_timestamp_ntfs_handler(RzCore *core, int argc, const char **argv) {
	char *date = NULL;
	const ut8 *block = core->block;
	ut32 len = core->blocksize;
	bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");
	if (len < sizeof(ut64)) {
		RZ_LOG_ERROR("The block size is less than 8.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	for (ut64 i = 0; i < len; i += sizeof(ut64)) {
		ut64 dt = rz_read_ble64(block + i, big_endian);
		date = rz_time_date_w32_to_string(dt);
		rz_cons_printf("%s\n", date);
		free(date);
	}
	return RZ_CMD_STATUS_OK;
}

static void cmd_print_format(RzCore *core, const char *_input, const ut8 *block, int len) {
	char *input = NULL;
	int mode = RZ_PRINT_MUSTSEE;
	switch (_input[1]) {
	case '*': // "pf*"
		_input++;
		mode = RZ_PRINT_SEEFLAGS;
		break;
	case 'q': // "pfq"
		_input++;
		mode = RZ_PRINT_QUIET | RZ_PRINT_MUSTSEE;
		break;
	case 'd': // "pfd"
		_input++;
		mode = RZ_PRINT_DOT;
		break;
	case 'j': // "pfj"
		_input++;
		mode = RZ_PRINT_JSON;
		break;
	case 'v': // "pfv"
		_input++;
		mode = RZ_PRINT_VALUE | RZ_PRINT_MUSTSEE;
		break;
	case 'c': // "pfc"
		_input++;
		mode = RZ_PRINT_STRUCT;
		break;
	case 's': { // "pfs"
		const char *val = NULL;
		_input += 2;
		if (*_input == '.') {
			_input++;
			val = rz_type_db_format_get(core->analysis->typedb, _input);
			if (val) {
				rz_cons_printf("%d\n", rz_type_format_struct_size(core->analysis->typedb, val, mode, 0));
			} else {
				RZ_LOG_ERROR("core: Struct %s not defined\nUsage: pfs.struct_name | pfs format\n", _input);
			}
		} else if (*_input == ' ') {
			while (*_input == ' ' && *_input != '\0') {
				_input++;
			}
			if (*_input) {
				rz_cons_printf("%d\n", rz_type_format_struct_size(core->analysis->typedb, _input, mode, 0));
			} else {
				RZ_LOG_ERROR("core: Struct %s not defined\nUsage: pfs.struct_name | pfs format\n", _input);
			}
		} else {
			RZ_LOG_ERROR("core: Usage: pfs.struct_name | pfs format\n");
		}
		return;
	}
	case '?': // "pf?"
		_input += 2;
		if (*_input) {
			if (*_input == '?') {
				_input++;
				if (_input && *_input == '?') {
					_input++;
					if (_input && *_input == '?') {
						print_format_help_help_help_help(core);
					} else {
						rz_core_cmd_help(core, help_detail2_pf);
					}
				} else {
					rz_core_cmd_help(core, help_detail_pf);
				}
			} else {
				const char *struct_name = rz_str_trim_head_ro(_input);
				const char *val = rz_type_db_format_get(core->analysis->typedb, struct_name);
				if (val) {
					rz_cons_printf("%s\n", val);
				} else {
					RZ_LOG_ERROR("core: Struct %s is not defined\n", _input);
				}
			}
		} else {
			rz_core_cmd_help(core, help_msg_pf);
		}
		return;
	case 'o': // "pfo"
		if (_input[2] == '?') {
			char *prefix = rz_path_prefix(NULL);
			char *sdb_format = rz_path_home_prefix(RZ_SDB_FORMAT);
			eprintf("|Usage: pfo [format-file]\n"
				" %s\n"
				" " RZ_JOIN_3_PATHS("%s", RZ_SDB_FORMAT, "") "\n",
				sdb_format, prefix);
			free(sdb_format);
			free(prefix);
		} else if (_input[2] == ' ') {
			const char *fname = rz_str_trim_head_ro(_input + 3);
			char *home_formats = rz_path_home_prefix(RZ_SDB_FORMAT);
			char *home = rz_file_path_join(home_formats, fname);
			free(home_formats);
			char *system_formats = rz_path_system(RZ_SDB_FORMAT);
			char *path = rz_file_path_join(system_formats, fname);
			free(system_formats);
			if (rz_str_endswith(_input, ".h")) {
				char *error_msg = NULL;
				const char *dir = rz_config_get(core->config, "dir.types");
				int result = rz_type_parse_file(core->analysis->typedb, path, dir, &error_msg);
				if (!result) {
					rz_core_cmd0(core, ".ts*");
				} else {
					RZ_LOG_ERROR("core: Parse error: %s\n", error_msg);
					free(error_msg);
				}
			} else {
				if (!rz_core_cmd_file(core, home) && !rz_core_cmd_file(core, path)) {
					if (!rz_core_cmd_file(core, _input + 3)) {
						RZ_LOG_ERROR("core: pfo: cannot open format file at '%s'\n", path);
					}
				}
			}
			free(home);
			free(path);
		} else {
			RzList *files;
			RzListIter *iter;
			const char *fn;
			char *home = rz_path_home_prefix(RZ_SDB_FORMAT);
			if (home) {
				files = rz_sys_dir(home);
				rz_list_foreach (files, iter, fn) {
					if (*fn && *fn != '.') {
						rz_cons_println(fn);
					}
				}
				rz_list_free(files);
				free(home);
			}
			char *path = rz_path_system(RZ_SDB_FORMAT);
			if (path) {
				files = rz_sys_dir(path);
				rz_list_foreach (files, iter, fn) {
					if (*fn && *fn != '.') {
						rz_cons_println(fn);
					}
				}
				rz_list_free(files);
				free(path);
			}
		}
		free(input);
		return;
	} // switch

	input = strdup(_input);
	/* syntax aliasing bridge for 'pf foo=xxd' -> 'pf.foo xxd' */
	if (input[1] == ' ') {
		char *eq = strchr(input + 2, '=');
		if (eq) {
			input[1] = '.';
			*eq = ' ';
		}
	}

	bool listFormats = false;
	if (input[1] == '.') {
		listFormats = true;
	} else if (!strcmp(input, "*") && mode == RZ_PRINT_SEEFLAGS) {
		listFormats = true;
	}

	core->print->reg = rz_core_reg_default(core);
	core->print->get_register = rz_reg_get;
	core->print->get_register_value = rz_reg_get_value;

	int o_blocksize = core->blocksize;

	if (listFormats) {
		core->print->num = core->num;
		/* print all stored format */
		if (!input[1] || !input[2]) { // "pf."
			RzListIter *iter;
			char *fmt = NULL;
			RzList *fmtl = rz_type_db_format_all(core->analysis->typedb);
			rz_list_foreach (fmtl, iter, fmt) {
				rz_cons_printf("pf.%s\n", fmt);
			}
			rz_list_free(fmtl);
			/* delete a format */
		} else if (input[1] && input[2] == '-') { // "pf-"
			if (input[3] == '*') { // "pf-*"
				rz_type_db_format_purge(core->analysis->typedb);
			} else { // "pf-xxx"
				rz_type_db_format_delete(core->analysis->typedb, input + 3);
			}
		} else {
			char *name = strdup(input + (input[1] ? 2 : 1));
			char *space = strchr(name, ' ');
			char *eq = strchr(name, '=');
			char *dot = strchr(name, '.');

			if (eq && !dot) {
				*eq = ' ';
				space = eq;
				eq = NULL;
			}

			/* store a new format */
			if (space && (!eq || space < eq)) {
				*space++ = 0;
				if (strchr(name, '.')) {
					RZ_LOG_ERROR("core: Struct or fields name can not contain dot symbol (.)\n");
				} else {
					// pf.foo=xxx
					rz_type_db_format_set(core->analysis->typedb, name, space);
				}
				free(name);
				free(input);
				return;
			}

			if (!strchr(name, '.') &&
				!rz_type_db_format_get(core->analysis->typedb, name)) {
				RZ_LOG_ERROR("core: Cannot find '%s' format.\n", name);
				free(name);
				free(input);
				return;
			}

			char *delim = strchr(name, '.');
			if (delim) {
				int len = delim - name;
				if (len > 0) {
					name[len] = '\0';
				}
			}

			/* Load format from name into fmt to get the size */
			/* This make sure the whole structure will be printed */
			const char *fmt = NULL;
			fmt = rz_type_db_format_get(core->analysis->typedb, name);
			if (fmt) {
				int size = rz_type_format_struct_size(core->analysis->typedb, fmt, mode, 0) + 10;
				if (size > core->blocksize) {
					rz_core_block_size(core, size);
				}
			}
			/* display a format */
			if (dot) {
				*dot++ = 0;
				eq = strchr(dot, '=');
				if (eq) { // Write mode (pf.field=value)
					*eq++ = 0;
					mode = RZ_PRINT_MUSTSET;
					char *format = rz_type_format_data(core->analysis->typedb, core->print, core->offset,
						core->block, core->blocksize, name, mode, eq, dot);
					if (format) {
						rz_cons_print(format);
						free(format);
					}
				} else {
					char *format = rz_type_format_data(core->analysis->typedb, core->print, core->offset,
						core->block, core->blocksize, name, mode, NULL, dot);
					if (format) {
						rz_cons_print(format);
						free(format);
					}
				}
			} else {
				char *format = rz_type_format_data(core->analysis->typedb, core->print, core->offset,
					core->block, core->blocksize, name, mode, NULL, NULL);
				if (format) {
					rz_cons_print(format);
					free(format);
				}
			}
			free(name);
		}
	} else {
		/* This make sure the structure will be printed entirely */
		const char *fmt = rz_str_trim_head_ro(input + 1);
		int struct_sz = rz_type_format_struct_size(core->analysis->typedb, fmt, mode, 0);
		size_t size = RZ_MAX(core->blocksize, struct_sz);
		ut8 *buf = calloc(1, size);
		if (!buf) {
			RZ_LOG_ERROR("core: cannot allocate %zu byte(s)\n", size);
			goto stage_left;
		}
		memcpy(buf, core->block, core->blocksize);
		/* check if fmt is '\d+ \d+<...>', common mistake due to usage string*/
		bool syntax_ok = true;
		char *args = strdup(fmt);
		if (!args) {
			RZ_LOG_ERROR("core: Mem Allocation.");
			free(args);
			free(buf);
			goto stage_left;
		}
		const char *arg1 = strtok(args, " ");
		if (arg1 && rz_str_isnumber(arg1)) {
			syntax_ok = false;
			RZ_LOG_ERROR("core: Usage: pf [0|cnt][format-string]\n");
		}
		free(args);
		if (syntax_ok) {
			char *format = rz_type_format_data(core->analysis->typedb, core->print, core->offset,
				buf, size, fmt, mode, NULL, NULL);
			if (format) {
				rz_cons_print(format);
				free(format);
			}
		}
		free(buf);
	}
stage_left:
	free(input);
	rz_core_block_size(core, o_blocksize);
}

// > pxa
/* In this function, most of the buffers have 4 times
 * the required length. This is because we supports colours,
 * that are 4 chars long. */
#define append(x, y) \
	{ \
		strcat(x, y); \
		x += strlen(y); \
	}

#define Pal(x, y) (x->cons && x->cons->context->pal.y) ? x->cons->context->pal.y

static void annotated_hexdump(RzCore *core, int len) {
	if (!len) {
		return;
	}
	const int usecolor = rz_config_get_i(core->config, "scr.color");
	int nb_cols = rz_config_get_i(core->config, "hex.cols");
	core->print->use_comments = rz_config_get_i(core->config, "hex.comments");
	int flagsz = rz_config_get_i(core->config, "hex.flagsz");
	bool showSection = rz_config_get_i(core->config, "hex.section");
	const ut8 *buf = core->block;
	ut64 addr = core->offset;
	int color_idx = 0;
	char *bytes, *chars;
	char *ebytes, *echars; // They'll walk over the vars above
	ut64 fend = UT64_MAX;
	int i, j, low, max, here, rows;
	bool marks = false, setcolor = true, hascolor = false;
	ut8 ch = 0;
	char *colors[10] = { NULL };
	for (i = 0; i < 10; i++) {
		colors[i] = rz_cons_rainbow_get(i, 10, false);
	}
	const int col = core->print->col;
	RzFlagItem *flag, *current_flag = NULL;
	char **note;
	int html = rz_config_get_i(core->config, "scr.html");
	int nb_cons_cols;
	bool compact = false;

	if (core->print) {
		compact = core->print->flags & RZ_PRINT_FLAGS_COMPACT;
	}
	char *format = compact ? " %X %X" : " %X %X ";
	int step = compact ? 4 : 5;

	// Adjust the number of columns
	if (nb_cols < 1) {
		nb_cols = 16;
	}
	nb_cols -= (nb_cols % 2); // nb_cols should be even
	if (nb_cols < 1) {
		return;
	}

	nb_cons_cols = 12 + nb_cols * 2 + (nb_cols / 2);
	nb_cons_cols += 17;
	rows = len / nb_cols;

	chars = calloc(nb_cols * 40, sizeof(char));
	if (!chars)
		goto err_chars;
	note = calloc(nb_cols, sizeof(char *));
	if (!note)
		goto err_note;
	bytes = calloc(nb_cons_cols * 40, sizeof(char));
	if (!bytes)
		goto err_bytes;
#if 1
	int addrpadlen = strlen(sdb_fmt("%08" PFMT64x, addr)) - 8;
	char addrpad[32];
	if (addrpadlen > 0) {
		memset(addrpad, ' ', addrpadlen);
		addrpad[addrpadlen] = 0;
		// Compute, then show the legend
		strcpy(bytes, addrpad);
	} else {
		*addrpad = 0;
		addrpadlen = 0;
	}
	strcpy(bytes + addrpadlen, "- offset -  ");
#endif
	j = strlen(bytes);
	for (i = 0; i < nb_cols; i += 2) {
		sprintf(bytes + j, format, (i & 0xf), (i + 1) & 0xf);
		j += step;
	}
	j--;
	strcpy(bytes + j, "     ");
	j += 2;
	for (i = 0; i < nb_cols; i++) {
		sprintf(bytes + j + i, "%0X", i % 17);
	}
	if (usecolor) {
		const char *color_title = Pal(core, offset)
		    : Color_MAGENTA;
		rz_cons_strcat(color_title);
		rz_cons_strcat(bytes);
		rz_cons_strcat(Color_RESET);
	} else {
		rz_cons_strcat(bytes);
	}
	rz_cons_newline();

	// hexdump
	for (i = 0; i < rows; i++) {
		bytes[0] = '\0';
		chars[0] = '\0';
		ebytes = bytes;
		echars = chars;
		hascolor = false;
		ut64 ea = addr;
		if (core->print->pava) {
			ut64 va = rz_io_p2v(core->io, addr);
			if (va != UT64_MAX) {
				ea = va;
			}
		}

		if (usecolor) {
			append(ebytes, core->cons->context->pal.offset);
		}
		if (showSection) {
			const char *name = rz_core_get_section_name(core, ea);
			char *s = rz_str_newf("%20s ", name);
			append(ebytes, s);
			free(s);
		}
		ebytes += sprintf(ebytes, "0x%08" PFMT64x, ea);
		if (usecolor) {
			append(ebytes, Color_RESET);
		}
		append(ebytes, (col == 1) ? " |" : "  ");
		bool hadflag = false;
		for (j = 0; j < nb_cols; j++) {
			setcolor = true;
			RZ_FREE(note[j]);

			// TODO: in pava mode we should read addr or ea? // imho ea. but wat about hdrs and such
			RzIntervalNode *meta_node = rz_meta_get_in(core->analysis, ea + j, RZ_META_TYPE_FORMAT);
			RzAnalysisMetaItem *meta = meta_node ? meta_node->data : NULL;
			if (meta && meta->type == RZ_META_TYPE_FORMAT && meta_node->start == addr + j) {
				rz_cons_printf(".format %s ; size=", meta->str);
				rz_core_cmdf(core, "pfs %s", meta->str);
				rz_core_cmdf(core, "pf %s @ 0x%08" PFMT64x, meta->str, meta_node->start);
				if (usecolor) {
					append(ebytes, Color_INVERT);
					append(echars, Color_INVERT);
				}
				hadflag = true;
			}
			if (meta) {
				meta = NULL;
			}
			// collect comments
			const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, addr + j);
			if (comment) {
				note[j] = rz_str_newf(";%s", comment);
				marks = true;
			}

			// collect flags
			flag = rz_flag_get_i(core->flags, addr + j);
			if (flag) { // Beginning of a flag
				if (flagsz) {
					fend = addr + flagsz; // core->blocksize;
				} else {
					fend = addr + j + flag->size;
				}
				free(note[j]);
				note[j] = rz_str_prepend(strdup(flag->name), "/");
				marks = true;
				color_idx++;
				color_idx %= 10;
				current_flag = flag;
				if (showSection) {
					rz_cons_printf("%20s ", "");
				}
				if (flag->offset == addr + j) {
					if (usecolor) {
						append(ebytes, Color_INVERT);
						append(echars, Color_INVERT);
					}
					hadflag = true;
				}
			} else {
				// Are we past the current flag?
				if (current_flag && addr + j > (current_flag->offset + current_flag->size)) {
					setcolor = false;
					current_flag = NULL;
				}
				// Turn colour off if we're at the end of the current flag
				if (fend == UT64_MAX || fend <= addr + j) {
					setcolor = false;
				}
			}
			if (usecolor) {
				if (!setcolor) {
					const char *bytecolor = rz_print_byte_color(core->print, ch);
					if (bytecolor) {
						append(ebytes, bytecolor);
						append(echars, bytecolor);
						hascolor = true;
					}
				} else if (!hascolor) {
					hascolor = true;
					if (current_flag && current_flag->color) {
						char *ansicolor = rz_cons_pal_parse(current_flag->color, NULL);
						if (ansicolor) {
							append(ebytes, ansicolor);
							append(echars, ansicolor);
							free(ansicolor);
						}
					} else { // Use "random" colours
						append(ebytes, colors[color_idx]);
						append(echars, colors[color_idx]);
					}
				}
			}
			here = RZ_MIN((i * nb_cols) + j, core->blocksize);
			ch = buf[here];
			if (core->print->ocur != -1) {
				low = RZ_MIN(core->print->cur, core->print->ocur);
				max = RZ_MAX(core->print->cur, core->print->ocur);
			} else {
				low = max = core->print->cur;
			}
			if (core->print->cur_enabled) {
				if (low == max) {
					if (low == here) {
						if (html || !usecolor) {
							append(ebytes, "[");
							append(echars, "[");
						} else {
							append(echars, Color_INVERT);
							append(ebytes, Color_INVERT);
						}
					}
				} else {
					if (here >= low && here < max) {
						if (html || !usecolor) {
							append(ebytes, "[");
							append(echars, "[");
						} else {
							if (usecolor) {
								append(ebytes, Color_INVERT);
								append(echars, Color_INVERT);
							}
						}
					}
				}
			}
			sprintf(ebytes, "%02x", ch);
			// rz_print_byte (core->print, "%02x ", j, ch);
			ebytes += strlen(ebytes);
			if (hadflag) {
				if (usecolor) {
					append(ebytes, Color_INVERT_RESET);
					append(echars, Color_INVERT_RESET);
				}
				hadflag = false;
			}
			sprintf(echars, "%c", IS_PRINTABLE(ch) ? ch : '.');
			echars++;
			if (core->print->cur_enabled && max == here) {
				if (!html && usecolor) {
					append(ebytes, Color_RESET);
					append(echars, Color_RESET);
				}
				hascolor = false;
			}

			if (j < (nb_cols - 1) && (j % 2) && !compact) {
				append(ebytes, " ");
			}

			if (fend != UT64_MAX && fend == addr + j + 1) {
				if (!html && usecolor) {
					append(ebytes, Color_RESET);
					append(echars, Color_RESET);
				}
				fend = UT64_MAX;
				hascolor = false;
			}
		}
		if (!html && usecolor) {
			append(ebytes, Color_RESET);
			append(echars, Color_RESET);
		}
		append(ebytes, (col == 1) ? "| " : (col == 2) ? " |"
							      : "  ");
		if (col == 2) {
			append(echars, "|");
		}

		if (marks) { // show comments and flags
			int hasline = 0;
			int out_sz = nb_cons_cols + 20;
			char *out = calloc(out_sz, sizeof(char));
			memset(out, ' ', nb_cons_cols - 1);
			for (j = 0; j < nb_cols; j++) {
				if (note[j]) {
					int off = (j * 3) - (j / 2) + 13;
					int notej_len = strlen(note[j]);
					int sz = RZ_MIN(notej_len, nb_cons_cols - off);
					if (compact) {
						off -= (j / 2);
					} else {
						if (j % 2) {
							off--;
						}
					}
					memcpy(out + off, note[j], sz);
					if (sz < notej_len) {
						out[off + sz - 2] = '.';
						out[off + sz - 1] = '.';
					}
					hasline = (out[off] != ' ');
					RZ_FREE(note[j]);
				}
			}
			out[out_sz - 1] = 0;
			if (hasline) {
				rz_cons_strcat(addrpad);
				rz_cons_strcat(out);
				rz_cons_newline();
			}
			marks = false;
			free(out);
		}
		rz_cons_strcat(bytes);
		rz_cons_strcat(chars);

		if (core->print->use_comments) {
			for (j = 0; j < nb_cols; j++) {
				const char *comment = core->print->get_comments(core->print->user, addr + j);
				if (comment) {
					rz_cons_printf(" ; %s", comment);
				}
			}
		}

		rz_cons_newline();
		addr += nb_cols;
	}

	free(bytes);
err_bytes:
	free(note);
err_note:
	free(chars);
err_chars:
	for (i = 0; i < RZ_ARRAY_SIZE(colors); i++) {
		free(colors[i]);
	}
}

RZ_API void rz_core_print_examine(RzCore *core, const char *str) {
	char cmd[128], *p;
	ut64 addr = core->offset;
	int size = (core->analysis->bits / 4);
	int count = atoi(str);
	int i, n;
	if (count < 1) {
		count = 1;
	}
	// skipspaces
	while (*str >= '0' && *str <= '9') {
		str++;
	}
	// "px/" alone isn't a full command.
	if (!str[0]) {
		return;
	}
	switch (str[1]) {
	case 'b': size = 1; break;
	case 'h': size = 2; break;
	case 'd': size = 4; break;
	case 'w': size = 4; break;
	case 'g': size = 8; break;
	}
	if ((p = strchr(str, ' '))) {
		*p++ = 0;
		addr = rz_num_math(core->num, p);
	}
	switch (*str) {
	case '?':
		eprintf(
			"Format is x/[num][format][size]\n"
			"Num specifies the number of format elements to display\n"
			"Format letters are o(octal), x(hex), d(decimal), u(unsigned decimal),\n"
			"  t(binary), f(float), a(address), i(instruction), c(char) and s(string),\n"
			"  T(OSType), A(floating point values in hex).\n"
			"Size letters are b(byte), h(halfword), w(word), g(giant, 8 bytes).\n");
		break;
	case 's': // "x/s"
		rz_core_cmdf(core, "psb @! %d @ 0x%" PFMT64x, count * size, addr);
		break;
	case 'o': // "x/o"
		rz_core_cmdf(core, "pxo %d @ 0x%" PFMT64x, count * size, addr);
		break;
	case 'f':
	case 'A': // XXX (float in hex)
		n = 3;
		snprintf(cmd, sizeof(cmd), "pxo %d @ 0x%" PFMT64x,
			count * size, addr);
		strcpy(cmd, "pf ");
		for (i = 0; i < count && n < sizeof(cmd); i++) {
			cmd[n++] = 'f';
		}
		cmd[n] = 0;
		rz_core_cmd0(core, cmd);
		break;
	case 'x':
		switch (size) {
		default:
		case 1:
			rz_core_cmdf(core, "px %d @ 0x%" PFMT64x, count, addr);
			break;
		case 2:
			rz_core_cmdf(core, "px%c %d @ 0x%" PFMT64x,
				'h', count * 2, addr);
			break;
		case 4:
			rz_core_cmdf(core, "px%c %d @ 0x%" PFMT64x,
				'w', count * 4, addr);
			break;
		case 8:
			rz_core_cmdf(core, "px%c %d @ 0x%" PFMT64x,
				'q', count * 8, addr);
			break;
		}
		break;
	case 'a':
	case 'd':
		rz_core_cmdf(core, "pxw %d @ 0x%" PFMT64x, count * size, addr);
		break;
	case 'i':
		rz_core_cmdf(core, "pdq %d @ 0x%" PFMT64x, count, addr);
		break;
	}
}

static bool cmd_print_pxA(RzCore *core, int len, RzOutputMode mode) {
	if (!len) {
		return false;
	}
	RzConsPrintablePalette *pal = &core->cons->context->pal;
	int show_offset = true;
	int cols = rz_config_get_i(core->config, "hex.cols");
	int show_color = rz_config_get_i(core->config, "scr.color");
	int onechar = rz_config_get_i(core->config, "hex.onechar");
	bool hex_offset = rz_config_get_i(core->config, "hex.offset");
	int bgcolor_in_heap = false;
	bool show_cursor = core->print->cur_enabled;
	char buf[2];
	char *bgcolor, *fgcolor, *text;
	ut64 i, c, oi;
	RzAnalysisOp op;
	ut8 *data;
	int datalen;
	switch (mode) {
	case RZ_OUTPUT_MODE_LONG:
		datalen = cols * 8 * core->cons->rows;
		data = malloc(datalen);
		rz_io_read_at(core->io, core->offset, data, datalen);
		len = datalen;
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		data = core->block;
		datalen = core->blocksize;
		break;
	default:
		rz_warn_if_reached();
		return false;
	}
	if (len < 1) {
		len = datalen;
	}
	if (len < 0 || len > datalen) {
		RZ_LOG_ERROR("core: Invalid length\n");
		return false;
	}
	if (onechar) {
		cols *= 4;
	} else {
		cols *= 2;
	}
	if (show_offset) {
		char offstr[128];
		snprintf(offstr, sizeof(offstr),
			"0x%08" PFMT64x "  ", core->offset);
		if (strlen(offstr) > 12) {
			cols -= ((strlen(offstr) - 12) * 2);
		}
	}
	for (oi = i = c = 0; i < len; c++) {
		if (i && (cols != 0) && !(c % cols)) {
			show_offset = true;
			rz_cons_printf("  %" PFMT64u "\n", i - oi);
			oi = i;
		}
		if (show_offset && hex_offset) {
			rz_cons_printf("0x%08" PFMT64x "  ", core->offset + i);
			show_offset = false;
		}
		if (bgcolor_in_heap) {
			free(bgcolor);
			bgcolor_in_heap = false;
		}
		bgcolor = Color_BGBLACK;
		fgcolor = Color_WHITE;
		text = NULL;
		if (rz_analysis_op(core->analysis, &op, core->offset + i, data + i, len - i, RZ_ANALYSIS_OP_MASK_BASIC) <= 0) {
			op.type = 0;
			bgcolor = Color_BGRED;
			op.size = 1;
		}
		switch (op.type) {
		case RZ_ANALYSIS_OP_TYPE_LEA:
		case RZ_ANALYSIS_OP_TYPE_MOV:
		case RZ_ANALYSIS_OP_TYPE_CAST:
		case RZ_ANALYSIS_OP_TYPE_LENGTH:
		case RZ_ANALYSIS_OP_TYPE_CMOV:
			text = "mv";
			bgcolor = pal->mov;
			fgcolor = Color_YELLOW;
			break;
		case RZ_ANALYSIS_OP_TYPE_PUSH:
		case RZ_ANALYSIS_OP_TYPE_UPUSH:
		case RZ_ANALYSIS_OP_TYPE_RPUSH:
			bgcolor = pal->push;
			fgcolor = Color_WHITE;
			text = "->";
			break;
		case RZ_ANALYSIS_OP_TYPE_IO:
			bgcolor = pal->swi;
			fgcolor = Color_WHITE;
			text = "io";
			break;
		case RZ_ANALYSIS_OP_TYPE_TRAP:
		case RZ_ANALYSIS_OP_TYPE_SWI:
		case RZ_ANALYSIS_OP_TYPE_NEW:
			// bgcolor = Color_BGRED;
			bgcolor = pal->trap; // rz_cons_swap_ground (pal->trap);
			fgcolor = Color_WHITE;
			text = "$$";
			break;
		case RZ_ANALYSIS_OP_TYPE_POP:
			text = "<-";
			bgcolor = rz_cons_swap_ground(pal->pop);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			break;
		case RZ_ANALYSIS_OP_TYPE_NOP:
			fgcolor = Color_WHITE;
			bgcolor = rz_cons_swap_ground(pal->nop);
			bgcolor_in_heap = true;
			text = "..";
			break;
		case RZ_ANALYSIS_OP_TYPE_MUL:
			fgcolor = Color_BLACK;
			bgcolor = rz_cons_swap_ground(pal->math);
			bgcolor_in_heap = true;
			text = "_*";
			break;
		case RZ_ANALYSIS_OP_TYPE_DIV:
			bgcolor = rz_cons_swap_ground(pal->math);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "_/";
			break;
		case RZ_ANALYSIS_OP_TYPE_AND:
			bgcolor = rz_cons_swap_ground(pal->bin);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "_&";
			break;
		case RZ_ANALYSIS_OP_TYPE_XOR:
			bgcolor = rz_cons_swap_ground(pal->bin);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "_^";
			break;
		case RZ_ANALYSIS_OP_TYPE_OR:
			bgcolor = rz_cons_swap_ground(pal->bin);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "_|";
			break;
		case RZ_ANALYSIS_OP_TYPE_SHR:
			bgcolor = rz_cons_swap_ground(pal->bin);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = ">>";
			break;
		case RZ_ANALYSIS_OP_TYPE_SHL:
			bgcolor = rz_cons_swap_ground(pal->bin);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "<<";
			break;
		case RZ_ANALYSIS_OP_TYPE_SUB:
			bgcolor = rz_cons_swap_ground(pal->math);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			text = "--";
			break;
		case RZ_ANALYSIS_OP_TYPE_ADD:
			bgcolor = rz_cons_swap_ground(pal->math);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			text = "++";
			break;
		case RZ_ANALYSIS_OP_TYPE_JMP:
		case RZ_ANALYSIS_OP_TYPE_UJMP:
		case RZ_ANALYSIS_OP_TYPE_IJMP:
		case RZ_ANALYSIS_OP_TYPE_RJMP:
		case RZ_ANALYSIS_OP_TYPE_IRJMP:
		case RZ_ANALYSIS_OP_TYPE_MJMP:
			bgcolor = rz_cons_swap_ground(pal->jmp);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "_J";
			break;
		case RZ_ANALYSIS_OP_TYPE_CJMP:
		case RZ_ANALYSIS_OP_TYPE_UCJMP:
			bgcolor = rz_cons_swap_ground(pal->cjmp);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "cJ";
			break;
		case RZ_ANALYSIS_OP_TYPE_CALL:
		case RZ_ANALYSIS_OP_TYPE_UCALL:
		case RZ_ANALYSIS_OP_TYPE_ICALL:
		case RZ_ANALYSIS_OP_TYPE_RCALL:
		case RZ_ANALYSIS_OP_TYPE_IRCALL:
		case RZ_ANALYSIS_OP_TYPE_UCCALL:
			bgcolor = rz_cons_swap_ground(pal->call);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			text = "_C";
			break;
		case RZ_ANALYSIS_OP_TYPE_ACMP:
		case RZ_ANALYSIS_OP_TYPE_CMP:
			bgcolor = rz_cons_swap_ground(pal->cmp);
			bgcolor_in_heap = true;
			fgcolor = Color_BLACK;
			text = "==";
			break;
		case RZ_ANALYSIS_OP_TYPE_RET:
			bgcolor = rz_cons_swap_ground(pal->ret);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			text = "_R";
			break;
		case -1:
		case RZ_ANALYSIS_OP_TYPE_ILL:
		case RZ_ANALYSIS_OP_TYPE_UNK:
			bgcolor = rz_cons_swap_ground(pal->invalid);
			bgcolor_in_heap = true;
			fgcolor = Color_WHITE;
			text = "XX";
			break;
#if 0
		default:
			color = Color_BGCYAN;
			fgcolor = Color_BLACK;
			break;
#endif
		}
		int opsz = RZ_MAX(op.size, 1);
		if (show_cursor) {
			if (core->print->cur >= i && core->print->cur < i + opsz) {
				rz_cons_invert(1, 1);
			}
		}
		if (onechar) {
			if (text) {
				if (text[0] == '_' || text[0] == '.') {
					buf[0] = text[1];
				} else {
					buf[0] = text[0];
				}
			} else {
				buf[0] = '.';
			}
			buf[1] = 0;
			text = buf;
		}
		if (show_color) {
			if (!text) {
				text = "  ";
			}
			rz_cons_printf("%s%s%s\x1b[0m", bgcolor, fgcolor, text);
		} else {
			if (text) {
				rz_cons_print(text);
			} else {
				rz_cons_print("  ");
			}
		}
		if (show_cursor) {
			if (core->print->cur >= i && core->print->cur < i + opsz) {
				rz_cons_invert(0, 1);
			}
		}
		i += opsz;
		rz_analysis_op_fini(&op);
	}
	rz_cons_printf("  %" PFMT64d "\n", i - oi);
	if (bgcolor_in_heap) {
		free(bgcolor);
	}
	if (data != core->block) {
		free(data);
	}

	return true;
}

/* Uses data from clipboard if value is NULL */
static bool print_operation_transform(RzCore *core, RzCoreWriteOp op, RZ_NULLABLE const char *val) {
	ut8 *hex = NULL;
	size_t hexlen = 0, buflen = 0;
	if (val) {
		hex = RZ_NEWS(ut8, (strlen(val) + 1) / 2);
		if (!hex) {
			return false;
		}
		hexlen = rz_hex_str2bin(val, hex);
	}
	ut8 *buf = rz_core_transform_op(core, core->offset, op, hex, hexlen, &buflen);
	free(hex);
	rz_core_print_hexdump(core, core->offset, buf, buflen, 16, 1, 1);
	free(buf);
	return true;
}

static void handle_entropy(RzCore *core, const char *name, const ut8 *block, int len) {
	RzHashSize digest_size = 0;
	ut8 *digest = rz_hash_cfg_calculate_small_block(core->hash, name, block, len, &digest_size);
	if (!digest) {
		return;
	}
	double entropy = rz_read_be_double(digest);
	rz_cons_printf("%f\n", entropy);
	free(digest);
}

static void handle_ssdeep(RzCore *core, const char *name, const ut8 *block, int len) {
	RzHashSize digest_size = 0;
	char *digest = (char *)rz_hash_cfg_calculate_small_block(core->hash, name, block, len, &digest_size);
	if (!digest) {
		return;
	}
	rz_cons_printf("%s\n", digest);
	free(digest);
}

static inline void hexprint(const ut8 *data, int len) {
	if (!data || len < 1) {
		return;
	}
	for (int i = 0; i < len; i++) {
		rz_cons_printf("%02x", data[i]);
	}
	rz_cons_newline();
}

static void handle_hash_cfg(RzCore *core, const char *name, const ut8 *block, int len) {
	RzHashSize digest_size = 0;
	ut8 *digest = rz_hash_cfg_calculate_small_block(core->hash, name, block, len, &digest_size);
	hexprint(digest, digest_size);
	free(digest);
}

RZ_IPI RzCmdStatus rz_cmd_print_hash_cfg_handler(RzCore *core, int argc, const char **argv) {
	const RzHashPlugin *plugin = rz_hash_plugin_by_name(core->hash, argv[1]);

	if (!plugin) {
		RZ_LOG_ERROR("algorithm '%s' does not exists\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}

	if (!strncmp(plugin->name, "entropy", strlen("entropy"))) {
		handle_entropy(core, plugin->name, core->block, core->blocksize);
	} else if (!strcmp(plugin->name, "ssdeep")) {
		handle_ssdeep(core, plugin->name, core->block, core->blocksize);
	} else {
		handle_hash_cfg(core, plugin->name, core->block, core->blocksize);
	}

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_print_hash_cfg_algo_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_core_hash_plugins_print(core->hash, state);
}

RZ_IPI RzCmdStatus rz_cmd_print_magic_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (mode == RZ_OUTPUT_MODE_JSON) {
		PJ *pj = pj_new();
		rz_core_magic(core, argv[1], true, pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	} else {
		// XXX: need cmd_magic header for rz_core_magic
		rz_core_magic(core, argv[1], true, NULL);
	}
	return RZ_CMD_STATUS_OK;
}

static int bbcmp(RzAnalysisBlock *a, RzAnalysisBlock *b) {
	return a->addr - b->addr;
}

/* TODO: integrate this into rz_analysis */
static void _pointer_table(RzCore *core, ut64 origin, ut64 offset, const ut8 *buf, int len, int step, RzOutputMode mode) {
	if (step < 1) {
		step = 4;
	}
	if (!rz_io_is_valid_offset(core->io, origin, 0) ||
		!rz_io_is_valid_offset(core->io, offset, 0)) {
		return;
	}
	if (origin != offset) {
		if (mode == RZ_OUTPUT_MODE_RIZIN) {
			rz_cons_printf("CC-@ 0x%08" PFMT64x "\n", origin);
			rz_cons_printf("CC switch table @ 0x%08" PFMT64x "\n", origin);
			rz_cons_printf("axd 0x%" PFMT64x " @ 0x%08" PFMT64x "\n", origin, offset);
		}
	}
	for (size_t i = 0, n = 0; (i + sizeof(st32)) <= len; i += step, n++) {
		st32 delta = rz_read_le32(buf + i);
		ut64 addr = offset + delta;
		if (!rz_io_is_valid_offset(core->io, addr, 0)) {
			// Lets check for jmptbl with not relative addresses
			// Like: jmp dword [eax*4 + jmptbl.0x5435345]
			if (!rz_io_is_valid_offset(core->io, delta, 0)) {
				break;
			}
			addr = delta;
		}
		if (mode == RZ_OUTPUT_MODE_RIZIN) {
			rz_cons_printf("af case.%zu.0x%" PFMT64x " 0x%08" PFMT64x "\n", n, offset, addr);
			rz_cons_printf("ax 0x%" PFMT64x " @ 0x%08" PFMT64x "\n", offset, addr);
			rz_cons_printf("ax 0x%" PFMT64x " @ 0x%08" PFMT64x "\n", addr, offset); // wrong, but useful because forward xrefs dont work :?
			// FIXME: "aho" doesn't accept anything here after the "case" word
			rz_cons_printf("aho case 0x%" PFMT64x " 0x%08" PFMT64x " @ 0x%08" PFMT64x "\n", (ut64)i, addr, offset + i); // wrong, but useful because forward xrefs dont work :?
			rz_cons_printf("ahs %d @ 0x%08" PFMT64x "\n", step, offset + i);
		} else {
			rz_cons_printf("0x%08" PFMT64x " -> 0x%08" PFMT64x "\n", offset + i, addr);
		}
	}
}

static void pr_bb(RzCore *core, RzAnalysisFunction *fcn, RzAnalysisBlock *b, bool emu, ut64 saved_gp, ut8 *saved_arena, char p_type, bool fromHere) {
	bool show_flags = rz_config_get_i(core->config, "asm.flags");
	const bool orig_bb_middle = rz_config_get_b(core->config, "asm.bb.middle");
	core->analysis->gp = saved_gp;
	if (fromHere) {
		if (b->addr < core->offset) {
			core->cons->null = true;
		} else {
			core->cons->null = false;
		}
	}
	if (emu) {
		if (b->parent_reg_arena) {
			ut64 gp;
			rz_reg_arena_poke(core->analysis->reg, b->parent_reg_arena);
			RZ_FREE(b->parent_reg_arena);
			gp = rz_reg_getv(core->analysis->reg, "gp");
			if (gp) {
				core->analysis->gp = gp;
			}
		} else {
			rz_reg_arena_poke(core->analysis->reg, saved_arena);
		}
	}
	rz_config_set_b(core->config, "asm.bb.middle", false);
	p_type == 'D'
		? rz_core_cmdf(core, "pD %" PFMT64u " @ 0x%" PFMT64x, b->size, b->addr)
		: rz_core_cmdf(core, "pI %" PFMT64u " @ 0x%" PFMT64x, b->size, b->addr);
	rz_config_set_b(core->config, "asm.bb.middle", orig_bb_middle);

	if (b->jump != UT64_MAX) {
		if (b->jump > b->addr) {
			RzAnalysisBlock *jumpbb = rz_analysis_get_block_at(b->analysis, b->jump);
			if (jumpbb && rz_list_contains(jumpbb->fcns, fcn)) {
				if (emu && core->analysis->last_disasm_reg && !jumpbb->parent_reg_arena) {
					jumpbb->parent_reg_arena = rz_reg_arena_dup(core->analysis->reg, core->analysis->last_disasm_reg);
				}
			}
		}
		if (p_type == 'D' && show_flags) {
			rz_cons_printf("| ----------- true: 0x%08" PFMT64x, b->jump);
		}
	}
	if (b->fail != UT64_MAX) {
		if (b->fail > b->addr) {
			RzAnalysisBlock *failbb = rz_analysis_get_block_at(b->analysis, b->fail);
			if (failbb && rz_list_contains(failbb->fcns, fcn)) {
				if (emu && core->analysis->last_disasm_reg && !failbb->parent_reg_arena) {
					failbb->parent_reg_arena = rz_reg_arena_dup(core->analysis->reg, core->analysis->last_disasm_reg);
				}
			}
		}
		if (p_type == 'D' && show_flags) {
			rz_cons_printf("  false: 0x%08" PFMT64x, b->fail);
		}
	}
	if (p_type == 'D' && show_flags) {
		rz_cons_newline();
	}
}

static void disasm_until_ret(RzCore *core, ut64 addr, int limit, RzOutputMode mode) {
	int p = 0;
	const bool show_color = rz_config_get_i(core->config, "scr.color");
	for (int i = 0; i < limit; i++) {
		RzAnalysisOp *op = rz_core_analysis_op(core, addr, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_DISASM);
		if (op) {
			char *mnem = op->mnemonic;
			char *m = malloc((strlen(mnem) * 2) + 32);
			strcpy(m, mnem);
			// rz_parse_parse (core->parser, op->mnemonic, m);
			if (mode == RZ_OUTPUT_MODE_QUIET) {
				rz_cons_printf("%s\n", m);
			} else {
				if (show_color) {
					const char *offsetColor = rz_cons_singleton()->context->pal.offset; // TODO etooslow. must cache
					rz_cons_printf("%s0x%08" PFMT64x "" Color_RESET "  %10s %s\n",
						offsetColor, addr + p, "", m);
				} else {
					rz_cons_printf("0x%08" PFMT64x "  %10s %s\n", addr + p, "", m);
				}
			}
			switch (op->type & 0xfffff) {
			case RZ_ANALYSIS_OP_TYPE_RET:
			case RZ_ANALYSIS_OP_TYPE_UJMP:
				goto beach;
				break;
			}
			if (op->type == RZ_ANALYSIS_OP_TYPE_JMP) {
				addr = op->jump;
			} else {
				addr += op->size;
			}
		} else {
			RZ_LOG_ERROR("Cannot get op at 0x%08" PFMT64x "\n", addr + p);
			rz_analysis_op_free(op);
			break;
		}
		// rz_io_read_at (core->io, n, rbuf, 512);
		rz_analysis_op_free(op);
	}
beach:
	return;
}

static void func_walk_blocks(RzCore *core, RzAnalysisFunction *f, bool fromHere, RzCmdStateOutput *state) {
	const bool orig_bb_middle = rz_config_get_b(core->config, "asm.bb.middle");
	rz_config_set_b(core->config, "asm.bb.middle", false);

	rz_list_sort(f->bbs, (RzListComparator)bbcmp);

	RzAnalysisBlock *b;
	RzListIter *iter;

	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		rz_cmd_state_output_array_start(state);
		rz_list_foreach (f->bbs, iter, b) {
			if (fromHere) {
				if (b->addr < core->offset) {
					core->cons->null = true;
				} else {
					core->cons->null = false;
				}
			}
			ut8 *buf = malloc(b->size);
			if (!buf) {
				RZ_LOG_ERROR("core: cannot allocate %" PFMT64u " byte(s)\n", b->size);
				return;
			}
			rz_io_read_at(core->io, b->addr, buf, b->size);
			rz_core_print_disasm_json(core, b->addr, buf, b->size, 0, state->d.pj);
			free(buf);
		}
		rz_cmd_state_output_array_end(state);
	} else {
		bool asm_lines = rz_config_get_i(core->config, "asm.lines.bb");
		bool emu = rz_config_get_i(core->config, "asm.emu");
		ut64 saved_gp = 0;
		ut8 *saved_arena = NULL;
		if (emu) {
			saved_gp = core->analysis->gp;
			saved_arena = rz_reg_arena_peek(core->analysis->reg);
		}
		rz_config_set_i(core->config, "asm.lines.bb", 0);

		rz_list_foreach (f->bbs, iter, b) {
			pr_bb(core, f, b, emu, saved_gp, saved_arena, 'I', fromHere);
		}
		if (emu) {
			core->analysis->gp = saved_gp;
			if (saved_arena) {
				rz_reg_arena_poke(core->analysis->reg, saved_arena);
				RZ_FREE(saved_arena);
			}
		}
		rz_config_set_i(core->config, "asm.lines.bb", asm_lines);
	}
	rz_config_set_b(core->config, "asm.bb.middle", orig_bb_middle);
}

static inline char cmd_pxb_p(char input) {
	return IS_PRINTABLE(input) ? input : '.';
}

static inline int cmd_pxb_k(const ut8 *buffer, int x) {
	return buffer[3 - x] << (8 * x);
}

static inline char *get_section_name(RzCore *core) {
	const char *csection = rz_core_get_section_name(core, core->offset);
	if (RZ_STR_ISEMPTY(csection)) {
		return strdup("unknown");
	}
	csection = rz_str_trim_head_ro(csection);
	char *section_name = strdup(csection);
	rz_str_trim_tail(section_name);
	if (RZ_STR_ISEMPTY(section_name)) {
		free(section_name);
		return strdup("unknown");
	}
	return section_name;
}

static void print_json_string(RzCore *core, const ut8 *block, ut32 len, RzStrEnc encoding, bool stop_at_nil) {
	char *section = get_section_name(core);
	if (!section) {
		return;
	}
	ut32 dlength = 0;
	RzStrStringifyOpt opt = { 0 };
	opt.buffer = block;
	opt.length = len;
	opt.encoding = encoding;
	opt.json = true;
	opt.stop_at_nil = stop_at_nil;
	char *dstring = rz_str_stringify_raw_buffer(&opt, &dlength);
	if (!dstring) {
		free(section);
		return;
	}

	PJ *pj = pj_new();
	if (!pj) {
		free(section);
		free(dstring);
		return;
	}

	const char *enc_name = rz_str_enc_as_string(encoding);
	pj_o(pj);
	pj_k(pj, "string");
	pj_raw(pj, "\"");
	pj_raw(pj, dstring);
	pj_raw(pj, "\"");
	pj_kn(pj, "offset", core->offset);
	pj_ks(pj, "section", section);
	pj_kn(pj, "length", dlength);
	pj_ks(pj, "type", enc_name);
	pj_end(pj);
	rz_cons_println(pj_string(pj));
	pj_free(pj);
	free(section);
	free(dstring);
}

static char *__op_refs(RzCore *core, RzAnalysisOp *op, int n) {
	RzStrBuf *sb = rz_strbuf_new("");
	if (n) {
		// RzList *list = rz_analysis_xrefs_get_from (core->analysis, op->addr);
		RzList *list = rz_analysis_xrefs_get_to(core->analysis, op->addr);
		RzAnalysisXRef *xref;
		RzListIter *iter;
		rz_list_foreach (list, iter, xref) {
			rz_strbuf_appendf(sb, "0x%08" PFMT64x " ", xref->to);
		}
	} else {
		if (op->jump != UT64_MAX) {
			rz_strbuf_appendf(sb, "0x%08" PFMT64x " ", op->jump);
		}
		if (op->fail != UT64_MAX) {
			rz_strbuf_appendf(sb, "0x%08" PFMT64x " ", op->fail);
		}
		if (op->ptr != UT64_MAX) {
			if (rz_io_is_valid_offset(core->io, op->ptr, false)) {
				rz_strbuf_appendf(sb, "0x%08" PFMT64x " ", op->ptr);
			}
		}
	}
	char *res = rz_strbuf_drain(sb);
	rz_str_trim(res);
	return res;
}

static inline char *__refs(RzCore *core, ut64 x) {
	if (!core->print->hasrefs) {
		return NULL;
	}

	char *refs = core->print->hasrefs(core->print->user, x, true);
	if (RZ_STR_ISNOTEMPTY(refs)) {
		rz_str_trim(refs);
	} else {
		RZ_FREE(refs);
	}
	return refs;
}

static bool cmd_pxr(RzCore *core, int len, RzCmdStateOutput *state, int wordsize, const char *query) {
	if (!len) {
		return true;
	}
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return false;
	}

	const ut8 *buf = core->block;

	bool be = core->analysis->big_endian;
	int end = RZ_MIN(core->blocksize, len);
	int bitsize = wordsize * 8;
	RzOutputMode mode = state->mode;
	if (mode == RZ_OUTPUT_MODE_TABLE) {
		RzTable *t = state->d.t;
		RzTableColumnType *n = rz_table_type("number");
		RzTableColumnType *s = rz_table_type("string");
		rz_table_add_column(t, n, "addr", 0);
		rz_table_add_column(t, n, "value", 0);
		rz_table_add_column(t, s, "refs", 0);
		for (ut64 i = 0; i + wordsize < end; i += wordsize) {
			ut64 addr = core->offset + i;
			ut64 val = rz_read_ble(buf + i, be, bitsize);
			char *refs = __refs(core, val);
			rz_table_add_rowf(t, "xxs", addr, val, refs);
			RZ_FREE(refs);
		}
		rz_table_query(t, query);
	} else if (mode == RZ_OUTPUT_MODE_JSON) {
		PJ *pj = state->d.pj;
		const int hex_depth = (int)rz_config_get_i(core->config, "hex.depth");
		pj_a(pj);
		for (ut64 i = 0; i + wordsize < end; i += wordsize) {
			ut64 addr = core->offset + i;
			ut64 val = rz_read_ble(buf + i, be, bitsize);
			pj_o(pj);
			pj_kn(pj, "addr", addr);
			pj_kn(pj, "value", val);
			char *refs = __refs(core, val);
			if (refs) {
				char *refstr = rz_str_escape(refs);
				pj_ks(pj, "refstr", rz_str_trim_head_ro(refstr));
				free(refstr);

				pj_k(pj, "ref");
				free(rz_core_analysis_hasrefs_to_depth(core, val, pj, hex_depth));
			}
			pj_end(pj);
		}
		pj_end(pj);
	} else if (mode == RZ_OUTPUT_MODE_QUIET) {
		for (ut64 i = 0; i + wordsize < end; i += wordsize) {
			ut64 val = rz_read_ble(buf + i, be, bitsize);
			char *refs = __refs(core, val);
			rz_strbuf_appendf(sb, "%s\n", refs);
		}
	} else if (mode == RZ_OUTPUT_MODE_RIZIN) {
		for (ut64 i = 0; i + wordsize < end; i += wordsize) {
			ut64 addr = core->offset + i;
			ut64 val = rz_read_ble(buf + i, be, bitsize);
			rz_strbuf_appendf(sb, "f pxr.%" PFMT64x " @ 0x%" PFMT64x "\n", val, addr);
		}
	} else if (mode == RZ_OUTPUT_MODE_STANDARD) {
		const int ocols = core->print->cols;
		int bitsize = core->rasm->bits;
		/* Thumb is 16bit arm but handles 32bit data */
		if (bitsize == 16) {
			bitsize = 32;
		}
		core->print->cols = 1;
		core->print->flags |= RZ_PRINT_FLAGS_REFS;
		rz_strbuf_append(sb, rz_print_hexdump_str(core->print, core->offset, core->block, RZ_MIN(len, core->blocksize), wordsize * 8, bitsize / 8, 1));
		core->print->flags &= ~RZ_PRINT_FLAGS_REFS;
		core->print->cols = ocols;
	} else {
		rz_warn_if_reached();
		rz_strbuf_free(sb);
		return false;
	}
	if (mode == RZ_OUTPUT_MODE_RIZIN || mode == RZ_OUTPUT_MODE_STANDARD || mode == RZ_OUTPUT_MODE_QUIET) {
		char *res = rz_strbuf_drain(sb);
		rz_cons_print(res);
		free(res);
	} else {
		rz_strbuf_free(sb);
	}
	return true;
}

static void core_print_2bpp_row(const ut8 *buf, bool useColor) {
	const char *symbols = "#=-.";
	for (ut32 i = 0, c = 0; i < 8; i++) {
		if (buf[1] & ((1 << 7) >> i)) {
			c = 2;
		}
		if (buf[0] & ((1 << 7) >> i)) {
			c++;
		}
		if (useColor) {
			char *color = "";
			switch (c) {
			case 0:
				color = Color_BGWHITE;
				break;
			case 1:
				color = Color_BGRED;
				break;
			case 2:
				color = Color_BGBLUE;
				break;
			case 3:
				color = Color_BGBLACK;
				break;
			}
			rz_cons_printf("%s  ", color);
		} else {
			const char ch = symbols[c % 4];
			rz_cons_printf("%c%c", ch, ch);
		}
		c = 0;
	}
}

static void core_print_2bpp_tiles(RzCore *core, ut32 tiles) {
	const ut8 *buf = core->block;
	bool useColor = rz_config_get_i(core->config, "scr.color") > 0;
	for (ut32 i = 0; i < 8; i++) {
		for (ut32 r = 0; r < tiles; r++) {
			core_print_2bpp_row(buf + 2 * i + r * 16, useColor);
		}
		if (useColor) {
			rz_cons_printf(Color_RESET "\n");
		} else {
			rz_cons_printf("\n");
		}
	}
}

static void core_print_raw_buffer(RzStrStringifyOpt *opt) {
	char *str = rz_str_stringify_raw_buffer(opt, NULL);
	if (str) {
		rz_cons_strcat(str);
		free(str);
	}
}

static RzCmdStatus core_auto_detect_and_print_string(RzCore *core, bool stop_at_nil, ut32 offset, RzOutputMode mode) {
	const ut8 *buffer = core->block + offset;
	const ut32 length = core->blocksize - offset;
	const char *enc_name = rz_config_get(core->config, "bin.str.enc");
	RzStrEnc encoding = rz_str_enc_string_as_type(enc_name);
	RzStrStringifyOpt opt = { 0 };

	if (encoding == RZ_STRING_ENC_GUESS) {
		encoding = rz_str_guess_encoding_from_buffer(buffer, length);
	}

	switch (mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		opt.buffer = buffer;
		opt.length = length;
		opt.encoding = encoding;
		opt.stop_at_nil = stop_at_nil;
		core_print_raw_buffer(&opt);
		break;
	case RZ_OUTPUT_MODE_JSON:
		print_json_string(core, buffer, length, encoding, stop_at_nil);
		break;
	default:
		RZ_LOG_ERROR("core: unsupported output mode\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_string_auto_detect_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	bool stop_at_nil = !strcmp(argv[1], "null");
	return core_auto_detect_and_print_string(core, stop_at_nil, 0, mode);
}

RZ_IPI RzCmdStatus rz_print_string_as_libcpp_string_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	ut32 bitness = (ut32)rz_config_get_i(core->config, "asm.bits");
	bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");

	switch (bitness) {
	case 32:
		/* fall-thru */
	case 64:
		break;
	default:
		RZ_LOG_ERROR("core: %u bits are not supported by %s\n", bitness, argv[0]);
		return RZ_CMD_STATUS_ERROR;
	}

	ut32 min_size = (bitness / 8) * 3;
	if (core->blocksize < 2 || core->blocksize < min_size) {
		RZ_LOG_ERROR("core: the block size is too small to read string (expected at least %u but got %u bytes).\n", core->blocksize, min_size);
		return RZ_CMD_STATUS_ERROR;
	}

	RzCmdStatus status = RZ_CMD_STATUS_ERROR;
	if (*core->block & 0x1) { // "long" string
		const ut8 *ptr = core->block + (bitness / 8) * 2;
		ut64 old_offset = core->offset;
		ut64 new_offset = rz_read_ble(ptr, big_endian, bitness);

		rz_core_seek(core, new_offset, SEEK_SET);
		rz_core_block_read(core);

		status = core_auto_detect_and_print_string(core, true, 0, mode);

		rz_core_seek(core, old_offset, SEEK_SET);
		rz_core_block_read(core);
	} else {
		status = core_auto_detect_and_print_string(core, true, 1, mode);
	}

	return status;
}

RZ_IPI RzCmdStatus rz_print_strings_current_block_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	RzListIter *it = NULL;
	RzDetectedString *detected = NULL;
	RzUtilStrScanOptions scan_opt = {
		.buf_size = core->blocksize,
		.max_uni_blocks = 4,
		.min_str_length = core->bin->minstrlen,
		.prefer_big_endian = false,
	};

	RzList *found = rz_list_newf((RzListFree)rz_detected_string_free);
	if (!found) {
		RZ_LOG_ERROR("core: failed to allocate RzList\n");
		return RZ_CMD_STATUS_ERROR;
	}

	if (rz_scan_strings_raw(core->block, found, &scan_opt, 0, core->blocksize, RZ_STRING_ENC_GUESS) < 0) {
		rz_list_free(found);
		return RZ_CMD_STATUS_ERROR;
	}

	rz_list_foreach (found, it, detected) {
		ut64 address = core->offset + detected->addr;
		if (mode != RZ_OUTPUT_MODE_QUIET) {
			rz_print_offset(core->print, address, 0, 0, 0, 0, NULL);
		}
		rz_cons_memcat(detected->string, detected->size);
		rz_cons_newline();
	}

	rz_list_free(found);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_first_string_current_block_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	RzDetectedString *detected = NULL;
	RzUtilStrScanOptions scan_opt = {
		.buf_size = core->blocksize,
		.max_uni_blocks = 4,
		.min_str_length = core->bin->minstrlen,
		.prefer_big_endian = false,
	};

	RzList *found = rz_list_newf((RzListFree)rz_detected_string_free);
	if (!found) {
		RZ_LOG_ERROR("core: failed to allocate RzList\n");
		return RZ_CMD_STATUS_ERROR;
	}

	if (rz_scan_strings_raw(core->block, found, &scan_opt, 0, core->blocksize, RZ_STRING_ENC_GUESS) < 0) {
		rz_list_free(found);
		return RZ_CMD_STATUS_ERROR;
	}

	detected = rz_list_first(found);
	if (detected) {
		rz_cons_memcat(detected->string, detected->size);
		rz_cons_newline();
	}

	rz_list_free(found);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_pascal_string_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	RzStrStringifyOpt opt = { 0 };
	bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");
	ut64 string_len = 0;
	ut32 offset = 0;

	if (!strcmp(argv[1], "8")) {
		string_len = (ut64)core->block[0];
		offset = 1;
	} else if (!strcmp(argv[1], "16")) {
		string_len = rz_read_ble16(core->block, big_endian);
		offset = 2;
	} else if (!strcmp(argv[1], "32")) {
		string_len = rz_read_ble32(core->block, big_endian);
		offset = 4;
	} else {
		string_len = rz_read_ble64(core->block, big_endian);
		offset = 8;
	}

	if (string_len < 1) {
		RZ_LOG_ERROR("core: string length is zero\n");
		return RZ_CMD_STATUS_ERROR;
	}

	if ((string_len + offset) > core->blocksize) {
		RZ_LOG_ERROR("core: string length exceeds block size\n");
		return RZ_CMD_STATUS_ERROR;
	}

	switch (mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		opt.buffer = core->block + offset;
		opt.length = string_len;
		opt.encoding = RZ_STRING_ENC_8BIT;
		opt.stop_at_nil = true;
		core_print_raw_buffer(&opt);
		break;
	case RZ_OUTPUT_MODE_JSON:
		print_json_string(core, core->block + offset, string_len, RZ_STRING_ENC_8BIT, true);
		break;
	default:
		RZ_LOG_ERROR("core: unsupported output mode\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_string_wrap_width_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	int h, w = rz_cons_get_size(&h);
	int colwidth = rz_config_get_i(core->config, "hex.cols") * 2;
	int width = (colwidth == 32) ? w : colwidth; // w;
	ut64 blocksize = core->blocksize;

	ut64 len = (h * w) / 3;
	rz_core_block_size(core, len);

	RzStrStringifyOpt opt = { 0 };
	opt.buffer = core->block;
	opt.length = len;
	opt.encoding = RZ_STRING_ENC_8BIT;
	opt.wrap_at = width;
	core_print_raw_buffer(&opt);
	rz_core_block_size(core, blocksize);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_string_escaped_newlines_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	RzStrStringifyOpt opt = { 0 };
	opt.buffer = core->block;
	opt.length = core->blocksize;
	opt.encoding = RZ_STRING_ENC_8BIT;
	opt.escape_nl = true;
	core_print_raw_buffer(&opt);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_string_c_cpp_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	char *str = rz_core_print_string_c_cpp(core);
	if (!str) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(str);
	free(str);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_hex_of_assembly_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	char *buf = rz_core_hex_of_assembly(core, argv[1]);
	if (!buf) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(buf);
	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_esil_of_assembly_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	char *buf = rz_core_esil_of_assembly(core, argv[1]);
	if (!buf) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_print(buf);
	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_assembly_of_hex_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	ut8 *hex = calloc(1, strlen(argv[1]) + 1);
	if (!hex) {
		RZ_LOG_ERROR("Fail to allocate memory\n");
		return RZ_CMD_STATUS_ERROR;
	}
	int len = rz_hex_str2bin(argv[1], hex);
	if (len < 1) {
		RZ_LOG_ERROR("rz_hex_str2bin: invalid hexstr\n");
		free(hex);
		return RZ_CMD_STATUS_ERROR;
	}
	char *buf = rz_core_assembly_of_hex(core, hex, len);
	if (!buf) {
		free(hex);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_print(buf);
	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_assembly_of_hex_alias_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	return rz_assembly_of_hex_handler(core, argc, argv, mode);
}

RZ_IPI RzCmdStatus rz_print_instructions_handler(RzCore *core, int argc, const char **argv) {
	ut64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	rz_core_print_disasm_instructions(core, len, 0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_instructions_function_handler(RzCore *core, int argc, const char **argv) {
	const RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset,
		RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
	if (!f) {
		RZ_LOG_ERROR("Cannot function at the specified address\n");
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 fcn_size = rz_analysis_function_linear_size((RzAnalysisFunction *)f);
	rz_core_print_disasm_instructions(core, fcn_size, 0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_esil_of_hex_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	ut8 *hex = calloc(1, strlen(argv[1]) + 1);
	if (!hex) {
		RZ_LOG_ERROR("Fail to allocate memory\n");
		return RZ_CMD_STATUS_ERROR;
	}
	int len = rz_hex_str2bin(argv[1], hex);
	if (len < 1) {
		RZ_LOG_ERROR("rz_hex_str2bin: invalid hexstr\n");
		free(hex);
		return RZ_CMD_STATUS_ERROR;
	}
	char *buf = rz_core_esil_of_hex(core, hex, len);
	if (!buf) {
		// rz_core_esil_of_hex outputs the error message
		free(hex);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_print(buf);
	free(buf);
	free(hex);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI int rz_cmd_print(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	st64 l;
	int i, len, ret;
	ut8 *block;
	ut32 tbs = core->blocksize;
	ut64 n, off;
	ut64 tmpseek = UT64_MAX;
	ret = 0;

	rz_print_init_rowoffsets(core->print);
	off = UT64_MAX;
	l = len = core->blocksize;
	if (input[0] && input[1]) {
		int idx = (input[0] == 'h') ? 2 : 1;
		const char *p = off ? strchr(input + idx, ' ') : NULL;
		if (p) {
			l = (int)rz_num_math(core->num, p + 1);
			/* except disasm and memoryfmt (pd, pm) and overlay (po) */
			if (input[0] != 'd' && input[0] != 't' && input[0] != 'D' && input[0] != 'm' &&
				input[0] != 'a' && input[0] != 'f' && input[0] != 'i' &&
				input[0] != 'I' && input[0] != 'o') {
				if (l < 0) {
					off = core->offset + l;
					len = l = -l;
					tmpseek = core->offset;
				} else {
					len = l;
					if (l > core->blocksize) {
						if (!rz_core_block_size(core, l)) {
							goto beach;
						}
					}
				}
			} else {
				len = l;
			}
		}
	}

	if (len > core->blocksize) {
		len = core->blocksize;
	}

	if (input[0] != 'd' && input[0] != 'm' && input[0] != 'a' && input[0] != 'f' && input[0] != 'i') {
		n = core->blocksize_max;
		i = (int)n;
		if (i != n) {
			i = 0;
		}
		if (i && l > i) {
			RZ_LOG_ERROR("core: This block size is too big (0x%" PFMT64x
				     " < 0x%" PFMT64x "). Did you mean 'p%c @ %s' instead?\n",
				n, l, *input, input + 2);
			goto beach;
		}
	}
	if (input[0] == 'x' || input[0] == 'D') {
		if (l > 0 && tmpseek == UT64_MAX) {
			if (!rz_core_block_size(core, l)) {
				RZ_LOG_ERROR("core: This block size is too big. Did you mean 'p%c @ %s' instead?\n",
					*input, input + 2);
				goto beach;
			}
		}
	}

	if (input[0] && input[0] != 'z' && input[1] == 'f' && input[2] != '?') {
		RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
		// RZ_ANALYSIS_FCN_TYPE_FCN|RZ_ANALYSIS_FCN_TYPE_SYM);
		if (f) {
			len = rz_analysis_function_linear_size(f);
			if (len > core->blocksize) {
				len = core->blocksize;
			}
		} else {
			RZ_LOG_ERROR("core: p: Cannot find function at 0x%08" PFMT64x "\n", core->offset);
			core->num->value = 0;
			goto beach;
		}
	}
	// TODO figure out why `f eax=33; f test=eax; pa call test` misassembles if len is 0
	core->num->value = len ? len : core->blocksize;
	if (off != UT64_MAX) {
		rz_core_seek(core, off, SEEK_SET);
		rz_core_block_read(core);
	}
	// TODO After core->block is removed, this should be changed to a block read.
	block = core->block;
	switch (*input) {
	case 'j': // "pj"
		if (input[1] == '?') {
			rz_core_cmd_help(core, help_msg_pj);
		} else if (input[1] == '.') {
			if (input[2] == '.') {
				ut8 *data = calloc(core->offset + 1, 1);
				if (data) {
					data[core->offset] = 0;
					(void)rz_io_read_at(core->io, 0, data, core->offset);
					char *res = rz_print_json_path((const char *)data, core->offset);
					if (res) {
						rz_cons_printf("-> res(%s)\n", res);
					}
					/*
					char *res = rz_print_json_indent ((char*)data, false, "  ", NULL);
					print_json_path (core, res);
					free (res);
*/
				} else {
					RZ_LOG_ERROR("core: Cannot allocate %d\n", (int)(core->offset));
				}
			} else {
				rz_core_cmdf(core, "pj %" PFMT64u " @ 0", core->offset);
			}
		} else {
			if (core->blocksize < 4 || !memcmp(core->block, "\xff\xff\xff\xff", 4)) {
				RZ_LOG_ERROR("core: Cannot read\n");
			} else {
				char *res = rz_print_json_indent((const char *)core->block, true, "  ", NULL);
				rz_cons_printf("%s\n", res);
				free(res);
			}
		}
		break;
	case 'm': // "pm"
		if (input[1] == '?') {
			rz_cons_printf("|Usage: pm [file|directory]\n"
				       "| rz_magic will use given file/dir as reference\n"
				       "| output of those magic can contain expressions like:\n"
				       "|   foo@ 0x40   # use 'foo' magic file on address 0x40\n"
				       "|   @ 0x40      # use current magic file on address 0x40\n"
				       "|   \\n         # append newline\n"
				       "| e dir.magic  # defaults to " RZ_JOIN_2_PATHS("{RZ_PREFIX}", RZ_SDB_MAGIC) "\n"
														    "| /m           # search for magic signatures\n");
		} else if (input[1] == 'j') { // "pmj"
			const char *filename = rz_str_trim_head_ro(input + 2);
			PJ *pj = pj_new();
			rz_core_magic(core, filename, true, pj);
			rz_cons_println(pj_string(pj));
			pj_free(pj);
		} else {
			// XXX: need cmd_magic header for rz_core_magic
			const char *filename = rz_str_trim_head_ro(input + 1);
			rz_core_magic(core, filename, true, NULL);
		}
		break;
	case 'x': // "px"
	{
		bool show_offset = rz_config_get_i(core->config, "hex.offset");
		if (show_offset) {
			core->print->flags |= RZ_PRINT_FLAGS_OFFSET;
		} else {
			core->print->flags &= ~RZ_PRINT_FLAGS_OFFSET;
		}
		int show_header = rz_config_get_i(core->config, "hex.header");
		if (show_header) {
			core->print->flags |= RZ_PRINT_FLAGS_HEADER;
		} else {
			core->print->flags &= ~RZ_PRINT_FLAGS_HEADER;
		}
		/* Don't show comments in default case */
		core->print->use_comments = false;
	}
		rz_cons_break_push(NULL, NULL);
		switch (input[1]) {
		case '/': // "px/"
			rz_core_print_examine(core, input + 2);
			break;
		case '?':
		default:
			rz_core_cmd_help(core, help_msg_px);
			break;
		}
		rz_cons_break_pop();
		break;
	case '2': // "p2"
		if (l) {
			if (input[1] == '?') {
				rz_cons_printf("|Usage: p2 [number of bytes representing tiles]\n"
					       "NOTE: Only full tiles will be printed\n");
			} else {
				core_print_2bpp_tiles(core, len / 16);
			}
		}
		break;
	case '8': // "p8"
		if (input[1] == '?') {
			rz_cons_printf("|Usage: p8[fj] [len]     8bit hexpair list of bytes (see pcj)\n");
			rz_cons_printf(" p8  : print hexpairs string\n");
			rz_cons_printf(" p8f : print hexpairs of function (linear)\n");
			rz_cons_printf(" p8j : print hexpairs in JSON array\n");
		} else if (l) {
			if (!rz_core_block_size(core, len)) {
				len = core->blocksize;
			}
			if (input[1] == 'j') { // "p8j"
				rz_core_cmdf(core, "pcj %s", input + 2);
			} else if (input[1] == 'f') { // "p8f"
				rz_core_cmdf(core, "p8 $FS @ $FB");
			} else {
				rz_core_block_read(core);
				block = core->block;
				rz_print_bytes(core->print, block, len, "%02x");
			}
		}
		break;
	case 'g': // "pg"
		cmd_print_gadget(core, input + 1);
		break;
	case 'f': // "pf"
		cmd_print_format(core, input, block, len);
		break;
	default:
		rz_core_cmd_help(core, help_msg_p);
		break;
	}
beach:
	if (tmpseek != UT64_MAX) {
		rz_core_seek(core, tmpseek, SEEK_SET);
		rz_core_block_read(core);
	}
	if (tbs != core->blocksize) {
		rz_core_block_size(core, tbs);
	}
	return ret;
}

RZ_IPI int rz_cmd_hexdump(void *data, const char *input) {
	// TODO: Use the API directly
	return rz_core_cmdf(data, "px%s", input);
}

static int lenof(ut64 off, int two) {
	char buf[64];
	buf[0] = 0;
	if (two) {
		snprintf(buf, sizeof(buf), "+0x%" PFMT64x, off);
	} else {
		snprintf(buf, sizeof(buf), "0x%08" PFMT64x, off);
	}
	return strlen(buf);
}

RZ_API void rz_print_offset_sg(RzPrint *p, ut64 off, int invert, int offseg, int seggrn, int offdec, int delta, const char *label) {
	char space[32] = {
		0
	};
	const char *reset = p->resetbg ? Color_RESET : Color_RESET_NOBG;
	bool show_color = p->flags & RZ_PRINT_FLAGS_COLOR;
	if (show_color) {
		char rgbstr[32];
		const char *k = rz_cons_singleton()->context->pal.offset; // TODO etooslow. must cache
		const char *inv = invert ? RZ_CONS_INVERT(true, true) : "";
		if (p->flags & RZ_PRINT_FLAGS_RAINBOW) {
			k = rz_cons_rgb_str_off(rgbstr, sizeof(rgbstr), off);
		}
		if (offseg) {
			ut32 s, a;
			a = off & 0xffff;
			s = ((off - a) >> seggrn) & 0xffff;
			if (offdec) {
				snprintf(space, sizeof(space), "%d:%d", s, a);
				rz_cons_printf("%s%s%9s%s", k, inv, space, reset);
			} else {
				rz_cons_printf("%s%s%04x:%04x%s", k, inv, s, a, reset);
			}
		} else {
			int sz = lenof(off, 0);
			int sz2 = lenof(delta, 1);
			if (delta > 0 || label) {
				if (label) {
					const int label_padding = 10;
					if (delta > 0) {
						const char *pad = rz_str_pad(' ', sz - sz2 + label_padding);
						if (offdec) {
							rz_cons_printf("%s%s%s%s+%d%s", k, inv, label, reset, delta, pad);
						} else {
							rz_cons_printf("%s%s%s%s+0x%x%s", k, inv, label, reset, delta, pad);
						}
					} else {
						const char *pad = rz_str_pad(' ', sz + label_padding);
						rz_cons_printf("%s%s%s%s%s", k, inv, label, reset, pad);
					}
				} else {
					const char *pad = rz_str_pad(' ', sz - sz2);
					if (offdec) {
						rz_cons_printf("%s+%d%s", pad, delta, reset);
					} else {
						rz_cons_printf("%s+0x%x%s", pad, delta, reset);
					}
				}
			} else {
				if (offdec) {
					snprintf(space, sizeof(space), "%" PFMT64u, off);
					rz_cons_printf("%s%s%10s%s", k, inv, space, reset);
				} else {
					if (p->wide_offsets) {
						rz_cons_printf("%s%s0x%016" PFMT64x "%s", k, inv, off, reset);
					} else {
						rz_cons_printf("%s%s0x%08" PFMT64x "%s", k, inv, off, reset);
					}
				}
			}
		}
		rz_cons_print(" ");
	} else {
		if (offseg) {
			ut32 s, a;
			a = off & 0xffff;
			s = (off - a) >> seggrn;
			if (offdec) {
				snprintf(space, sizeof(space), "%d:%d", s & 0xffff, a & 0xffff);
				rz_cons_printf("%9s%s", space, reset);
			} else {
				rz_cons_printf("%04x:%04x", s & 0xFFFF, a & 0xFFFF);
			}
		} else {
			int sz = lenof(off, 0);
			int sz2 = lenof(delta, 1);
			const char *pad = rz_str_pad(' ', sz - 5 - sz2 - 3);
			if (delta > 0) {
				if (offdec) {
					rz_cons_printf("%s+%d%s", pad, delta, reset);
				} else {
					rz_cons_printf("%s+0x%x%s", pad, delta, reset);
				}
			} else {
				if (offdec) {
					snprintf(space, sizeof(space), "%" PFMT64u, off);
					rz_cons_printf("%10s", space);
				} else {
					rz_cons_printf("0x%08" PFMT64x " ", off);
				}
			}
		}
	}
}

// TODO : move to rz_util? .. depends on rz_cons...
// XXX: dupe of rz_print_addr
RZ_API void rz_print_offset(RzPrint *p, ut64 off, int invert, int offseg, int offdec, int delta, const char *label) {
	rz_print_offset_sg(p, off, invert, offseg, 4, offdec, delta, label);
}

RZ_IPI RzCmdStatus rz_print_utf16le_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (mode == RZ_OUTPUT_MODE_JSON) {
		print_json_string(core, core->block, core->blocksize, RZ_STRING_ENC_UTF16LE, true);
	} else {
		RzStrStringifyOpt opt = { 0 };
		opt.buffer = core->block;
		opt.length = core->blocksize;
		opt.encoding = RZ_STRING_ENC_UTF16LE;
		opt.stop_at_nil = true;
		core_print_raw_buffer(&opt);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_utf32le_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (mode == RZ_OUTPUT_MODE_JSON) {
		print_json_string(core, core->block, core->blocksize, RZ_STRING_ENC_UTF32LE, true);
	} else {
		RzStrStringifyOpt opt = { 0 };
		opt.buffer = core->block;
		opt.length = core->blocksize;
		opt.encoding = RZ_STRING_ENC_UTF32LE;
		opt.stop_at_nil = true;
		core_print_raw_buffer(&opt);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_utf16be_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (mode == RZ_OUTPUT_MODE_JSON) {
		print_json_string(core, core->block, core->blocksize, RZ_STRING_ENC_UTF16BE, true);
	} else {
		RzStrStringifyOpt opt = { 0 };
		opt.buffer = core->block;
		opt.length = core->blocksize;
		opt.encoding = RZ_STRING_ENC_UTF16BE;
		opt.stop_at_nil = true;
		core_print_raw_buffer(&opt);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_utf32be_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (mode == RZ_OUTPUT_MODE_JSON) {
		print_json_string(core, core->block, core->blocksize, RZ_STRING_ENC_UTF32BE, true);
	} else {
		RzStrStringifyOpt opt = { 0 };
		opt.buffer = core->block;
		opt.length = core->blocksize;
		opt.encoding = RZ_STRING_ENC_UTF32BE;
		opt.stop_at_nil = true;
		core_print_raw_buffer(&opt);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_hexdump_annotated_handler(RzCore *core, int argc, const char **argv) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	if (len % 16) {
		len += 16 - (len % 16);
	}
	annotated_hexdump(core, len);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_op_analysis_color_map_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(cmd_print_pxA(core, len, state->mode));
}

RZ_IPI RzCmdStatus rz_print_hexdump_bits_handler(RzCore *core, int argc, const char **argv) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	if (!len) {
		return RZ_CMD_STATUS_OK;
	}

	char buf[32];
	for (int i = 0, c = 0; i < len; i++, c++) {
		if (c == 0) {
			ut64 ea = core->offset + i;
			if (core->print->pava) {
				ut64 va = rz_io_p2v(core->io, ea);
				if (va != UT64_MAX) {
					ea = va;
				}
			}
			char *string = rz_print_section_str(core->print, ea);
			rz_cons_print(string);
			free(string);
			rz_print_offset(core->print, ea, 0, 0, 0, 0, NULL);
		}
		rz_str_bits(buf, core->block + i, 8, NULL);

		// split bits
		memmove(buf + 5, buf + 4, 5);
		buf[4] = 0;

		rz_print_cursor(core->print, i, 1, 1);
		rz_cons_printf("%s.%s  ", buf, buf + 5);
		rz_print_cursor(core->print, i, 1, 0);
		if (c == 3) {
			const ut8 *b = core->block + i - 3;
			int (*k)(const ut8 *, int) = cmd_pxb_k;
			char (*p)(char) = cmd_pxb_p;

			int n = k(b, 0) | k(b, 1) | k(b, 2) | k(b, 3);
			rz_cons_printf("0x%08x  %c%c%c%c\n",
				n, p(b[0]), p(b[1]), p(b[2]), p(b[3]));
			c = -1;
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_hexdump_comments_handler(RzCore *core, int argc, const char **argv) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(rz_core_print_hexdump_or_hexdiff(core, RZ_OUTPUT_MODE_STANDARD, core->offset, len, true));
}

RZ_IPI RzCmdStatus rz_print_hexdump_signed_integer_common_handler(RzCore *core, int argc, const char **argv,
	RzCmdStateOutput *state, ut8 n) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(rz_core_print_dump(core, state->mode, core->offset, n, len, RZ_CORE_PRINT_FORMAT_TYPE_INTEGER));
}

RZ_IPI RzCmdStatus rz_print_hexdump_signed_integer_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_print_hexdump_signed_integer_common_handler(core, argc, argv, state, 1);
}
RZ_IPI RzCmdStatus rz_print_hexdump_signed_integer2_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_print_hexdump_signed_integer_common_handler(core, argc, argv, state, 2);
}
RZ_IPI RzCmdStatus rz_print_hexdump_signed_integer4_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_print_hexdump_signed_integer_common_handler(core, argc, argv, state, 4);
}
RZ_IPI RzCmdStatus rz_print_hexdump_signed_integer8_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_print_hexdump_signed_integer_common_handler(core, argc, argv, state, 8);
}

RZ_IPI RzCmdStatus rz_print_hexdump_emoji_handler(RzCore *core, int argc, const char **argv) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	if (!len) {
		return RZ_CMD_STATUS_OK;
	}
	static const char emoji[] = {
		'\x8c', '\x80', '\x8c', '\x82', '\x8c', '\x85', '\x8c', '\x88',
		'\x8c', '\x99', '\x8c', '\x9e', '\x8c', '\x9f', '\x8c', '\xa0',
		'\x8c', '\xb0', '\x8c', '\xb1', '\x8c', '\xb2', '\x8c', '\xb3',
		'\x8c', '\xb4', '\x8c', '\xb5', '\x8c', '\xb7', '\x8c', '\xb8',
		'\x8c', '\xb9', '\x8c', '\xba', '\x8c', '\xbb', '\x8c', '\xbc',
		'\x8c', '\xbd', '\x8c', '\xbe', '\x8c', '\xbf', '\x8d', '\x80',
		'\x8d', '\x81', '\x8d', '\x82', '\x8d', '\x83', '\x8d', '\x84',
		'\x8d', '\x85', '\x8d', '\x86', '\x8d', '\x87', '\x8d', '\x88',
		'\x8d', '\x89', '\x8d', '\x8a', '\x8d', '\x8b', '\x8d', '\x8c',
		'\x8d', '\x8d', '\x8d', '\x8e', '\x8d', '\x8f', '\x8d', '\x90',
		'\x8d', '\x91', '\x8d', '\x92', '\x8d', '\x93', '\x8d', '\x94',
		'\x8d', '\x95', '\x8d', '\x96', '\x8d', '\x97', '\x8d', '\x98',
		'\x8d', '\x9c', '\x8d', '\x9d', '\x8d', '\x9e', '\x8d', '\x9f',
		'\x8d', '\xa0', '\x8d', '\xa1', '\x8d', '\xa2', '\x8d', '\xa3',
		'\x8d', '\xa4', '\x8d', '\xa5', '\x8d', '\xa6', '\x8d', '\xa7',
		'\x8d', '\xa8', '\x8d', '\xa9', '\x8d', '\xaa', '\x8d', '\xab',
		'\x8d', '\xac', '\x8d', '\xad', '\x8d', '\xae', '\x8d', '\xaf',
		'\x8d', '\xb0', '\x8d', '\xb1', '\x8d', '\xb2', '\x8d', '\xb3',
		'\x8d', '\xb4', '\x8d', '\xb5', '\x8d', '\xb6', '\x8d', '\xb7',
		'\x8d', '\xb8', '\x8d', '\xb9', '\x8d', '\xba', '\x8d', '\xbb',
		'\x8d', '\xbc', '\x8e', '\x80', '\x8e', '\x81', '\x8e', '\x82',
		'\x8e', '\x83', '\x8e', '\x84', '\x8e', '\x85', '\x8e', '\x88',
		'\x8e', '\x89', '\x8e', '\x8a', '\x8e', '\x8b', '\x8e', '\x8c',
		'\x8e', '\x8d', '\x8e', '\x8e', '\x8e', '\x8f', '\x8e', '\x92',
		'\x8e', '\x93', '\x8e', '\xa0', '\x8e', '\xa1', '\x8e', '\xa2',
		'\x8e', '\xa3', '\x8e', '\xa4', '\x8e', '\xa5', '\x8e', '\xa6',
		'\x8e', '\xa7', '\x8e', '\xa8', '\x8e', '\xa9', '\x8e', '\xaa',
		'\x8e', '\xab', '\x8e', '\xac', '\x8e', '\xad', '\x8e', '\xae',
		'\x8e', '\xaf', '\x8e', '\xb0', '\x8e', '\xb1', '\x8e', '\xb2',
		'\x8e', '\xb3', '\x8e', '\xb4', '\x8e', '\xb5', '\x8e', '\xb7',
		'\x8e', '\xb8', '\x8e', '\xb9', '\x8e', '\xba', '\x8e', '\xbb',
		'\x8e', '\xbd', '\x8e', '\xbe', '\x8e', '\xbf', '\x8f', '\x80',
		'\x8f', '\x81', '\x8f', '\x82', '\x8f', '\x83', '\x8f', '\x84',
		'\x8f', '\x86', '\x8f', '\x87', '\x8f', '\x88', '\x8f', '\x89',
		'\x8f', '\x8a', '\x90', '\x80', '\x90', '\x81', '\x90', '\x82',
		'\x90', '\x83', '\x90', '\x84', '\x90', '\x85', '\x90', '\x86',
		'\x90', '\x87', '\x90', '\x88', '\x90', '\x89', '\x90', '\x8a',
		'\x90', '\x8b', '\x90', '\x8c', '\x90', '\x8d', '\x90', '\x8e',
		'\x90', '\x8f', '\x90', '\x90', '\x90', '\x91', '\x90', '\x92',
		'\x90', '\x93', '\x90', '\x94', '\x90', '\x95', '\x90', '\x96',
		'\x90', '\x97', '\x90', '\x98', '\x90', '\x99', '\x90', '\x9a',
		'\x90', '\x9b', '\x90', '\x9c', '\x90', '\x9d', '\x90', '\x9e',
		'\x90', '\x9f', '\x90', '\xa0', '\x90', '\xa1', '\x90', '\xa2',
		'\x90', '\xa3', '\x90', '\xa4', '\x90', '\xa5', '\x90', '\xa6',
		'\x90', '\xa7', '\x90', '\xa8', '\x90', '\xa9', '\x90', '\xaa',
		'\x90', '\xab', '\x90', '\xac', '\x90', '\xad', '\x90', '\xae',
		'\x90', '\xaf', '\x90', '\xb0', '\x90', '\xb1', '\x90', '\xb2',
		'\x90', '\xb3', '\x90', '\xb4', '\x90', '\xb5', '\x90', '\xb6',
		'\x90', '\xb7', '\x90', '\xb8', '\x90', '\xb9', '\x90', '\xba',
		'\x90', '\xbb', '\x90', '\xbc', '\x90', '\xbd', '\x90', '\xbe',
		'\x91', '\x80', '\x91', '\x82', '\x91', '\x83', '\x91', '\x84',
		'\x91', '\x85', '\x91', '\x86', '\x91', '\x87', '\x91', '\x88',
		'\x91', '\x89', '\x91', '\x8a', '\x91', '\x8b', '\x91', '\x8c',
		'\x91', '\x8d', '\x91', '\x8e', '\x91', '\x8f', '\x91', '\x90',
		'\x91', '\x91', '\x91', '\x92', '\x91', '\x93', '\x91', '\x94',
		'\x91', '\x95', '\x91', '\x96', '\x91', '\x97', '\x91', '\x98',
		'\x91', '\x99', '\x91', '\x9a', '\x91', '\x9b', '\x91', '\x9c',
		'\x91', '\x9d', '\x91', '\x9e', '\x91', '\x9f', '\x91', '\xa0',
		'\x91', '\xa1', '\x91', '\xa2', '\x91', '\xa3', '\x91', '\xa4',
		'\x91', '\xa5', '\x91', '\xa6', '\x91', '\xa7', '\x91', '\xa8',
		'\x91', '\xa9', '\x91', '\xaa', '\x91', '\xae', '\x91', '\xaf',
		'\x91', '\xba', '\x91', '\xbb', '\x91', '\xbc', '\x91', '\xbd',
		'\x91', '\xbe', '\x91', '\xbf', '\x92', '\x80', '\x92', '\x81',
		'\x92', '\x82', '\x92', '\x83', '\x92', '\x84', '\x92', '\x85'
	};
	int cols = core->print->cols;
	if (cols < 1) {
		cols = 1;
	}
	for (int i = 0; i < len; i += cols) {
		rz_print_addr(core->print, core->offset + i);
		for (int j = i; j < i + cols; j += 1) {
			ut8 *p = (ut8 *)core->block + j;
			if (j < len) {
				rz_cons_printf("\xf0\x9f%c%c ", emoji[*p * 2], emoji[*p * 2 + 1]);
			} else {
				rz_cons_print("  ");
			}
		}
		rz_cons_print(" ");
		for (int j = i; j < len && j < i + cols; j += 1) {
			ut8 *p = (ut8 *)core->block + j;
			rz_print_byte(core->print, "%c", j, *p);
		}
		rz_cons_newline();
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_hexdump_function_handler(RzCore *core, int argc, const char **argv) {
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_print_hexdump_hexii_handler(RzCore *core, int argc, const char **argv) {
	core->print->show_offset = rz_config_get_i(core->config, "hex.offset");
	rz_print_hexii(core->print, core->offset, core->block,
		(int)core->blocksize, rz_config_get_i(core->config, "hex.cols"));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_hexword_references_common_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state, int wordsize) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	const char *query = argc > 2 ? argv[2] : NULL;
	switch (wordsize) {
	case 1:
	case 2:
	case 4:
	case 8:
		cmd_pxr(core, len, state, wordsize, query);
		break;
	default:
		rz_warn_if_reached();
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_hexword_references_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int wordsize = rz_analysis_get_address_bits(core->analysis) / 8;
	return rz_print_hexword_references_common_handler(core, argc, argv, state, wordsize);
}

RZ_IPI RzCmdStatus rz_print_hexword_references_1_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_print_hexword_references_common_handler(core, argc, argv, state, 1);
}

RZ_IPI RzCmdStatus rz_print_hexword_references_2_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_print_hexword_references_common_handler(core, argc, argv, state, 2);
}

RZ_IPI RzCmdStatus rz_print_hexword_references_4_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_print_hexword_references_common_handler(core, argc, argv, state, 4);
}

RZ_IPI RzCmdStatus rz_print_hexword_references_8_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_print_hexword_references_common_handler(core, argc, argv, state, 8);
}

RZ_IPI RzCmdStatus rz_print_hexdump_sparse_handler(RzCore *core, int argc, const char **argv) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	if (!len) {
		return RZ_CMD_STATUS_OK;
	}
	core->print->flags |= RZ_PRINT_FLAGS_SPARSE;
	rz_core_print_hexdump(core, core->offset, core->block, len, 16, 1, 1);
	core->print->flags &= (int)(((ut32)-1) & (~RZ_PRINT_FLAGS_SPARSE));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_delta_pointer_table_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	if (!len) {
		return RZ_CMD_STATUS_OK;
	}
	ut64 origin = argc > 2 ? rz_num_math(core->num, argv[2]) : core->offset;
	// _pointer_table does rz_core_cmd with @, so it modifies core->block
	// and this results in an UAF access when iterating over the jmptable
	// so we do a new allocation to avoid that issue
	ut8 *block = calloc(len, 1);
	if (!block) {
		return RZ_CMD_STATUS_ERROR;
	}
	memcpy(block, core->block, len);
	_pointer_table(core, origin, core->offset, block, len, 4, state->mode);
	free(block);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_hexdump_hexless_bytes_handler(RzCore *core, int argc, const char **argv) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	core->print->flags |= RZ_PRINT_FLAGS_NONHEX;
	rz_core_print_hexdump(core, core->offset,
		core->block, len, 8, 1, 1);
	core->print->flags &= ~RZ_PRINT_FLAGS_NONHEX;
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_hexdump_hexless_words_handler(RzCore *core, int argc, const char **argv) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	if (!len) {
		return RZ_CMD_STATUS_OK;
	}
	ut8 *buf = calloc(len, 4);
	if (!buf) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_io_read_at(core->io, core->offset, buf, len * 4);
	core->print->flags |= RZ_PRINT_FLAGS_NONHEX;
	rz_core_print_hexdump(core, core->offset, buf, len * 4, 8, 1, 1);
	core->print->flags &= ~RZ_PRINT_FLAGS_NONHEX;
	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_hexdump_hexpair_bytes_handler(RzCore *core, int argc, const char **argv) {
	int len = (int)rz_str_nlen((const char *)core->block, core->blocksize);
	if (!len) {
		return RZ_CMD_STATUS_OK;
	}
	rz_print_bytes(core->print, core->block, len, "%02x");
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_hexdump_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(rz_core_print_hexdump_or_hexdiff(core, state->mode, core->offset, len, false));
}

RZ_IPI RzCmdStatus rz_print_hexdump_n_lines_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(rz_core_print_hexdump_or_hexdiff(core, state->mode, core->offset, core->print->cols * len, false));
}

RZ_IPI RzCmdStatus rz_print_hexdump_hex_common_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state, ut8 n) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(rz_core_print_dump(core, state->mode, core->offset, n, len, RZ_CORE_PRINT_FORMAT_TYPE_HEXADECIMAL));
}

RZ_IPI RzCmdStatus rz_print_hexdump_hex2_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_print_hexdump_hex_common_handler(core, argc, argv, state, 2);
}
RZ_IPI RzCmdStatus rz_print_hexdump_hex4_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_print_hexdump_hex_common_handler(core, argc, argv, state, 4);
}
RZ_IPI RzCmdStatus rz_print_hexdump_hex8_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_print_hexdump_hex_common_handler(core, argc, argv, state, 8);
}

RZ_IPI RzCmdStatus rz_print_hexdump_hexl_common_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state, ut8 n) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	bool hex_offset = rz_config_get_b(core->config, "hex.offset");
	bool quiet = state->mode == RZ_OUTPUT_MODE_QUIET || state->mode == RZ_OUTPUT_MODE_QUIETEST;
	return bool2status(rz_core_print_hexdump_byline(core, !quiet && hex_offset, core->offset, len, n));
}

RZ_IPI RzCmdStatus rz_print_hexdump_hex2l_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_print_hexdump_hexl_common_handler(core, argc, argv, state, 2);
}
RZ_IPI RzCmdStatus rz_print_hexdump_hex4l_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_print_hexdump_hexl_common_handler(core, argc, argv, state, 4);
}
RZ_IPI RzCmdStatus rz_print_hexdump_hex8l_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_print_hexdump_hexl_common_handler(core, argc, argv, state, 8);
}

RZ_IPI RzCmdStatus rz_print_hexdump_oct_handler(RzCore *core, int argc, const char **argv) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(rz_core_print_dump(core, RZ_OUTPUT_MODE_STANDARD, core->offset, 1, len, RZ_CORE_PRINT_FORMAT_TYPE_OCTAL));
}

#define CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL(name, type) \
	RZ_IPI RzCmdStatus name(RzCore *core, int argc, const char **argv) { \
        const int size = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize; \
		char *code = rz_lang_byte_array(core->block, size, core->blocksize_max, type); \
		if (RZ_STR_ISNOTEMPTY(code)) { \
			rz_cons_println(code); \
		} \
		RzCmdStatus result = code ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR; \
		free(code); \
		return result; \
	}

#define CMD_PRINT_BYTE_ARRAY_HANDLER_ENDIAN(name, type) \
	RZ_IPI RzCmdStatus name(RzCore *core, int argc, const char **argv) { \
		bool big_endian = rz_config_get_b(core->config, "cfg.bigendian"); \
		char *code = rz_lang_byte_array(core->block, core->blocksize, core->blocksize, big_endian ? type##_BE : type##_LE); \
		if (RZ_STR_ISNOTEMPTY(code)) { \
			rz_cons_println(code); \
		} \
		RzCmdStatus result = code ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR; \
		free(code); \
		return result; \
	}

CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL(rz_cmd_print_byte_array_rizin_handler, RZ_LANG_BYTE_ARRAY_RIZIN);
CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL(rz_cmd_print_byte_array_asm_handler, RZ_LANG_BYTE_ARRAY_ASM);
CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL(rz_cmd_print_byte_array_bash_handler, RZ_LANG_BYTE_ARRAY_BASH);
CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL(rz_cmd_print_byte_array_c_cpp_bytes_handler, RZ_LANG_BYTE_ARRAY_C_CPP_BYTES);
CMD_PRINT_BYTE_ARRAY_HANDLER_ENDIAN(rz_cmd_print_byte_array_c_cpp_half_word_handler, RZ_LANG_BYTE_ARRAY_C_CPP_HALFWORDS);
CMD_PRINT_BYTE_ARRAY_HANDLER_ENDIAN(rz_cmd_print_byte_array_c_cpp_word_handler, RZ_LANG_BYTE_ARRAY_C_CPP_WORDS);
CMD_PRINT_BYTE_ARRAY_HANDLER_ENDIAN(rz_cmd_print_byte_array_c_cpp_double_word_handler, RZ_LANG_BYTE_ARRAY_C_CPP_DOUBLEWORDS);
CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL(rz_cmd_print_byte_array_golang_handler, RZ_LANG_BYTE_ARRAY_GOLANG);
CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL(rz_cmd_print_byte_array_java_handler, RZ_LANG_BYTE_ARRAY_JAVA);
CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL(rz_cmd_print_byte_array_json_handler, RZ_LANG_BYTE_ARRAY_JSON);
CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL(rz_cmd_print_byte_array_kotlin_handler, RZ_LANG_BYTE_ARRAY_KOTLIN);
CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL(rz_cmd_print_byte_array_nodejs_handler, RZ_LANG_BYTE_ARRAY_NODEJS);
CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL(rz_cmd_print_byte_array_objc_handler, RZ_LANG_BYTE_ARRAY_OBJECTIVE_C);
CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL(rz_cmd_print_byte_array_python_handler, RZ_LANG_BYTE_ARRAY_PYTHON);
CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL(rz_cmd_print_byte_array_rust_handler, RZ_LANG_BYTE_ARRAY_RUST);
CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL(rz_cmd_print_byte_array_swift_handler, RZ_LANG_BYTE_ARRAY_SWIFT);
CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL(rz_cmd_print_byte_array_yara_handler, RZ_LANG_BYTE_ARRAY_YARA);
#undef CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL
#undef CMD_PRINT_BYTE_ARRAY_HANDLER_ENDIAN

RZ_IPI RzCmdStatus rz_cmd_print_byte_array_with_inst_handler(RzCore *core, int argc, const char **argv) {
	rz_core_block_read(core);
    const int size = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize; \
	char *code = rz_core_print_bytes_with_inst(core, core->block, core->offset, size);
	if (!code) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(code);
	free(code);
	return RZ_CMD_STATUS_OK;
}

static void disassembly_as_table(RzTable *t, RzCore *core, int n_instrs, int n_bytes) {
	ut8 buffer[256];
	rz_table_set_columnsf(t, "snssssss", "name", "addr", "bytes", "disasm", "comment", "esil", "refs", "xrefs");
	const int minopsz = 1;
	const int options = RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT | RZ_ANALYSIS_OP_MASK_DISASM | RZ_ANALYSIS_OP_MASK_ESIL;
	const int addrbytes = core->io->addrbytes;
	ut64 offset = core->offset;
	ut64 inc = 0;
	for (int i = 0, j = 0; rz_disasm_check_end(n_instrs, i, n_bytes, j * addrbytes); i++, offset += inc, j += inc) {
		RzAnalysisOp *op = rz_core_analysis_op(core, offset, options);
		if (!op || op->size < 1) {
			i += minopsz;
			inc = minopsz;
			continue;
		}
		const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, offset);
		if (!comment) {
			comment = "";
		}
		rz_io_read_at(core->io, offset, buffer, RZ_MIN(op->size, sizeof(buffer)));
		char *bytes = rz_hex_bin2strdup(buffer, op->size);
		RzFlagItem *flag = rz_flag_get_i(core->flags, offset);
		char *function_name = flag ? flag->name : "";
		const char *esil = RZ_STRBUF_SAFEGET(&op->esil);
		char *refs = __op_refs(core, op, 0);
		char *xrefs = __op_refs(core, op, 1);
		rz_table_add_rowf(t, "sXssssss", function_name, offset, bytes, op->mnemonic, comment, esil, refs, xrefs);
		free(bytes);
		free(xrefs);
		free(refs);
		inc = op->size;
		rz_analysis_op_free(op);
	}
}

static bool core_disassembly(RzCore *core, int n_bytes, int n_instrs, RzCmdStateOutput *state, bool cbytes) {
	ut32 old_blocksize = core->blocksize;
	ut64 old_offset = core->offset;
	if (!rz_core_handle_backwards_disasm(core, &n_instrs, &n_bytes)) {
		return false;
	}

	RZ_LOG_VERBOSE("disassembly at: 0x%" PFMT64x " "
		       "blocksize: %" PFMT32d " "
		       "n_bytes: %" PFMT32d " "
		       "n_instrs: %" PFMT32d "\n",
		core->offset, core->blocksize, n_bytes, n_instrs);
	RzCoreDisasmOptions disasm_options = {
		.cbytes = cbytes,
	};
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		rz_core_print_disasm(core, core->offset, core->block, n_bytes,
			n_bytes > 0 && !n_instrs ? n_bytes : n_instrs, state, &disasm_options);
		break;
	case RZ_OUTPUT_MODE_TABLE:
		disassembly_as_table(state->d.t, core, n_instrs, n_bytes);
		break;
	case RZ_OUTPUT_MODE_JSON:
		rz_cmd_state_output_array_start(state);
		rz_core_print_disasm_json(core, core->offset, core->block, n_bytes, n_instrs, state->d.pj);
		rz_cmd_state_output_array_end(state);
		break;
	case RZ_OUTPUT_MODE_QUIET:
		rz_core_disasm_pdi(core, n_instrs, n_bytes, 0);
		break;
	default:
		rz_warn_if_reached();
		break;
	}

	rz_core_block_size(core, old_blocksize);
	if (core->offset != old_offset) {
		rz_core_seek(core, old_offset, true);
	}
	return true;
}

RZ_IPI RzCmdStatus rz_cmd_disassembly_n_bytes_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int n_bytes = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(core_disassembly(core, n_bytes, 0, state, true));
}

RZ_IPI RzCmdStatus rz_cmd_disassembly_n_instructions_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int n_instrs = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : 0;
	return bool2status(core_disassembly(core, argc > 1 && n_instrs == 0 ? 0 : (int)core->blocksize, n_instrs, state, false));
}

RZ_IPI RzCmdStatus rz_cmd_disassembly_all_possible_opcodes_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	ut64 n_bytes = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	ut8 *buffer = RZ_NEWS0(ut8, n_bytes);
	RzPVector *vec = NULL;
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	if (!buffer) {
		goto fail;
	}
	if (!rz_io_read_at(core->io, core->offset, buffer, n_bytes)) {
		goto fail;
	}
	vec = rz_core_disasm_all_possible_opcodes(core, buffer, core->offset, n_bytes);
	if (!vec) {
		goto fail;
	}

	bool color = rz_config_get_i(core->config, "scr.color") > 0;
	void **p;
	rz_cmd_state_output_array_start(state);
	rz_cons_break_push(NULL, NULL);
	rz_pvector_foreach (vec, p) {
		RzCoreDisasmOp *op = *p;
		switch (state->mode) {
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("0x%08" PFMT64x " %20s  %s\n", op->offset, op->hex, color ? op->assembly_colored : op->assembly);
			break;
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_kn(state->d.pj, "addr", op->offset);
			pj_ks(state->d.pj, "bytes", op->hex);
			pj_ks(state->d.pj, "inst", op->assembly);
			pj_end(state->d.pj);
			break;
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("%s\n", color ? op->assembly_colored : op->assembly);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_cons_break_pop();
	rz_cmd_state_output_array_end(state);

ret:
	free(buffer);
	rz_pvector_free(vec);
	return res;
fail:
	res = RZ_CMD_STATUS_ERROR;
	goto ret;
}

RZ_IPI RzCmdStatus rz_cmd_disassembly_all_possible_opcodes_treeview_handler(RzCore *core, int argc, const char **argv) {
#define TREEVIEW_N_BYTES 28
	ut8 buffer[TREEVIEW_N_BYTES];
	RzPVector *vec = NULL;
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	if (!rz_io_read_at(core->io, core->offset, buffer, TREEVIEW_N_BYTES)) {
		goto fail;
	}
	vec = rz_core_disasm_all_possible_opcodes(core, buffer, core->offset, TREEVIEW_N_BYTES);
	if (!vec) {
		goto fail;
	}

	bool color = rz_config_get_i(core->config, "scr.color") > 0;
	void **p;
	int position = 0;
	rz_pvector_foreach (vec, p) {
		RzCoreDisasmOp *op = *p;
		if (op->size < 1) {
			continue;
		}
		int padding = position * 2;
		int space = 60 - padding;
		if ((position + op->size) >= 30) {
			ut32 last = (30 - position) * 2;
			op->hex[last - 1] = '.';
			op->hex[last] = 0;
		}
		rz_cons_printf("0x%08" PFMT64x " %*s%*s %s\n", op->offset, padding, "", -space, op->hex, color ? op->assembly_colored : op->assembly);
		position++;
	}

ret:
	rz_pvector_free(vec);
	return res;
fail:
	res = RZ_CMD_STATUS_ERROR;
	goto ret;
}

RZ_IPI RzCmdStatus rz_cmd_disassembly_basic_block_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisBlock *b = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
	core->num->value = 0;
	if (!b) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}

	ut8 *block = malloc(b->size + 1);
	if (!block) {
		RZ_LOG_ERROR("Cannot allocate buffer\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_io_read_at(core->io, b->addr, block, b->size);
	RzCoreDisasmOptions disasm_options = {
		.cbytes = 2,
	};
	rz_cmd_state_output_array_start(state);
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		core->num->value = rz_core_print_disasm(core, b->addr, block, b->size, 9999, state, &disasm_options);
		break;
	case RZ_OUTPUT_MODE_JSON:
		core->num->value = 1;
		rz_core_print_disasm_json(core, b->addr, block, b->size, 0, state->d.pj);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	rz_cmd_state_output_array_end(state);

	free(block);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_disassembly_basic_block_as_text_json_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisBlock *b = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
	core->num->value = 0;
	if (!b) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}

	ut8 *block = malloc(b->size + 1);
	if (!block) {
		RZ_LOG_ERROR("Cannot allocate buffer\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_io_read_at(core->io, b->addr, block, b->size);
	RzCoreDisasmOptions disasm_options = {
		.cbytes = 2,
	};
	core->num->value = rz_core_print_disasm(core, b->addr, block, b->size, 9999, state, &disasm_options);

	free(block);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_comments_in_n_instructions_handler(RzCore *core, int argc, const char **argv) {
	st64 parsed = argc > 1 ? (st64)rz_num_math(core->num, argv[1]) : core->blocksize;
	if (parsed > ST16_MAX || parsed < ST16_MIN) {
		RZ_LOG_ERROR("the number of instructions is too big (%d < n_instrs < %d).\n", ST16_MAX, ST16_MIN);
		return RZ_CMD_STATUS_ERROR;
	}
	int n_instrs = parsed;
	if (rz_core_disasm_pdi(core, n_instrs, 0, 'C') < 0) {
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_disassembly_n_instructions_with_flow_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	st64 parsed = argc > 1 ? (st64)rz_num_math(core->num, argv[1]) : (core->blocksize / 4);
	if (parsed > ST16_MAX || parsed < ST16_MIN) {
		RZ_LOG_ERROR("the number of instructions is too big (%d < n_instrs < %d).\n", ST16_MAX, ST16_MIN);
		return RZ_CMD_STATUS_ERROR;
	}
	int n_instrs = parsed;
	// this command is going to be removed when esil will be removed.
	rz_core_disasm_pde(core, n_instrs, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_disassembly_function_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	core->num->value = 0;
	ut32 old_blocksize = core->blocksize;
	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_ROOT);
	if (!function) {
		function = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	}
	if (!function) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}

	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		bool ret = rz_core_print_function_disasm_json(core, function, state->d.pj);
		rz_core_block_size(core, old_blocksize);
		return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
	}

	ut64 linear_size = rz_analysis_function_linear_size(function);
	ut64 max_real_size = rz_analysis_function_realsize(function) + 4096;
	if (max_real_size < linear_size) {
		RZ_LOG_ERROR("Linear size differs too much from the bbsum, please use pdr instead.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	ut64 start = function->addr; // For pdf, start disassembling at the entrypoint
	ut64 end = rz_analysis_function_max_addr(function);
	if (end <= start) {
		RZ_LOG_ERROR("Cannot print function because the end offset is less or equal to the start offset\n");
		return RZ_CMD_STATUS_ERROR;
	}

	ut64 size = end - start;
	ut8 *bytes = malloc(size);
	if (!bytes) {
		RZ_LOG_ERROR("Cannot allocate buffer\n");
		return RZ_CMD_STATUS_ERROR;
	}

	(void)rz_io_read_at(core->io, start, bytes, size);
	RzCoreDisasmOptions disasm_options = {
		.cbytes = 1,
		.function = function,
	};
	core->num->value = rz_core_print_disasm(core, start, bytes, size, size, state, &disasm_options);
	free(bytes);

	rz_core_block_size(core, old_blocksize);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_function_rzil_handler(RzCore *core, int argc, const char **argv) {
	ut64 oldoff = core->offset;
	RzList *list = rz_analysis_get_functions_in(core->analysis, core->offset);
	if (rz_list_empty(list)) {
		RZ_LOG_ERROR("No function found in 0x%08" PFMT64x ".\n", core->offset);
		goto exit;
	}
	if (rz_list_length(list) > 1) {
		RZ_LOG_ERROR("Multiple overlapping functions found at 0x%" PFMT64x ". "
			     "Re-run this command at the entrypoint of one of them to disambiguate.\n",
			core->offset);
		goto exit;
	}
	RzAnalysisFunction *fcn = rz_list_first(list);
	if (!fcn) {
		rz_warn_if_reached();
	}

	ut64 start = fcn->addr;
	ut64 end = rz_analysis_function_max_addr(fcn);
	if (end <= start) {
		RZ_LOG_ERROR("Cannot print function because the end offset is less or equal to the start offset\n");
		goto exit;
	}

	ut64 size = end - start;
	rz_core_seek(core, start, true);
	rz_core_analysis_bytes_il(core, core->block, size, 0, false);
	rz_core_seek(core, oldoff, true);
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
exit:
	rz_list_free(list);
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_disassembly_function_summary_handler(RzCore *core, int argc, const char **argv) {
	ut32 old_blocksize = core->blocksize;
	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
	if (!function) {
		RZ_LOG_ERROR("cannot find function at 0x%08" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	ut32 rs = rz_analysis_function_realsize(function);
	ut32 fs = rz_analysis_function_linear_size(function);
	rz_core_block_size(core, RZ_MAX(rs, fs));
	char *string = rz_core_print_disasm_strings(core, RZ_CORE_DISASM_STRINGS_MODE_INST, 0, function);
	rz_core_block_size(core, old_blocksize);
	if (!string) {
		RZ_LOG_ERROR("failed summarize %" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_print(string);
	free(string);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_disassembly_n_instrs_as_text_json_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	ut32 old_blocksize = core->blocksize;
	ut64 old_offset = core->offset;
	core->num->value = 0;

	st64 parsed = argc > 1 ? (st64)rz_num_math(core->num, argv[1]) : 0;
	if (parsed > ST16_MAX || parsed < ST16_MIN) {
		RZ_LOG_ERROR("the number of instructions is too big (%d < n_instrs < %d).\n", ST16_MAX, ST16_MIN);
		return RZ_CMD_STATUS_ERROR;
	}
	int n_instrs = parsed;
	if (n_instrs < 0) {
		ut64 new_offset = old_offset;
		if (!rz_core_prevop_addr(core, old_offset, -n_instrs, &new_offset)) {
			new_offset = rz_core_prevop_addr_force(core, old_offset, -n_instrs);
		}
		ut32 new_blocksize = new_offset - old_blocksize;
		if (new_blocksize > old_blocksize) {
			rz_core_block_size(core, new_blocksize);
		}
		rz_core_seek(core, new_offset, true);
	} else {
		rz_core_block_read(core);
	}

	state->mode = RZ_OUTPUT_MODE_JSON;

	if (rz_cons_singleton()->is_html) {
		rz_cons_singleton()->is_html = false;
		rz_cons_singleton()->was_html = true;
	}
	RzCoreDisasmOptions disasm_options = {
		.cbytes = 1,
	};
	core->num->value = rz_core_print_disasm(core, core->offset, core->block, core->blocksize, RZ_ABS(n_instrs), state, &disasm_options);

	if (n_instrs < 0) {
		rz_core_block_size(core, old_blocksize);
		rz_core_seek(core, old_offset, true);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_disassembly_all_methods_class_handler(RzCore *core, int argc, const char **argv) {
	ut32 old_blocksize = core->blocksize;
	ut64 old_offset = core->offset;

	int len = 0;
	ut64 at = findClassBounds(core, &len);
	if (!at) {
		RZ_LOG_ERROR("Cannot find class at 0x%" PFMT64x ".\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}

	rz_core_seek(core, at, true);

	// TODO: remove this and use C api.
	// on success returns 0 else negative
	int ret = rz_core_cmdf(core, "pD %d", len);

	rz_core_block_size(core, old_blocksize);
	rz_core_seek(core, old_offset, true);
	return ret >= 0 ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_sizes_of_n_instructions_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	ut32 old_blocksize = core->blocksize;
	ut64 old_offset = core->offset;
	st64 ret = 0;

	st64 parsed = argc > 1 ? (st64)rz_num_math(core->num, argv[1]) : (core->blocksize / 4);
	if (parsed > ST16_MAX || parsed < ST16_MIN) {
		RZ_LOG_ERROR("the number of instructions is too big (%d < n_instrs < %d).\n", ST16_MAX, ST16_MIN);
		return RZ_CMD_STATUS_ERROR;
	}
	int n_instrs = parsed;
	if (n_instrs < 0) {
		ut64 new_offset = old_offset;
		if (!rz_core_prevop_addr(core, old_offset, -n_instrs, &new_offset)) {
			new_offset = rz_core_prevop_addr_force(core, old_offset, -n_instrs);
		}
		ut32 new_blocksize = new_offset - old_blocksize;
		if (new_blocksize > old_blocksize) {
			rz_core_block_size(core, new_blocksize);
		}
		rz_core_seek(core, new_offset, true);
	} else {
		rz_core_block_read(core);
	}

	rz_cmd_state_output_array_start(state);
	rz_cons_break_push(NULL, NULL);
	for (ut32 i = 0, j = 0; i < core->blocksize && j < RZ_ABS(n_instrs); i += ret, j++) {
		RzAsmOp asm_op = { 0 };
		ret = rz_asm_disassemble(core->rasm, &asm_op, core->block + i, core->blocksize - i);
		if (rz_cons_is_breaked()) {
			break;
		}
		// be sure to return 0 when it fails to disassemble the
		// instruction to uniform the output across all disassemblers.
		int op_size = ret < 1 ? 0 : ret;
		switch (state->mode) {
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("%d\n", op_size);
			break;
		case RZ_OUTPUT_MODE_JSON:
			pj_N(state->d.pj, op_size);
			break;
		default:
			rz_warn_if_reached();
			return RZ_CMD_STATUS_ERROR;
		}
		if (ret < 1) {
			ret = 1;
		}
	}
	rz_cons_break_pop();
	rz_cmd_state_output_array_end(state);

	if (n_instrs < 0) {
		rz_core_block_size(core, old_blocksize);
		rz_core_seek(core, old_offset, true);
	}
	return RZ_CMD_STATUS_OK;
}

static void disassemble_till_return_is_found(RzCore *core, ut64 offset, ut64 limit, RzCmdStateOutput *state) {
	bool src_color = rz_config_get_i(core->config, "scr.color") > 0;
	const char *off_color = src_color ? rz_cons_singleton()->context->pal.b0x00 : "";
	const char *ret_color = src_color ? rz_cons_singleton()->context->pal.jmp : "";
	const char *end_color = src_color ? Color_RESET : "";

	for (ut64 i = 0; i < limit; i++) {
		RzAnalysisOp *op = rz_core_analysis_op(core, offset, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_DISASM);
		if (!op) {
			return;
		}

		switch (state->mode) {
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("%s%s%s\n", ret_color, op->mnemonic, end_color);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("%s0x%08" PFMT64x "%s %-11s%s\n", off_color, core->offset + i, ret_color, op->mnemonic, end_color);
			break;
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_ks(state->d.pj, "mnemonic", op->mnemonic);
			pj_kn(state->d.pj, "address", core->offset + i);
			pj_end(state->d.pj);
			break;
		default:
			rz_warn_if_reached();
			break;
		}

		if (!(op->type & (RZ_ANALYSIS_OP_TYPE_RET | RZ_ANALYSIS_OP_TYPE_UJMP))) {
			rz_analysis_op_free(op);
			return;
		}

		if (op->type == RZ_ANALYSIS_OP_TYPE_JMP) {
			offset = op->jump;
		} else {
			offset += op->size;
		}

		rz_analysis_op_free(op);
	}
}

RZ_IPI RzCmdStatus rz_cmd_disassemble_ropchain_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	ut64 limit = argc > 1 ? rz_num_math(core->num, argv[1]) : 1024;
	if (limit > 1024) {
		RZ_LOG_ERROR("the limit value exceeds the max value (1024).\n");
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 asm_bits = core->rasm->bits;
	bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");
	bool src_color = rz_config_get_i(core->config, "scr.color") > 0;

	const char *off_color = src_color ? rz_cons_singleton()->context->pal.offset : "";
	const char *num_color = src_color ? rz_cons_singleton()->context->pal.num : "";
	const char *end_color = src_color ? Color_RESET : "";

	if (asm_bits < 64) {
		asm_bits = 32;
	}

	ut32 asm_bytes = asm_bits / 8;
	if (core->blocksize < asm_bytes) {
		RZ_LOG_ERROR("block size is not enough big to host a word (needs to be >= %u bytes).\n", asm_bytes);
		return RZ_CMD_STATUS_ERROR;
	}

	ut8 *bytes = RZ_NEWS0(ut8, core->blocksize);
	if (!bytes) {
		RZ_LOG_ERROR("cannot allocate buffer.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	(void)rz_io_read_at(core->io, core->offset, bytes, core->blocksize);

	rz_cmd_state_output_array_start(state);
	for (ut32 i = 0; i < core->blocksize - asm_bytes; i += asm_bytes) {
		ut64 number = rz_read_ble(bytes + i, big_endian, asm_bits);
		switch (state->mode) {
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("%s0x%08" PFMT64x "%s %s0x%08" PFMT64x "%s\n", off_color, core->offset + i, end_color, num_color, number, end_color);
			disassemble_till_return_is_found(core, core->offset + i, limit, state);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("[%s0x%08" PFMT64x "%s] %s0x%08" PFMT64x "%s\n", off_color, core->offset + i, end_color, num_color, number, end_color);
			disassemble_till_return_is_found(core, core->offset + i, limit, state);
			break;
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_kn(state->d.pj, "address", core->offset + i);
			pj_kn(state->d.pj, "bits", asm_bits);
			pj_kn(state->d.pj, "word", number);
			pj_ka(state->d.pj, "opcodes");
			disassemble_till_return_is_found(core, core->offset + i, limit, state);
			pj_end(state->d.pj);
			pj_end(state->d.pj);
			break;
		default:
			rz_warn_if_reached();
			return RZ_CMD_STATUS_ERROR;
		}
	}
	rz_cmd_state_output_array_end(state);

	return RZ_CMD_STATUS_OK;
}

static bool core_walk_function_blocks(RzCore *core, RzAnalysisFunction *f, RzCmdStateOutput *state, char type_print, bool fromHere) {
	RzListIter *iter;
	RzAnalysisBlock *b = NULL;
	const bool orig_bb_middle = rz_config_get_b(core->config, "asm.bb.middle");
	rz_config_set_b(core->config, "asm.bb.middle", false);

	if (rz_list_length(f->bbs) >= 1) {
		ut32 fcn_size = rz_analysis_function_realsize(f);
		b = rz_list_get_top(f->bbs);
		if (b->size > fcn_size) {
			b->size = fcn_size;
		}
	}

	rz_list_sort(f->bbs, (RzListComparator)bbcmp);
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		rz_list_foreach (f->bbs, iter, b) {
			ut8 *buf = malloc(b->size);
			if (!buf) {
				RZ_LOG_ERROR("cannot allocate %" PFMT64u " byte(s)\n", b->size);
				return false;
			}
			(void)rz_io_read_at(core->io, b->addr, buf, b->size);
			rz_core_print_disasm_json(core, b->addr, buf, b->size, 0, state->d.pj);
			free(buf);
		}
	} else {
		bool asm_lines = rz_config_get_i(core->config, "asm.lines.bb");
		bool emu = rz_config_get_i(core->config, "asm.emu");
		ut64 saved_gp = 0;
		ut8 *saved_arena = NULL;
		if (emu) {
			saved_gp = core->analysis->gp;
			saved_arena = rz_reg_arena_peek(core->analysis->reg);
		}
		rz_config_set_i(core->config, "asm.lines.bb", 0);
		rz_list_foreach (f->bbs, iter, b) {
			pr_bb(core, f, b, emu, saved_gp, saved_arena, type_print, fromHere);
		}
		if (emu) {
			core->analysis->gp = saved_gp;
			if (saved_arena) {
				rz_reg_arena_poke(core->analysis->reg, saved_arena);
				RZ_FREE(saved_arena);
			}
		}
		rz_config_set_i(core->config, "asm.lines.bb", asm_lines);
	}
	rz_config_set_b(core->config, "asm.bb.middle", orig_bb_middle);
	return true;
}

RZ_IPI RzCmdStatus rz_cmd_disassemble_recursively_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	// RZ_ANALYSIS_FCN_TYPE_FCN|RZ_ANALYSIS_FCN_TYPE_SYM);
	if (!function) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}

	rz_cmd_state_output_array_start(state);
	bool ret = core_walk_function_blocks(core, function, state, 'D', false);
	rz_cmd_state_output_array_end(state);
	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_disassemble_recursively_from_current_block_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	// RZ_ANALYSIS_FCN_TYPE_FCN|RZ_ANALYSIS_FCN_TYPE_SYM);
	if (!function) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}

	rz_cmd_state_output_array_start(state);
	bool ret = core_walk_function_blocks(core, function, state, 'D', true);
	rz_cmd_state_output_array_end(state);
	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_disassemble_recursively_no_function_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	ut64 old_offset = core->offset;
	RzAnalysisOp aop = { 0 };
	ut32 aop_type;
	ut64 aop_jump;
	int aop_size;

	rz_cmd_state_output_array_start(state);
	for (ut64 count = core->blocksize, offset = core->offset; count > 0; count--) {
		rz_core_seek(core, offset, true);

		rz_analysis_op_init(&aop);
		int ret = rz_analysis_op(core->analysis, &aop, offset, core->block, core->blocksize, RZ_ANALYSIS_OP_MASK_BASIC);
		if (ret > 0) {
			aop_type = aop.type;
			aop_jump = aop.jump;
			aop_size = aop.size;
		}
		rz_analysis_op_fini(&aop);

		if (ret < 1 || aop_size < 1) {
			offset++;
			continue;
		}

		core_disassembly(core, core->blocksize, 1, state, false);

		switch (aop_type) {
		case RZ_ANALYSIS_OP_TYPE_JMP:
			offset = aop_jump;
			continue;
		case RZ_ANALYSIS_OP_TYPE_UCJMP:
			break;
		case RZ_ANALYSIS_OP_TYPE_RET:
			count = 1; // stop disassembling when hitting RET
			break;
		default:
			break;
		}
		offset += aop_size;
	}
	rz_cmd_state_output_array_end(state);

	rz_core_seek(core, old_offset, true);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_disassemble_summarize_n_bytes_handler(RzCore *core, int argc, const char **argv) {
	ut64 n_bytes = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;

	// small patch to reuse rz_core_print_disasm_strings which
	// needs to be rewritten entirely
	char *string = rz_core_print_disasm_strings(core, argc > 1 ? RZ_CORE_DISASM_STRINGS_MODE_BYTES : RZ_CORE_DISASM_STRINGS_MODE_INST, n_bytes, NULL);
	if (!string) {
		RZ_LOG_ERROR("failed summarize bytes %" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_print(string);
	free(string);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_disassemble_summarize_function_handler(RzCore *core, int argc, const char **argv) {
	char *string = rz_core_print_disasm_strings(core, RZ_CORE_DISASM_STRINGS_MODE_FUNCTION, 0, NULL);
	if (!string) {
		RZ_LOG_ERROR("failed summarize function %" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_print(string);
	free(string);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_disassemble_summarize_block_handler(RzCore *core, int argc, const char **argv) {
	// small patch to reuse rz_core_print_disasm_strings which
	// needs to be rewritten entirely
	char *string = rz_core_print_disasm_strings(core, RZ_CORE_DISASM_STRINGS_MODE_BLOCK, 0, NULL);
	if (!string) {
		RZ_LOG_ERROR("failed summarize block %" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_print(string);
	free(string);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_base64_encode_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	char *buf = rz_base64_encode_dyn((const unsigned char *)core->block, core->blocksize);
	if (!buf) {
		RZ_LOG_ERROR("rz_base64_encode_dyn: error\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println((const char *)buf);
	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_base64_decode_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	ut8 *buf = rz_base64_decode_dyn((const char *)core->block, core->blocksize);
	if (!buf) {
		RZ_LOG_ERROR("rz_base64_decode_dyn: error\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println((const char *)buf);
	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_bitstream_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	int len = (int)rz_num_math(core->num, argv[1]);
	int skip = (int)rz_num_math(core->num, argv[2]);
	if (len < 0 || skip < 0) {
		RZ_LOG_ERROR("len and skip should be positive numbers\n");
		return RZ_CMD_STATUS_ERROR;
	}
	// `pb len skip` means skip <skip> bits then print <len> bits
	char *buf = RZ_NEWS0(char, len + skip + 1);
	if (!buf) {
		RZ_LOG_ERROR("Fail to allocate memory\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_str_bits(buf, core->block, len + skip, NULL);
	rz_cons_println(buf + skip);
	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_byte_bitstream_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	ut64 start = core->offset;
	int len = (int)rz_num_math(core->num, argv[1]);
	if (len < 0) {
		start = core->offset + len;
		len *= -1;
	}
	ut8 *bit_buf = RZ_NEWS0(ut8, len);
	char *str_buf = RZ_NEWS0(char, len * 8 + 1);
	if (!bit_buf || !str_buf) {
		RZ_LOG_ERROR("Fail to allocate memory\n");
		free(bit_buf);
		free(str_buf);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_io_read_at(core->io, start, bit_buf, len);
	rz_str_bits(str_buf, (const ut8 *)bit_buf, len * 8, NULL);
	rz_cons_println(str_buf);
	free(bit_buf);
	free(str_buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_print_asn1_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	RzASN1Object *asn1 = rz_asn1_object_parse(core->block, core->blocksize);
	if (!asn1) {
		RZ_LOG_ERROR("core: Malformed object: did you supply enough data?\ntry to change the block size (see b? or @!<size>)\n");
		return RZ_CMD_STATUS_ERROR;
	}
	char *res = rz_asn1_to_string(asn1, 0, mode == RZ_OUTPUT_MODE_STANDARD);
	rz_asn1_object_free(asn1);
	if (!res) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%s", res);
	free(res);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_print_protobuf_standard_handler(RzCore *core, int argc, const char **argv) {
	char *s = rz_protobuf_decode(core->block, core->blocksize, false);
	if (!s) {
		RZ_LOG_ERROR("core: Malformed object: did you supply enough data?\ntry to change the block size (see b? or @!<size>)\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%s", s);
	free(s);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_print_protobuf_verbose_handler(RzCore *core, int argc, const char **argv) {
	char *s = rz_protobuf_decode(core->block, core->blocksize, true);
	if (!s) {
		RZ_LOG_ERROR("core: Malformed object: did you supply enough data?\ntry to change the block size (see b? or @!<size>)\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%s", s);
	free(s);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_print_pkcs7_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	char *res = NULL;
	RzCMS *cms = rz_pkcs7_cms_parse(core->block, core->blocksize);
	if (!cms) {
		RZ_LOG_ERROR("core: Malformed object: did you supply enough data?\ntry to change the block size (see b? or @!<size>)\n");
	}

	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		rz_pkcs7_cms_json(cms, state->d.pj);
		break;
	default:
		res = rz_pkcs7_cms_to_string(cms);
		if (res) {
			rz_cons_printf("%s", res);
			free(res);
		}
		break;
	}
	rz_pkcs7_cms_free(cms);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_print_x509_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	char *res = NULL;
	RzStrBuf *sb = NULL;
	RzX509Certificate *x509 = rz_x509_certificate_parse2(core->block, core->blocksize);
	if (!x509) {
		RZ_LOG_ERROR("core: Malformed object: did you supply enough data?\ntry to change the block size (see b? or @!<size>)\n");
		return RZ_CMD_STATUS_ERROR;
	}

	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		rz_x509_certificate_json(state->d.pj, x509);
		break;
	default:
		sb = rz_strbuf_new(NULL);
		if (!sb) {
			RZ_LOG_ERROR("core: failed to allocate RzStrBuf\n");
			rz_x509_certificate_free(x509);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_x509_certificate_dump(x509, NULL, sb);
		res = rz_strbuf_drain(sb);
		if (res) {
			rz_cons_printf("%s", res);
			free(res);
		}
		break;
	}
	rz_x509_certificate_free(x509);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_print_axml_handler(RzCore *core, int argc, const char **argv) {
	char *s = rz_axml_decode(core->block, core->blocksize);
	if (!s) {
		RZ_LOG_ERROR("core: Malformed object: did you supply enough data?\ntry to change the block size (see b? or @!<size>)\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%s", s);
	free(s);
	return RZ_CMD_STATUS_OK;
}

typedef struct {
	ut64 size;
	ut64 repeat;
	bool useBytes;
} PrintValueOptions;

static void print_value_single(RzCore *core, PrintValueOptions *opts, ut64 address, ut64 value, RzCmdStateOutput *state) {
	switch (state->mode) {
	case RZ_OUTPUT_MODE_RIZIN:
		rz_cons_printf("f pval.0x%08" PFMT64x " @ %" PFMT64d "\n", address, value);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		switch (opts->size) {
		case 1:
			rz_cons_printf("0x%02" PFMT64x "\n", value);
			break;
		case 2:
			rz_cons_printf("0x%04" PFMT64x "\n", value);
			break;
		case 4:
			rz_cons_printf("0x%08" PFMT64x "\n", value);
			break;
		case 8:
			rz_cons_printf("0x%016" PFMT64x "\n", value);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		break;
	case RZ_OUTPUT_MODE_JSON: {
		// TODO: Use API instead of the command
		char *str = rz_core_cmd_str(core, "ps");
		rz_str_trim(str);
		char *p = str;
		if (p) {
			while (*p) {
				if (*p == '\\' && p[1] == 'x') {
					memmove(p, p + 4, strlen(p + 4) + 1);
				}
				p++;
			}
		}
		pj_o(state->d.pj);
		pj_k(state->d.pj, "value");
		switch (opts->size) {
		case 1:
		case 2:
			pj_i(state->d.pj, value);
			break;
		case 4:
		case 8:
			pj_n(state->d.pj, value);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		pj_ks(state->d.pj, "string", str);
		free(str);
		pj_end(state->d.pj);
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}
}

static bool print_value(RzCore *core, PrintValueOptions *opts, RzCmdStateOutput *state) {
	ut64 old_at = core->offset;
	ut8 *block = core->block;
	int blocksize = core->blocksize;
	ut8 *block_end = core->block + blocksize;

	bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");
	if (block + 8 >= block_end) {
		RZ_LOG_ERROR("core: block is truncated.\n");
		return false;
	}
	ut64 repeat = opts->repeat;
	if (opts->useBytes && opts->size > 0 && repeat > 0) {
		repeat /= opts->size;
	}
	ut64 at = old_at;
	rz_cmd_state_output_array_start(state);
	do {
		rz_core_seek(core, at, false);

		ut64 v = 0;
		switch (opts->size) {
		case 1:
			v = rz_read_ble8(block);
			block += opts->size;
			break;
		case 2:
			v = rz_read_ble16(block, big_endian);
			block += opts->size;
			break;
		case 4:
			v = rz_read_ble32(block, big_endian);
			block += opts->size;
			break;
		case 8:
			v = rz_read_ble64(block, big_endian);
			block += opts->size;
			break;
		case 0:
			v = rz_read_ble64(block, big_endian);
			opts->size = core->rasm->bits / 8;
			switch (core->rasm->bits / 8) {
			case 1: v &= UT8_MAX; break;
			case 2: v &= UT16_MAX; break;
			case 4: v &= UT32_MAX; break;
			case 8: v &= UT64_MAX; break;
			default: break;
			}
			block += core->rasm->bits / 8;
			break;
		}
		print_value_single(core, opts, at, v, state);
		repeat--;
		at += opts->size;
	} while (repeat > 0);
	rz_cmd_state_output_array_end(state);
	rz_core_seek(core, old_at, false);
	return true;
}

static RzCmdStatus print_value_size(RzCore *core, RzCmdStateOutput *state, int argc, const char **argv, ut64 size) {
	int repeat = argc > 1 ? rz_num_math(NULL, argv[1]) : 1;
	if (repeat < 0) {
		return RZ_CMD_STATUS_ERROR;
	}
	PrintValueOptions opts = {
		.size = size,
		.repeat = repeat,
		.useBytes = false
	};
	return bool2status(print_value(core, &opts, state));
}

RZ_IPI RzCmdStatus rz_print_value_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return print_value_size(core, state, argc, argv, 0);
}

RZ_IPI RzCmdStatus rz_print_value1_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return print_value_size(core, state, argc, argv, 1);
}

RZ_IPI RzCmdStatus rz_print_value2_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return print_value_size(core, state, argc, argv, 2);
}

RZ_IPI RzCmdStatus rz_print_value4_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return print_value_size(core, state, argc, argv, 4);
}

RZ_IPI RzCmdStatus rz_print_value8_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return print_value_size(core, state, argc, argv, 8);
}

RZ_IPI RzCmdStatus rz_print_url_encode_handler(RzCore *core, int argc, const char **argv) {
	ut64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	RzStrStringifyOpt opt = { 0 };
	opt.buffer = core->block;
	opt.length = len;
	opt.encoding = RZ_STRING_ENC_8BIT;
	opt.urlencode = true;
	core_print_raw_buffer(&opt);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_url_encode_wide_handler(RzCore *core, int argc, const char **argv) {
	ut64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	RzStrStringifyOpt opt = { 0 };
	opt.buffer = core->block;
	opt.length = len;
	opt.encoding = RZ_STRING_ENC_UTF16LE;
	opt.urlencode = true;
	core_print_raw_buffer(&opt);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_url_encode_zero_handler(RzCore *core, int argc, const char **argv) {
	ut64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	RzStrStringifyOpt opt = { 0 };
	opt.buffer = core->block;
	opt.length = len;
	opt.stop_at_nil = true;
	opt.encoding = RZ_STRING_ENC_8BIT;
	opt.urlencode = true;
	core_print_raw_buffer(&opt);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_pattern0_handler(RzCore *core, int argc, const char **argv) {
	st64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	if (len < 1) {
		RZ_LOG_ERROR("Invalid pattern length\n");
		return RZ_CMD_STATUS_ERROR;
	}
	for (st64 i = 0; i < len; i++) {
		rz_cons_print("00");
	}
	rz_cons_newline();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_pattern1_handler(RzCore *core, int argc, const char **argv) {
	st8 len = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	if (len < 1) {
		RZ_LOG_ERROR("Invalid pattern length\n");
		return RZ_CMD_STATUS_ERROR;
	}
	ut8 min = (core->offset & 0xff);
	for (ut8 i = 0; i < len; i++) {
		rz_cons_printf("%02x", i + min);
	}
	rz_cons_newline();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_pattern2_handler(RzCore *core, int argc, const char **argv) {
	st16 len = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	if (len < 1) {
		RZ_LOG_ERROR("Invalid pattern length\n");
		return RZ_CMD_STATUS_ERROR;
	}
	// TODO: honor cfg.bigendian
	ut16 min = (core->offset & 0xffff);
	for (ut16 i = 0; i < len; i++) {
		rz_cons_printf("%04x", i + min);
	}
	rz_cons_newline();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_pattern4_handler(RzCore *core, int argc, const char **argv) {
	st32 len = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	if (len < 1) {
		RZ_LOG_ERROR("Invalid pattern length\n");
		return RZ_CMD_STATUS_ERROR;
	}
	// TODO: honor cfg.bigendian
	ut32 min = (core->offset & UT32_MAX);
	for (ut32 i = 0; i < len; i++) {
		rz_cons_printf("%08" PFMT32x, i + min);
	}
	rz_cons_newline();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_pattern8_handler(RzCore *core, int argc, const char **argv) {
	st64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	if (len < 1) {
		RZ_LOG_ERROR("Invalid pattern length\n");
		return RZ_CMD_STATUS_ERROR;
	}
	// TODO: honor cfg.bigendian
	ut64 min = (core->offset);
	for (ut64 i = 0; i < len; i++) {
		rz_cons_printf("%016" PFMT64x, i + min);
	}
	rz_cons_newline();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_pattern_latin_alphabet_handler(RzCore *core, int argc, const char **argv) {
	st64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	if (len < 1) {
		RZ_LOG_ERROR("Invalid pattern length\n");
		return RZ_CMD_STATUS_ERROR;
	}
	size_t bs = 4;
	ut8 *buf = calloc(bs, 1);
	if (!buf) {
		RZ_LOG_ERROR("Cannot allocate buffer\n");
		return RZ_CMD_STATUS_ERROR;
	}
	for (st64 i = 0; i < len; i++) {
		incAlphaBuffer(buf, bs);
		for (st64 j = 0; j < bs; j++) {
			rz_cons_printf("%c", buf[j] ? buf[j] : 'A');
		}
		rz_cons_printf(" ");
	}
	rz_cons_newline();
	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_pattern_debrujin_handler(RzCore *core, int argc, const char **argv) {
	st64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	if (len < 1) {
		RZ_LOG_ERROR("Invalid pattern length\n");
		return RZ_CMD_STATUS_ERROR;
	}
	ut8 *buf = (ut8 *)rz_debruijn_pattern(len, 0, NULL);
	if (!buf) {
		RZ_LOG_ERROR("Cannot generate De Brujin pattern\n");
		return RZ_CMD_STATUS_ERROR;
	}
	for (st64 i = 0; i < len; i++) {
		rz_cons_printf("%02x", buf[i]);
	}
	rz_cons_newline();
	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_pattern_oxff_handler(RzCore *core, int argc, const char **argv) {
	st64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	if (len < 1) {
		RZ_LOG_ERROR("Invalid pattern length\n");
		return RZ_CMD_STATUS_ERROR;
	}
	for (st64 i = 0; i < len; i++) {
		rz_cons_print("ff");
	}
	rz_cons_newline();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_pattern_num_handler(RzCore *core, int argc, const char **argv) {
	st64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	if (len < 1) {
		RZ_LOG_ERROR("Invalid pattern length\n");
		return RZ_CMD_STATUS_ERROR;
	}
	size_t bs = 4;
	ut8 *buf = calloc(bs, 1);
	if (!buf) {
		RZ_LOG_ERROR("Cannot allocate buffer\n");
		return RZ_CMD_STATUS_ERROR;
	}
	for (st64 i = 0; i < len; i++) {
		incDigitBuffer(buf, bs);
		for (st64 j = 0; j < bs; j++) {
			rz_cons_printf("%c", buf[j] ? buf[j] : '0');
		}
		rz_cons_printf(" ");
	}
	rz_cons_newline();
	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_operation_2swap_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(print_operation_transform(core, RZ_CORE_WRITE_OP_BYTESWAP2, NULL));
}

RZ_IPI RzCmdStatus rz_print_operation_4swap_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(print_operation_transform(core, RZ_CORE_WRITE_OP_BYTESWAP4, NULL));
}

RZ_IPI RzCmdStatus rz_print_operation_8swap_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(print_operation_transform(core, RZ_CORE_WRITE_OP_BYTESWAP8, NULL));
}

RZ_IPI RzCmdStatus rz_print_operation_add_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(print_operation_transform(core, RZ_CORE_WRITE_OP_ADD, argv[1]));
}

RZ_IPI RzCmdStatus rz_print_operation_and_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(print_operation_transform(core, RZ_CORE_WRITE_OP_AND, argv[1]));
}

RZ_IPI RzCmdStatus rz_print_operation_div_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(print_operation_transform(core, RZ_CORE_WRITE_OP_DIV, argv[1]));
}

RZ_IPI RzCmdStatus rz_print_operation_shl_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(print_operation_transform(core, RZ_CORE_WRITE_OP_SHIFT_LEFT, argv[1]));
}

RZ_IPI RzCmdStatus rz_print_operation_mul_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(print_operation_transform(core, RZ_CORE_WRITE_OP_MUL, argv[1]));
}

RZ_IPI RzCmdStatus rz_print_operation_or_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(print_operation_transform(core, RZ_CORE_WRITE_OP_OR, argv[1]));
}

RZ_IPI RzCmdStatus rz_print_operation_shr_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(print_operation_transform(core, RZ_CORE_WRITE_OP_SHIFT_RIGHT, argv[1]));
}

RZ_IPI RzCmdStatus rz_print_operation_sub_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(print_operation_transform(core, RZ_CORE_WRITE_OP_SUB, argv[1]));
}

RZ_IPI RzCmdStatus rz_print_operation_xor_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(print_operation_transform(core, RZ_CORE_WRITE_OP_XOR, argv[1]));
}

RZ_IPI RzCmdStatus rz_print_key_randomart_handler(RzCore *core, int argc, const char **argv) {
	ut64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	if (len == 0) {
		return RZ_CMD_STATUS_ERROR;
	}
	len = len > core->blocksize ? core->blocksize : len;
	char *s = rz_hash_cfg_randomart(core->block, len, core->offset);
	rz_cons_println(s);
	free(s);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_key_mosaic_handler(RzCore *core, int argc, const char **argv) {
	ut64 len = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	if (len == 0) {
		return RZ_CMD_STATUS_ERROR;
	}
	len = len > core->blocksize ? core->blocksize : len;
	int w, h;
	RzConsCanvas *c;
	w = rz_cons_get_size(&h);
	ut64 offset0 = core->offset;
	int cols = (w / 20);
	int rows = (h / 12);
	int i, j;
	char *s;
	if (rows < 1) {
		rows = 1;
	}
	c = rz_cons_canvas_new(w, rows * 11);
	for (i = 0; i < rows; i++) {
		for (j = 0; j < cols; j++) {
			rz_cons_canvas_gotoxy(c, j * 20, i * 11);
			core->offset += len;
			rz_io_read_at(core->io, core->offset, core->block, len);
			s = rz_hash_cfg_randomart(core->block, len, core->offset);
			rz_cons_canvas_write(c, s);
			free(s);
		}
	}
	rz_cons_canvas_print(c);
	rz_cons_canvas_free(c);
	rz_io_read_at(core->io, offset0, core->block, len);
	core->offset = offset0;
	rz_cons_printf("\n");
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_instr_handler(RzCore *core, int argc, const char **argv) {
	ut64 N = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	if (N == 0) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_print_disasm_instructions(core, 0, N);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_instr_opcodes_handler(RzCore *core, int argc, const char **argv) {
	ut64 N = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	if (N == 0) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_print_disasm_all(core, core->offset, N, N, 'i');
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_instr_block_handler(RzCore *core, int argc, const char **argv) {
	RzAnalysisBlock *b = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
	if (!b) {
		RZ_LOG_ERROR("core: Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		core->num->value = 0;
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_print_disasm_instructions(core, b->size - (core->offset - b->addr), 0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_instr_esil_handler(RzCore *core, int argc, const char **argv) {
	ut64 N = argc > 1 ? rz_num_math(core->num, argv[1]) : core->blocksize;
	if (N == 0) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_core_disasm_pdi(core, N, 0, 'e');
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_instr_function_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		return rz_cmd_disassembly_function_handler(core, argc, argv, state);
	}
	RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset,
		RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
	if (!f) {
		return RZ_CMD_STATUS_ERROR;
	}

	ut32 bsz = core->blocksize;
	// int fsz = rz_analysis_function_realsize (f);
	int fsz = rz_analysis_function_linear_size(f); // we want max-min here
	rz_core_block_size(core, fsz);
	rz_core_print_disasm_instructions(core, fsz, 0);
	rz_core_block_size(core, bsz);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_calls_function_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzListIter *iter;
	RzAnalysisXRef *xrefi;
	RzList *refs = NULL;

	rz_cmd_state_output_array_start(state);
	// get function in current offset
	RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset,
		RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);

	if (!f) {
		rz_cmd_state_output_array_end(state);
		return RZ_CMD_STATUS_ERROR;
	}

	// get all the calls of the function
	refs = rz_core_analysis_fcn_get_calls(core, f);
	if (rz_list_empty(refs)) {
		rz_cmd_state_output_array_end(state);
		rz_list_free(refs);
		return RZ_CMD_STATUS_OK;
	}

	// store current configurations
	RzConfigHold *hc = rz_config_hold_new(core->config);
	rz_config_hold_i(hc, "asm.offset", NULL);
	rz_config_hold_i(hc, "asm.comments", NULL);
	rz_config_hold_i(hc, "asm.tabs", NULL);
	rz_config_hold_i(hc, "asm.bytes", NULL);
	rz_config_hold_i(hc, "emu.str", NULL);

	// temporarily replace configurations
	rz_config_set_i(core->config, "asm.offset", false);
	rz_config_set_i(core->config, "asm.comments", false);
	rz_config_set_i(core->config, "asm.tabs", 0);
	rz_config_set_i(core->config, "asm.bytes", false);
	rz_config_set_i(core->config, "emu.str", false);

	// iterate over all call references
	rz_list_foreach (refs, iter, xrefi) {
		if (state->mode == RZ_OUTPUT_MODE_JSON) {
			RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, xrefi->to,
				RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
			char *dst = rz_str_newf((f ? f->name : "0x%08" PFMT64x), xrefi->to);
			char *dst2 = NULL;
			RzAnalysisOp *op = rz_core_analysis_op(core, xrefi->to, RZ_ANALYSIS_OP_MASK_BASIC);
			RzBinReloc *rel = rz_core_getreloc(core, xrefi->to, op->size);
			if (rel) {
				if (rel && rel->import && rel->import->name) {
					dst2 = rel->import->name;
				} else if (rel && rel->symbol && rel->symbol->name) {
					dst2 = rel->symbol->name;
				}
			} else {
				dst2 = dst;
			}
			pj_o(state->d.pj);
			pj_ks(state->d.pj, "dest", dst2);
			pj_kn(state->d.pj, "addr", xrefi->to);
			pj_kn(state->d.pj, "at", xrefi->from);
			pj_end(state->d.pj);
			rz_analysis_op_free(op);
			free(dst);
		} else {
			ut64 off = core->offset;
			rz_core_seek(core, xrefi->from, true);
			core_disassembly(core, 1, 1, state, false);
			rz_core_seek(core, off, true);
		}
	}

	rz_list_free(refs);

	// restore saved configuration
	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);

	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_instr_recursive_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset,
		RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
	if (!f) {
		RZ_LOG_ERROR("core: Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		core->num->value = 0;
		return RZ_CMD_STATUS_ERROR;
	}
	func_walk_blocks(core, f, false, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_instr_recursive_at_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset,
		RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
	if (!f) {
		RZ_LOG_ERROR("core: Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		core->num->value = 0;
		return RZ_CMD_STATUS_ERROR;
	}
	func_walk_blocks(core, f, true, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_instr_until_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	ut64 limit = argc > 1 ? rz_num_math(core->num, argv[1]) : 1024;
	disasm_until_ret(core, core->offset, limit, state->mode);
	return RZ_CMD_STATUS_OK;
}

typedef struct rz_core_analysis_stats_range_t {
	RzCoreAnalysisStats *as;
	ut64 from;
	ut64 to;
	ut64 piece;
} RzCoreAnalysisStatsRange;

static RzCoreAnalysisStatsRange *analysis_stats_range(RzCore *core, int width) {
	int cols = rz_config_get_i(core->config, "hex.cols");
	int w = RZ_MAX(cols, width);

	ut64 from = UT64_MAX;
	ut64 to = 0;

	RzList *list = rz_core_get_boundaries_prot(core, -1, NULL, "search");
	if (rz_list_empty(list)) {
		RZ_LOG_ERROR("No range to calculate stats for.\n");
		rz_list_free(list);
		return NULL;
	}
	RzCoreAnalysisStatsRange *srange = RZ_NEW0(RzCoreAnalysisStatsRange);
	if (!srange) {
		rz_list_free(list);
		return NULL;
	}
	RzListIter *iter;
	RzIOMap *map;
	rz_list_foreach (list, iter, map) {
		ut64 f = rz_itv_begin(map->itv);
		ut64 t = rz_itv_end(map->itv);
		if (f < from) {
			from = f;
		}
		if (t > to) {
			to = t;
		}
	}
	rz_list_free(list);
	srange->from = from;
	srange->to = to;

	ut64 piece = RZ_MAX((to - from) / w, 1);
	if (piece * w != to - from) {
		// add 1 to compute `piece = ceil((to - from) / w)` instead
		piece++;
	}
	srange->piece = piece;

	srange->as = rz_core_analysis_get_stats(core, from, to - 1, piece);
	return srange;
}

static void analysis_stats_range_free(RzCoreAnalysisStatsRange *srange) {
	if (!srange) {
		return;
	}
	rz_core_analysis_stats_free(srange->as);
	free(srange);
}

static void analysis_stats_standard_info(RzCore *core, RzCoreAnalysisStatsRange *srange, RzCoreAnalysisStatsItem *sitem, ut64 blockidx, bool use_color) {
	ut64 at = rz_core_analysis_stats_get_block_from(srange->as, blockidx);
	ut64 ate = rz_core_analysis_stats_get_block_to(srange->as, blockidx) + 1;
	if (core->offset >= at && core->offset < ate) {
		rz_cons_memcat("^", 1);
	} else {
		RzIOMap *s = rz_io_map_get(core->io, at);
		if (use_color) {
			if (s) {
				if (s->perm & RZ_PERM_X) {
					rz_cons_print(rz_cons_singleton()->context->pal.graph_ujump);
				} else {
					rz_cons_print(rz_cons_singleton()->context->pal.graph_true);
				}
			} else {
				rz_cons_print(rz_cons_singleton()->context->pal.graph_false);
			}
		}
		if (sitem->strings > 0) {
			rz_cons_memcat("z", 1);
		} else if (sitem->symbols > 0) {
			rz_cons_memcat("s", 1);
		} else if (sitem->functions > 0) {
			rz_cons_memcat("F", 1);
		} else if (sitem->comments > 0) {
			rz_cons_memcat("c", 1);
		} else if (sitem->flags > 0) {
			rz_cons_memcat(".", 1);
		} else if (sitem->in_functions > 0) {
			rz_cons_memcat("f", 1);
		} else {
			rz_cons_memcat("_", 1);
		}
	}
	if (use_color) {
		rz_cons_print(Color_RESET);
	}
}

static void analysis_stats_json_info(RzCore *core, RzCoreAnalysisStats *as, RzCoreAnalysisStatsItem *sitem, ut64 blockidx, RzCmdStateOutput *state) {
	ut64 at = rz_core_analysis_stats_get_block_from(as, blockidx);
	ut64 ate = rz_core_analysis_stats_get_block_to(as, blockidx) + 1;
	pj_o(state->d.pj);
	if ((sitem->flags) || (sitem->functions) || (sitem->comments) || (sitem->symbols) || (sitem->perm) || (sitem->strings)) {
		pj_kn(state->d.pj, "offset", at);
		pj_kn(state->d.pj, "size", ate - at);
	}
	if (sitem->flags) {
		pj_ki(state->d.pj, "flags", sitem->flags);
	}
	if (sitem->functions) {
		pj_ki(state->d.pj, "functions", sitem->functions);
	}
	if (sitem->in_functions) {
		pj_ki(state->d.pj, "in_functions", sitem->in_functions);
	}
	if (sitem->comments) {
		pj_ki(state->d.pj, "comments", sitem->comments);
	}
	if (sitem->symbols) {
		pj_ki(state->d.pj, "symbols", sitem->symbols);
	}
	if (sitem->strings) {
		pj_ki(state->d.pj, "strings", sitem->strings);
	}
	if (sitem->perm) {
		pj_ks(state->d.pj, "perm", rz_str_rwx_i(sitem->perm));
	}
	pj_end(state->d.pj);
}

static void analysis_stats_table_info(RzCore *core, RzCoreAnalysisStats *as, RzCoreAnalysisStatsItem *sitem, ut64 blockidx, RzCmdStateOutput *state) {
	ut64 at = rz_core_analysis_stats_get_block_from(as, blockidx);
	if ((sitem->flags) || (sitem->functions) || (sitem->comments) || (sitem->symbols) || (sitem->strings)) {
		rz_table_add_rowf(state->d.t, "sddddd", sdb_fmt("0x%09" PFMT64x "", at), sitem->flags,
			sitem->functions, sitem->comments, sitem->symbols, sitem->strings);
	}
}

static void analysis_stats_entropy_info(RzCore *core, RzCoreAnalysisStats *as, ut64 blockidx, bool use_color) {
	ut64 at = rz_core_analysis_stats_get_block_from(as, blockidx);
	ut64 ate = rz_core_analysis_stats_get_block_to(as, blockidx) + 1;
	ut8 *blockptr = malloc(ate - at);
	if (!blockptr) {
		return;
	}
	if (rz_io_read_at(core->io, at, blockptr, (ate - at))) {
		ut8 entropy = (ut8)(rz_hash_entropy_fraction(blockptr, (ate - at)) * 255);
		entropy = 9 * entropy / 200; // normalize entropy from 0 to 9
		if (use_color) {
			const char *color =
				(entropy > 6) ? Color_BGRED : (entropy > 3) ? Color_BGGREEN
									    : Color_BGBLUE;
			rz_cons_printf("%s%d" Color_RESET, color, entropy);
		} else {
			rz_cons_printf("%d", entropy);
		}
	}
	free(blockptr);
	if (use_color) {
		rz_cons_print(Color_RESET);
	}
}

RZ_IPI RzCmdStatus rz_print_minus_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int width = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)(core->print->cols * 2.7);
	RzCoreAnalysisStatsRange *srange = analysis_stats_range(core, width);
	if (!srange) {
		RZ_LOG_ERROR("Cannot find valid range for calculating the analysis information\n");
		return RZ_CMD_STATUS_ERROR;
	}
	bool use_color = rz_config_get_i(core->config, "scr.color");
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_o(state->d.pj);
		pj_kn(state->d.pj, "from", srange->from);
		pj_kn(state->d.pj, "to", srange->to);
		pj_ki(state->d.pj, "blocksize", srange->piece);
		pj_ka(state->d.pj, "blocks");
		for (size_t i = 0; i < rz_vector_len(&srange->as->blocks); i++) {
			RzCoreAnalysisStatsItem *sitem = rz_vector_index_ptr(&srange->as->blocks, i);
			analysis_stats_json_info(core, srange->as, sitem, i, state);
		}
		pj_end(state->d.pj);
		pj_end(state->d.pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("0x%08" PFMT64x " [", srange->from);
		for (size_t i = 0; i < rz_vector_len(&srange->as->blocks); i++) {
			RzCoreAnalysisStatsItem *sitem = rz_vector_index_ptr(&srange->as->blocks, i);
			analysis_stats_standard_info(core, srange, sitem, i, use_color);
		}
		rz_cons_printf("] 0x%08" PFMT64x "\n", srange->to);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
	analysis_stats_range_free(srange);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_minus_entropy_handler(RzCore *core, int argc, const char **argv) {
	int width = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)(core->print->cols * 2.7);
	RzCoreAnalysisStatsRange *srange = analysis_stats_range(core, width);
	if (!srange) {
		RZ_LOG_ERROR("Cannot find valid range for calculating the analysis information\n");
		return RZ_CMD_STATUS_ERROR;
	}
	bool use_color = rz_config_get_i(core->config, "scr.color");
	rz_cons_printf("0x%08" PFMT64x " [", srange->from);
	for (size_t i = 0; i < rz_vector_len(&srange->as->blocks); i++) {
		analysis_stats_entropy_info(core, srange->as, i, use_color);
	}
	rz_cons_printf("] 0x%08" PFMT64x "\n", srange->to);
	analysis_stats_range_free(srange);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_minus_table_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int width = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)(core->print->cols * 2.7);
	RzCoreAnalysisStatsRange *srange = analysis_stats_range(core, width);
	if (!srange) {
		RZ_LOG_ERROR("Cannot find valid range for calculating the analysis information\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cmd_state_output_array_start(state);
	rz_cmd_state_output_set_columnsf(state, "sddddd", "offset", "flags", "funcs", "cmts", "syms", "str");
	state->d.t->showSum = true;
	state->d.t->showFancy = true;
	for (size_t i = 0; i < rz_vector_len(&srange->as->blocks); i++) {
		RzCoreAnalysisStatsItem *sitem = rz_vector_index_ptr(&srange->as->blocks, i);
		analysis_stats_table_info(core, srange->as, sitem, i, state);
	}
	rz_cmd_state_output_array_end(state);
	analysis_stats_range_free(srange);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_columns_disassembly_handler(RzCore *core, int argc, const char **argv) {
	int h, w = rz_cons_get_size(&h);
	int colwidth = rz_config_get_i(core->config, "hex.cols") * 2.5;
	if (colwidth < 1) {
		colwidth = 16;
	}
	int i, columns = w / colwidth;
	int user_rows = argc > 1 ? rz_num_math(core->num, argv[1]) : -1;
	int rows = user_rows > 0 ? user_rows : h - 2;

	RzConfigHold *ch = rz_config_hold_new(core->config);
	rz_config_hold_i(ch, "asm.offset", "asm.bytes", NULL);
	if (rz_config_get_i(core->config, "asm.minicols")) {
		rz_config_set_b(core->config, "asm.offset", false);
	}
	rz_config_set_b(core->config, "asm.bytes", false);

	RzConsCanvas *c = rz_cons_canvas_new(w, rows);
	ut64 osek = core->offset;
	int pos_i = 0;
	c->color = rz_config_get_i(core->config, "scr.color");
	for (i = 0; i < columns; i++) {
		(void)rz_cons_canvas_gotoxy(c, i * (w / columns), 0);
		// TODO: Use the API directly
		char *cmd = rz_str_newf("pdq %d @i:%d", rows, pos_i);
		char *dis = rz_core_cmd_str(core, cmd);
		if (dis) {
			RzList *dis_lines = rz_str_split_duplist_n(dis, "\n", 0, false);
			ut32 n_lines = rz_list_length(dis_lines);
			rz_list_free(dis_lines);

			// If the output contains more lines than expected, do not move
			// forward the whole chunk as some data will be hidden.
			if (n_lines > rows) {
				pos_i -= (n_lines - rows - 1);
			}

			rz_cons_canvas_write(c, dis);
		}
		free(cmd);
		free(dis);

		pos_i += rows;
	}
	rz_core_seek(core, osek, true);

	rz_cons_canvas_print(c);
	rz_cons_canvas_free(c);
	rz_cons_printf("\n");

	rz_config_hold_restore(ch);
	rz_config_hold_free(ch);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_columns_debug_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_config_get_b(core->config, "cfg.debug")) {
		RZ_LOG_ERROR("Command works only in debug mode\n");
		return RZ_CMD_STATUS_ERROR;
	}
	int h, w = rz_cons_get_size(&h);
	int i;
	int rows = h - 2;
	int obsz = core->blocksize;
	int user_rows = argc > 1 ? rz_num_math(core->num, argv[1]) : -1;
	if (user_rows > 0) {
		rows = user_rows;
	}
	bool asm_minicols = rz_config_get_i(core->config, "asm.minicols");
	char *o_ao = strdup(rz_config_get(core->config, "asm.offset"));
	char *o_ab = strdup(rz_config_get(core->config, "asm.bytes"));
	if (asm_minicols) {
		// Set asm.offset and asm.bytes configs to false to avoid printing them
		rz_config_set_b(core->config, "asm.offset", false);
		rz_config_set_b(core->config, "asm.bytes", false);
	}
	rz_config_set_b(core->config, "asm.bytes", false);
	RzConsCanvas *c = rz_cons_canvas_new(w, rows);
	ut64 osek = core->offset;
	c->color = rz_config_get_i(core->config, "scr.color");
	rz_core_block_size(core, rows * 32);
	char *cmd = NULL;
	int columns = 2;
	for (i = 0; i < columns; i++) {
		switch (i) {
		case 0:
			(void)rz_cons_canvas_gotoxy(c, 0, 0);
			// TODO: Use the API directly
			cmd = rz_str_newf("dr; ?e; ?e backtrace:; dbt");
			break;
		case 1:
			(void)rz_cons_canvas_gotoxy(c, 28, 0);
			// TODO: Use the API directly
			// cmd = rz_str_newf ("pxw 128@r:SP;pd@r:PC");
			cmd = rz_str_newf("%s 128 @r:SP; pd @ 0x%" PFMT64x, rz_core_print_stack_command(core), osek);
			break;
		}
		char *dis = rz_core_cmd_str(core, cmd);
		rz_cons_canvas_write(c, dis);
		free(cmd);
		free(dis);
	}
	rz_core_block_size(core, obsz);
	rz_core_seek(core, osek, true);

	rz_cons_canvas_print(c);
	rz_cons_canvas_free(c);
	if (asm_minicols) {
		rz_config_set(core->config, "asm.offset", o_ao);
		rz_config_set(core->config, "asm.bytes", o_ab);
	}
	rz_config_set(core->config, "asm.bytes", o_ab);
	free(o_ao);
	free(o_ab);
	rz_cons_printf("\n");
	return RZ_CMD_STATUS_OK;
}

static bool print_hexdump_columns(RzCore *core, int user_rows, bool has_header, const char *xcmd) {
	int h, w = rz_cons_get_size(&h);
	int hex_cols = rz_config_get_i(core->config, "hex.cols");
	int colwidth = hex_cols * 5;
	int i, columns = w / (colwidth * 0.9);
	int rows = user_rows > 0 ? user_rows : h - 2;

	RzConfigHold *ch = rz_config_hold_new(core->config);
	rz_config_hold_i(ch, "hex.cols", NULL);
	rz_config_set_i(core->config, "hex.cols", colwidth / 5);

	// Add one more line for the hexdump header
	int canvas_rows = rows + (has_header ? 1 : 0);
	RzConsCanvas *c = rz_cons_canvas_new(w, canvas_rows);
	if (!c) {
		RZ_LOG_ERROR("core: Couldn't allocate a canvas with %d rows\n", rows);
		rz_config_set_i(core->config, "hex.cols", hex_cols);
		return false;
	}

	ut64 tsek = core->offset;
	c->color = rz_config_get_i(core->config, "scr.color");
	int bsize = hex_cols * rows;
	if (!strcmp(xcmd, "pxAl")) {
		bsize *= 12;
	}
	for (i = 0; i < columns; i++) {
		(void)rz_cons_canvas_gotoxy(c, i * (w / columns), 0);
		char *cmd = rz_str_newf("%s %d @ %" PFMT64u, xcmd, bsize, tsek);
		char *dis = rz_core_cmd_str(core, cmd);
		if (dis) {
			RzList *dis_lines = rz_str_split_duplist_n(dis, "\n", 0, false);
			// Count the lines do not contain actual data and handle them for
			// the next column
			RzListIter *it;
			char *line;
			int i = 0, diff_lines = 0;
			rz_list_foreach (dis_lines, it, line) {
				if (line[0] == ' ' && i < canvas_rows) {
					diff_lines++;
				}
				i++;
			}
			rz_list_free(dis_lines);
			if (!UT64_MUL_OVFCHK(diff_lines, hex_cols)) {
				tsek -= diff_lines * hex_cols;
			}

			rz_cons_canvas_write(c, dis);
			free(dis);
		}
		free(cmd);
		tsek += bsize;
	}

	rz_cons_canvas_print(c);
	rz_cons_canvas_free(c);
	rz_cons_printf("\n");

	rz_config_hold_restore(ch);
	rz_config_hold_free(ch);
	return true;
}

RZ_IPI RzCmdStatus rz_print_columns_hex_annotated_handler(RzCore *core, int argc, const char **argv) {
	int user_rows = argc > 1 ? rz_num_math(core->num, argv[1]) : -1;
	return bool2status(print_hexdump_columns(core, user_rows, true, "pxa"));
}

RZ_IPI RzCmdStatus rz_print_columns_hex_op_colored_handler(RzCore *core, int argc, const char **argv) {
	int user_rows = argc > 1 ? rz_num_math(core->num, argv[1]) : -1;
	return bool2status(print_hexdump_columns(core, user_rows, false, "pxAl"));
}

RZ_IPI RzCmdStatus rz_print_columns_hex_handler(RzCore *core, int argc, const char **argv) {
	int user_rows = argc > 1 ? rz_num_math(core->num, argv[1]) : -1;
	return bool2status(print_hexdump_columns(core, user_rows, true, "px"));
}

RZ_IPI RzCmdStatus rz_print_columns_hex_words_handler(RzCore *core, int argc, const char **argv) {
	int user_rows = argc > 1 ? rz_num_math(core->num, argv[1]) : -1;
	return bool2status(print_hexdump_columns(core, user_rows, false, "pxw"));
}

RZ_IPI RzCmdStatus rz_print_equal_d_handler(RzCore *core, int argc, const char **argv) {
	int min = -1, max = 0, dict = 0, range = 0;
	bool histogram[256] = { 0 };
	const ut8 *block = core->block;
	ut32 bsz = core->blocksize;
	for (size_t i = 0; i < bsz; i++) {
		histogram[block[i]] = true;
	}
	for (size_t i = 0; i < 256; i++) {
		if (histogram[i]) {
			if (min == -1) {
				min = i;
			}
			max = i;
			dict++;
		}
	}
	range = max - min;
	rz_cons_printf("min:              %d  0x%x\n", min, min);
	rz_cons_printf("max:              %d  0x%x\n", max, max);
	rz_cons_printf("unique (count):   %d  0x%x\n", dict, dict);
	rz_cons_printf("range (max-min):  %d  0x%x\n", range, range);
	rz_cons_printf("size (of block):  %d  0x%x\n", bsz, bsz);
	return RZ_CMD_STATUS_OK;
}

typedef struct core_block_range_t {
	ut64 from;
	ut64 to;
	ut64 totalsize;
	int nblocks;
	st64 blocksize;
	int skipblocks;
} CoreBlockRange;

static CoreBlockRange *calculate_blocks_range(RzCore *core, ut64 from, ut64 to, ut64 totalsize, int nblocks, int skipblocks) {
	if (nblocks == 0) {
		return NULL;
	}
	CoreBlockRange *brange = RZ_NEW0(CoreBlockRange);
	if (!brange) {
		return NULL;
	}

	if (totalsize == UT64_MAX) {
		if (rz_config_get_b(core->config, "cfg.debug")) {
			RzDebugMap *map = rz_debug_map_get(core->dbg, core->offset);
			if (map) {
				brange->totalsize = map->addr_end - map->addr;
				brange->from = map->addr;
			}
		} else {
			if (core->file && core->io) {
				brange->totalsize = rz_io_fd_size(core->io, core->file->fd);
				if ((st64)brange->totalsize < 1) {
					brange->totalsize = UT64_MAX;
				}
			}
			if (brange->totalsize == UT64_MAX) {
				RZ_LOG_ERROR("core: Cannot determine file size\n");
				free(brange);
				return NULL;
			}
		}
	} else {
		brange->totalsize = totalsize;
	}
	st64 blocksize = core->blocksize;
	// If we are not in the debug mode - use only current mapped ranges
	if (!rz_config_get_b(core->config, "cfg.debug")) {
		RzList *boundaries = rz_core_get_boundaries_prot(core, -1, NULL, "zoom");
		if (!boundaries) {
			free(brange);
			return NULL;
		}
		RzIOMap *map = rz_list_first(boundaries);
		if (map) {
			brange->from = map->itv.addr;
			RzIOMap *m;
			RzListIter *iter;
			rz_list_foreach (boundaries, iter, m) {
				brange->to = rz_itv_end(m->itv);
			}
			brange->totalsize = brange->to - brange->from;
		} else {
			brange->from = core->offset;
		}
		rz_list_free(boundaries);
	}
	if (nblocks < 1) {
		brange->nblocks = brange->totalsize / blocksize;
	} else {
		blocksize = brange->totalsize / nblocks;
		brange->nblocks = nblocks;
	}
	if (skipblocks > 0) {
		brange->skipblocks = skipblocks;
	}
	brange->blocksize = blocksize;
	return brange;
}

typedef enum {
	HISTOGRAM_ANALYSIS_BASIC_BLOCKS,
	HISTOGRAM_ANALYSIS_INVALID_INSTRUCTIONS,
	HISTOGRAM_ANALYSIS_CALL_INSTRUCTIONS,
	HISTOGRAM_ANALYSIS_JUMP_INSTRUCTIONS,
	HISTOGRAM_ANALYSIS_PRIV_INSTRUCTIONS,
} CoreAnalysisHistogramType;

static inline void data_array_increment_element(ut8 *data, int i) {
	if (data[i] < 0xff) {
		data[i]++;
	}
}

static bool if_aop_match_hist_type(RzAnalysisOp *op, CoreAnalysisHistogramType t) {
	switch (t) {
	case HISTOGRAM_ANALYSIS_BASIC_BLOCKS:
		/* We do not need to check the op type in this case */
		return false;
	case HISTOGRAM_ANALYSIS_CALL_INSTRUCTIONS: {
		switch (op->type) {
		case RZ_ANALYSIS_OP_TYPE_RCALL:
		case RZ_ANALYSIS_OP_TYPE_UCALL:
		case RZ_ANALYSIS_OP_TYPE_CALL:
			return true;
		}
		break;
	}
	case HISTOGRAM_ANALYSIS_PRIV_INSTRUCTIONS: {
		if (op->family == RZ_ANALYSIS_OP_FAMILY_PRIV) {
			return true;
		}
		switch (op->type) {
		case RZ_ANALYSIS_OP_TYPE_SWI:
			return true;
		}
		break;
	}
	case HISTOGRAM_ANALYSIS_INVALID_INSTRUCTIONS: {
		switch (op->type) {
		case RZ_ANALYSIS_OP_TYPE_TRAP:
		case RZ_ANALYSIS_OP_TYPE_ILL:
			return true;
		}
		break;
	}
	case HISTOGRAM_ANALYSIS_JUMP_INSTRUCTIONS: {
		switch (op->type) {
		case RZ_ANALYSIS_OP_TYPE_JMP:
		// case RZ_ANALYSIS_OP_TYPE_RJMP:
		// case RZ_ANALYSIS_OP_TYPE_UJMP:
		case RZ_ANALYSIS_OP_TYPE_CJMP:
			return true;
		default:
			break;
		}
		break;
	}
	}
	return false;
}

// Counts all analysis metainformation units per block
static ut8 *analysis_stats_histogram_data(RzCore *core, CoreBlockRange *brange) {
	ut8 *data = calloc(1, brange->nblocks);
	if (!data) {
		RZ_LOG_ERROR("core: Failed to allocate memory");
		return NULL;
	}
	// FIXME: Should we just use the value from brange instead?
	ut64 to = brange->from + (brange->blocksize * brange->nblocks) - 1;
	if (to < brange->from) {
		free(data);
		return NULL;
	}
	RzCoreAnalysisStats *as = rz_core_analysis_get_stats(core, brange->from, to, brange->blocksize);
	if (!as) {
		free(data);
		return NULL;
	}
	for (size_t i = 0; i < RZ_MIN(brange->nblocks, rz_vector_len(&as->blocks)); i++) {
		int value = 0;
		RzCoreAnalysisStatsItem *block = rz_vector_index_ptr(&as->blocks, i);
		value += block->functions;
		value += block->in_functions;
		value += block->comments;
		value += block->symbols;
		value += block->flags;
		value += block->strings;
		value += block->blocks;
		data[i] = RZ_MIN(255, value);
	}
	rz_core_analysis_stats_free(as);
	return data;
}

static ut8 *analysis_histogram_data(RzCore *core, CoreBlockRange *brange, CoreAnalysisHistogramType hist_type) {
	size_t j, i = 0;
	ut8 *data = calloc(1, brange->nblocks);
	if (!data) {
		RZ_LOG_ERROR("core: Failed to allocate memory");
		return NULL;
	}
	for (i = 0; i < brange->nblocks; i++) {
		if (rz_cons_is_breaked()) {
			break;
		}
		ut64 off = brange->from + (i + brange->skipblocks) * brange->blocksize;
		for (j = 0; j < brange->blocksize; j++) {
			if (hist_type == HISTOGRAM_ANALYSIS_BASIC_BLOCKS) {
				RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, off + j, 0);
				if (fcn) {
					data[i] = rz_list_length(fcn->bbs);
				}
				continue;
			}
			RzAnalysisOp *op = rz_core_analysis_op(core, off + j, RZ_ANALYSIS_OP_MASK_BASIC);
			if (op) {
				if (op->size < 1) {
					// do nothing
					if (hist_type == HISTOGRAM_ANALYSIS_INVALID_INSTRUCTIONS) {
						data_array_increment_element(data, i);
					}
				} else {
					if (if_aop_match_hist_type(op, hist_type)) {
						data_array_increment_element(data, i);
					}
				}
				if (op->size > 0) {
					j += op->size - 1;
				}
				rz_analysis_op_free(op);
			} else {
				if (hist_type == HISTOGRAM_ANALYSIS_INVALID_INSTRUCTIONS) {
					data_array_increment_element(data, i);
				}
			}
		}
	}
	return data;
}

static bool print_histogram(RzCore *core, RZ_NULLABLE RzHistogramOptions *opts, const ut8 *data, ut64 offset, int width, int step, bool vertical) {
	RzStrBuf *strbuf = NULL;
	bool hex_offset = rz_config_get_i(core->config, "hex.offset");
	core->print->num = core->num;
	if (hex_offset) {
		// TODO: Currently this option doesn't affect horizontal histograms
		core->print->flags |= RZ_PRINT_FLAGS_OFFSET;
	} else {
		core->print->flags &= ~RZ_PRINT_FLAGS_OFFSET;
	}
	if (opts) {
		strbuf = vertical ? rz_histogram_vertical(opts, data, width, step) : rz_histogram_horizontal(opts, data, width, 14);
	} else {
		RzHistogramOptions default_opts = {
			.unicode = rz_config_get_b(core->config, "scr.utf8"),
			.thinline = !rz_config_get_b(core->config, "scr.hist.block"),
			.legend = false,
			.offset = rz_config_get_b(core->config, "hex.offset"),
			.offpos = offset,
			.cursor = false,
			.curpos = 0,
			.color = rz_config_get_i(core->config, "scr.color"),
			.pal = &core->cons->context->pal
		};
		strbuf = vertical ? rz_histogram_vertical(&default_opts, data, width, step) : rz_histogram_horizontal(&default_opts, data, width, 14);
	}
	if (!strbuf) {
		return false;
	} else {
		char *histogram = rz_strbuf_drain(strbuf);
		rz_cons_print(histogram);
		free(histogram);
	}
	return true;
}

static void showcursor(RzCore *core, int x) {
	if (!x) {
		int wheel = rz_config_get_i(core->config, "scr.wheel");
		if (wheel) {
			rz_cons_enable_mouse(true);
		}
	} else {
		rz_cons_enable_mouse(false);
	}
	rz_cons_show_cursor(x);
}

static RzCmdStatus print_visual_bytes(RzCore *core, RZ_NONNULL const unsigned char *data, RZ_NONNULL CoreBlockRange *brange) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: visual mode requires scr.interactive=true.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	RzConsCanvas *can;
	bool exit_histogram = false, is_error = false;
	RzConfigHold *hc = rz_config_hold_new(core->config);
	if (!hc) {
		return false;
	}
	rz_config_hold_i(hc, "asm.pseudo", "asm.esil", "asm.cmt.right", NULL);

	int h, w = rz_cons_get_size(&h);
	can = rz_cons_canvas_new(w, h);
	if (!can) {
		w = 80;
		h = 25;
		can = rz_cons_canvas_new(w, h);
		if (!can) {
			RZ_LOG_ERROR("core: cannot create RzCons.canvas context. Invalid screen "
				     "size? See scr.columns + scr.rows\n");
			rz_config_hold_restore(hc);
			rz_config_hold_free(hc);
			return false;
		}
	}
	can->color = rz_config_get_i(core->config, "scr.color");

	RzHistogramOptions *opts = rz_histogram_options_new();
	if (!opts) {
		rz_config_hold_restore(hc);
		rz_config_hold_free(hc);
		rz_cons_canvas_free(can);
		return RZ_CMD_STATUS_ERROR;
	}
	opts->unicode = rz_config_get_b(core->config, "scr.utf8");
	opts->thinline = !rz_config_get_b(core->config, "scr.hist.block");
	opts->legend = false;
	opts->offset = rz_config_get_b(core->config, "hex.offset");
	opts->offpos = brange->from;
	opts->cursor = false;
	opts->curpos = 0;
	opts->color = rz_config_get_i(core->config, "scr.color");
	opts->pal = &core->cons->context->pal;
	RzHistogramInteractive *hist = rz_histogram_interactive_new(can, opts);
	hist->size = brange->nblocks;
	if (!hist) {
		rz_histogram_options_free(hist->opts);
		rz_config_hold_restore(hc);
		rz_config_hold_free(hc);
		rz_cons_canvas_free(can);
		return RZ_CMD_STATUS_ERROR;
	}

	int okey, key;
	while (!exit_histogram && !is_error && !rz_cons_is_breaked()) {
		showcursor(core, false);
		w = rz_cons_get_size(&h);
		rz_cons_canvas_resize(hist->can, w, h);
		hist->w = w;
		hist->h = h;
		RzStrBuf *str = rz_histogram_interactive_horizontal(hist, data);
		rz_cons_canvas_write(hist->can, str->ptr);
		rz_cons_canvas_print_region(hist->can);
		rz_cons_newline();
		rz_cons_visual_flush();
		okey = rz_cons_readchar();
		key = rz_cons_arrow_to_hjkl(okey);
		switch (key) {
		case '?':
			rz_cons_clear00();
			rz_cons_printf("Visual Ascii Art graph keybindings:\n"
				       " +/-    - zoom in/out\n"
				       " hl    	- move left and right\n"
				       " q      - back to Visual mode\n");
			rz_cons_less();
			rz_cons_any_key(NULL);
			break;
		case 'h':
			hist->barnumber = (hist->barnumber > 0) ? (hist->barnumber - 1) : (brange->nblocks - 1);
			break;
		case 'l':
			hist->barnumber = (hist->barnumber == brange->nblocks - 1) ? (0) : (hist->barnumber + 1);
			break;
		case '+':
			rz_histogram_interactive_zoom_in(hist);
			break;
		case '-':
			rz_histogram_interactive_zoom_out(hist);
			break;
		case 'q':
		case 'Q':
		case ' ':
			exit_histogram = true;
			break;
		default:
			break;
		}
		rz_cons_clear00();
	}
	rz_cons_break_pop();
	core->cons->event_resize = NULL;
	core->cons->event_data = NULL;
	core->keep_asmqjmps = false;
	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);
	rz_histogram_interactive_free(hist);
	rz_cons_show_cursor(true);
	rz_cons_enable_mouse(false);

	return RZ_CMD_STATUS_OK;
}

static CoreBlockRange *parse_args_calculate_range(RzCore *core, int argc, const char **argv) {
	int nblocks = argc > 1 ? rz_num_math(core->num, argv[1]) : -1;
	ut64 totalsize = argc > 2 ? rz_num_math(core->num, argv[2]) : UT64_MAX;
	int skipblocks = argc > 3 ? rz_num_math(core->num, argv[3]) : -1;
	CoreBlockRange *brange = calculate_blocks_range(core, 0, 0, totalsize, nblocks, skipblocks);
	if (!brange) {
		RZ_LOG_ERROR("Cannot calculate blocks range\n");
	}
	return brange;
}

static RzCmdStatus print_histogram_bytes(RzCore *core, int argc, const char **argv, bool vertical, bool isinteractive) {
	CoreBlockRange *brange = parse_args_calculate_range(core, argc, argv);
	if (!brange) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut8 *data = calloc(1, brange->nblocks);
	rz_io_read_at(core->io, core->offset, data, brange->nblocks);
	if (isinteractive) {
		if (!print_visual_bytes(core, data, brange)) {
			RZ_LOG_ERROR("Cannot generate interactive histogram\n");
			free(brange);
			free(data);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		if (!print_histogram(core, NULL, data, brange->from, brange->nblocks, brange->blocksize, vertical)) {
			RZ_LOG_ERROR("Cannot generate %s histogram\n", vertical ? "vertical" : "horizontal");
			free(brange);
			free(data);
			return RZ_CMD_STATUS_ERROR;
		}
	}
	free(brange);
	free(data);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_equal_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_bytes(core, argc, argv, true, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_bytes(core, argc, argv, false, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_visual_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_bytes(core, argc, argv, false, true);
}

static RzCmdStatus print_histogram_entropy(RzCore *core, int argc, const char **argv, bool vertical, bool isinteractive) {
	CoreBlockRange *brange = parse_args_calculate_range(core, argc, argv);
	if (!brange) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut8 *data = calloc(1, brange->nblocks);
	ut8 *tmp = malloc(brange->blocksize);
	if (!tmp) {
		RZ_LOG_ERROR("core: failed to malloc memory");
		free(data);
		free(brange);
		return RZ_CMD_STATUS_ERROR;
	}
	for (size_t i = 0; i < brange->nblocks; i++) {
		ut64 off = brange->from + (brange->blocksize * (i + brange->skipblocks));
		rz_io_read_at(core->io, off, tmp, brange->blocksize);
		data[i] = (ut8)(255 * rz_hash_entropy_fraction(tmp, brange->blocksize));
	}
	free(tmp);
	if (isinteractive) {
		if (!print_visual_bytes(core, data, brange)) {
			RZ_LOG_ERROR("Cannot generate interactive histogram\n");
			free(brange);
			free(data);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		if (!print_histogram(core, NULL, data, brange->from, brange->nblocks, brange->blocksize, vertical)) {
			RZ_LOG_ERROR("Cannot generate %s histogram\n", vertical ? "vertical" : "horizontal");
			free(data);
			free(brange);
			return RZ_CMD_STATUS_ERROR;
		}
	}
	free(data);
	free(brange);
	return RZ_CMD_STATUS_OK;
}

static bool print_rising_and_falling_entropy_table(RzCore *core, RzCmdStateOutput *state, CoreBlockRange *brange, ut8 *tmp, double fallingthreshold, double risingthreshold) {
	bool resetFlag = 1;
	st8 lastEdge = 0;
	RzTable *t = state->d.t;
	RzTableColumnType *n = rz_table_type("number");
	RzTableColumnType *s = rz_table_type("string");
	rz_table_add_column(t, n, "addr", 0);
	rz_table_add_column(t, n, "index", 0);
	rz_table_add_column(t, s, "edge_type", 0);
	rz_table_add_column(t, n, "entropy_value", 0);
	for (int i = 0; i < brange->nblocks; i++) {
		ut64 off = brange->from + (brange->blocksize * (i));
		if (!rz_io_read_at(core->io, off, tmp, brange->blocksize))
			return false;
		double data = rz_hash_entropy_fraction(tmp, brange->blocksize);
		// reseting flag if goes above falling threshold and below rising threshold
		if (resetFlag == 0 && lastEdge == 0 && data > fallingthreshold) {
			resetFlag = 1;
		} else if (resetFlag == 0 && lastEdge == 1 && data < risingthreshold) {
			resetFlag = 1;
		}
		// if reset flag is true
		// than if entopy goes above threshold printing rising entropy edge
		// and if entropy goes below threshold printing falling entropy edge
		if (resetFlag == 1 && data >= risingthreshold) {
			// rising edge print
			resetFlag = 0;
			lastEdge = 1;
			rz_table_add_rowf(t, "xnsf", off, i, "rising entropy edge", data);
		} else if (resetFlag == 1 && data <= fallingthreshold) {
			// falling edge print
			resetFlag = 0;
			lastEdge = 0;
			rz_table_add_rowf(t, "xnsf", off, i, "falling entropy edge", data);
		}
	}
	return true;
}

static bool print_rising_and_falling_entropy_JSON(RzCore *core, RzCmdStateOutput *state, CoreBlockRange *brange, ut8 *tmp, double fallingthreshold, double risingthreshold) {
	bool resetFlag = 1;
	st8 lastEdge = 0;
	PJ *pj = state->d.pj;
	pj_a(pj);
	for (int i = 0; i < brange->nblocks; i++) {
		ut64 off = brange->from + (brange->blocksize * (i));
		if (!rz_io_read_at(core->io, off, tmp, brange->blocksize))
			return false;
		double data = rz_hash_entropy_fraction(tmp, brange->blocksize);
		// reseting flag if goes above falling threshold and below rising threshold
		if (resetFlag == 0 && lastEdge == 0 && data > fallingthreshold) {
			resetFlag = 1;
		} else if (resetFlag == 0 && lastEdge == 1 && data < risingthreshold) {
			resetFlag = 1;
		}
		// if reset flag is true
		// than if entopy goes above threshold printing rising entropy edge
		// and if entropy goes below threshold printing falling entropy edge
		if (resetFlag == 1 && data >= risingthreshold) {
			// rising edge print
			resetFlag = 0;
			lastEdge = 1;
			pj_o(pj);
			pj_kn(pj, "addr", off);
			pj_kn(pj, "index", i);
			pj_ks(pj, "edge_type", "rising entropy edge");
			pj_kd(pj, "entropy_value", data);
			pj_end(pj);
		} else if (resetFlag == 1 && data <= fallingthreshold) {
			// falling edge print
			resetFlag = 0;
			lastEdge = 0;
			pj_o(pj);
			pj_kn(pj, "addr", off);
			pj_kn(pj, "index", i);
			pj_ks(pj, "edge_type", "falling entropy edge");
			pj_kd(pj, "entropy_value", data);
			pj_end(pj);
		}
	}
	pj_end(pj);
	return true;
}

static bool print_rising_and_falling_entropy_quiet(RzCore *core, CoreBlockRange *brange, ut8 *tmp, double fallingthreshold, double risingthreshold) {
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		RZ_LOG_ERROR("core: failed to malloc memory");
		return false;
	}
	bool resetFlag = 1;
	st8 lastEdge = 0;
	for (int i = 0; i < brange->nblocks; i++) {
		ut64 off = brange->from + (brange->blocksize * (i));
		if (!rz_io_read_at(core->io, off, tmp, brange->blocksize)) {
			rz_strbuf_free(buf);
			return false;
		}
		double data = rz_hash_entropy_fraction(tmp, brange->blocksize);
		// reseting flag if goes above falling threshold and below rising threshold
		if (resetFlag == 0 && lastEdge == 0 && data > fallingthreshold) {
			resetFlag = 1;
		} else if (resetFlag == 0 && lastEdge == 1 && data < risingthreshold) {
			resetFlag = 1;
		}
		// if reset flag is true
		// than if entopy goes above threshold printing rising entropy edge
		// and if entropy goes below threshold printing falling entropy edge
		if (resetFlag == 1 && data >= risingthreshold) {
			// rising edge print
			resetFlag = 0;
			lastEdge = 1;
			rz_strbuf_appendf(buf, "0x%08" PFMT64x "\n", off);
		} else if (resetFlag == 1 && data <= fallingthreshold) {
			// falling edge print
			resetFlag = 0;
			lastEdge = 0;
			rz_strbuf_appendf(buf, "0x%08" PFMT64x "\n", off);
		}
	}
	char *res = rz_strbuf_drain(buf);
	rz_cons_print(res);
	free(res);
	return true;
}

static bool print_rising_and_falling_entropy_standard(RzCore *core, CoreBlockRange *brange, ut8 *tmp, double fallingthreshold, double risingthreshold) {
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		RZ_LOG_ERROR("core: failed to malloc memory");
		return false;
	}
	bool resetFlag = 1;
	st8 lastEdge = 0;
	for (int i = 0; i < brange->nblocks; i++) {
		ut64 off = brange->from + (brange->blocksize * (i));
		if (!rz_io_read_at(core->io, off, tmp, brange->blocksize)) {
			rz_strbuf_free(buf);
			return false;
		}
		double data = rz_hash_entropy_fraction(tmp, brange->blocksize);
		// reseting flag if goes above falling threshold and below rising threshold
		if (resetFlag == 0 && lastEdge == 0 && data > fallingthreshold) {
			resetFlag = 1;
		} else if (resetFlag == 0 && lastEdge == 1 && data < risingthreshold) {
			resetFlag = 1;
		}
		// if reset flag is true
		// than if entopy goes above threshold printing rising entropy edge
		// and if entropy goes below threshold printing falling entropy edge
		if (resetFlag == 1 && data >= risingthreshold) {
			// rising edge print
			resetFlag = 0;
			lastEdge = 1;
			rz_strbuf_appendf(buf, "0x%08" PFMT64x " Rising entropy edge\n", off);
		} else if (resetFlag == 1 && data <= fallingthreshold) {
			// falling edge print
			resetFlag = 0;
			lastEdge = 0;
			rz_strbuf_appendf(buf, "0x%08" PFMT64x " Falling entropy edge\n", off);
		}
	}
	char *res = rz_strbuf_drain(buf);
	rz_cons_print(res);
	free(res);
	return true;
}

static bool print_rising_and_falling_entropy_long(RzCore *core, CoreBlockRange *brange, ut8 *tmp, double fallingthreshold, double risingthreshold) {
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		RZ_LOG_ERROR("core: failed to malloc memory");
		return false;
	}
	bool resetFlag = 1;
	st8 lastEdge = 0;
	for (int i = 0; i < brange->nblocks; i++) {
		ut64 off = brange->from + (brange->blocksize * (i));
		if (!rz_io_read_at(core->io, off, tmp, brange->blocksize)) {
			rz_strbuf_free(buf);
			return false;
		}
		double data = rz_hash_entropy_fraction(tmp, brange->blocksize);
		// reseting flag if goes above falling threshold and below rising threshold
		if (resetFlag == 0 && lastEdge == 0 && data > fallingthreshold) {
			resetFlag = 1;
		} else if (resetFlag == 0 && lastEdge == 1 && data < risingthreshold) {
			resetFlag = 1;
		}
		// if reset flag is true
		// than if entopy goes above threshold printing rising entropy edge
		// and if entropy goes below threshold printing falling entropy edge
		if (resetFlag == 1 && data >= risingthreshold) {
			// rising edge print
			resetFlag = 0;
			lastEdge = 1;
			rz_strbuf_appendf(buf, "0x%08" PFMT64x " ", off);
			rz_strbuf_appendf(buf, "%03x Rising entropy edge (%8lf)\n", i, data);
		} else if (resetFlag == 1 && data <= fallingthreshold) {
			// falling edge print
			resetFlag = 0;
			lastEdge = 0;
			rz_strbuf_appendf(buf, "0x%08" PFMT64x " ", off);
			rz_strbuf_appendf(buf, "%03x Falling entropy edge (%8lf)\n", i, data);
		}
	}
	char *res = rz_strbuf_drain(buf);
	rz_cons_print(res);
	free(res);
	return true;
}

static RzCmdStatus print_rising_and_falling_entropy(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	double risingthreshold = 0.95;
	double fallingthreshold = 0.85;
	if (argc >= 3) {
		risingthreshold = rz_num_get_float(core->num, argv[1]);
		fallingthreshold = rz_num_get_float(core->num, argv[2]);
	}
	if (fallingthreshold > risingthreshold) {
		RZ_LOG_ERROR("falling threshold is greater than rising threshold");
		return RZ_CMD_STATUS_ERROR;
	}
	if (risingthreshold > 1) {
		RZ_LOG_ERROR("threshold can't be greater than 1");
		return RZ_CMD_STATUS_ERROR;
	}
	int nblocks = -1;
	ut64 totalsize = UT64_MAX;
	int skipblocks = -1;
	CoreBlockRange *brange = calculate_blocks_range(core, 0, 0, totalsize, nblocks, skipblocks);
	if (!brange) {
		RZ_LOG_ERROR("Cannot calculate blocks range\n");
		return RZ_CMD_STATUS_ERROR;
	}
	ut8 *tmp = malloc(brange->blocksize);
	if (!tmp) {
		RZ_LOG_ERROR("core: failed to malloc memory");
		free(brange);
		return RZ_CMD_STATUS_ERROR;
	}
	switch (state->mode) {
	case RZ_OUTPUT_MODE_TABLE:
		if (!print_rising_and_falling_entropy_table(core, state, brange, tmp, fallingthreshold, risingthreshold)) {
			free(tmp);
			free(brange);
			return RZ_CMD_STATUS_ERROR;
		}
		break;
	case RZ_OUTPUT_MODE_JSON:
		if (!print_rising_and_falling_entropy_JSON(core, state, brange, tmp, fallingthreshold, risingthreshold)) {
			free(tmp);
			free(brange);
			return RZ_CMD_STATUS_ERROR;
		}
		break;
	case RZ_OUTPUT_MODE_QUIET:
		if (!print_rising_and_falling_entropy_quiet(core, brange, tmp, fallingthreshold, risingthreshold)) {
			free(tmp);
			free(brange);
			return RZ_CMD_STATUS_ERROR;
		}
		break;
	case RZ_OUTPUT_MODE_STANDARD:
		if (!print_rising_and_falling_entropy_standard(core, brange, tmp, fallingthreshold, risingthreshold)) {
			free(tmp);
			free(brange);
			return RZ_CMD_STATUS_ERROR;
		}
		break;
	case RZ_OUTPUT_MODE_LONG:
		if (!print_rising_and_falling_entropy_long(core, brange, tmp, fallingthreshold, risingthreshold)) {
			free(tmp);
			free(brange);
			return RZ_CMD_STATUS_ERROR;
		}
		break;
	default:
		rz_warn_if_reached();
		free(tmp);
		free(brange);
		return RZ_CMD_STATUS_ERROR;
	}
	free(tmp);
	free(brange);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_equal_entropy_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_entropy(core, argc, argv, true, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_entropy_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_entropy(core, argc, argv, false, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_entropy_visual_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_entropy(core, argc, argv, false, true);
}

RZ_IPI RzCmdStatus rz_print_rising_and_falling_entropy_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return print_rising_and_falling_entropy(core, argc, argv, state);
}

static RzCmdStatus print_histogram_marks(RzCore *core, int argc, const char **argv, bool vertical, bool isinteractive) {
	CoreBlockRange *brange = parse_args_calculate_range(core, argc, argv);
	if (!brange) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut8 *data = calloc(1, brange->nblocks);
	ut8 *tmp = malloc(brange->blocksize);
	if (!tmp) {
		free(data);
		free(brange);
		RZ_LOG_ERROR("core: failed to malloc memory");
		return RZ_CMD_STATUS_ERROR;
	}
	for (size_t i = 0; i < brange->nblocks; i++) {
		ut64 off = brange->from + (brange->blocksize * (i + brange->skipblocks));
		for (size_t j = 0; j < brange->blocksize; j++) {
			if (rz_flag_get_at(core->flags, off + j, false)) {
				data_array_increment_element(data, i);
			}
		}
	}
	free(tmp);
	if (isinteractive) {
		if (!print_visual_bytes(core, data, brange)) {
			RZ_LOG_ERROR("Cannot generate interactive histogram\n");
			free(brange);
			free(data);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		if (!print_histogram(core, NULL, data, brange->from, brange->nblocks, brange->blocksize, vertical)) {
			RZ_LOG_ERROR("Cannot generate %s histogram\n", vertical ? "vertical" : "horizontal");
			free(data);
			free(brange);
			return RZ_CMD_STATUS_ERROR;
		}
	}
	free(data);
	free(brange);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_equal_m_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_marks(core, argc, argv, true, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_m_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_marks(core, argc, argv, false, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_m_visual_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_marks(core, argc, argv, false, true);
}

static RzCmdStatus print_histogram_0x00(RzCore *core, int argc, const char **argv, bool vertical, bool isinteractive) {
	CoreBlockRange *brange = parse_args_calculate_range(core, argc, argv);
	if (!brange) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut8 *data = calloc(1, brange->nblocks);
	ut8 *tmp = malloc(brange->blocksize);
	if (!tmp) {
		free(data);
		free(brange);
		RZ_LOG_ERROR("core: failed to malloc memory");
		return RZ_CMD_STATUS_ERROR;
	}
	for (size_t i = 0; i < brange->nblocks; i++) {
		int k = 0;
		ut64 off = brange->from + (brange->blocksize * (i + brange->skipblocks));
		rz_io_read_at(core->io, off, tmp, brange->blocksize);
		for (size_t j = k = 0; j < brange->blocksize; j++) {
			if (!tmp[j]) {
				k++;
			}
		}
		data[i] = 256 * k / brange->blocksize;
	}
	free(tmp);
	if (isinteractive) {
		if (!print_visual_bytes(core, data, brange)) {
			RZ_LOG_ERROR("Cannot generate interactive histogram\n");
			free(brange);
			free(data);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		if (!print_histogram(core, NULL, data, brange->from, brange->nblocks, brange->blocksize, vertical)) {
			RZ_LOG_ERROR("Cannot generate %s histogram\n", vertical ? "vertical" : "horizontal");
			free(data);
			free(brange);
			return RZ_CMD_STATUS_ERROR;
		}
	}
	free(data);
	free(brange);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_equal_0x00_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_0x00(core, argc, argv, true, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_0x00_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_0x00(core, argc, argv, false, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_0x00_visual_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_0x00(core, argc, argv, false, true);
}

static RzCmdStatus print_histogram_0xff(RzCore *core, int argc, const char **argv, bool vertical, bool isinteractive) {
	CoreBlockRange *brange = parse_args_calculate_range(core, argc, argv);
	if (!brange) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut8 *data = calloc(1, brange->nblocks);
	ut8 *tmp = malloc(brange->blocksize);
	if (!tmp) {
		free(data);
		free(brange);
		RZ_LOG_ERROR("core: failed to malloc memory");
		return RZ_CMD_STATUS_ERROR;
	}
	for (size_t i = 0; i < brange->nblocks; i++) {
		int k = 0;
		ut64 off = brange->from + (brange->blocksize * (i + brange->skipblocks));
		rz_io_read_at(core->io, off, tmp, brange->blocksize);
		for (size_t j = k = 0; j < brange->blocksize; j++) {
			if (tmp[j] == 0xff) {
				k++;
			}
		}
		data[i] = 256 * k / brange->blocksize;
	}
	free(tmp);
	if (isinteractive) {
		if (!print_visual_bytes(core, data, brange)) {
			RZ_LOG_ERROR("Cannot generate interactive histogram\n");
			free(brange);
			free(data);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		if (!print_histogram(core, NULL, data, brange->from, brange->nblocks, brange->blocksize, vertical)) {
			RZ_LOG_ERROR("Cannot generate %s histogram\n", vertical ? "vertical" : "horizontal");
			free(data);
			free(brange);
			return RZ_CMD_STATUS_ERROR;
		}
	}
	free(data);
	free(brange);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_equal_0xff_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_0xff(core, argc, argv, true, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_0xff_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_0xff(core, argc, argv, false, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_0xff_visual_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_0xff(core, argc, argv, false, true);
}

static RzCmdStatus print_histogram_printable(RzCore *core, int argc, const char **argv, bool vertical, bool isinteractive) {
	CoreBlockRange *brange = parse_args_calculate_range(core, argc, argv);
	if (!brange) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut8 *data = calloc(1, brange->nblocks);
	ut8 *tmp = malloc(brange->blocksize);
	if (!tmp) {
		free(data);
		free(brange);
		RZ_LOG_ERROR("core: failed to malloc memory");
		return RZ_CMD_STATUS_ERROR;
	}
	for (size_t i = 0; i < brange->nblocks; i++) {
		int k = 0;
		ut64 off = brange->from + (brange->blocksize * (i + brange->skipblocks));
		rz_io_read_at(core->io, off, tmp, brange->blocksize);
		for (size_t j = k = 0; j < brange->blocksize; j++) {
			if (IS_PRINTABLE(tmp[j])) {
				k++;
			}
		}
		data[i] = 256 * k / brange->blocksize;
	}
	free(tmp);
	if (isinteractive) {
		if (!print_visual_bytes(core, data, brange)) {
			RZ_LOG_ERROR("Cannot generate interactive histogram\n");
			free(brange);
			free(data);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		if (!print_histogram(core, NULL, data, brange->from, brange->nblocks, brange->blocksize, vertical)) {
			RZ_LOG_ERROR("Cannot generate %s histogram\n", vertical ? "vertical" : "horizontal");
			free(data);
			free(brange);
			return RZ_CMD_STATUS_ERROR;
		}
	}
	free(data);
	free(brange);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_equal_printable_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_printable(core, argc, argv, true, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_printable_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_printable(core, argc, argv, false, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_printable_visual_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_printable(core, argc, argv, false, true);
}

static RzCmdStatus print_histogram_z(RzCore *core, int argc, const char **argv, bool vertical, bool isinteractive) {
	CoreBlockRange *brange = parse_args_calculate_range(core, argc, argv);
	if (!brange) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut8 *data = calloc(1, brange->nblocks);
	ut8 *tmp = malloc(brange->blocksize);
	if (!tmp) {
		free(data);
		free(brange);
		RZ_LOG_ERROR("core: failed to malloc memory");
		return RZ_CMD_STATUS_ERROR;
	}
	size_t len = 0;
	for (size_t i = 0; i < brange->nblocks; i++) {
		int k = 0;
		ut64 off = brange->from + (brange->blocksize * (i + brange->skipblocks));
		rz_io_read_at(core->io, off, tmp, brange->blocksize);
		for (size_t j = k = 0; j < brange->blocksize; j++) {
			if (IS_PRINTABLE(tmp[j])) {
				if ((j + 1) < brange->blocksize && tmp[j + 1] == 0) {
					k++;
					j++;
				}
				if (len++ > 8) {
					k++;
				}
			} else {
				len = 0;
			}
		}
		data[i] = 256 * k / brange->blocksize;
	}
	free(tmp);
	if (isinteractive) {
		if (!print_visual_bytes(core, data, brange)) {
			RZ_LOG_ERROR("Cannot generate interactive histogram\n");
			free(brange);
			free(data);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		if (!print_histogram(core, NULL, data, brange->from, brange->nblocks, brange->blocksize, vertical)) {
			free(data);
			free(brange);
			RZ_LOG_ERROR("Cannot generate %s histogram\n", vertical ? "vertical" : "horizontal");
			return RZ_CMD_STATUS_ERROR;
		}
	}
	free(data);
	free(brange);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_equal_z_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_z(core, argc, argv, true, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_z_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_z(core, argc, argv, false, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_z_visual_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_z(core, argc, argv, false, true);
}

static RzCmdStatus print_histogram_stats(RzCore *core, int argc, const char **argv, bool vertical, bool isinteractive) {
	CoreBlockRange *brange = parse_args_calculate_range(core, argc, argv);
	if (!brange) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut8 *data = analysis_stats_histogram_data(core, brange);
	if (!data) {
		free(brange);
		RZ_LOG_ERROR("core: failed to access analysis stats");
		return RZ_CMD_STATUS_ERROR;
	}
	if (isinteractive) {
		if (!print_visual_bytes(core, data, brange)) {
			RZ_LOG_ERROR("Cannot generate interactive histogram\n");
			free(brange);
			free(data);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		if (!print_histogram(core, NULL, data, brange->from, brange->nblocks, brange->blocksize, vertical)) {
			RZ_LOG_ERROR("Cannot generate %s histogram\n", vertical ? "vertical" : "horizontal");
			free(data);
			free(brange);
			return RZ_CMD_STATUS_ERROR;
		}
	}
	free(data);
	free(brange);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_equal_stats_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_stats(core, argc, argv, true, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_stats_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_stats(core, argc, argv, false, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_stats_visual_handler(RzCore *core, int argc, const char **argv) {
	return print_histogram_stats(core, argc, argv, false, true);
}

static RzCmdStatus analysis_hist_handler(RzCore *core, int argc, const char **argv, CoreAnalysisHistogramType hist_type, bool vertical, bool isinteractive) {
	CoreBlockRange *brange = parse_args_calculate_range(core, argc, argv);
	if (!brange) {
		return RZ_CMD_STATUS_ERROR;
	}
	ut8 *data = analysis_histogram_data(core, brange, hist_type);
	if (!data) {
		free(brange);
		RZ_LOG_ERROR("core: failed to access analyzed instructions for specified range");
		return RZ_CMD_STATUS_ERROR;
	}
	if (isinteractive) {
		if (!print_visual_bytes(core, data, brange)) {
			RZ_LOG_ERROR("Cannot generate interactive histogram\n");
			free(brange);
			free(data);
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		if (!print_histogram(core, NULL, data, brange->from, brange->nblocks, brange->blocksize, vertical)) {
			RZ_LOG_ERROR("Cannot generate %s histogram\n", vertical ? "vertical" : "horizontal");
			free(data);
			free(brange);
			return RZ_CMD_STATUS_ERROR;
		}
	}
	free(data);
	free(brange);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_equal_bbs_handler(RzCore *core, int argc, const char **argv) {
	return analysis_hist_handler(core, argc, argv, HISTOGRAM_ANALYSIS_BASIC_BLOCKS, true, false);
}

RZ_IPI RzCmdStatus rz_print_equal_call_handler(RzCore *core, int argc, const char **argv) {
	return analysis_hist_handler(core, argc, argv, HISTOGRAM_ANALYSIS_CALL_INSTRUCTIONS, true, false);
}

RZ_IPI RzCmdStatus rz_print_equal_jump_handler(RzCore *core, int argc, const char **argv) {
	return analysis_hist_handler(core, argc, argv, HISTOGRAM_ANALYSIS_JUMP_INSTRUCTIONS, true, false);
}

RZ_IPI RzCmdStatus rz_print_equal_priv_handler(RzCore *core, int argc, const char **argv) {
	return analysis_hist_handler(core, argc, argv, HISTOGRAM_ANALYSIS_PRIV_INSTRUCTIONS, true, false);
}

RZ_IPI RzCmdStatus rz_print_equal_invalid_handler(RzCore *core, int argc, const char **argv) {
	return analysis_hist_handler(core, argc, argv, HISTOGRAM_ANALYSIS_INVALID_INSTRUCTIONS, true, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_bbs_handler(RzCore *core, int argc, const char **argv) {
	return analysis_hist_handler(core, argc, argv, HISTOGRAM_ANALYSIS_BASIC_BLOCKS, false, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_call_handler(RzCore *core, int argc, const char **argv) {
	return analysis_hist_handler(core, argc, argv, HISTOGRAM_ANALYSIS_CALL_INSTRUCTIONS, false, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_jump_handler(RzCore *core, int argc, const char **argv) {
	return analysis_hist_handler(core, argc, argv, HISTOGRAM_ANALYSIS_JUMP_INSTRUCTIONS, false, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_priv_handler(RzCore *core, int argc, const char **argv) {
	return analysis_hist_handler(core, argc, argv, HISTOGRAM_ANALYSIS_PRIV_INSTRUCTIONS, false, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_invalid_handler(RzCore *core, int argc, const char **argv) {
	return analysis_hist_handler(core, argc, argv, HISTOGRAM_ANALYSIS_INVALID_INSTRUCTIONS, false, false);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_bbs_visual_handler(RzCore *core, int argc, const char **argv) {
	return analysis_hist_handler(core, argc, argv, HISTOGRAM_ANALYSIS_BASIC_BLOCKS, false, true);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_call_visual_handler(RzCore *core, int argc, const char **argv) {
	return analysis_hist_handler(core, argc, argv, HISTOGRAM_ANALYSIS_CALL_INSTRUCTIONS, false, true);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_jump_visual_handler(RzCore *core, int argc, const char **argv) {
	return analysis_hist_handler(core, argc, argv, HISTOGRAM_ANALYSIS_JUMP_INSTRUCTIONS, false, true);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_priv_visual_handler(RzCore *core, int argc, const char **argv) {
	return analysis_hist_handler(core, argc, argv, HISTOGRAM_ANALYSIS_PRIV_INSTRUCTIONS, false, true);
}

RZ_IPI RzCmdStatus rz_print_equal_equal_invalid_visual_handler(RzCore *core, int argc, const char **argv) {
	return analysis_hist_handler(core, argc, argv, HISTOGRAM_ANALYSIS_INVALID_INSTRUCTIONS, false, true);
}

RZ_IPI RzCmdStatus rz_print_equal_two_handler(RzCore *core, int argc, const char **argv) {
	short *word = (short *)core->block;
	size_t i, words = core->blocksize / 2;
	int step = rz_num_math(core->num, argv[1]);
	ut64 oldword = 0;
	for (i = 0; i < words; i++) {
		ut64 word64 = word[i] + ST16_MAX;
		rz_cons_printf("0x%08" PFMT64x " %8d  ", core->offset + (i * 2), word[i]);
		RzBarOptions baropts = {
			.unicode = rz_config_get_b(core->config, "scr.utf8"),
			.thinline = !rz_config_get_b(core->config, "scr.hist.block"),
			.legend = false,
			.offset = rz_config_get_b(core->config, "hex.offset"),
			.offpos = 0,
			.cursor = false,
			.curpos = 0,
			.color = rz_config_get_i(core->config, "scr.color")
		};
		RzStrBuf *strbuf = rz_progressbar(&baropts, word64 * 100 / UT16_MAX, 60);
		if (!strbuf) {
			RZ_LOG_ERROR("Cannot generate vertical histogram\n");
		} else {
			char *bar = rz_strbuf_drain(strbuf);
			rz_cons_print(bar);
			free(bar);
		}
		rz_cons_printf(" %" PFMT64d, word64 - oldword);
		oldword = word64;
		rz_cons_newline();
		i += step;
	}
	return RZ_CMD_STATUS_OK;
}

static void printraw(RzCore *core, int len) {
	ut8 *data = malloc(len);
	if (!data) {
		return;
	}
	if (rz_io_read_at(core->io, core->offset, data, len)) {
		rz_print_raw(core->print, core->offset, data, len);
	}
	free(data);
	core->cons->newline = core->cmd_in_backticks ? false : true;
}

RZ_IPI RzCmdStatus rz_cmd_print_raw_handler(RzCore *core, int argc, const char **argv) {
	int len = argc > 1 ? rz_num_math(core->num, argv[1]) : strlen((const char *)core->block);
	if (len < 0) {
		return RZ_CMD_STATUS_ERROR;
	}
	printraw(core, len);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_print_raw_colors_handler(RzCore *core, int argc, const char **argv) {
	int len = argc > 1 ? rz_num_math(core->num, argv[1]) : strlen((const char *)core->block);
	if (len < 0) {
		return RZ_CMD_STATUS_ERROR;
	}
	colordump(core, core->block, len);
	return RZ_CMD_STATUS_OK;
}

static bool gunzip_and_print_block(RzCore *core, bool verbose) {
	int outlen = 0;
	int inConsumed = 0;
	ut8 *out;
	out = rz_inflate(core->block, core->blocksize, &inConsumed, &outlen);
	if (!out) {
		return false;
	}
	if (verbose) {
		rz_cons_printf("consumed: %d produced: %d\n", inConsumed, outlen);
	}
	rz_cons_memcat((const char *)out, outlen);
	free(out);
	return true;
}

RZ_IPI RzCmdStatus rz_cmd_print_raw_gunzip_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(gunzip_and_print_block(core, false));
}

RZ_IPI RzCmdStatus rz_cmd_print_raw_gunzip_verbose_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(gunzip_and_print_block(core, true));
}

RZ_IPI RzCmdStatus rz_cmd_print_raw_printable_handler(RzCore *core, int argc, const char **argv) {
	int a = rz_config_get_i(core->config, "hex.bytes");
	rz_config_set_i(core->config, "hex.bytes", false);
	// TODO: Use the API instead of commands
	rz_core_cmd0(core, "pxx");
	rz_config_set_i(core->config, "hex.bytes", a);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_print_raw_string_handler(RzCore *core, int argc, const char **argv) {
	int len = argc > 1 ? rz_num_math(core->num, argv[1]) : strlen((const char *)core->block);
	if (len < 0) {
		return RZ_CMD_STATUS_ERROR;
	}
	printraw(core, len);
	return RZ_CMD_STATUS_OK;
}
