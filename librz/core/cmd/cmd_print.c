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

#define PF_USAGE_STR "pf[.k[.f[=v]]|[v]]|[n]|[0|cnt][fmt] [a0 a1 ...]"

static const char *help_msg_pp[] = {
	"Usage: pp[d]", "", "print patterns",
	"pp0", "", "print buffer filled with zeros",
	"pp1", "", "print incremental byte pattern (honor lower bits of cur address and bsize)",
	"pp2", "", "print incremental word pattern",
	"pp4", "", "print incremental dword pattern",
	"pp8", "", "print incremental qword pattern",
	"ppa", "[lu]", "latin alphabet (lowercase, uppercases restrictions)",
	"ppd", "", "print debruijn pattern (see rz-gg -P, -q and wopD)",
	"ppf", "", "print buffer filled with 0xff",
	"ppn", "", "numeric pin patterns",
	NULL
};

static const char *help_msg_pc[] = {
	"Usage:", "pc", " # Print in code",
	"pc", "", "C",
	"pc*", "", "print 'wx' rizin commands",
	"pcA", "", ".bytes with instructions in comments",
	"pca", "", "GAS .byte blob",
	"pcd", "", "C dwords (8 byte)",
	"pch", "", "C half-words (2 byte)",
	"pci", "", "C array of bytes with instructions",
	"pcJ", "", "javascript",
	"pcj", "", "json",
	"pck", "", "kotlin",
	"pco", "", "Objective-C",
	"pcp", "", "python",
	"pcr", "", "rust",
	"pcS", "", "shellscript that reconstructs the bin",
	"pcs", "", "string",
	"pcv", "", "JaVa",
	"pcV", "", "V (vlang.io)",
	"pcw", "", "C words (4 byte)",
	"pcy", "", "yara",
	"pcz", "", "Swift",
	NULL
};

static const char *help_msg_pF[] = {
	"Usage: pF[apdbA]", "[len]", "parse ASN1, PKCS, X509, DER, protobuf, axml",
	"pFa", "[len]", "decode ASN1 from current block",
	"pFaq", "[len]", "decode ASN1 from current block (quiet output)",
	"pFb", "[len]", "decode raw proto buffers.",
	"pFbv", "[len]", "decode raw proto buffers (verbose).",
	"pFo", "[len]", "decode ASN1 OID",
	"pFp", "[len]", "decode PKCS7",
	"pFx", "[len]", "Same with X509",
	"pFA", "[len]", "decode Android Binary XML from current block",
	NULL
};

static const char *help_msg_pr[] = {
	"Usage: pr[glx]", "[size]", "print N raw bytes",
	"prc", "[=fep..]", "print bytes as colors in palette",
	"prg", "[?]", "print raw GUNZIPped block",
	"prx", "", "printable chars with real offset (hyew)",
	"prz", "", "print raw zero terminated string",
	NULL
};

static const char *help_msg_prg[] = {
	"Usage: prg[io]", "", "print raw GUNZIPped block",
	"prg", "", "print gunzipped data of current block",
	"prgi", "", "show consumed bytes when inflating",
	"prgo", "", "show output bytes after inflating",
	NULL
};

static const char *help_msg_amper[] = {
	"Usage:", "&[-|<cmd>]", "Manage tasks (WARNING: Experimental. Use with caution!)",
	"&", " <cmd>", "run <cmd> in a new background task",
	"&t", " <cmd>", "run <cmd> in a new transient background task (auto-delete when it is finished)",
	"&", "", "list all tasks",
	"&j", "", "list all tasks (in JSON)",
	"&=", " 3", "show output of task 3",
	"&b", " 3", "break task 3",
	"&-", " 1", "delete task #1 or schedule for deletion when it is finished",
	"&", "-*", "delete all done tasks",
	"&?", "", "show this help",
	"&&", " 3", "wait until task 3 is finished",
	"&&", "", "wait until all tasks are finished",
	NULL
};

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
	"pA", "[n_ops]", "show n_ops address and type",
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
	"pz", "[?] [len]", "print zoom view (see pz? for help)",
	NULL
};

static const char *help_msg_pxd[] = {
	"Usage:", "pxd[1248] ([len])", "show decimal byte/short/word/dword dumps",
	"pxd", "", "show decimal hexdumps",
	"pxd2", "", "show shorts hexdump",
	"pxd4", "", "show dword hexdump (int)",
	"pxd8", "", "show qword hexdump (int)",
	NULL
};

static const char *help_msg_p_equal[] = {
	"Usage:", "p=[=bep?][qj] [N] ([len]) ([offset]) ", "show entropy/printable chars/chars bars",
	"e ", "zoom.in", "specify range for zoom",
	"p=", "", "print bytes of current block in bars",
	"p==", "[..]", "same subcommands as p=, using column bars instead of rows",
	"p=", "0", "number of 0x00 bytes for each filesize/blocksize",
	"p=", "2", "short (signed int16) bars, good for waves",
	"p=", "a", "analysis bbs maps",
	"p=", "A", "analysis stats maps (see p-)",
	"p=", "b", "same as above",
	"p=", "c", "number of calls per block",
	"p=", "d", "min/max/number of unique bytes in block",
	"p=", "e", "entropy for each filesize/blocksize",
	"p=", "F", "number of 0xFF bytes for each filesize/blocksize",
	"p=", "i", "number of invalid instructions per block",
	"p=", "j", "number of jumps and conditional jumps in block",
	"p=", "m", "number of flags and marks in block",
	"p=", "p", "number of printable bytes for each filesize/blocksize",
	"p=", "s", "number of syscall and privileged instructions",
	"p=", "z", "number of chars in strings in block",
	NULL
};

static const char *help_msg_pj[] = {
	"Usage:", "pj[..] [size]", "",
	"pj", "", "print current block as indented JSON",
	"pj.", "", "print as indented JSON from 0 to the current offset",
	"pj..", "", "print JSON path from 0 to the current offset",
	NULL
};

static const char *help_msg_p_minus[] = {
	"Usage:", "p-[hj] [nblocks] ", "bar|json|histogram blocks",
	"p-", "", "show ascii-art bar of metadata in file boundaries",
	"p-e", "", "show ascii-art bar of entropy per block",
	"p-h", "", "show histogram analysis of metadata per block",
	"p-j", "", "show json format",
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

static const char *help_msg_pi[] = {
	"Usage:", "pi[befr] [num]", "",
	"pia", "", "print all possible opcodes (byte per byte)",
	"pib", "", "print instructions of basic block",
	"pie", "", "print offset + esil expression",
	"pif", "[?]", "print instructions of function",
	"pir", "", "like 'pdr' but with 'pI' output",
	"piu", "[q] [limit]", "disasm until ujmp or ret is found (see pdp)",
	"pix", "  [hexpairs]", "alias for pad",
	NULL
};

static const char *help_msg_pif[] = {
	"Usage:",
	"pif[cj]",
	"",
	"pif?",
	"",
	"print this help message",
	"pifc",
	"",
	"print all calls from this function",
	"pifcj",
	"",
	"print all calls from this function in JSON format",
	"pifj",
	"",
	"print instructions of function in JSON format",
};

static const char *help_msg_po[] = {
	"Usage:", "po[24aAdlmorsx]", " [hexpairs] @ addr[!bsize]",
	"po[24aAdlmorsx]", "", "without hexpair values, clipboard is used",
	"po2", " [val]", "2=  2 byte endian swap",
	"po4", " [val]", "4=  4 byte endian swap",
	"poa", " [val]", "+=  addition (f.ex: poa 0102)",
	"poA", " [val]", "&=  and",
	"pod", " [val]", "/=  divide",
	"pol", " [val]", "<<= shift left",
	"pom", " [val]", "*=  multiply",
	"poo", " [val]", "|=  or",
	"por", " [val]", ">>= shift right",
	"pos", " [val]", "-=  substraction",
	"pox", " [val]", "^=  xor  (f.ex: pox 0x90)",
	NULL
};

static const char *help_msg_ps[] = {
	"Usage:", "ps[bijqpsuwWxz+] [N]", "Print String",
	"ps", "", "print string",
	"ps+", "[j]", "print libc++ std::string (same-endian, ascii, zero-terminated)",
	"psb", "", "print strings in current block",
	"psi", "", "print string inside curseek",
	"psj", "", "print string in JSON format",
	"psp", "[j]", "print pascal string",
	"pss", "", "print string in screen (wrap width)",
	"psu", "[zj]", "print utf16 unicode (json)",
	"psw", "[j]", "print 16bit wide little endian string",
	"psW", "[j]", "print 32bit wide little endian string",
	"psx", "", "show string with escaped chars",
	"psz", "[j]", "print zero-terminated string",
	NULL
};

static const char *help_msg_pv[] = {
	"Usage: pv[j][1,2,4,8,z]", "", "",
	"pv", "", "print bytes based on asm.bits",
	"pv1", "", "print 1 byte in memory",
	"pv2", "", "print 2 bytes in memory",
	"pv4", "", "print 4 bytes in memory",
	"pv8", "", "print 8 bytes in memory",
	"pvz", "", "print value as string (alias for ps)",
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

// colordump
static void cmd_prc(RzCore *core, const ut8 *block, int len) {
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

static void cmd_pCd(RzCore *core, const char *input) {
	int h, w = rz_cons_get_size(&h);
	int colwidth = rz_config_get_i(core->config, "hex.cols") * 2.5;
	if (colwidth < 1) {
		colwidth = 16;
	}
	int i, columns = w / colwidth;
	int rows = h - 2;
	int obsz = core->blocksize;
	int user_rows = rz_num_math(core->num, input);
	bool asm_minicols = rz_config_get_i(core->config, "asm.minicols");
	char *o_ao = strdup(rz_config_get(core->config, "asm.offset"));
	char *o_ab = strdup(rz_config_get(core->config, "asm.bytes"));
	if (asm_minicols) {
		rz_config_set(core->config, "asm.offset", "false");
		// rz_config_set (core->config, "asm.bytes", "false");
	}
	rz_config_set(core->config, "asm.bytes", "false");
	if (user_rows > 0) {
		rows = user_rows + 1;
	}
	RzConsCanvas *c = rz_cons_canvas_new(w, rows);
	ut64 osek = core->offset;
	c->color = rz_config_get_i(core->config, "scr.color");
	rz_core_block_size(core, rows * 32);
	for (i = 0; i < columns; i++) {
		(void)rz_cons_canvas_gotoxy(c, i * (w / columns), 0);
		char *cmd = rz_str_newf("pdq %d @i:%d", rows, rows * i);
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
}

static void findMethodBounds(RzList *methods, ut64 *min, ut64 *max) {
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

static void cmd_pCD(RzCore *core, const char *input) {
	int h, w = rz_cons_get_size(&h);
	int i;
	int rows = h - 2;
	int obsz = core->blocksize;
	int user_rows = rz_num_math(core->num, input);
	bool asm_minicols = rz_config_get_i(core->config, "asm.minicols");
	char *o_ao = strdup(rz_config_get(core->config, "asm.offset"));
	char *o_ab = strdup(rz_config_get(core->config, "asm.bytes"));
	if (asm_minicols) {
		rz_config_set(core->config, "asm.offset", "false");
		rz_config_set(core->config, "asm.bytes", "false");
	}
	rz_config_set(core->config, "asm.bytes", "false");
	if (user_rows > 0) {
		rows = user_rows + 1;
	}
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
			cmd = rz_str_newf("dr;?e;?e backtrace:;dbt");
			break;
		case 1:
			(void)rz_cons_canvas_gotoxy(c, 28, 0);
			// cmd = rz_str_newf ("pxw 128@r:SP;pd@r:PC");
			cmd = rz_str_newf("%s 128@r:SP;pd@ 0x%" PFMT64x, core->stkcmd, osek);
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
}

static void cmd_pCx(RzCore *core, const char *input, const char *xcmd) {
	int h, w = rz_cons_get_size(&h);
	int hex_cols = rz_config_get_i(core->config, "hex.cols");
	int colwidth = hex_cols * 5;
	int i, columns = w / (colwidth * 0.9);
	int rows = h - 2;
	int user_rows = rz_num_math(core->num, input);
	rz_config_set_i(core->config, "hex.cols", colwidth / 5);
	if (user_rows > 0) {
		rows = user_rows + 1;
	}
	RzConsCanvas *c = rz_cons_canvas_new(w, rows);
	if (!c) {
		eprintf("Couldn't allocate a canvas with %d rows\n", rows);
		goto err;
	}

	ut64 tsek = core->offset;
	c->color = rz_config_get_i(core->config, "scr.color");
	int bsize = hex_cols * rows;
	if (!strcmp(xcmd, "pxA")) {
		bsize *= 12;
	}
	for (i = 0; i < columns; i++) {
		(void)rz_cons_canvas_gotoxy(c, i * (w / columns), 0);
		char *cmd = rz_str_newf("%s %d @ %" PFMT64u, xcmd, bsize, tsek);
		char *dis = rz_core_cmd_str(core, cmd);
		if (dis) {
			rz_cons_canvas_write(c, dis);
			free(dis);
		}
		free(cmd);
		tsek += bsize - 32;
	}

	rz_cons_canvas_print(c);
	rz_cons_canvas_free(c);
err:
	rz_config_set_i(core->config, "hex.cols", hex_cols);
}

static void cmd_print_eq_dict(RzCore *core, const ut8 *block, int bsz) {
	int i;
	int min = -1;
	int max = 0;
	int dict = 0;
	int range = 0;
	bool histogram[256] = { 0 };
	for (i = 0; i < bsz; i++) {
		histogram[block[i]] = true;
	}
	for (i = 0; i < 256; i++) {
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
}

RZ_API void rz_core_set_asm_configs(RzCore *core, char *arch, ut32 bits, int segoff) {
	rz_config_set(core->config, "asm.arch", arch);
	rz_config_set_i(core->config, "asm.bits", bits);
	// XXX - this needs to be done here, because
	// if arch == x86 and bits == 16, segoff automatically changes
	rz_config_set_i(core->config, "asm.segoff", segoff);
}

static void cmd_p_minus_e(RzCore *core, ut64 at, ut64 ate) {
	ut8 *blockptr = malloc(ate - at);
	if (!blockptr) {
		return;
	}
	if (rz_io_read_at(core->io, at, blockptr, (ate - at))) {
		ut8 entropy = (ut8)(rz_hash_entropy_fraction(core->hash, blockptr, (ate - at)) * 255);
		entropy = 9 * entropy / 200; // normalize entropy from 0 to 9
		if (rz_config_get_i(core->config, "scr.color")) {
			const char *color =
				(entropy > 6) ? Color_BGRED : (entropy > 3) ? Color_BGGREEN
									    : Color_BGBLUE;
			rz_cons_printf("%s%d" Color_RESET, color, entropy);
		} else {
			rz_cons_printf("%d", entropy);
		}
	}
	free(blockptr);
}

static void helpCmdTasks(RzCore *core) {
	// TODO: integrate with =h& and bg analysis/string/searches/..
	rz_core_cmd_help(core, help_msg_amper);
}

static void print_format_help_help_help_help(RzCore *core) {
	const char *help_msg[] = {
		"    STAHP IT!!!", "", "",
		NULL
	};
	rz_core_cmd_help(core, help_msg);
}

static void cmd_print_fromage(RzCore *core, const char *input, const ut8 *data, int size) {
	switch (*input) {
	case 'a': {
		asn1_setformat(input[1] != 'q');
		RASN1Object *asn1 = rz_asn1_create_object(data, size, data);
		if (asn1) {
			char *res = rz_asn1_to_string(asn1, 0, NULL);
			rz_asn1_free_object(asn1);
			if (res) {
				rz_cons_printf("%s\n", res);
				free(res);
			}
		} else {
			eprintf("Malformed object: did you supply enough data?\ntry to change the block size (see b?)\n");
		}
	} break;
	case 'x': // "pFx" x509
	{
		RX509Certificate *x509 = rz_x509_parse_certificate(rz_asn1_create_object(data, size, data));
		if (x509) {
			RzStrBuf *sb = rz_strbuf_new("");
			rz_x509_certificate_dump(x509, NULL, sb);
			char *res = rz_strbuf_drain(sb);
			if (res) {
				rz_cons_printf("%s\n", res);
				free(res);
			}
			rz_x509_free_certificate(x509);
		} else {
			eprintf("Malformed object: did you supply enough data?\ntry to change the block size (see b?)\n");
		}
	} break;
	case 'p': // "pFp"
	{
		RCMS *cms = rz_pkcs7_parse_cms(data, size);
		if (cms) {
			char *res = rz_pkcs7_cms_to_string(cms);
			if (res) {
				rz_cons_printf("%s\n", res);
				free(res);
			}
			rz_pkcs7_free_cms(cms);
		} else {
			eprintf("Malformed object: did you supply enough data?\ntry to change the block size (see b?)\n");
		}
	} break;
	case 'b': // "pFb"
	{
		char *s = rz_protobuf_decode(data, size, input[1] == 'v');
		if (s) {
			rz_cons_printf("%s", s);
			free(s);
		}
	} break;
	case 'A': // "pFA"
	{
		char *s = rz_axml_decode(data, size);
		if (s) {
			rz_cons_printf("%s", s);
			free(s);
		} else {
			eprintf("Malformed object: did you supply enough data?\ntry to change the block size (see b?)\n");
		}
	} break;
	default:
	case '?': // "pF?"
		rz_core_cmd_help(core, help_msg_pF);
		break;
	}
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
		int x = rz_num_math(core->num, argv[1]);
		int y = rz_num_math(core->num, argv[2]);
		int w = rz_num_math(core->num, argv[3]);
		int h = rz_num_math(core->num, argv[4]);
		if (x && y && w && h) {
			cmd = rz_str_dup(cmd, argv[5]);
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
		eprintf("TODO: Change gadget background color\n");
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
				eprintf("Struct %s not defined\nUsage: pfs.struct_name | pfs format\n", _input);
			}
		} else if (*_input == ' ') {
			while (*_input == ' ' && *_input != '\0') {
				_input++;
			}
			if (*_input) {
				rz_cons_printf("%d\n", rz_type_format_struct_size(core->analysis->typedb, _input, mode, 0));
			} else {
				eprintf("Struct %s not defined\nUsage: pfs.struct_name | pfs format\n", _input);
			}
		} else {
			eprintf("Usage: pfs.struct_name | pfs format\n");
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
					eprintf("Struct %s is not defined\n", _input);
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
					eprintf("Parse error: %s\n", error_msg);
					free(error_msg);
				}
			} else {
				if (!rz_core_cmd_file(core, home) && !rz_core_cmd_file(core, path)) {
					if (!rz_core_cmd_file(core, _input + 3)) {
						eprintf("pfo: cannot open format file at '%s'\n", path);
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
					eprintf("Struct or fields name can not contain dot symbol (.)\n");
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
				eprintf("Cannot find '%s' format.\n", name);
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
		int size = RZ_MAX(core->blocksize, struct_sz);
		ut8 *buf = calloc(1, size);
		if (!buf) {
			eprintf("cannot allocate %d byte(s)\n", size);
			goto stage_left;
		}
		memcpy(buf, core->block, core->blocksize);
		/* check if fmt is '\d+ \d+<...>', common mistake due to usage string*/
		bool syntax_ok = true;
		char *args = strdup(fmt);
		if (!args) {
			rz_cons_printf("Error: Mem Allocation.");
			free(args);
			free(buf);
			goto stage_left;
		}
		const char *arg1 = strtok(args, " ");
		if (arg1 && rz_str_isnumber(arg1)) {
			syntax_ok = false;
			rz_cons_printf("Usage: pf [0|cnt][format-string]\n");
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
static void annotated_hexdump(RzCore *core, const char *str, int len) {
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
		rz_cons_strcat(Color_GREEN);
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
#if 0
	Size letters are b(byte), h (halfword), w (word), g (giant, 8 bytes).
#endif
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
		rz_core_cmdf(core, "psb %d @ 0x%" PFMT64x, count * size, addr);
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

static int cmd_print_pxA(RzCore *core, int len, const char *input) {
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
	if (*input == 'v') {
		datalen = cols * 8 * core->cons->rows;
		data = malloc(datalen);
		rz_io_read_at(core->io, core->offset, data, datalen);
		len = datalen;
	} else {
		data = core->block;
		datalen = core->blocksize;
	}
	if (len < 1) {
		len = datalen;
	}
	if (len < 0 || len > datalen) {
		eprintf("Invalid length\n");
		return 0;
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

static ut8 *old_transform_op(RzCore *core, const char *val, char op, int *buflen) {
	RzCoreWriteOp wop;
	switch (op) {
	case '2':
		wop = RZ_CORE_WRITE_OP_BYTESWAP2;
		break;
	case '4':
		wop = RZ_CORE_WRITE_OP_BYTESWAP4;
		break;
	case '8':
		wop = RZ_CORE_WRITE_OP_BYTESWAP8;
		break;
	case 'a':
		wop = RZ_CORE_WRITE_OP_ADD;
		break;
	case 'A':
		wop = RZ_CORE_WRITE_OP_AND;
		break;
	case 'd':
		wop = RZ_CORE_WRITE_OP_DIV;
		break;
	case 'l':
		wop = RZ_CORE_WRITE_OP_SHIFT_LEFT;
		break;
	case 'm':
		wop = RZ_CORE_WRITE_OP_MUL;
		break;
	case 'o':
		wop = RZ_CORE_WRITE_OP_OR;
		break;
	case 'r':
		wop = RZ_CORE_WRITE_OP_SHIFT_RIGHT;
		break;
	case 's':
		wop = RZ_CORE_WRITE_OP_SUB;
		break;
	case 'x':
		wop = RZ_CORE_WRITE_OP_XOR;
		break;
	default:
		wop = RZ_CORE_WRITE_OP_XOR;
		rz_warn_if_reached();
		break;
	}

	ut8 *hex = NULL;
	int hexlen = -1;
	if (val) {
		val = rz_str_trim_head_ro(val);
		hex = RZ_NEWS(ut8, (strlen(val) + 1) / 2);
		if (!hex) {
			return NULL;
		}

		hexlen = rz_hex_str2bin(val, hex);
	}
	ut8 *result = rz_core_transform_op(core, core->offset, wop, hex, hexlen, buflen);
	free(hex);
	return result;
}

static void cmd_print_op(RzCore *core, const char *input) {
	ut8 *buf;
	int buflen = -1;

	if (!input[0])
		return;
	switch (input[1]) {
	case 'a':
	case 's':
	case 'A':
	case 'x':
	case 'r':
	case 'l':
	case 'm':
	case 'd':
	case 'o':
	case '2':
	case '4':
		if (input[2]) { // parse val from arg
			buf = old_transform_op(core, input + 3, input[1], &buflen);
		} else { // use clipboard instead of val
			buf = old_transform_op(core, NULL, input[1], &buflen);
		}
		break;
	case 'n':
		buf = old_transform_op(core, "ff", 'x', &buflen);
		break;
	case '\0':
	case '?':
	default:
		rz_core_cmd_help(core, help_msg_po);
		return;
	}
	if (buf) {
		rz_print_hexdump(core->print, core->offset, buf,
			buflen, 16, 1, 1);
		free(buf);
	}
}

static void printraw(RzCore *core, int len) {
	int obsz = core->blocksize;
	int restore_obsz = 0;
	if (len != obsz) {
		if (!rz_core_block_size(core, len)) {
			len = core->blocksize;
		} else {
			restore_obsz = 1;
		}
	}
	rz_print_raw(core->print, core->offset, core->block, len);
	if (restore_obsz) {
		(void)rz_core_block_size(core, obsz);
	}
	core->cons->newline = core->cmd_in_backticks ? false : true;
}

static void _handle_call(RzCore *core, char *line, char **str) {
	rz_return_if_fail(core && line && str && core->rasm && core->rasm->cur);
	if (strstr(core->rasm->cur->arch, "x86")) {
		*str = strstr(line, "call ");
	} else if (strstr(core->rasm->cur->arch, "arm")) {
		*str = strstr(line, " b ");
		if (*str && strstr(*str, " 0x")) {
			/*
			 * avoid treating branches to
			 * non-symbols as calls
			 */
			*str = NULL;
		}
		if (!*str) {
			*str = strstr(line, "bl ");
		}
		if (!*str) {
			*str = strstr(line, "bx ");
		}
	}
}

// TODO: this is just a PoC, the disasm loop should be rewritten
// TODO: this is based on string matching, it should be written upon RzAnalysisOp to know
// when we have a call and such
static void disasm_strings(RzCore *core, const char *input, RzAnalysisFunction *fcn) {
	const char *linecolor = NULL;
	char *ox, *qo, *string = NULL;
	char *line, *s, *str, *string2 = NULL;
	char *switchcmp = NULL;
	int i, count, use_color = rz_config_get_i(core->config, "scr.color");
	bool show_comments = rz_config_get_i(core->config, "asm.comments");
	bool show_offset = rz_config_get_i(core->config, "asm.offset");
	bool asm_tabs = rz_config_get_i(core->config, "asm.tabs");
	bool scr_html = rz_config_get_i(core->config, "scr.html");
	bool asm_dwarf = rz_config_get_i(core->config, "asm.dwarf");
	bool asm_flags = rz_config_get_i(core->config, "asm.flags");
	bool asm_cmt_right = rz_config_get_i(core->config, "asm.cmt.right");
	bool asm_emu = rz_config_get_i(core->config, "asm.emu");
	bool emu_str = rz_config_get_i(core->config, "emu.str");
	rz_config_set_i(core->config, "emu.str", true);
	RzConsPrintablePalette *pal = &core->cons->context->pal;
	// force defaults
	rz_config_set_i(core->config, "asm.offset", true);
	rz_config_set_i(core->config, "asm.dwarf", true);
	rz_config_set_i(core->config, "scr.color", COLOR_MODE_DISABLED);
	rz_config_set_i(core->config, "asm.tabs", 0);
	rz_config_set_i(core->config, "scr.html", 0);
	rz_config_set_i(core->config, "asm.cmt.right", true);

	line = NULL;
	s = NULL;
	if (!strncmp(input, "dsb", 3)) {
		RzAnalysisBlock *bb = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
		if (bb) {
			line = s = rz_core_cmd_strf(core, "pD %" PFMT64u " @ 0x%08" PFMT64x, bb->size, bb->addr);
		}
	} else if (!strncmp(input, "dsf", 3) || !strncmp(input, "dsr", 3)) {
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_NULL);
		if (fcn) {
			line = s = rz_core_cmd_str(core, "pdr");
		} else {
			eprintf("Cannot find function.\n");
			rz_config_set_i(core->config, "scr.color", use_color);
			rz_config_set_i(core->config, "asm.cmt.right", asm_cmt_right);
			goto restore_conf;
		}
	} else if (!strncmp(input, "ds ", 3)) {
		line = s = rz_core_cmd_strf(core, "pD %s", input + 3);
	} else {
		line = s = rz_core_cmd_str(core, "pd");
	}

	rz_config_set_i(core->config, "scr.html", scr_html);
	rz_config_set_i(core->config, "scr.color", use_color);
	rz_config_set_i(core->config, "asm.cmt.right", asm_cmt_right);
	count = rz_str_split(s, '\n');
	if (!line || !*line || count < 1) {
		//	RZ_FREE (s);
		goto restore_conf;
	}
	for (i = 0; i < count; i++) {
		ut64 addr = UT64_MAX;
		ox = strstr(line, "0x");
		qo = strchr(line, '\"');
		RZ_FREE(string);
		if (ox) {
			addr = rz_num_get(NULL, ox);
		}
		if (qo) {
			char *qoe = strrchr(qo + 1, '"');
			if (qoe) {
				int raw_len = qoe - qo - 1;
				int actual_len = 0;
				char *ptr = qo + 1;
				for (; ptr < qoe; ptr++) {
					if (*ptr == '\\' && ptr + 1 < qoe) {
						int i, body_len;
						switch (*(ptr + 1)) {
						case 'x':
							body_len = 3;
							break;
						case 'u':
							body_len = 5;
							break;
						case 'U':
							body_len = 9;
							break;
						default:
							body_len = 1;
						}
						for (i = 0; i < body_len && ptr < qoe; i++) {
							ptr++;
						}
					}
					actual_len++;
				}
				if (actual_len > 2) {
					string = rz_str_ndup(qo, raw_len + 2);
				}
				linecolor = RZ_CONS_COLOR(comment);
			}
		}
		ox = strstr(line, "; 0x");
		if (!ox) {
			ox = strstr(line, "@ 0x");
		}
		if (ox) {
			char *qoe = strchr(ox + 3, ' ');
			if (!qoe) {
				qoe = strchr(ox + 3, '\x1b');
			}
			int len = qoe ? qoe - ox : strlen(ox + 3);
			string2 = rz_str_ndup(ox + 2, len - 1);
			if (rz_num_get(NULL, string2) < 0x100) {
				RZ_FREE(string2);
			}
		}
		if (asm_flags) {
			str = strstr(line, ";-- ");
			if (str) {
				if (!rz_str_startswith(str + 4, "case")) {
					rz_cons_printf("%s\n", str);
				}
			}
		}
#define USE_PREFIXES 1
#if USE_PREFIXES
		// XXX leak
		str = strstr(line, " obj.");
		if (!str) {
			str = strstr(line, " str.");
			if (!str) {
				str = strstr(line, " imp.");
				if (!str) {
					str = strstr(line, " fcn.");
					if (!str) {
						str = strstr(line, " sub.");
					}
				}
			}
		}
#else
		if (strchr(line, ';')) {
			const char *dot = rz_str_rchr(line, NULL, '.');
			if (dot) {
				const char *o = rz_str_rchr(line, dot, ' ');
				if (o) {
					str = (char *)o;
				} else {
					eprintf("Warning: missing summary reference: %s\n", dot);
				}
			}
		}
#endif
		if (str) {
			str = strdup(str);
			char *qoe = NULL;
			if (!qoe) {
				qoe = strchr(str + 1, '\x1b');
			}
			if (!qoe) {
				qoe = strchr(str + 1, ';');
			}
			if (!qoe) {
				qoe = strchr(str + 1, ' ');
			}
			if (qoe) {
				free(string2);
				string2 = rz_str_ndup(str + 1, qoe - str - 1);
			} else {
				free(string2);
				string2 = strdup(str + 1);
			}
			if (string2) {
				RZ_FREE(string);
				string = string2;
				string2 = NULL;
			}
		}
		RZ_FREE(string2);
		_handle_call(core, line, &str);
		if (!str) {
			str = strstr(line, "sym.");
			if (!str) {
				str = strstr(line, "fcn.");
			}
		}
		if (str) {
			str = strdup(str);
			char *qoe = strchr(str, ';');
			if (qoe) {
				char *t = str;
				str = rz_str_ndup(str, qoe - str);
				free(t);
			}
		}
		if (str) {
			string2 = strdup(str);
			linecolor = RZ_CONS_COLOR(call);
		}
		if (!string && string2) {
			string = string2;
			string2 = NULL;
		}
		if (strstr(line, "XREF")) {
			addr = UT64_MAX;
		}
		if (addr != UT64_MAX) {
			const char *str = NULL;
			if (show_comments) {
				char *comment = rz_core_analysis_get_comments(core, addr);
				if (comment) {
					if (switchcmp) {
						if (strcmp(comment, switchcmp)) {
							if (show_offset) {
								rz_cons_printf("%s0x%08" PFMT64x " ", use_color ? pal->offset : "", addr);
							}
							rz_cons_printf("%s%s\n", use_color ? pal->comment : "", comment);
						}
					} else {
						if (show_offset) {
							rz_cons_printf("%s0x%08" PFMT64x " ", use_color ? pal->offset : "", addr);
						}
						rz_cons_printf("%s%s\n", use_color ? pal->comment : "", comment);
					}
					if (rz_str_startswith(comment, "switch table")) {
						switchcmp = strdup(comment);
					}
					RZ_FREE(comment);
				}
			}

			if (fcn) {
				bool label = false;
				/* show labels, basic blocks and (conditional) branches */
				RzAnalysisBlock *bb;
				RzListIter *iter;
				rz_list_foreach (fcn->bbs, iter, bb) {
					if (addr == bb->jump) {
						if (show_offset) {
							rz_cons_printf("%s0x%08" PFMT64x ":\n", use_color ? Color_YELLOW : "", addr);
						}
						label = true;
						break;
					}
				}
				if (!label && strstr(line, "->")) {
					rz_cons_printf("%s0x%08" PFMT64x ":\n", use_color ? Color_YELLOW : "", addr);
				}
				if (strstr(line, "=<")) {
					rz_list_foreach (fcn->bbs, iter, bb) {
						if (addr >= bb->addr && addr < bb->addr + bb->size) {
							const char *op;
							if (use_color) {
								op = (bb->fail == UT64_MAX) ? Color_GREEN "jmp" : "cjmp";
							} else {
								op = (bb->fail == UT64_MAX) ? "jmp" : "cjmp";
							}
							if (show_offset) {
								rz_cons_printf("%s0x%08" PFMT64x " " Color_RESET, use_color ? pal->offset : "", addr);
							}
							rz_cons_printf("%s 0x%08" PFMT64x "%s\n",
								op, bb->jump, use_color ? Color_RESET : "");
							break;
						}
					}
				}
			}
			if (string && *string) {
				if (string && !strncmp(string, "0x", 2)) {
					str = string;
				}
				if (string2 && !strncmp(string2, "0x", 2)) {
					str = string2;
				}
				ut64 ptr = rz_num_math(NULL, str);
				RzFlagItem *flag = NULL;
				if (str) {
					flag = rz_core_flag_get_by_spaces(core->flags, ptr);
				}
				if (!flag) {
					if (string && !strncmp(string, "0x", 2)) {
						RZ_FREE(string);
					}
					if (string2 && !strncmp(string2, "0x", 2)) {
						RZ_FREE(string2);
					}
				}
				if (string && addr != UT64_MAX && addr != UT32_MAX) {
					rz_str_trim(string);
					if (string2) {
						rz_str_trim(string2);
					}
					//// TODO implememnt avoid duplicated strings
					// eprintf ("---> %s\n", string);
					if (use_color) {
						if (show_offset) {
							rz_cons_printf("%s0x%08" PFMT64x " " Color_RESET, use_color ? pal->offset : "", addr);
						}
						rz_cons_printf("%s%s%s%s%s%s%s\n",
							linecolor ? linecolor : "",
							string2 ? string2 : "", string2 ? " " : "", string,
							flag ? " " : "", flag ? flag->name : "", Color_RESET);
					} else {
						if (show_offset) {
							rz_cons_printf("0x%08" PFMT64x " ", addr);
						}
						rz_cons_printf("%s%s%s%s%s\n",
							string2 ? string2 : "", string2 ? " " : "", string,
							flag ? " " : "", flag ? flag->name : "");
					}
				}
			}
		}
		line += strlen(line) + 1;
	}
	// rz_cons_printf ("%s", s);
	free(string2);
	free(string);
	free(s);
	free(str);
	free(switchcmp);
restore_conf:
	rz_config_set_i(core->config, "asm.offset", show_offset);
	rz_config_set_i(core->config, "asm.dwarf", asm_dwarf);
	rz_config_set_i(core->config, "asm.tabs", asm_tabs);
	rz_config_set_i(core->config, "scr.html", scr_html);
	rz_config_set_i(core->config, "asm.emu", asm_emu);
	rz_config_set_i(core->config, "emu.str", emu_str);
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

	if (!strncmp(plugin->name, "entropy", 7)) {
		handle_entropy(core, plugin->name, core->block, core->blocksize);
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

// XXX blocksize is missing
static void cmd_print_pv(RzCore *core, const char *input, bool useBytes) {
	const char *stack[] = {
		"ret", "arg0", "arg1", "arg2", "arg3", "arg4", NULL
	};
	ut8 *block = core->block;
	int blocksize = core->blocksize;
	ut8 *block_end = core->block + blocksize;
	int i, n = core->rasm->bits / 8;
	int type = 'v';
	bool fixed_size = true;
	switch (input[0]) {
	case '1': // "pv1"
		n = 1;
		input++;
		break;
	case '2': // "pv2"
		n = 2;
		input++;
		break;
	case '4': // "pv4"
		n = 4;
		input++;
		break;
	case '8': // "pv8"
		n = 8;
		input++;
		break;
	default:
		if (*input && input[1] == 'j') {
			input++;
		}
		fixed_size = false;
		break;
	}
	const char *arg = strchr(input, ' ');
	if (arg) {
		arg = rz_str_trim_head_ro(arg + 1);
	} else {
		arg = input;
	}
	st64 repeat = rz_num_math(core->num, arg);
	if (repeat < 0) {
		repeat = 1;
	}
	if (useBytes && n > 0 && repeat > 0) {
		repeat /= n;
	}
	if (repeat < 1) {
		repeat = 1;
	}
	// variables can be
	switch (input[0]) {
	case 'z': // "pvz"
		type = 'z';
		if (input[1]) {
			input++;
		} else {
			rz_core_cmdf(core, "ps");
			break;
		}
		/* fallthrough */
		// case ' ': // "pv "
		for (i = 0; stack[i]; i++) {
			if (!strcmp(input + 1, stack[i])) {
				if (type == 'z') {
					rz_core_cmdf(core, "ps @ [`drn sp`+%d]", n * i);
				} else {
					rz_core_cmdf(core, "?v [`drn sp`+%d]", n * i);
				}
			}
		}
		break;
	case '*': { // "pv*"
		for (i = 0; i < repeat; i++) {
			const bool be = core->print->big_endian;
			ut64 at = core->offset + (i * n);
			ut8 *b = block + (i * n);
			switch (n) {
			case 1:
				rz_cons_printf("f pval.0x%08" PFMT64x " @ %d\n", at, rz_read_ble8(b));
				break;
			case 2:
				rz_cons_printf("f pval.0x%08" PFMT64x " @ %d\n", at, rz_read_ble16(b, be));
				break;
			case 4:
				rz_cons_printf("f pval.0x%08" PFMT64x " @ %d\n", at, rz_read_ble32(b, be));
				break;
			case 8:
			default:
				rz_cons_printf("f pval.0x%08" PFMT64x " @ %" PFMT64d "\n", at, rz_read_ble64(b, be));
				break;
			}
		}
		break;
	}
	case 'j': { // "pvj"
		PJ *pj = pj_new();
		if (!pj) {
			return;
		}
		pj_a(pj);
		ut64 at = core->offset;
		ut64 oldAt = at;
		for (i = 0; i < repeat; i++) {
			rz_core_seek(core, at, false);
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
			// rz_num_get is going to use a dangling pointer since the internal
			// token that RzNum holds ([$$]) has been already freed by rz_core_cmd_str
			// rz_num_math reloads a new token so the dangling pointer is gone
			pj_o(pj);
			pj_k(pj, "value");
			switch (n) {
			case 1:
				pj_i(pj, rz_read_ble8(block));
				break;
			case 2:
				pj_i(pj, rz_read_ble16(block, core->print->big_endian));
				break;
			case 4:
				pj_n(pj, (ut64)rz_read_ble32(block, core->print->big_endian));
				break;
			case 8:
			default:
				pj_n(pj, rz_read_ble64(block, core->print->big_endian));
				break;
			}
			pj_ks(pj, "string", str);
			pj_end(pj);
			free(str);
			at += n;
		}
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
		rz_core_seek(core, oldAt, false);
		break;
	}
	case '?': // "pv?"
		rz_core_cmd_help(core, help_msg_pv);
		break;
	default:
		do {
			repeat--;
			if (block + 8 >= block_end) {
				eprintf("Truncated. TODO: use rz_io_read apis insgtead of depending on blocksize\n");
				break;
			}
			ut64 v;
			if (!fixed_size) {
				n = 0;
			}
			switch (n) {
			case 1:
				v = rz_read_ble8(block);
				rz_cons_printf("0x%02" PFMT64x "\n", v);
				block += 1;
				break;
			case 2:
				v = rz_read_ble16(block, core->print->big_endian);
				rz_cons_printf("0x%04" PFMT64x "\n", v);
				block += 2;
				break;
			case 4:
				v = rz_read_ble32(block, core->print->big_endian);
				rz_cons_printf("0x%08" PFMT64x "\n", v);
				block += 4;
				break;
			case 8:
				v = rz_read_ble64(block, core->print->big_endian);
				rz_cons_printf("0x%016" PFMT64x "\n", v);
				block += 8;
				break;
			default:
				v = rz_read_ble64(block, core->print->big_endian);
				switch (core->rasm->bits / 8) {
				case 1: rz_cons_printf("0x%02" PFMT64x "\n", v & UT8_MAX); break;
				case 2: rz_cons_printf("0x%04" PFMT64x "\n", v & UT16_MAX); break;
				case 4: rz_cons_printf("0x%08" PFMT64x "\n", v & UT32_MAX); break;
				case 8: rz_cons_printf("0x%016" PFMT64x "\n", v & UT64_MAX); break;
				default: break;
				}
				block += core->rasm->bits / 8;
				break;
			}
		} while (repeat > 0);
		break;
	}
}

static bool cmd_print_blocks(RzCore *core, const char *input) {
	bool result = false;
	char mode = input[0];
	RzList *list = NULL;
	RzCoreAnalysisStats *as = NULL;
	RzTable *t = NULL;
	PJ *pj = NULL;
	if (mode == '?') {
		rz_core_cmd_help(core, help_msg_p_minus);
		return false;
	}

	if (mode && mode != ' ') {
		input++;
	}

	int w = (input[0] == ' ')
		? (int)rz_num_math(core->num, input + 1)
		: (int)(core->print->cols * 2.7);
	if (w == 0) {
		rz_core_cmd_help(core, help_msg_p_minus);
		return false;
	}
	int cols = rz_config_get_i(core->config, "hex.cols");
	w = RZ_MAX(cols, w);

	ut64 off = core->offset;
	ut64 from = UT64_MAX;
	ut64 to = 0;

	list = rz_core_get_boundaries_prot(core, -1, NULL, "search");
	if (!list || rz_list_empty(list)) {
		RZ_LOG_ERROR("No range to calculate stats for.\n");
		result = true;
		goto cleanup;
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
	list = NULL;
	ut64 piece = RZ_MAX((to - from) / w, 1);
	if (piece * w != to - from) {
		// add 1 to compute `piece = ceil((to - from) / w)` instead
		piece++;
	}
	as = rz_core_analysis_get_stats(core, from, to - 1, piece);
	if (!as) {
		goto cleanup;
	}

	switch (mode) {
	case 'j': // "p-j"
		pj = pj_new();
		if (!pj) {
			goto cleanup;
		}
		pj_o(pj);
		pj_kn(pj, "from", from);
		pj_kn(pj, "to", to);
		pj_ki(pj, "blocksize", piece);
		pj_k(pj, "blocks");
		pj_a(pj);
		break;
	case 'h': { // "p-h"
		t = rz_core_table(core);
		if (!t) {
			goto cleanup;
		}
		t->showSum = true;
		rz_table_set_columnsf(t, "sddddd", "offset", "flags", "funcs", "cmts", "syms", "str");
		break;
	}
	case 'e':
	default:
		rz_cons_printf("0x%08" PFMT64x " [", from);
	}

	bool use_color = rz_config_get_i(core->config, "scr.color");
	int len = 0;
	for (size_t i = 0; i < rz_vector_len(&as->blocks); i++) {
		RzCoreAnalysisStatsItem *block = rz_vector_index_ptr(&as->blocks, i);
		ut64 at = rz_core_analysis_stats_get_block_from(as, i);
		ut64 ate = rz_core_analysis_stats_get_block_to(as, i) + 1;
		switch (mode) {
		case 'j':
			pj_o(pj);
			if ((block->flags) || (block->functions) || (block->comments) || (block->symbols) || (block->perm) || (block->strings)) {
				pj_kn(pj, "offset", at);
				pj_kn(pj, "size", ate - at);
			}
			if (block->flags) {
				pj_ki(pj, "flags", block->flags);
			}
			if (block->functions) {
				pj_ki(pj, "functions", block->functions);
			}
			if (block->in_functions) {
				pj_ki(pj, "in_functions", block->in_functions);
			}
			if (block->comments) {
				pj_ki(pj, "comments", block->comments);
			}
			if (block->symbols) {
				pj_ki(pj, "symbols", block->symbols);
			}
			if (block->strings) {
				pj_ki(pj, "strings", block->strings);
			}
			if (block->perm) {
				pj_ks(pj, "perm", rz_str_rwx_i(block->perm));
			}
			pj_end(pj);
			len++;
			break;
		case 'h':
			if ((block->flags) || (block->functions) || (block->comments) || (block->symbols) || (block->strings)) {
				rz_table_add_rowf(t, "sddddd", sdb_fmt("0x%09" PFMT64x "", at), block->flags,
					block->functions, block->comments, block->symbols, block->strings);
			}
			break;
		case 'e': // p-e
			cmd_p_minus_e(core, at, ate);
			break;
		default: { // p--
			if (off >= at && off < ate) {
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
				if (block->strings > 0) {
					rz_cons_memcat("z", 1);
				} else if (block->symbols > 0) {
					rz_cons_memcat("s", 1);
				} else if (block->functions > 0) {
					rz_cons_memcat("F", 1);
				} else if (block->comments > 0) {
					rz_cons_memcat("c", 1);
				} else if (block->flags > 0) {
					rz_cons_memcat(".", 1);
				} else if (block->in_functions > 0) {
					rz_cons_memcat("f", 1);
				} else {
					rz_cons_memcat("_", 1);
				}
			}
		} break;
		}
	}
	switch (mode) {
	case 'j':
		pj_end(pj);
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		break;
	case 'h': {
		char *table_string = rz_table_tofancystring(t);
		if (!table_string) {
			goto cleanup;
		}
		rz_cons_printf("\n%s\n", table_string);
		free(table_string);
		break;
	}
	case 'e':
	default:
		if (use_color) {
			rz_cons_print(Color_RESET);
		}
		rz_cons_printf("] 0x%08" PFMT64x "\n", to);
		break;
	}
	result = true;
cleanup:
	pj_free(pj);
	rz_table_free(t);
	rz_list_free(list);
	rz_core_analysis_stats_free(as);
	return result;
}

static bool checkAnalType(RzAnalysisOp *op, int t) {
	if (t == 'c') {
		switch (op->type) {
		case RZ_ANALYSIS_OP_TYPE_RCALL:
		case RZ_ANALYSIS_OP_TYPE_UCALL:
		case RZ_ANALYSIS_OP_TYPE_CALL:
			return true;
		}
	} else if (t == 's') {
		if (op->family == RZ_ANALYSIS_OP_FAMILY_PRIV) {
			return true;
		}
		switch (op->type) {
		case RZ_ANALYSIS_OP_TYPE_SWI:
			return true;
		}
	} else if (t == 'i') {
		switch (op->type) {
		case RZ_ANALYSIS_OP_TYPE_TRAP:
		case RZ_ANALYSIS_OP_TYPE_ILL:
			return true;
		}
	} else if (t == 'j') {
		switch (op->type) {
		case RZ_ANALYSIS_OP_TYPE_JMP:
		// case RZ_ANALYSIS_OP_TYPE_RJMP:
		// case RZ_ANALYSIS_OP_TYPE_UJMP:
		case RZ_ANALYSIS_OP_TYPE_CJMP:
			return true;
		default:
			break;
		}
	}
	return false;
}

static inline void matchBar(ut8 *ptr, int i) {
	if (ptr[i] < 0xff) {
		ptr[i]++;
	}
}

static ut8 *analBars(RzCore *core, size_t type, size_t nblocks, size_t blocksize, size_t skipblocks, ut64 from) {
	size_t j, i = 0;
	ut8 *ptr = calloc(1, nblocks);
	if (!ptr) {
		eprintf("Error: failed to malloc memory");
		return NULL;
	}
	if (type == 'A') {
		ut64 to = from + (blocksize * nblocks) - 1;
		if (to < from) {
			return NULL;
		}
		RzCoreAnalysisStats *as = rz_core_analysis_get_stats(core, from, to, blocksize);
		if (!as) {
			free(ptr);
			return NULL;
		}
		for (size_t i = 0; i < RZ_MIN(nblocks, rz_vector_len(&as->blocks)); i++) {
			int value = 0;
			RzCoreAnalysisStatsItem *block = rz_vector_index_ptr(&as->blocks, i);
			value += block->functions;
			value += block->in_functions;
			value += block->comments;
			value += block->symbols;
			value += block->flags;
			value += block->strings;
			value += block->blocks;
			ptr[i] = RZ_MIN(255, value);
		}
		rz_core_analysis_stats_free(as);
		return ptr;
	}
	for (i = 0; i < nblocks; i++) {
		if (rz_cons_is_breaked()) {
			break;
		}
		ut64 off = from + (i + skipblocks) * blocksize;
		for (j = 0; j < blocksize; j++) {
			if (type == 'a') {
				RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, off + j, 0);
				if (fcn) {
					ptr[i] = rz_list_length(fcn->bbs);
				}
				continue;
			}
			RzAnalysisOp *op = rz_core_analysis_op(core, off + j, RZ_ANALYSIS_OP_MASK_BASIC);
			if (op) {
				if (op->size < 1) {
					// do nothing
					if (type == 'i') {
						matchBar(ptr, i);
					}
				} else {
					if (checkAnalType(op, type)) {
						matchBar(ptr, i);
					}
				}
				if (op->size > 0) {
					j += op->size - 1;
				}
				rz_analysis_op_free(op);
			} else {
				if (type == 'i') {
					matchBar(ptr, i);
				}
			}
		}
	}
	return ptr;
}

static void core_print_columns(RzCore *core, const ut8 *buf, ut32 len, ut32 height) {
	size_t i, j;
	bool colors = rz_config_get_i(core->config, "scr.color") > 0;
	RzCons *cons = rz_cons_singleton();
	RzConsPrintablePalette *pal = &cons->context->pal;
	ut32 cols = 78;
	ut32 rows = height > 0 ? height : 10;
	const char *vline = cons->use_utf8 ? RUNE_LINE_VERT : "|";
	const char *block = cons->use_utf8 ? UTF_BLOCK : "#";
	const char *kol[5];
	kol[0] = pal->call;
	kol[1] = pal->jmp;
	kol[2] = pal->cjmp;
	kol[3] = pal->mov;
	kol[4] = pal->nop;
	if (colors) {
		for (i = 0; i < rows; i++) {
			size_t threshold = i * (0xff / rows);
			size_t koli = i * 5 / rows;
			for (j = 0; j < cols; j++) {
				int realJ = j * len / cols;
				if (255 - buf[realJ] < threshold || (i + 1 == rows)) {
					if (core->print->histblock) {
						rz_cons_printf("%s%s%s", kol[koli], block, Color_RESET);
					} else {
						rz_cons_printf("%s%s%s", kol[koli], vline, Color_RESET);
					}
				} else {
					rz_cons_print(" ");
				}
			}
			rz_cons_print("\n");
		}
		return;
	}

	for (i = 0; i < rows; i++) {
		size_t threshold = i * (0xff / rows);
		for (j = 0; j < cols; j++) {
			size_t realJ = j * len / cols;
			if (255 - buf[realJ] < threshold) {
				if (core->print->histblock) {
					rz_cons_printf("%s%s%s", Color_BGGRAY, block, Color_RESET);
				} else {
					rz_cons_printf("%s", vline);
				}
			} else if (i + 1 == rows) {
				rz_cons_print("_");
			} else {
				rz_cons_print(" ");
			}
		}
		rz_cons_print("\n");
	}
}

static void cmd_print_bars(RzCore *core, const char *input) {
	bool print_bars = false;
	ut8 *ptr = NULL;
	// p=e [nblocks] [totalsize] [skip]
	int nblocks = -1;
	ut64 totalsize = UT64_MAX;
	int skipblocks = -1;
	RzIOMap *map;
	RzListIter *iter;
	ut64 from = 0, to = 0;
	RzList *list = rz_core_get_boundaries_prot(core, -1, NULL, "zoom");
	if (!list) {
		goto beach;
	}

	ut64 blocksize = 0;
	int mode = 'b'; // e, p, b, ...
	int submode = 0; // q, j, ...

	if (input[0]) {
		char *spc = strchr(input, ' ');
		if (spc) {
			nblocks = rz_num_math(core->num, spc + 1);
			if (nblocks < 1) {
				goto beach;
			}
			spc = strchr(spc + 1, ' ');
			if (spc) {
				totalsize = rz_num_math(core->num, spc + 1);
				spc = strchr(spc + 1, ' ');
				if (spc) {
					skipblocks = rz_num_math(core->num, spc + 1);
				}
			}
		}
		mode = input[1];
		if (mode && mode != ' ' && input[2]) {
			submode = input[2];
		}
	}
	if (skipblocks < 0) {
		skipblocks = 0;
	}
	if (totalsize == UT64_MAX) {
		if (rz_config_get_b(core->config, "cfg.debug")) {
			RzDebugMap *map = rz_debug_map_get(core->dbg, core->offset);
			if (map) {
				totalsize = map->addr_end - map->addr;
				from = map->addr;
			}
		} else {
			if (core->file && core->io) {
				totalsize = rz_io_fd_size(core->io, core->file->fd);
				if ((st64)totalsize < 1) {
					totalsize = UT64_MAX;
				}
			}
			if (totalsize == UT64_MAX) {
				eprintf("Cannot determine file size\n");
				goto beach;
			}
		}
	}
	blocksize = (blocksize > 0) ? (totalsize / blocksize) : (core->blocksize);
	if (blocksize < 1) {
		eprintf("Invalid block size: %d\n", (int)blocksize);
		goto beach;
	}
	if (!rz_config_get_b(core->config, "cfg.debug")) {
		RzIOMap *map1 = rz_list_first(list);
		if (map1) {
			from = map1->itv.addr;
			rz_list_foreach (list, iter, map) {
				to = rz_itv_end(map->itv);
			}
			totalsize = to - from;
		} else {
			from = core->offset;
		}
	}
	if (nblocks < 1) {
		nblocks = totalsize / blocksize;
	} else {
		blocksize = totalsize / nblocks;
		if (blocksize < 1) {
			eprintf("Invalid block size: %d\n", (int)blocksize);
			goto beach;
		}
	}
	switch (mode) {
	case '?': // bars
		rz_core_cmd_help(core, help_msg_p_equal);
		break;
	case '=': // "p=="
		switch (submode) {
		case '?':
			rz_core_cmd_help(core, help_msg_p_equal);
			break;
		case '0': // 0x00 bytes
		case 'f': // 0xff bytes
		case 'F': // 0xff bytes
		case 'A': // analysis stats
		case 'a': // analysis basic blocks
		case 'p': // printable chars
		case 'z': // zero terminated strings
		case 'b': // zero terminated strings
		{
			ut64 i, j, k;
			ptr = calloc(1, nblocks);
			if (!ptr) {
				eprintf("Error: failed to malloc memory");
				goto beach;
			}
			ut8 *p = calloc(1, blocksize);
			if (!p) {
				RZ_FREE(ptr);
				eprintf("Error: failed to malloc memory");
				goto beach;
			}
			int len = 0;
			if (submode == 'A') {
				ut64 to = from + totalsize - 1;
				if (to < from) {
					free(p);
					goto beach;
				}
				RzCoreAnalysisStats *as = rz_core_analysis_get_stats(core, from, to, blocksize);
				if (!as) {
					free(p);
					goto beach;
				}
				for (size_t i = 0; i < RZ_MIN(nblocks, rz_vector_len(&as->blocks)); i++) {
					RzCoreAnalysisStatsItem *block = rz_vector_index_ptr(&as->blocks, i);
					int value = 0;
					value += block->functions;
					value += block->in_functions;
					value += block->comments;
					value += block->symbols;
					value += block->flags;
					value += block->strings;
					value += block->blocks;
					ptr[i] = 256 * value / blocksize;
					ptr[i] *= 3;
				}
				rz_core_analysis_stats_free(as);
			} else
				for (i = 0; i < nblocks; i++) {
					ut64 off = from + blocksize * (i + skipblocks);
					rz_io_read_at(core->io, off, p, blocksize);
					for (j = k = 0; j < blocksize; j++) {
						switch (submode) {
						case 'a': {
							RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, off + j, 0);
							if (fcn) {
								k += rz_list_length(fcn->bbs);
								k = RZ_MAX(255, k);
							}
						} break;
						case '0':
							if (!p[j]) {
								k++;
							}
							break;
						case 'f':
							if (p[j] == 0xff) {
								k++;
							}
							break;
						case 'z':
							if ((IS_PRINTABLE(p[j]))) {
								if ((j + 1) < blocksize && p[j + 1] == 0) {
									k++;
									j++;
								}
								if (len++ > 8) {
									k++;
								}
							} else {
								len = 0;
							}
							break;
						case 'p':
							if ((IS_PRINTABLE(p[j]))) {
								k++;
							}
							break;
						}
					}
					ptr[i] = 256 * k / blocksize;
				}
			core_print_columns(core, ptr, nblocks, 14);
			free(p);
		} break;
		case 'e': // "p=e"
		{
			ut8 *p;
			int i = 0;
			ptr = calloc(1, nblocks);
			if (!ptr) {
				eprintf("Error: failed to malloc memory");
				goto beach;
			}
			p = malloc(blocksize);
			if (!p) {
				RZ_FREE(ptr);
				eprintf("Error: failed to malloc memory");
				goto beach;
			}
			for (i = 0; i < nblocks; i++) {
				ut64 off = from + (blocksize * (i + skipblocks));
				rz_io_read_at(core->io, off, p, blocksize);
				ptr[i] = (ut8)(255 * rz_hash_entropy_fraction(core->hash, p, blocksize));
			}
			free(p);
			core_print_columns(core, ptr, nblocks, 14);
		} break;
		default:
			core_print_columns(core, core->block, core->blocksize, 14);
			break;
		}
		break;
	case '2': // "p=2"
	{
		short *word = (short *)core->block;
		int i, words = core->blocksize / 2;
		int step = rz_num_math(core->num, input + 2);
		ut64 oldword = 0;
		for (i = 0; i < words; i++) {
			ut64 word64 = word[i] + ST16_MAX;
			rz_cons_printf("0x%08" PFMT64x " %8d  ", core->offset + (i * 2), word[i]);
			rz_print_progressbar(core->print, word64 * 100 / UT16_MAX, 60);
			rz_cons_printf(" %" PFMT64d, word64 - oldword);
			oldword = word64;
			rz_cons_newline();
			i += step;
		}
	} break;
	case 'd': // "p=d"
		ptr = NULL;
		if (input[2]) {
			ut64 bufsz = rz_num_math(core->num, input + 3);
			ut64 curbsz = core->blocksize;
			if (bufsz < 1) {
				bufsz = curbsz;
			}
			if (bufsz > core->blocksize) {
				rz_core_block_size(core, bufsz);
				rz_core_block_read(core);
			}
			cmd_print_eq_dict(core, core->block, bufsz);
			if (bufsz != curbsz) {
				rz_core_block_size(core, curbsz);
			}
		} else {
			cmd_print_eq_dict(core, core->block, core->blocksize);
		}
		break;
	case 'j': // "p=j" cjmp and jmp
	case 'A': // "p=A" analysis info
	case 'a': // "p=a" bb info
	case 'c': // "p=c" calls
	case 'i': // "p=i" invalid
	case 's': // "p=s" syscalls
		if ((ptr = analBars(core, mode, nblocks, blocksize, skipblocks, from))) {
			print_bars = true;
		}
		break;
	case 'm': {
		ut8 *p;
		int j, i = 0;
		ptr = calloc(1, nblocks);
		if (!ptr) {
			eprintf("Error: failed to malloc memory");
			goto beach;
		}
		p = malloc(blocksize);
		if (!p) {
			RZ_FREE(ptr);
			eprintf("Error: failed to malloc memory");
			goto beach;
		}
		for (i = 0; i < nblocks; i++) {
			ut64 off = from + (blocksize * (i + skipblocks));
			for (j = 0; j < blocksize; j++) {
				if (rz_flag_get_at(core->flags, off + j, false)) {
					matchBar(ptr, i);
				}
			}
		}
		free(p);
		print_bars = true;
	} break;
	case 'e': // "p=e" entropy
	{
		ut8 *p;
		int i = 0;
		ptr = calloc(1, nblocks);
		if (!ptr) {
			eprintf("Error: failed to malloc memory");
			goto beach;
		}
		p = malloc(blocksize);
		if (!p) {
			RZ_FREE(ptr);
			eprintf("Error: failed to malloc memory");
			goto beach;
		}
		for (i = 0; i < nblocks; i++) {
			ut64 off = from + (blocksize * (i + skipblocks));
			rz_io_read_at(core->io, off, p, blocksize);
			ptr[i] = (ut8)(255 * rz_hash_entropy_fraction(core->hash, p, blocksize));
		}
		free(p);
		print_bars = true;
	} break;
	case '0': // 0x00 bytes
	case 'F': // 0xff bytes
	case 'p': // printable chars
	case 'z': // zero terminated strings
	{
		ut8 *p;
		ut64 i, j, k;
		ptr = calloc(1, nblocks);
		if (!ptr) {
			eprintf("Error: failed to malloc memory");
			goto beach;
		}
		p = calloc(1, blocksize);
		if (!p) {
			RZ_FREE(ptr);
			eprintf("Error: failed to malloc memory");
			goto beach;
		}
		int len = 0;
		for (i = 0; i < nblocks; i++) {
			ut64 off = from + blocksize * (i + skipblocks);
			rz_io_read_at(core->io, off, p, blocksize);
			for (j = k = 0; j < blocksize; j++) {
				switch (mode) {
				case '0':
					if (!p[j]) {
						k++;
					}
					break;
				case 'f':
					if (p[j] == 0xff) {
						k++;
					}
					break;
				case 'z':
					if ((IS_PRINTABLE(p[j]))) {
						if ((j + 1) < blocksize && p[j + 1] == 0) {
							k++;
							j++;
						}
						if (len++ > 8) {
							k++;
						}
					} else {
						len = 0;
					}
					break;
				case 'p':
					if ((IS_PRINTABLE(p[j]))) {
						k++;
					}
					break;
				}
			}
			ptr[i] = 256 * k / blocksize;
		}
		free(p);
		print_bars = true;
	} break;
	case 'b': // bytes
	case '\0':
		ptr = calloc(1, nblocks);
		rz_io_read_at(core->io, from, ptr, nblocks);
		// TODO: support print_bars
		rz_print_fill(core->print, ptr, nblocks, from, blocksize);
		RZ_FREE(ptr);
		break;
	}
	if (print_bars) {
		bool hex_offset = rz_config_get_i(core->config, "hex.offset");
		if (hex_offset) {
			core->print->flags |= RZ_PRINT_FLAGS_OFFSET;
		} else {
			core->print->flags &= ~RZ_PRINT_FLAGS_OFFSET;
		}
		int i;
		switch (submode) {
		case 'j': {
			PJ *pj = pj_new();
			if (!pj) {
				return;
			}

			pj_o(pj);
			pj_kn(pj, "blocksize", blocksize);
			pj_kn(pj, "address", from);
			pj_kn(pj, "size", totalsize);
			pj_k(pj, "entropy");
			pj_a(pj);

			for (i = 0; i < nblocks; i++) {
				ut8 ep = ptr[i];
				ut64 off = blocksize * i;
				off += from;
				pj_o(pj);
				pj_kn(pj, "addr", off);
				pj_ki(pj, "value", ep);
				pj_end(pj);
			}
			pj_end(pj);
			pj_end(pj);
			rz_cons_println(pj_string(pj));
			pj_free(pj);
		} break;
		case 'q':
			for (i = 0; i < nblocks; i++) {
				ut64 off = from + (blocksize * i);
				if (core->print->cur_enabled) {
					if (i == core->print->cur) {
						rz_cons_printf("> ");
						core->num->value = off;
					} else {
						rz_cons_printf("  ");
					}
				}
				rz_cons_printf("0x%08" PFMT64x " %d %d\n", off, i, ptr[i]);
			}
			break;
		default:
			core->print->num = core->num;
			rz_print_fill(core->print, ptr, nblocks, from, blocksize);
			break;
		}
	}
beach:
	rz_list_free(list);
	free(ptr);
}

static int bbcmp(RzAnalysisBlock *a, RzAnalysisBlock *b) {
	return a->addr - b->addr;
}

/* TODO: integrate this into rz_analysis */
static void _pointer_table(RzCore *core, ut64 origin, ut64 offset, const ut8 *buf, int len, int step, int mode) {
	int i;
	ut64 addr;
	st32 *delta; // only for step == 4
	if (step < 1) {
		step = 4;
	}
	if (!rz_io_is_valid_offset(core->io, origin, 0) ||
		!rz_io_is_valid_offset(core->io, offset, 0)) {
		return;
	}
	if (origin != offset) {
		switch (mode) {
		case '*':
			rz_cons_printf("CC-@ 0x%08" PFMT64x "\n", origin);
			rz_cons_printf("CC switch table @ 0x%08" PFMT64x "\n", origin);
			rz_cons_printf("axd 0x%" PFMT64x " @ 0x%08" PFMT64x "\n", origin, offset);
			break;
		case '.':
			rz_meta_del(core->analysis, RZ_META_TYPE_COMMENT, origin, 1);
			rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, origin, "switch table");
			rz_core_cmdf(core, "f switch.0x%08" PFMT64x " @ 0x%08" PFMT64x "\n", origin, origin);
			rz_core_cmdf(core, "f jmptbl.0x%08" PFMT64x " @ 0x%08" PFMT64x "\n", offset, offset); // origin, origin);
			rz_analysis_xrefs_set(core->analysis, offset, origin, RZ_ANALYSIS_XREF_TYPE_DATA);
			break;
		}
	} else if (mode == '.') {
		rz_meta_del(core->analysis, RZ_META_TYPE_COMMENT, origin, 1);
		rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, offset, "switch basic block");
		rz_core_cmdf(core, "f switch.0x%08" PFMT64x " @ 0x%08" PFMT64x "\n", offset, offset); // basic block @ 0x%08"PFMT64x "\n", offset);
	}
	int n = 0;
	for (i = 0; (i + sizeof(st32)) <= len; i += step, n++) {
		delta = (st32 *)(buf + i);
		addr = offset + *delta;
		if (!rz_io_is_valid_offset(core->io, addr, 0)) {
			// Lets check for jmptbl with not relative addresses
			// Like: jmp dword [eax*4 + jmptbl.0x5435345]
			if (!rz_io_is_valid_offset(core->io, *delta, 0)) {
				break;
			}
			addr = *delta;
		}
		if (mode == '*') {
			rz_cons_printf("af case.%d.0x%" PFMT64x " 0x%08" PFMT64x "\n", n, offset, addr);
			rz_cons_printf("ax 0x%" PFMT64x " @ 0x%08" PFMT64x "\n", offset, addr);
			rz_cons_printf("ax 0x%" PFMT64x " @ 0x%08" PFMT64x "\n", addr, offset); // wrong, but useful because forward xrefs dont work :?
			// FIXME: "aho" doesn't accept anything here after the "case" word
			rz_cons_printf("aho case 0x%" PFMT64x " 0x%08" PFMT64x " @ 0x%08" PFMT64x "\n", (ut64)i, addr, offset + i); // wrong, but useful because forward xrefs dont work :?
			rz_cons_printf("ahs %d @ 0x%08" PFMT64x "\n", step, offset + i);
		} else if (mode == '.') {
			const char *case_name = rz_str_newf("case.%d.0x%" PFMT64x, n, offset);
			rz_core_analysis_function_add(core, case_name, addr, false);
			rz_analysis_xrefs_set(core->analysis, addr, offset, RZ_ANALYSIS_XREF_TYPE_NULL);
			rz_analysis_xrefs_set(core->analysis, offset, addr, RZ_ANALYSIS_XREF_TYPE_NULL); // wrong, but useful because forward xrefs dont work :?
			const char *case_comment = rz_str_newf("case %d:", n);
			rz_core_meta_comment_add(core, case_comment, addr);
			rz_analysis_hint_set_type(core->analysis, offset + i, RZ_ANALYSIS_OP_TYPE_CASE); // wrong, but useful because forward xrefs dont work :?
			rz_analysis_hint_set_size(core->analysis, offset + i, step);
		} else {
			rz_cons_printf("0x%08" PFMT64x " -> 0x%08" PFMT64x "\n", offset + i, addr);
		}
	}
}

static void __printPattern(RzCore *core, const char *_input) {
	char *input = strdup(_input);
	const char *arg = rz_str_nextword(input, ' ');
	size_t i, j;
	st64 len = arg ? rz_num_math(core->num, arg) : core->blocksize;
	if (len < 1) {
		eprintf("Invalid length\n");
		return;
	}
	switch (input[0]) {
	case 'd': // "ppd"
		// debruijn pattern
		{
			ut8 *buf = (ut8 *)rz_debruijn_pattern(len, 0, NULL);
			for (i = 0; i < len; i++) {
				rz_cons_printf("%02x", buf[i]);
			}
			rz_cons_newline();
			free(buf);
		}
		break;
	case '1': // "pp1"
		// incremental byte sequence
		{
			int min = (core->offset & 0xff);
			for (i = 0; i < len; i++) {
				rz_cons_printf("%02zx", i + min);
			}
			rz_cons_newline();
		}
		break;
	case '2': // "pp2"
		// incremental half word sequences
		{
			// TODO: honor cfg.bigendian
			int min = (core->offset & 0xffff);
			for (i = 0; i < len; i++) {
				rz_cons_printf("%04zx", i + min);
			}
			rz_cons_newline();
		}
		break;
	case '4': // "pp4"
		// incremental half word sequences
		{
			// TODO: honor cfg.bigendian
			int min = (core->offset & UT32_MAX);
			for (i = 0; i < len; i++) {
				rz_cons_printf("%08zx", i + min);
			}
			rz_cons_newline();
		}
		break;
	case '8': // "pp8"
		// incremental half word sequences
		{
			// TODO: honor cfg.bigendian
			ut64 min = (core->offset);
			for (i = 0; i < len; i++) {
				rz_cons_printf("%016" PFMT64x, i + min);
			}
			rz_cons_newline();
		}
		break;
	case 'f': // "ppf"
		// zero ssled
		{
			ut8 *buf = (ut8 *)rz_debruijn_pattern(len, 0, NULL);
			for (i = 0; i < len; i++) {
				rz_cons_printf("%02x", 0xff);
			}
			rz_cons_newline();
			free(buf);
		}
		break;
	case '0': // "pp0"
		// zero ssled
		{
			ut8 *buf = (ut8 *)rz_debruijn_pattern(len, 0, NULL);
			for (i = 0; i < len; i++) {
				rz_cons_printf("%02x", 0);
			}
			rz_cons_newline();
			free(buf);
		}
		break;
	case 'a':
		// TODO
		{
			size_t bs = 4; // XXX hardcoded
			ut8 *buf = calloc(bs, 1);
			// for (;i>0;i--) { incDigitBuffer (buf, bs); }
			for (i = 0; i < len; i++) {
				incAlphaBuffer(buf, bs);
				for (j = 0; j < bs; j++) {
					rz_cons_printf("%c", buf[j] ? buf[j] : 'A');
				}
				rz_cons_printf(" ");
			}
			rz_cons_newline();
			free(buf);
		}
		break;
	case 'n': // "ppn"
	{
		size_t bs = 4; // XXX hardcoded
		ut8 *buf = calloc(bs, 1);
		// for (;i>0;i--) { incDigitBuffer (buf, bs); }
		for (i = 0; i < len; i++) {
			incDigitBuffer(buf, bs);
			for (j = 0; j < bs; j++) {
				rz_cons_printf("%c", buf[j] ? buf[j] : '0');
			}
			rz_cons_printf(" ");
		}
		rz_cons_newline();
		free(buf);
	} break;
	default:
		rz_core_cmd_help(core, help_msg_pp);
		break;
	}
	free(input);
}

static void pr_bb(RzCore *core, RzAnalysisFunction *fcn, RzAnalysisBlock *b, bool emu, ut64 saved_gp, ut8 *saved_arena, char p_type, bool fromHere) {
	bool show_flags = rz_config_get_i(core->config, "asm.flags");
	const char *orig_bb_middle = rz_config_get(core->config, "asm.bb.middle");
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
	if (b->parent_stackptr != INT_MAX) {
		core->analysis->stackptr = b->parent_stackptr;
	}
	rz_config_set_i(core->config, "asm.bb.middle", false);
	p_type == 'D'
		? rz_core_cmdf(core, "pD %" PFMT64u " @ 0x%" PFMT64x, b->size, b->addr)
		: rz_core_cmdf(core, "pI %" PFMT64u " @ 0x%" PFMT64x, b->size, b->addr);
	rz_config_set(core->config, "asm.bb.middle", orig_bb_middle);

	if (b->jump != UT64_MAX) {
		if (b->jump > b->addr) {
			RzAnalysisBlock *jumpbb = rz_analysis_get_block_at(b->analysis, b->jump);
			if (jumpbb && rz_list_contains(jumpbb->fcns, fcn)) {
				if (emu && core->analysis->last_disasm_reg && !jumpbb->parent_reg_arena) {
					jumpbb->parent_reg_arena = rz_reg_arena_dup(core->analysis->reg, core->analysis->last_disasm_reg);
				}
				if (jumpbb->parent_stackptr == INT_MAX) {
					jumpbb->parent_stackptr = core->analysis->stackptr + b->stackptr;
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
				if (failbb->parent_stackptr == INT_MAX) {
					failbb->parent_stackptr = core->analysis->stackptr + b->stackptr;
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

#if 0
dsmap {
	rz_itv_t addr;
	ut64 size;
	ut8 *dis;
}
#endif

static void disasm_until_ret(RzCore *core, ut64 addr, char type_print, const char *arg) {
	int p = 0;
	const bool show_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
	int i, limit = 1024;
	if (arg && *arg && arg[1]) {
		limit = rz_num_math(core->num, arg + 1);
	}
	for (i = 0; i < limit; i++) {
		RzAnalysisOp *op = rz_core_analysis_op(core, addr, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_DISASM);
		if (op) {
			char *mnem = op->mnemonic;
			char *m = malloc((strlen(mnem) * 2) + 32);
			strcpy(m, mnem);
			// rz_parse_parse (core->parser, op->mnemonic, m);
			if (type_print == 'q') {
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
			eprintf("[pdp] Cannot get op at 0x%08" PFMT64x "\n", addr + p);
			rz_analysis_op_free(op);
			break;
		}
		// rz_io_read_at (core->io, n, rbuf, 512);
		rz_analysis_op_free(op);
	}
beach:
	return;
}

static void func_walk_blocks(RzCore *core, RzAnalysisFunction *f, char input, char type_print, bool fromHere) {
	RzListIter *iter;
	RzAnalysisBlock *b = NULL;
	const char *orig_bb_middle = rz_config_get(core->config, "asm.bb.middle");
	rz_config_set_i(core->config, "asm.bb.middle", false);
	PJ *pj = NULL;

	// XXX: hack must be reviewed/fixed in code analysis
	if (!b) {
		if (rz_list_length(f->bbs) >= 1) {
			ut32 fcn_size = rz_analysis_function_realsize(f);
			b = rz_list_get_top(f->bbs);
			if (b->size > fcn_size) {
				b->size = fcn_size;
			}
		}
	}
	rz_list_sort(f->bbs, (RzListComparator)bbcmp);
	if (input == 'j' && b) {
		pj = pj_new();
		if (!pj) {
			return;
		}
		pj_a(pj);
		rz_list_foreach (f->bbs, iter, b) {
			if (fromHere) {
				if (b->addr < core->offset) {
					core->cons->null = true;
				} else {
					core->cons->null = false;
				}
			}
			ut8 *buf = malloc(b->size);
			if (buf) {
				rz_io_read_at(core->io, b->addr, buf, b->size);
				rz_core_print_disasm_json(core, b->addr, buf, b->size, 0, pj);
				free(buf);
			} else {
				eprintf("cannot allocate %" PFMT64u " byte(s)\n", b->size);
			}
		}
		pj_end(pj);
		rz_cons_printf("%s\n", pj_string(pj));
		pj_free(pj);
	} else {
		bool asm_lines = rz_config_get_i(core->config, "asm.lines.bb");
		bool emu = rz_config_get_i(core->config, "asm.emu");
		ut64 saved_gp = 0;
		ut8 *saved_arena = NULL;
		int saved_stackptr = core->analysis->stackptr;
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
		core->analysis->stackptr = saved_stackptr;
		rz_config_set_i(core->config, "asm.lines.bb", asm_lines);
	}
	rz_config_set(core->config, "asm.bb.middle", orig_bb_middle);
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

static void cmd_pxr(RzCore *core, int len, int mode, int wordsize, const char *arg) {
	PJ *pj = NULL;
	RzTable *t = NULL;
	if (mode == ',') {
		t = rz_table_new();
		RzTableColumnType *n = rz_table_type("number");
		RzTableColumnType *s = rz_table_type("string");
		rz_table_add_column(t, n, "addr", 0);
		rz_table_add_column(t, n, "value", 0);
		rz_table_add_column(t, s, "refs", 0);
	}
	if (mode == 'j') {
		pj = pj_new();
		if (!pj) {
			return;
		}
	}
	if (mode == 'j' || mode == ',' || mode == '*' || mode == 'q') {
		size_t i;
		const int be = core->analysis->big_endian;
		if (pj) {
			pj_a(pj);
		}
		const ut8 *buf = core->block;

		bool withref = false;
		int end = RZ_MIN(core->blocksize, len);
		int bitsize = wordsize * 8;
		for (i = 0; i + wordsize < end; i += wordsize) {
			ut64 addr = core->offset + i;
			ut64 val = rz_read_ble(buf + i, be, bitsize);
			if (pj) {
				pj_o(pj);
				pj_kn(pj, "addr", addr);
				pj_kn(pj, "value", val);
			}

			// XXX: this only works in little endian
			withref = false;
			char *refs = NULL;
			if (core->print->hasrefs) {
				char *rstr = core->print->hasrefs(core->print->user, val, true);
				if (RZ_STR_ISNOTEMPTY(rstr)) {
					rz_str_trim(rstr);
					if (pj) {
						char *ns = rz_str_escape(rstr);
						pj_ks(pj, "refstr", rz_str_trim_head_ro(ns));
						pj_k(pj, "ref");
						const int hex_depth = rz_config_get_i(core->config, "hex.depth");
						free(rz_core_analysis_hasrefs_to_depth(core, val, pj, hex_depth));
						pj_end(pj);
						free(ns);
					}
					withref = true;
				}
				refs = rstr;
			}
			if (mode == '*' && RZ_STR_ISNOTEMPTY(refs)) {
				// Show only the mapped ones?
				rz_cons_printf("f pxr.%" PFMT64x " @ 0x%" PFMT64x "\n", val, addr);
			} else if (mode == 'q' && RZ_STR_ISNOTEMPTY(refs)) {
				rz_cons_printf("%s\n", refs);
			}
			if (t) {
				rz_table_add_rowf(t, "xxs", addr, val, refs);
			}
			RZ_FREE(refs);
			if (!withref && pj) {
				pj_end(pj);
			}
		}
		if (t) {
			rz_table_query(t, arg ? arg + 1 : NULL);
			char *s = rz_table_tostring(t);
			rz_cons_println(s);
			free(s);
			rz_table_free(t);
		}
		if (pj) {
			pj_end(pj);
			rz_cons_println(pj_string(pj));
			pj_free(pj);
		}
	} else {
		const int ocols = core->print->cols;
		int bitsize = core->rasm->bits;
		/* Thumb is 16bit arm but handles 32bit data */
		if (bitsize == 16) {
			bitsize = 32;
		}
		core->print->cols = 1;
		core->print->flags |= RZ_PRINT_FLAGS_REFS;
		rz_cons_break_push(NULL, NULL);
		rz_print_hexdump(core->print, core->offset,
			core->block, RZ_MIN(len, core->blocksize),
			wordsize * 8, bitsize / 8, 1);
		rz_cons_break_pop();
		core->print->flags &= ~RZ_PRINT_FLAGS_REFS;
		core->print->cols = ocols;
	}
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

RZ_IPI RzCmdStatus rz_print_string_c_cpp_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	char *str = rz_core_print_string_c_cpp(core);
	if (!str) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(str);
	rz_free(str);
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
			eprintf("This block size is too big (0x%" PFMT64x
				" < 0x%" PFMT64x "). Did you mean 'p%c @ %s' instead?\n",
				n, l, *input, input + 2);
			goto beach;
		}
	}
	if (input[0] == 'x' || input[0] == 'D') {
		if (l > 0 && tmpseek == UT64_MAX) {
			if (!rz_core_block_size(core, l)) {
				eprintf("This block size is too big. Did you mean 'p%c @ %s' instead?\n",
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
			eprintf("p: Cannot find function at 0x%08" PFMT64x "\n", core->offset);
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
						eprintf("-> res(%s)\n", res);
					}
					/*
					char *res = rz_print_json_indent ((char*)data, false, "  ", NULL);
					print_json_path (core, res);
					free (res);
*/
				} else {
					eprintf("Cannot allocate %d\n", (int)(core->offset));
				}
			} else {
				rz_core_cmdf(core, "pj %" PFMT64u " @ 0", core->offset);
			}
		} else {
			if (core->blocksize < 4 || !memcmp(core->block, "\xff\xff\xff\xff", 4)) {
				eprintf("Cannot read\n");
			} else {
				char *res = rz_print_json_indent((const char *)core->block, true, "  ", NULL);
				rz_cons_printf("%s\n", res);
				free(res);
			}
		}
		break;
	case 'v': // "pv"
		cmd_print_pv(core, input + 1, false);
		break;
	case 'V': // "pv"
		cmd_print_pv(core, input + 1, true);
		break;
	case '-': // "p-"
		return cmd_print_blocks(core, input + 1);
	case '=': // "p="
		cmd_print_bars(core, input);
		break;
	case 'A': // "pA"
	{
		const ut64 saved_from = rz_config_get_i(core->config, "search.from"),
			   saved_to = rz_config_get_i(core->config, "search.to"),
			   saved_maxhits = rz_config_get_i(core->config, "search.maxhits");

		int want = rz_num_math(core->num, input + 1);
		if (input[1] == '?') {
			rz_core_cmd0(core, "/A?");
		} else {
			rz_config_set_i(core->config, "search.maxhits", want);
			rz_config_set_i(core->config, "search.from", core->offset);
			rz_config_set_i(core->config, "search.to", core->offset + core->blocksize);
			rz_core_cmd0(core, "/A");
			rz_config_set_i(core->config, "search.maxhits", saved_maxhits);
			rz_config_set_i(core->config, "search.from", saved_from);
			rz_config_set_i(core->config, "search.to", saved_to);
		}
	} break;
	case 'b': { // "pb"
		if (input[1] == '?') {
			rz_cons_printf("|Usage: p[bB] [len] ([skip])  ; see also pB and pxb\n");
		} else if (l != 0) {
			int from, to;
			const int size = len * 8;
			char *spc, *buf = malloc(size + 1);
			spc = strchr(input, ' ');
			if (spc) {
				len = rz_num_math(core->num, spc + 1);
				if (len < 1) {
					len = 1;
				}
				spc = strchr(spc + 1, ' ');
				if (spc) {
					from = rz_num_math(core->num, spc + 1);
				} else {
					from = 0;
				}
				to = from + len;
			} else {
				from = 0;
				to = size;
			}
			if (buf) {
				int buf_len;
				rz_str_bits(buf, block, size, NULL);
				buf_len = strlen(buf);
				if (from >= 0 && to >= 0) {
					if (from >= buf_len) {
						from = buf_len;
					}
					if (to < buf_len) {
						buf[to] = 0;
						// buf[buf_len - 1] = 0;
					}
					rz_cons_println(buf + from);
				}
				free(buf);
			} else {
				eprintf("ERROR: Cannot malloc %d byte(s)\n", size);
			}
		}
	} break;
	case 'B': { // "pB"
		if (input[1] == '?') {
			rz_cons_printf("|Usage: p[bB] [len]       bitstream of N bytes\n");
		} else if (l != 0) {
			int size;
			char *buf;
			if (!rz_core_block_size(core, len)) {
				len = core->blocksize;
			}
			size = len * 8;
			buf = malloc(size + 1);
			if (buf) {
				rz_str_bits(buf, core->block, size, NULL);
				rz_cons_println(buf);
				free(buf);
			} else {
				eprintf("ERROR: Cannot malloc %d byte(s)\n", size);
			}
		}
	} break;
	case 'I': // "pI"
		switch (input[1]) {
		case 'f': // "pIf"
		{
			const RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset,
				RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
			if (f) {
				rz_core_print_disasm_instructions(core,
					rz_analysis_function_linear_size((RzAnalysisFunction *)f), 0);
				break;
			}
			break;
		}
		case '?': // "pi?"
			rz_cons_printf("|Usage: p[iI][df] [len]   print N instructions/bytes"
				       "(f=func) (see pi? and pdq)\n");
			break;
		default:
			if (l) {
				rz_core_print_disasm_instructions(core, l, 0);
			}
		}
		break;
	case 'i': // "pi"
		switch (input[1]) {
		case '?':
			// rz_cons_printf ("|Usage: pi[defj] [num]\n");
			rz_core_cmd_help(core, help_msg_pi);
			break;
		case 'u': // "piu" disasm until ret/jmp . todo: accept arg to specify type
			disasm_until_ret(core, core->offset, input[2], input + 2);
			break;
		case 'a': // "pia" is like "pda", but with "pi" output
			if (l != 0) {
				rz_core_print_disasm_all(core, core->offset,
					l, len, 'i');
			}
			break;
		case 'e': // "pie"
			if (l != 0) {
				rz_core_disasm_pdi(core, l, 0, 'e');
			}
			break;
		case 'f': // "pif"
			if (input[2] == '?') { // "pif?"
				rz_core_cmd_help(core, help_msg_pif);
			} else if (input[2] == 'j') {
				rz_core_cmdf(core, "pdfj%s", input + 3);
			} else if (input[2] == 'c') { // "pifc"
				RzListIter *iter;
				RzAnalysisXRef *xrefi;
				RzList *refs = NULL;
				PJ *pj = NULL;

				// check for bounds
				if (input[3] != 0) {
					if (input[3] == 'j') { // "pifcj"
						pj = pj_new();
						pj_a(pj);
					}
				}
				// get function in current offset
				RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset,
					RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);

				// validate that a function was found in the given address
				if (!f) {
					// print empty json object
					if (pj) {
						pj_end(pj);
						rz_cons_println(pj_string(pj));
						pj_free(pj);
					}
					break;
				}
				// get all the calls of the function
				refs = rz_core_analysis_fcn_get_calls(core, f);

				// sanity check
				if (!rz_list_empty(refs)) {

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
						if (pj) {
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
							pj_o(pj);
							pj_ks(pj, "dest", dst2);
							pj_kn(pj, "addr", xrefi->to);
							pj_kn(pj, "at", xrefi->from);
							pj_end(pj);
							rz_analysis_op_free(op);
						} else {
							char *s = rz_core_cmd_strf(core, "pdq %i @ 0x%08" PFMT64x, 1, xrefi->from);
							rz_cons_printf("%s", s);
						}
					}

					// restore saved configuration
					rz_config_hold_restore(hc);
					rz_config_hold_free(hc);
				}
				// print json object
				if (pj) {
					pj_end(pj);
					rz_cons_println(pj_string(pj));
					pj_free(pj);
				}
			} else if (l != 0) {
				RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset,
					RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
				if (f) {
					ut32 bsz = core->blocksize;
					// int fsz = rz_analysis_function_realsize (f);
					int fsz = rz_analysis_function_linear_size(f); // we want max-min here
					rz_core_block_size(core, fsz);
					rz_core_print_disasm_instructions(core, fsz, 0);
					rz_core_block_size(core, bsz);
				} else {
					rz_core_print_disasm_instructions(core,
						core->blocksize, l);
				}
			}
			break;
		case 'r': // "pir"
		{
			RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset,
				RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
			if (f) {
				func_walk_blocks(core, f, input[2], 'I', input[2] == '.');
			} else {
				eprintf("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
				core->num->value = 0;
			}
		} break;
		case 'b': // "pib"
		{
			RzAnalysisBlock *b = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
			if (b) {
				rz_core_print_disasm_instructions(core, b->size - (core->offset - b->addr), 0);
			} else {
				eprintf("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
				core->num->value = 0;
			}
		} break;
		default: // "pi"
			if (l != 0) {
				rz_core_print_disasm_instructions(core, 0, l);
			}
			break;
		}
		goto beach;
	case 'p': // "pp"
		__printPattern(core, input + 1);
		break;
	case 's': // "ps"
		switch (input[1]) {
		case '?': // "ps?"
			rz_core_cmd_help(core, help_msg_ps);
			break;
		case 'j': // "psj"
			if (l > 0) {
				if (input[2] == ' ' && input[3]) {
					len = rz_num_math(core->num, input + 3);
					len = RZ_MIN(len, core->blocksize);
				}
				RzStrEnc enc = rz_str_guess_encoding_from_buffer(core->block, len);
				print_json_string(core, core->block, len, enc, l != len);
			}
			break;
		case 'i': // "psi"
			if (l > 0) {
				ut8 *buf = malloc(1024 + 1);
				int delta = 512;
				ut8 *p, *e, *b;
				if (!buf) {
					return 0;
				}
				buf[1024] = 0;
				if (core->offset < delta) {
					delta = core->offset;
				}
				p = buf + delta;
				rz_io_read_at(core->io, core->offset - delta, buf, 1024);
				for (b = p; b > buf; b--) {
					if (!IS_PRINTABLE(*b)) {
						b++;
						break;
					}
				}
				for (e = p; e < (buf + 1024); e++) {
					if (!IS_PRINTABLE(*b)) {
						*e = 0;
						e--;
						break;
					}
				}
				rz_cons_strcat((const char *)b);
				rz_cons_newline();
				// rz_print_string (core->print, core->offset, b,
				// (size_t)(e-b), 0);
				free(buf);
			}
			break;
		case 'x': // "psx"
			if (l > 0) {
				RzStrStringifyOpt opt = { 0 };
				opt.buffer = block;
				opt.length = len;
				opt.encoding = RZ_STRING_ENC_8BIT;
				opt.escape_nl = true;
				core_print_raw_buffer(&opt);
			}
			break;
		case 'b': // "psb"
			if (l > 0) {
				int quiet = input[2] == 'q'; // "psbq"
				char *s = malloc(core->blocksize + 1);
				int i, j, hasnl = 0;
				if (s) {
					if (!quiet) {
						rz_print_offset(core->print, core->offset, 0, 0, 0, 0, NULL);
					}
					// TODO: filter more chars?
					for (i = j = 0; i < core->blocksize; i++) {
						char ch = (char)block[i];
						if (!ch) {
							if (!hasnl) {
								s[j] = 0;
								if (*s) {
									rz_cons_println(s);
									if (!quiet) {
										rz_print_offset(core->print, core->offset + i, 0, 0, 0, 0, NULL);
									}
								}
								j = 0;
								s[0] = 0;
							}
							hasnl = 1;
							continue;
						}
						hasnl = 0;
						if (IS_PRINTABLE(ch)) {
							s[j++] = ch;
						}
					}
					s[j] = 0;
					rz_cons_print(s); // TODO: missing newline?
					free(s);
				}
			}
			break;
		case 'z': // "psz"
			if (l > 0) {
				char *s = malloc(core->blocksize + 1);
				int i, j;
				if (s) {
					// TODO: filter more chars?
					for (i = j = 0; i < core->blocksize; i++) {
						char ch = (char)core->block[i];
						if (!ch) {
							break;
						}
						if (IS_PRINTABLE(ch)) {
							s[j++] = ch;
						}
					}
					s[j] = '\0';
					if (input[2] == 'j') { // pszj
						print_json_string(core, (const ut8 *)s, j, RZ_STRING_ENC_8BIT, true);
					} else {
						rz_cons_println(s);
					}
					free(s);
				}
			}
			break;
		case 'p': // "psp"
			if (l > 0) {
				int mylen = core->block[0];
				// TODO: add support for 2-4 byte length pascal strings
				if (mylen < core->blocksize) {
					if (input[2] == 'j') { // pspj
						print_json_string(core, core->block + 1, mylen, RZ_STRING_ENC_8BIT, true);
					} else {
						RzStrStringifyOpt opt = { 0 };
						opt.buffer = core->block + 1;
						opt.length = mylen;
						opt.encoding = RZ_STRING_ENC_8BIT;
						opt.stop_at_nil = true;
						core_print_raw_buffer(&opt);
					}
					core->num->value = mylen;
				} else {
					core->num->value = 0; // error
				}
			}
			break;
		case 'w': // "psw"
			if (l > 0) {
				if (input[2] == 'j') { // pswj
					print_json_string(core, core->block, len, RZ_STRING_ENC_UTF16LE, true);
				} else {
					RzStrStringifyOpt opt = { 0 };
					opt.buffer = core->block;
					opt.length = len;
					opt.encoding = RZ_STRING_ENC_UTF16LE;
					opt.stop_at_nil = true;
					core_print_raw_buffer(&opt);
				}
			}
			break;
		case 'W': // "psW"
			if (l > 0) {
				if (input[2] == 'j') { // psWj
					print_json_string(core, core->block, len, RZ_STRING_ENC_UTF32LE, true);
				} else {
					RzStrStringifyOpt opt = { 0 };
					opt.buffer = core->block;
					opt.length = len;
					opt.encoding = RZ_STRING_ENC_UTF32LE;
					opt.stop_at_nil = true;
					core_print_raw_buffer(&opt);
				}
			}
			break;
		case ' ': // "ps"
		{
			RzStrEnc enc = rz_str_guess_encoding_from_buffer(core->block, l);
			RzStrStringifyOpt opt = { 0 };
			opt.buffer = core->block;
			opt.length = l;
			opt.encoding = enc;
			core_print_raw_buffer(&opt);
		} break;
		case 'u': // "psu"
			if (l > 0) {
				bool json = input[2] == 'j'; // "psuj"
				if (input[2] == 'z') { // "psuz"
					int i, z;
					const char *p = (const char *)core->block;
					for (i = 0, z = 0; i < len; i++) {
						// looking for double zeros '\0\0'.
						if (!p[i] && !z)
							z = 1;
						else if (!p[i] && z) {
							len = i - 1;
							break;
						}
					}
					json = input[3] == 'j'; // "psuzj"
				}
				if (json) { // psuj
					print_json_string(core, core->block, len, RZ_STRING_ENC_UTF16LE, true);
				} else {
					char *str = rz_str_utf16_encode((const char *)core->block, len);
					rz_cons_println(str);
					free(str);
				}
			}
			break;
		case 's': // "pss"
			if (l > 0) {
				int h, w = rz_cons_get_size(&h);
				int colwidth = rz_config_get_i(core->config, "hex.cols") * 2;
				int width = (colwidth == 32) ? w : colwidth; // w;
				int bs = core->blocksize;
				if (len == bs) {
					len = (h * w) / 3;
					rz_core_block_size(core, len);
				}
				RzStrStringifyOpt opt = { 0 };
				opt.buffer = core->block;
				opt.length = len;
				opt.encoding = RZ_STRING_ENC_8BIT;
				opt.wrap_at = width;
				core_print_raw_buffer(&opt);
				rz_core_block_size(core, bs);
			}
			break;
		case '+': // "ps+"
			if (l > 0) {
				const bool json = input[2] == 'j'; // ps+j
				ut64 bitness = rz_config_get_i(core->config, "asm.bits");
				if (bitness != 32 && bitness != 64) {
					eprintf("Error: bitness of %" PFMT64u " not supported\n", bitness);
					break;
				}
				if (*core->block & 0x1) { // "long" string
					if (bitness == 64) {
						rz_core_cmdf(core, "ps%c @ 0x%" PFMT64x, json ? 'j' : ' ', *((ut64 *)core->block + 2));
					} else {
						rz_core_cmdf(core, "ps%c @ 0x%" PFMT32x, json ? 'j' : ' ', *((ut32 *)core->block + 2));
					}
				} else if (json) {
					print_json_string(core, core->block + 1, len, RZ_STRING_ENC_8BIT, true);
				} else {
					RzStrStringifyOpt opt = { 0 };
					opt.buffer = core->block + 1;
					opt.length = len;
					opt.encoding = RZ_STRING_ENC_8BIT;
					opt.stop_at_nil = true;
					core_print_raw_buffer(&opt);
				}
			}
			break;
		default:
			if (l > 0) {
				RzStrStringifyOpt opt = { 0 };
				opt.buffer = core->block;
				opt.length = len;
				opt.encoding = RZ_STRING_ENC_8BIT;
				opt.stop_at_nil = true;
				core_print_raw_buffer(&opt);
			}
			break;
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
	case 'u': // "pu"
		if (input[1] == '?') {
			rz_cons_printf("|Usage: pu[w0] [len]       print N url"
				       "encoded bytes (w=wide, 0=stop at nil)\n");
		} else {
			if (l > 0) {
				RzStrStringifyOpt opt = { 0 };
				opt.buffer = core->block;
				opt.length = len;
				opt.encoding = input[1] == 'w' ? RZ_STRING_ENC_UTF16LE : RZ_STRING_ENC_8BIT;
				opt.stop_at_nil = input[1] == '0';
				opt.urlencode = true;
				core_print_raw_buffer(&opt);
			}
		}
		break;
	case 'c': // "pc"
		if (input[1] == '?') {
			rz_core_cmd_help(core, help_msg_pc);
		} else if (l) {
			const ut8 *buf = core->block;
			int i = 0;
			int j = 0;
			if (input[1] == 'A') { // "pcA"
				rz_cons_printf("sub_0x%08" PFMT64x ":\n", core->offset);
				for (i = 0; i < len; i++) {
					RzAsmOp asmop = {
						0
					};
					(void)rz_asm_disassemble(core->rasm, &asmop, buf + i, len - i);
					int sz = asmop.size;
					if (sz < 1) {
						sz = 1;
					}
					rz_cons_printf(" .byte ");
					for (j = 0; j < sz; j++) {
						rz_cons_printf("%s0x%02x", j ? ", " : "", buf[i]);
						i++;
					}
					rz_cons_printf("  // %s\n", rz_strbuf_get(&asmop.buf_asm));
					i--;
				}
				rz_cons_printf(".equ shellcode_len, %d\n", len);
			} else {
				char *str = NULL;
				bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");
				switch (input[1]) {
				case '*': // "pc*" // rizin commands
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, RZ_LANG_BYTE_ARRAY_RIZIN);
					break;
				case 'a': // "pca" // GAS asm
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, RZ_LANG_BYTE_ARRAY_ASM);
					break;
				case 'b': // "pcb" // bash shellscript
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, RZ_LANG_BYTE_ARRAY_BASH);
					break;
				case 'n': // "pcn" // nodejs
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, RZ_LANG_BYTE_ARRAY_NODEJS);
					break;
				case 'g': // "pcg" // golang
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, RZ_LANG_BYTE_ARRAY_GOLANG);
					break;
				case 'k': // "pck" kotlin
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, RZ_LANG_BYTE_ARRAY_KOTLIN);
					break;
				case 's': // "pcs" // swift
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, RZ_LANG_BYTE_ARRAY_SWIFT);
					break;
				case 'r': // "pcr" // Rust
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, RZ_LANG_BYTE_ARRAY_RUST);
					break;
				case 'o': // "pco" // Objective-C
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, RZ_LANG_BYTE_ARRAY_OBJECTIVE_C);
					break;
				case 'J': // "pcJ" // java
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, RZ_LANG_BYTE_ARRAY_JAVA);
					break;
				case 'y': // "pcy" // yara
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, RZ_LANG_BYTE_ARRAY_YARA);
					break;
				case 'j': // "pcj" // json
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, RZ_LANG_BYTE_ARRAY_JSON);
					break;
				case 'p': // "pcp" // python
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, RZ_LANG_BYTE_ARRAY_PYTHON);
					break;
				case 'h': // "pch" // C half words with asm
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, big_endian ? RZ_LANG_BYTE_ARRAY_C_CPP_HALFWORDS_BE : RZ_LANG_BYTE_ARRAY_C_CPP_HALFWORDS_LE);
					break;
				case 'w': // "pcw" // C words with asm
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, big_endian ? RZ_LANG_BYTE_ARRAY_C_CPP_WORDS_BE : RZ_LANG_BYTE_ARRAY_C_CPP_WORDS_LE);
					break;
				case 'd': // "pcd" // C double-words with asm
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, big_endian ? RZ_LANG_BYTE_ARRAY_C_CPP_DOUBLEWORDS_BE : RZ_LANG_BYTE_ARRAY_C_CPP_DOUBLEWORDS_LE);
					break;
				default: // "pc" // C bytes
					str = rz_lang_byte_array(core->block, len < 0 ? 0 : len, RZ_LANG_BYTE_ARRAY_C_CPP_BYTES);
					break;
				}
				if (str) {
					rz_cons_println(str);
					free(str);
				}
			}
		}
		break;
	case 'C': // "pC"
		switch (input[1]) {
		case 0:
			cmd_pCd(core, "");
			break;
		case ' ':
		case 'd':
			cmd_pCd(core, input + 2);
			break;
		case 'D':
			cmd_pCD(core, input + 2);
			break;
		case 'a':
			cmd_pCx(core, input + 2, "pxa");
			break;
		case 'A':
			cmd_pCx(core, input + 2, "pxA");
			break;
		case 'x':
			cmd_pCx(core, input + 2, "px");
			break;
		case 'w':
			cmd_pCx(core, input + 2, "pxw");
			break;
		case 'c':
			cmd_pCx(core, input + 2, "pc");
			break;
		default:
			eprintf("Usage: pCd\n");
			break;
		}
		break;
	case 'r': // "pr"
		switch (input[1]) {
		case 'c': // "prc" // color raw dump
			cmd_prc(core, block, len);
			break;
		case '?':
			rz_core_cmd_help(core, help_msg_pr);
			break;
		case 'g': // "prg" // gunzip
			switch (input[2]) {
			case '?':
				rz_core_cmd_help(core, help_msg_prg);
				break;
			case 'i': // "prgi"
			{
				int outlen = 0;
				int inConsumed = 0;
				ut8 *out;
				out = rz_inflate(block, core->blocksize, &inConsumed, &outlen);
				rz_cons_printf("%d\n", inConsumed);
				free(out);
			} break;
			case 'o': // "prgo"
			{
				int outlen = 0;
				ut8 *out;
				out = rz_inflate(block, core->blocksize, NULL, &outlen);
				rz_cons_printf("%d\n", outlen);
				free(out);
			} break;
			default: {
				int outlen = 0;
				ut8 *out;
				out = rz_inflate(block, core->blocksize, NULL, &outlen);
				if (out) {
					rz_cons_memcat((const char *)out, outlen);
				}
				free(out);
			}
			}
			break;
		/* TODO: compact */
		case 'x': // "prx"
		{
			int a = rz_config_get_i(core->config, "hex.bytes");
			rz_config_set_i(core->config, "hex.bytes", false);
			rz_core_cmdf(core, "px%s", input + 1);
			rz_config_set_i(core->config, "hex.bytes", a);
		} break;
		case 'z': // "prz"
			if (l != 0) {
				printraw(core, strlen((const char *)core->block));
			}
			break;
		default:
			if (l != 0) {
				printraw(core, len);
			}
			break;
		}
		break;
	case 'o': // "po"
		cmd_print_op(core, input);
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
			rz_core_cmd_help(core, help_msg_px);
			break;
		case '0': // "px0"
			if (l) {
				int len = rz_str_nlen((const char *)core->block, core->blocksize);
				rz_print_bytes(core->print, core->block, len, "%02x");
			}
			break;
		case 'a': // "pxa"
			if (l != 0) {
				if (len % 16) {
					len += 16 - (len % 16);
				}
				annotated_hexdump(core, input + 2, len);
			}
			break;
		case 'x': // "pxx"
			if (l != 0) {
				core->print->flags |= RZ_PRINT_FLAGS_NONHEX;
				rz_print_hexdump(core->print, core->offset,
					core->block, len, 8, 1, 1);
				core->print->flags &= ~RZ_PRINT_FLAGS_NONHEX;
			}
			break;
		case 'X': // "pxX"
			if (l != 0) {
				ut8 *buf = calloc(len, 4);
				if (buf) {
					rz_io_read_at(core->io, core->offset, buf, len * 4);
					core->print->flags |= RZ_PRINT_FLAGS_NONHEX;
					rz_print_hexdump(core->print, core->offset, buf, len * 4, 8, 1, 1);
					core->print->flags &= ~RZ_PRINT_FLAGS_NONHEX;
					free(buf);
				}
			}
			break;
		case 'A': // "pxA"
			if (input[2] == '?') {
				rz_core_cmd_help(core, help_msg_pxA);
			} else if (l) {
				cmd_print_pxA(core, len, input + 2);
			}
			break;
		case 'b': // "pxb"
			if (l) {
				ut32 n;
				int i, c;
				char buf[32];
				for (i = c = 0; i < len; i++, c++) {
					if (c == 0) {
						ut64 ea = core->offset + i;
						if (core->print->pava) {
							ut64 va = rz_io_p2v(core->io, ea);
							if (va != UT64_MAX) {
								ea = va;
							}
						}
						rz_print_section(core->print, ea);
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

						n = k(b, 0) | k(b, 1) | k(b, 2) | k(b, 3);
						rz_cons_printf("0x%08x  %c%c%c%c\n",
							n, p(b[0]), p(b[1]), p(b[2]), p(b[3]));
						c = -1;
					}
				}
			}
			break;
		case 'c': // "pxc"
		{
			int ocomments = core->print->use_comments;
			core->print->use_comments = core->print->flags & RZ_PRINT_FLAGS_COMMENT;
			if (l) {
				ut64 from = rz_config_get_i(core->config, "diff.from");
				ut64 to = rz_config_get_i(core->config, "diff.to");
				if (from == to && !from) {
					rz_core_block_size(core, len);
					len = core->blocksize;
					rz_print_hexdump(core->print, core->offset,
						core->block, core->blocksize, 16, 1, 1);
				} else {
					rz_core_print_cmp(core, from, to);
				}
				core->num->value = len;
			}
			core->print->use_comments = ocomments;
		} break;
		case 'i': // "pxi"
			if (l != 0) {
				core->print->show_offset = rz_config_get_i(core->config, "hex.offset");
				rz_print_hexii(core->print, core->offset, core->block,
					core->blocksize, rz_config_get_i(core->config, "hex.cols"));
			}
			break;
		case 't': // "pxt"
		{
			ut64 origin = core->offset;
			const char *arg = strchr(input, ' ');
			if (arg) {
				origin = rz_num_math(core->num, arg + 1);
			}
			// _pointer_table does rz_core_cmd with @, so it modifies core->block
			// and this results in an UAF access when iterating over the jmptable
			// so we do a new allocation to avoid that issue
			ut8 *block = calloc(len, 1);
			if (block) {
				memcpy(block, core->block, len);
				_pointer_table(core, origin, core->offset, block, len, 4, input[2]);
				free(block);
			}
		} break;
		case 'r': // "pxr"
			if (l) {
				int mode = input[2];
				int wordsize = rz_analysis_get_address_bits(core->analysis) / 8;
				if (mode == '?') {
					eprintf("Usage: pxr[1248][*,jq] [length]\n");
					break;
				}
				if (mode && isdigit(mode)) {
					char tmp[2] = { input[2], 0 };
					wordsize = atoi(tmp);
					mode = input[3];
				}
				switch (wordsize) {
				case 1:
				case 2:
				case 4:
				case 8:
					cmd_pxr(core, len, mode, wordsize, mode ? strchr(input, mode) : NULL);
					break;
				default:
					eprintf("Invalid word size. Use 1, 2, 4 or 8.\n");
					break;
				}
			}
			break;
		case 's': // "pxs"
			if (l) {
				core->print->flags |= RZ_PRINT_FLAGS_SPARSE;
				rz_print_hexdump(core->print, core->offset, core->block, len, 16, 1, 1);
				core->print->flags &= (((ut32)-1) & (~RZ_PRINT_FLAGS_SPARSE));
			}
			break;
		case 'e': // "pxe" // emoji dump
			if (l != 0) {
				int j;
				char emoji[] = {
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
				for (i = 0; i < len; i += cols) {
					rz_print_addr(core->print, core->offset + i);
					for (j = i; j < i + cols; j += 1) {
						ut8 *p = (ut8 *)core->block + j;
						if (j < len) {
							rz_cons_printf("\xf0\x9f%c%c ", emoji[*p * 2], emoji[*p * 2 + 1]);
						} else {
							rz_cons_print("  ");
						}
					}
					rz_cons_print(" ");
					for (j = i; j < len && j < i + cols; j += 1) {
						ut8 *p = (ut8 *)core->block + j;
						rz_print_byte(core->print, "%c", j, *p);
					}
					rz_cons_newline();
				}
			}
			break;
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
	case 'F': // "pF"
		cmd_print_fromage(core, input + 1, block, len);
		break;
	case 'k': // "pk"
		if (input[1] == '?') {
			rz_cons_printf("|Usage: pk [len]       print key in randomart\n");
			rz_cons_printf("|Usage: pkill [process-name]\n");
		} else if (!strncmp(input, "kill", 4)) {
			RzListIter *iter;
			RzDebugPid *pid;
			const char *arg = strchr(input, ' ');
			RzList *pids = (core->dbg->cur && core->dbg->cur->pids)
				? core->dbg->cur->pids(core->dbg, 0)
				: NULL;
			if (arg && *++arg) {
				rz_list_foreach (pids, iter, pid) {
					if (strstr(pid->path, arg)) {
						rz_cons_printf("dk 9 %d\n", pid->pid);
					}
					// rz_debug_kill (core->dbg, pid->pid, pid->pid, 9); // kill -9
				}
			}
			rz_list_free(pids);
		} else if (l > 0) {
			len = len > core->blocksize ? core->blocksize : len;
			char *s = rz_hash_cfg_randomart(block, len, core->offset);
			rz_cons_println(s);
			free(s);
		}
		break;
	case 'K': // "pK"
		if (input[1] == '?') {
			rz_cons_printf("|Usage: pK [len]       print key in randomart mosaic\n");
		} else if (l > 0) {
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
		}
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
	return rz_cmd_print(data, input - 1);
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
	ut64 oldsize = core->blocksize;
	ut64 len = argc == 2 ? rz_num_math(core->num, argv[1]) : oldsize;
	if (len > oldsize) {
		rz_core_block_size(core, len);
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
		print_json_string(core, core->block, len, RZ_STRING_ENC_UTF16LE, true);
	} else {
		RzStrStringifyOpt opt = { 0 };
		opt.buffer = core->block;
		opt.length = len;
		opt.encoding = RZ_STRING_ENC_UTF16LE;
		opt.stop_at_nil = true;
		core_print_raw_buffer(&opt);
	}
	if (len > oldsize) {
		rz_core_block_size(core, oldsize);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_utf32le_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	ut64 oldsize = core->blocksize;
	ut64 len = argc == 2 ? rz_num_math(core->num, argv[1]) : oldsize;
	if (len > oldsize) {
		rz_core_block_size(core, len);
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
		print_json_string(core, core->block, len, RZ_STRING_ENC_UTF32LE, true);
	} else {
		RzStrStringifyOpt opt = { 0 };
		opt.buffer = core->block;
		opt.length = len;
		opt.encoding = RZ_STRING_ENC_UTF32LE;
		opt.stop_at_nil = true;
		core_print_raw_buffer(&opt);
	}
	if (len > oldsize) {
		rz_core_block_size(core, oldsize);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_utf16be_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	ut64 oldsize = core->blocksize;
	ut64 len = argc == 2 ? rz_num_math(core->num, argv[1]) : oldsize;
	if (len > oldsize) {
		rz_core_block_size(core, len);
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
		print_json_string(core, core->block, len, RZ_STRING_ENC_UTF16BE, true);
	} else {
		RzStrStringifyOpt opt = { 0 };
		opt.buffer = core->block;
		opt.length = len;
		opt.encoding = RZ_STRING_ENC_UTF16BE;
		opt.stop_at_nil = true;
		core_print_raw_buffer(&opt);
	}
	if (len > oldsize) {
		rz_core_block_size(core, oldsize);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_utf32be_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	ut64 oldsize = core->blocksize;
	ut64 len = argc == 2 ? rz_num_math(core->num, argv[1]) : oldsize;
	if (len > oldsize) {
		rz_core_block_size(core, len);
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
		print_json_string(core, core->block, len, RZ_STRING_ENC_UTF32BE, true);
	} else {
		RzStrStringifyOpt opt = { 0 };
		opt.buffer = core->block;
		opt.length = len;
		opt.encoding = RZ_STRING_ENC_UTF32BE;
		opt.stop_at_nil = true;
		core_print_raw_buffer(&opt);
	}
	if (len > oldsize) {
		rz_core_block_size(core, oldsize);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_hexdump_signed_int_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int n = (int)rz_num_math(core->num, argv[1]);
	int len = argc > 2 ? (int)rz_num_math(core->num, argv[2]) : (int)core->blocksize;
	return bool2status(rz_core_print_dump(core, state, core->offset, n, len, RZ_CORE_PRINT_FORMAT_TYPE_INTEGER));
}

RZ_IPI RzCmdStatus rz_print_hexdump_handler(RzCore *core, int argc, const char **argv) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(rz_core_print_hexdump_(core, core->offset, len));
}

RZ_IPI RzCmdStatus rz_print_hexdump_n_lines_handler(RzCore *core, int argc, const char **argv) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(rz_core_print_hexdump_(core, core->offset, core->print->cols * len));
}

RZ_IPI RzCmdStatus rz_print_hexdump_hex2_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(rz_core_print_dump(core, state, core->offset, 2, len, RZ_CORE_PRINT_FORMAT_TYPE_HEXADECIMAL));
}
RZ_IPI RzCmdStatus rz_print_hexdump_hex4_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(rz_core_print_dump(core, state, core->offset, 4, len, RZ_CORE_PRINT_FORMAT_TYPE_HEXADECIMAL));
}
RZ_IPI RzCmdStatus rz_print_hexdump_hex8_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(rz_core_print_dump(core, state, core->offset, 8, len, RZ_CORE_PRINT_FORMAT_TYPE_HEXADECIMAL));
}

static inline bool print_nullable(char *str) {
	if (!str) {
		return false;
	}
	rz_cons_print(str);
	free(str);
	return true;
}

RZ_IPI RzCmdStatus rz_print_hexdump_hex2l_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(print_nullable(rz_core_print_hexdump_byline(core, state, core->offset, len, 2)));
}

RZ_IPI RzCmdStatus rz_print_hexdump_hex4l_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(print_nullable(rz_core_print_hexdump_byline(core, state, core->offset, len, 4)));
}

RZ_IPI RzCmdStatus rz_print_hexdump_hex8l_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(print_nullable(rz_core_print_hexdump_byline(core, state, core->offset, len, 8)));
}

RZ_IPI RzCmdStatus rz_print_hexdump_oct_handler(RzCore *core, int argc, const char **argv) {
	int len = argc > 1 ? (int)rz_num_math(core->num, argv[1]) : (int)core->blocksize;
	return bool2status(rz_core_print_dump(core, NULL, core->offset, 1, len, RZ_CORE_PRINT_FORMAT_TYPE_OCTAL));
}

#define CMD_PRINT_BYTE_ARRAY_HANDLER_NORMAL(name, type) \
	RZ_IPI RzCmdStatus name(RzCore *core, int argc, const char **argv) { \
		char *code = rz_lang_byte_array(core->block, core->blocksize, type); \
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
		char *code = rz_lang_byte_array(core->block, core->blocksize, big_endian ? type##_BE : type##_LE); \
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
	bool color = rz_config_get_i(core->config, "scr.color") > 0;
	RzAsmOp asm_op = { 0 };
	ut32 old_blocksize = core->blocksize;
	const char *pal_reg = core->cons->context->pal.reg;
	const char *pal_num = core->cons->context->pal.num;

	if (n_bytes > old_blocksize) {
		rz_core_block_size(core, n_bytes);
		rz_core_block_read(core);
	}

	rz_cmd_state_output_array_start(state);
	rz_cons_break_push(NULL, NULL);
	for (ut64 position = 0; position < n_bytes && !rz_cons_is_breaked(); position++) {
		ut64 offset = core->offset + position;
		rz_asm_set_pc(core->rasm, offset);
		ut8 *buffer = core->block + position;
		ut32 length = n_bytes - position;
		int op_size = rz_asm_disassemble(core->rasm, &asm_op, buffer, length);
		char *op_hex = rz_hex_bin2strdup(buffer, RZ_MAX(op_size, 1));
		char *assembly = strdup(op_size > 0 ? rz_asm_op_get_asm(&asm_op) : "illegal");
		char *colored = NULL;

		if (color && state->mode != RZ_OUTPUT_MODE_JSON) {
			RzAnalysisOp aop = { 0 };
			rz_analysis_op(core->analysis, &aop, offset, buffer, length, RZ_ANALYSIS_OP_MASK_ALL);
			char *tmp = rz_print_colorize_opcode(core->print, assembly, pal_reg, pal_num, false, 0);
			colored = rz_str_newf("%s%s" Color_RESET, rz_print_color_op_type(core->print, aop.type), tmp);
			free(tmp);
		}

		switch (state->mode) {
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("0x%08" PFMT64x " %20s  %s\n", offset, op_hex, colored ? colored : assembly);
			break;
		case RZ_OUTPUT_MODE_JSON:
			pj_o(state->d.pj);
			pj_kn(state->d.pj, "addr", offset);
			pj_ks(state->d.pj, "bytes", op_hex);
			pj_ks(state->d.pj, "inst", assembly);
			pj_end(state->d.pj);
			break;
		case RZ_OUTPUT_MODE_QUIET:
			rz_cons_printf("%s\n", colored ? colored : assembly);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
		free(op_hex);
		free(assembly);
		free(colored);
	}
	rz_cons_break_pop();
	rz_cmd_state_output_array_end(state);

	if (n_bytes > old_blocksize) {
		rz_core_block_size(core, old_blocksize);
		rz_core_block_read(core);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_disassembly_all_possible_opcodes_treeview_handler(RzCore *core, int argc, const char **argv) {
	bool color = rz_config_get_i(core->config, "scr.color") > 0;
	RzAsmOp asm_op = { 0 };
	const ut32 n_bytes = 28; // uses 56 chars
	ut32 old_blocksize = core->blocksize;
	const char *pal_reg = core->cons->context->pal.reg;
	const char *pal_num = core->cons->context->pal.num;

	if (old_blocksize < n_bytes) {
		rz_core_block_size(core, 256);
		rz_core_block_read(core);
	}

	rz_cons_break_push(NULL, NULL);
	for (ut32 position = 0; position < n_bytes && !rz_cons_is_breaked(); position++) {
		ut64 offset = core->offset + position;
		rz_asm_set_pc(core->rasm, offset);
		ut8 *buffer = core->block + position;
		ut32 length = RZ_MAX(n_bytes - position, core->blocksize - position);
		int op_size = rz_asm_disassemble(core->rasm, &asm_op, buffer, length);
		if (op_size < 1) {
			continue;
		}
		op_size = RZ_MAX(op_size, 1);
		char *op_hex = rz_hex_bin2strdup(buffer, op_size);
		char *assembly = strdup(op_size > 0 ? rz_asm_op_get_asm(&asm_op) : "illegal");
		char *colored = NULL;

		if (color) {
			RzAnalysisOp aop = { 0 };
			rz_analysis_op(core->analysis, &aop, offset, buffer, length, RZ_ANALYSIS_OP_MASK_ALL);
			char *tmp = rz_print_colorize_opcode(core->print, assembly, pal_reg, pal_num, false, 0);
			colored = rz_str_newf("%s%s" Color_RESET, rz_print_color_op_type(core->print, aop.type), tmp);
			free(tmp);
		}

		int padding = position * 2;
		int space = 60 - padding;

		if ((position + op_size) >= 30) {
			ut32 last = (30 - position) * 2;
			op_hex[last - 1] = '.';
			op_hex[last] = 0;
		}

		rz_cons_printf("0x%08" PFMT64x " %*s%*s %s\n", offset, padding, "", -space, op_hex, colored ? colored : assembly);
		free(op_hex);
		free(assembly);
		free(colored);
	}
	rz_cons_break_pop();

	if (old_blocksize < n_bytes) {
		rz_core_block_size(core, old_blocksize);
		rz_core_block_read(core);
	}
	return RZ_CMD_STATUS_OK;
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

RZ_IPI RzCmdStatus rz_cmd_disassembly_function_summary_handler(RzCore *core, int argc, const char **argv) {
	ut64 old_offset = core->offset;
	ut32 old_blocksize = core->blocksize;
	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
	if (!function) {
		RZ_LOG_ERROR("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	ut32 rs = rz_analysis_function_realsize(function);
	ut32 fs = rz_analysis_function_linear_size(function);
	rz_core_seek(core, old_offset, SEEK_SET);
	rz_core_block_size(core, RZ_MAX(rs, fs));
	disasm_strings(core, "dfs", function);

	rz_core_block_size(core, old_blocksize);
	rz_core_seek(core, old_offset, SEEK_SET);
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
	const char *orig_bb_middle = rz_config_get(core->config, "asm.bb.middle");
	rz_config_set_i(core->config, "asm.bb.middle", false);

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
		int saved_stackptr = core->analysis->stackptr;
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
		core->analysis->stackptr = saved_stackptr;
		rz_config_set_i(core->config, "asm.lines.bb", asm_lines);
	}
	rz_config_set(core->config, "asm.bb.middle", orig_bb_middle);
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

	// small patch to reuse disasm_strings which
	// needs to be rewritten entirely
	char input_cmd[256];
	rz_strf(input_cmd, "ds 0x%" PFMT64x, n_bytes);
	disasm_strings(core, argc > 1 ? input_cmd : "ds", NULL);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_disassemble_summarize_function_handler(RzCore *core, int argc, const char **argv) {
	disasm_strings(core, "dsf", NULL);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_disassemble_summarize_block_handler(RzCore *core, int argc, const char **argv) {
	ut64 n_bytes = argc > 1 ? rz_num_math(core->num, argv[1]) : 0;
	if (!n_bytes) {
		RZ_LOG_ERROR("Invalid number of bytes\n");
		return RZ_CMD_STATUS_ERROR;
	}

	// small patch to reuse disasm_strings which
	// needs to be rewritten entirely
	char input_cmd[256];
	rz_strf(input_cmd, "dsb 0x%" PFMT64x, n_bytes);
	disasm_strings(core, input_cmd, NULL);
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