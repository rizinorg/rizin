// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_asm.h"
#include "rz_core.h"
#include "rz_config.h"
#include "rz_util.h"
#include "rz_types.h"
#include <limits.h>

#include "core_private.h"

#define RZ_CORE_MAX_DISASM (1024 * 1024 * 8)
#define PF_USAGE_STR       "pf[.k[.f[=v]]|[v]]|[n]|[0|cnt][fmt] [a0 a1 ...]"

static int printzoomcallback(void *user, int mode, ut64 addr, ut8 *bufz, ut64 size);
static const char *help_msg_pa[] = {
	"Usage: pa[edD]", "[asm|hex]", "print (dis)assembled",
	"pa", " [assembly]", "print hexpairs of the given assembly expression",
	"paD", " [hexpairs]", "print assembly expression from hexpairs and show hexpairs",
	"pad", " [hexpairs]", "print assembly expression from hexpairs (alias for pdx, pix)",
	"pade", " [hexpairs]", "print ESIL expression from hexpairs",
	"pae", " [assembly]", "print ESIL expression of the given assembly expression",
	NULL
};

static const char *help_msg_pdf[] = {
	"Usage: pdf[bf]", "", "disassemble function",
	"pdf", "", "disassemble function",
	"pdfs", "", "disassemble function summary",
	NULL
};

static const char *help_msg_pp[] = {
	"Usage: pp[d]", "", "print patterns",
	"pp0", "", "print buffer filled with zeros",
	"pp1", "", "print incremental byte pattern (honor lower bits of cur address and bsize)",
	"pp2", "", "print incremental word pattern",
	"pp4", "", "print incremental dword pattern",
	"pp8", "", "print incremental qword pattern",
	"ppa", "[lu]", "latin alphabet (lowercase, uppercases restrictions)",
	"ppd", "", "print debruijn pattern (see rz_gg -P, -q and wopD)",
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

static const char *help_msg_p6[] = {
	"Usage: p6[de]", "[len]", "base64 decoding/encoding",
	"p6d", "[len]", "decode base64",
	"p6e", "[len]", "encode base64",
	NULL
};

static const char *help_msg_pF[] = {
	"Usage: pF[apdb]", "[len]", "parse ASN1, PKCS, X509, DER, protobuf",
	"pFa", "[len]", "decode ASN1 from current block",
	"pFaq", "[len]", "decode ASN1 from current block (quiet output)",
	"pFb", "[len]", "decode raw proto buffers.",
	"pFbv", "[len]", "decode raw proto buffers (verbose).",
	"pFo", "[len]", "decode ASN1 OID",
	"pFp", "[len]", "decode PKCS7",
	"pFx", "[len]", "Same with X509",
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
	"`", "pdi~push:0[0]`", "replace output of command inside the line",
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
	"p", "[iI][df] [len]", "print N ops/bytes (f=func) (see pi? and pdi)",
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
	"pC", "[aAcdDxw] [rows]", "print disassembly in columns (see hex.cols and pdi)",
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
	"pq", "[?][is] [len]", "print QR code with the first Nbytes",
	"pr", "[?][glx] [len]", "print N raw bytes (in lines or hexblocks, 'g'unzip)",
	"ps", "[?][pwz] [len]", "print pascal/wide/zero-terminated strings",
	"pt", "[?][dn] [len]", "print different timestamps",
	"pu", "[?][w] [len]", "print N url encoded bytes (w=wide)",
	"pv", "[?][jh] [mode]", "show variable/pointer/value in memory",
	"pwd", "", "display current working directory",
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

static const char *help_msg_pd[] = {
	"Usage:", "p[dD][ajbrfils] [len]", " # Print Disassembly",
	"NOTE: ", "len", "parameter can be negative",
	"NOTE: ", "", "Pressing ENTER on empty command will repeat last print command in next page",
	"pD", " N", "disassemble N bytes",
	"pd", " -N", "disassemble N instructions backward",
	"pd", " N", "disassemble N instructions",
	"pd--", "[n]", "context disassembly of N instructions",
	"pda", "[?]", "disassemble all possible opcodes (byte per byte)",
	"pdb", "", "disassemble basic block",
	"pdC", "", "show comments found in N instructions",
	"pde", "[q|qq|j] [N]", "disassemble N instructions following execution flow from current PC",
	"pdf", "", "disassemble function",
	"pdi", "", "like 'pi', with offset and bytes",
	"pdj", "", "disassemble to json",
	"pdJ", "", "formatted disassembly like pd as json",
	"pdk", "", "disassemble all methods of a class",
	"pdl", "", "show instruction sizes",
	"pdp", "", "disassemble by following pointers to read ropchains",
	"pdr", "", "recursive disassemble across the function graph",
	"pdR", "", "recursive disassemble block size bytes without analyzing functions",
	"pdr.", "", "recursive disassemble across the function graph (from current basic block)",
	"pds", "[?]", "disassemble summary (strings, calls, jumps, refs) (see pdsf and pdfs)",
	"pdt", " [n] [query]", "disassemble N instructions in a table (see dtd for debug traces)",
	"pdx", " [hex]", "alias for pad or pix",
	NULL
};

static const char *help_msg_pda[] = {
	"Usage:", "pda[j]", "Print disassembly of all possbile opcodes",
	"pdaj", "", "Display the disassembly of all possbile opcodes (byte per byte) in JSON",
	NULL
};

static const char *help_msg_pds[] = {
	"Usage:", "pds[bf]", "Summarize N bytes or function",
	"pdsf", "", "Summarize the current function",
	"pdsb", "", "Summarize N bytes",
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
	"Usage:", "pi[bdefrj] [num]", "",
	"pia", "", "print all possible opcodes (byte per byte)",
	"pib", "", "print instructions of basic block",
	"pid", "", "alias for pdi",
	"pie", "", "print offset + esil expression",
	"pif", "[?]", "print instructions of function",
	"pij", "", "print N instructions in JSON",
	"pir", "", "like 'pdr' but with 'pI' output",
	"piu", "[q] [limit]", "disasm until ujmp or ret is found (see pdp)",
	"pix", "  [hexpairs]", "alias for pdx and pad",
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
	"psq", "", "alias for pqs",
	"pss", "", "print string in screen (wrap width)",
	"psu", "[zj]", "print utf16 unicode (json)",
	"psw", "[j]", "print 16bit wide string",
	"psW", "[j]", "print 32bit wide string",
	"psx", "", "show string with escaped chars",
	"psz", "[j]", "print zero-terminated string",
	NULL
};

static const char *help_msg_pt[] = {
	"Usage: pt", "[dn]", "print timestamps",
	"pt.", "", "print current time",
	"pt", "", "print UNIX time (32 bit `cfg.bigendian`) Since January 1, 1970",
	"ptd", "", "print DOS time (32 bit `cfg.bigendian`) Since January 1, 1980",
	"pth", "", "print HFS time (32 bit `cfg.bigendian`) Since January 1, 1904",
	"ptn", "", "print NTFS time (64 bit `cfg.bigendian`) Since January 1, 1601",
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

const char *help_msg_pz[] = {
	"Usage: pz [len]", "", "print zoomed blocks (filesize/N)",
	"e ", "zoom.maxsz", "max size of block",
	"e ", "zoom.from", "start address",
	"e ", "zoom.to", "end address",
	"e ", "zoom.byte", "specify how to calculate each byte",
	"pzp", "", "number of printable chars",
	"pzf", "", "count of flags in block",
	"pzs", "", "strings in range",
	"pz0", "", "number of bytes with value '0'",
	"pzF", "", "number of bytes with value 0xFF",
	"pze", "", "calculate entropy and expand to 0-255 range",
	"pzh", "", "head (first byte value); This is the default mode",
	// "WARNING: On big files, use 'zoom.byte=h' or restrict ranges\n");
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

static void __cmd_pad(RzCore *core, const char *arg) {
	if (*arg == '?') {
		eprintf("Usage: pad [hexpairs] # disassembly given bytes\n");
		return;
	}
	rz_asm_set_pc(core->rasm, core->offset);
	bool is_pseudo = rz_config_get_i(core->config, "asm.pseudo");
	RzAsmCode *acode = rz_asm_mdisassemble_hexstr(core->rasm, is_pseudo ? core->parser : NULL, arg);
	if (acode) {
		rz_cons_print(acode->assembly);
		rz_asm_code_free(acode);
	} else {
		eprintf("Invalid hexstr\n");
	}
}

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
				int brightness = ((color_val & 0xff0000) >> 16) + 2 * ((color_val & 0xff00) >> 8) + (color_val & 0xff) / 2;
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

static void cmd_prc_zoom(RzCore *core, const char *input) {
	const char *chars = " .,:;!O@#";
	bool square = rz_config_get_i(core->config, "scr.square");
	int i, j;
	char ch, ch2, *color;
	int cols = rz_config_get_i(core->config, "hex.cols");
	bool show_color = rz_config_get_i(core->config, "scr.color");
	bool show_flags = rz_config_get_i(core->config, "asm.flags");
	bool show_cursor = core->print->cur_enabled;
	bool show_offset = rz_config_get_i(core->config, "hex.offset");
	bool show_unalloc = core->print->flags & RZ_PRINT_FLAGS_UNALLOC;
	ut8 *block = core->block;
	int len = core->blocksize;
	ut64 from = 0;
	ut64 to = 0;
	RzIOMap *map;
	RzListIter *iter;

	if (cols < 1 || cols > 0xfffff) {
		cols = 32;
	}
	RzList *list = rz_core_get_boundaries_prot(core, -1, NULL, "zoom");
	if (list && rz_list_length(list) > 0) {
		RzListIter *iter1 = list->head;
		RzIOMap *map1 = iter1->data;
		from = map1->itv.addr;
		rz_list_foreach (list, iter, map) {
			to = rz_itv_end(map->itv);
		}
	} else {
		from = core->offset;
		to = from + core->blocksize;
	}

	core->print->zoom->mode = (input && *input) ? input[1] : 'e';
	rz_print_zoom_buf(core->print, core, printzoomcallback, from, to, len, len);
	block = core->print->zoom->buf;
	switch (core->print->zoom->mode) {
	case 'f':
		// scale buffer for proper visualization of small numbers as colors
		for (i = 0; i < core->print->zoom->size; i++) {
			block[i] *= 8;
		}
		break;
	}

	for (i = 0; i < len; i += cols) {
		ut64 ea = core->offset + i;
		if (show_offset) {
			rz_print_addr(core->print, ea);
		}
		for (j = i; j < i + cols; j++) {
			if (j >= len) {
				break;
			}
			if (show_color) {
				char *str = rz_str_newf("rgb:fff rgb:%06x", colormap[block[j]]);
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
		char *cmd = rz_str_newf("pid %d @i:%d", rows, rows * i);
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

static ut64 findClassBounds(RzCore *core, const char *input, int *len) {
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

static char get_string_type(const ut8 *buf, ut64 len) {
	ut64 needle = 0;
	int rc, i;
	char str_type = 0;

	if (!buf) {
		return '?';
	}
	while (needle < len) {
		rc = rz_utf8_decode(buf + needle, len - needle, NULL);
		if (!rc) {
			needle++;
			continue;
		}
		if (needle + rc + 2 < len &&
			buf[needle + rc + 0] == 0x00 &&
			buf[needle + rc + 1] == 0x00 &&
			buf[needle + rc + 2] == 0x00) {
			str_type = 'w';
		} else {
			str_type = 'a';
		}
		for (i = 0; needle < len; i += rc) {
			RzRune r;
			if (str_type == 'w') {
				if (needle + 1 < len) {
					r = buf[needle + 1] << 8 | buf[needle];
					rc = 2;
				} else {
					break;
				}
			} else {
				rc = rz_utf8_decode(buf + needle, len - needle, &r);
				if (rc > 1) {
					str_type = 'u';
				}
			}
			/*Invalid sequence detected*/
			if (!rc) {
				needle++;
				break;
			}
			needle += rc;
		}
	}
	return str_type;
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

static void cmd_pDj(RzCore *core, const char *arg) {
	int bsize = rz_num_math(core->num, arg);
	if (bsize < 0) {
		bsize = -bsize;
	}
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_a(pj);
	ut8 *buf = malloc(bsize);
	if (buf) {
		rz_io_read_at(core->io, core->offset, buf, bsize);
		rz_core_print_disasm_json(core, core->offset, buf, bsize, 0, pj);
		free(buf);
	} else {
		eprintf("cannot allocate %d byte(s)\n", bsize);
	}
	pj_end(pj);
	rz_cons_println(pj_string(pj));
	pj_free(pj);
}

static void cmd_pdj(RzCore *core, const char *arg, ut8 *block) {
	int nblines = rz_num_math(core->num, arg);
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_a(pj);
	rz_core_print_disasm_json(core, core->offset, block, core->blocksize, nblines, pj);
	pj_end(pj);
	rz_cons_println(pj_string(pj));
	pj_free(pj);
}

static void cmd_p_minus_e(RzCore *core, ut64 at, ut64 ate) {
	ut8 *blockptr = malloc(ate - at);
	if (!blockptr) {
		return;
	}
	if (rz_io_read_at(core->io, at, blockptr, (ate - at))) {
		ut8 entropy = (ut8)(rz_hash_entropy_fraction(blockptr, (ate - at)) * 255);
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
	default:
	case '?': // "pF?"
		rz_core_cmd_help(core, help_msg_pF);
		break;
	}
}

RZ_API void rz_core_gadget_free(RzCoreGadget *g) {
	free(g->cmd);
	free(g);
}

static const char *help_msg_pg[] = {
	"Usage: pg[-]", "[asm|hex]", "print (dis)assembled",
	"pg", " [x y w h cmd]", "add a new gadget",
	"pg", "", "print them all",
	"pg", "*", "print the gadgets as rizin commands",
	"pg-", "*", "remove all the gadgets",
	NULL
};

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
		RzCoreGadget *g;
		RzListIter *iter;
		rz_list_foreach (core->gadgets, iter, g) {
			char *res = rz_core_cmd_str(core, g->cmd);
			if (res) {
				rz_cons_strcat_at(res, g->x, g->y, g->w, g->h);
				free(res);
			}
		}
	} else {
		rz_core_cmd_help(core, help_msg_pg);
	}
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
			val = sdb_get(core->print->formats, _input, NULL);
			if (val) {
				rz_cons_printf("%d\n", rz_print_format_struct_size(core->print, val, mode, 0));
			} else {
				eprintf("Struct %s not defined\nUsage: pfs.struct_name | pfs format\n", _input);
			}
		} else if (*_input == ' ') {
			while (*_input == ' ' && *_input != '\0') {
				_input++;
			}
			if (*_input) {
				rz_cons_printf("%d\n", rz_print_format_struct_size(core->print, _input, mode, 0));
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
				const char *val = sdb_get(core->print->formats, struct_name, NULL);
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
			eprintf("|Usage: pfo [format-file]\n"
				" " RZ_JOIN_3_PATHS("~", RZ_HOME_SDB_FORMAT, "") "\n"
										 " " RZ_JOIN_3_PATHS("%s", RZ_SDB_FORMAT, "") "\n",
				rz_sys_prefix(NULL));
		} else if (_input[2] == ' ') {
			const char *fname = rz_str_trim_head_ro(_input + 3);
			char *tmp = rz_str_newf(RZ_JOIN_2_PATHS(RZ_HOME_SDB_FORMAT, "%s"), fname);
			char *home = rz_str_home(tmp);
			free(tmp);
			tmp = rz_str_newf(RZ_JOIN_2_PATHS(RZ_SDB_FORMAT, "%s"), fname);
			char *path = rz_str_rz_prefix(tmp);
			if (rz_str_endswith(_input, ".h")) {
				char *error_msg = NULL;
				const char *dir = rz_config_get(core->config, "dir.types");
				char *out = rz_parse_c_file(core->analysis, path, dir, &error_msg);
				if (out) {
					rz_analysis_save_parsed_type(core->analysis, out);
					rz_core_cmd0(core, ".ts*");
					free(out);
				} else {
					eprintf("Parse error: %s\n", error_msg);
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
			free(tmp);
		} else {
			RzList *files;
			RzListIter *iter;
			const char *fn;
			char *home = rz_str_home(RZ_HOME_SDB_FORMAT RZ_SYS_DIR);
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
			char *path = rz_str_rz_prefix(RZ_SDB_FORMAT RZ_SYS_DIR);
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

	core->print->reg = core->dbg->reg;
	core->print->get_register = rz_reg_get;
	core->print->get_register_value = rz_reg_get_value;

	int o_blocksize = core->blocksize;

	if (listFormats) {
		core->print->num = core->num;
		/* print all stored format */
		if (!input[1] || !input[2]) { // "pf."
			SdbListIter *iter;
			SdbKv *kv;
			SdbList *sdbls = sdb_foreach_list(core->print->formats, true);
			ls_foreach (sdbls, iter, kv) {
				rz_cons_printf("pf.%s %s\n", sdbkv_key(kv), sdbkv_value(kv));
			}
			/* delete a format */
		} else if (input[1] && input[2] == '-') { // "pf-"
			if (input[3] == '*') { // "pf-*"
				sdb_free(core->print->formats);
				core->print->formats = sdb_new0();
			} else { // "pf-xxx"
				sdb_unset(core->print->formats, input + 3, 0);
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
					sdb_set(core->print->formats, name, space, 0);
				}
				free(name);
				free(input);
				return;
			}

			if (!strchr(name, '.') &&
				!sdb_get(core->print->formats, name, NULL)) {
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
			fmt = sdb_get(core->print->formats, name, NULL);
			if (fmt) {
				int size = rz_print_format_struct_size(core->print, fmt, mode, 0) + 10;
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
					rz_print_format(core->print, core->offset,
						core->block, core->blocksize, name, mode, eq, dot);
				} else {
					rz_print_format(core->print, core->offset,
						core->block, core->blocksize, name, mode, NULL, dot);
				}
			} else {
				rz_print_format(core->print, core->offset,
					core->block, core->blocksize, name, mode, NULL, NULL);
			}
			free(name);
		}
	} else {
		/* This make sure the structure will be printed entirely */
		const char *fmt = rz_str_trim_head_ro(input + 1);
		int struct_sz = rz_print_format_struct_size(core->print, fmt, mode, 0);
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
			goto stage_left;
		}
		const char *arg1 = strtok(args, " ");
		if (arg1 && rz_str_isnumber(arg1)) {
			syntax_ok = false;
			rz_cons_printf("Usage: pf [0|cnt][format-string]\n");
		}
		free(args);
		if (syntax_ok) {
			rz_print_format(core->print, core->offset,
				buf, size, fmt, mode, NULL, NULL);
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
		rz_core_cmdf(core, "pid %d @ 0x%" PFMT64x, count, addr);
		break;
	}
}

struct count_pz_t {
	RzSpace *flagspace;
	ut64 addr;
	ut64 size;
	int *ret;
};

static bool count_pzs(RzFlagItem *fi, void *u) {
	struct count_pz_t *user = (struct count_pz_t *)u;
	if (fi->space == user->flagspace &&
		((user->addr <= fi->offset && fi->offset < user->addr + user->size) ||
			(user->addr <= fi->offset + fi->size && fi->offset + fi->size < user->addr + user->size))) {
		(*user->ret)++;
	}

	return true;
}
static bool count_pzf(RzFlagItem *fi, void *u) {
	struct count_pz_t *user = (struct count_pz_t *)u;
	if (fi->offset <= user->addr && user->addr < fi->offset + fi->size) {
		(*user->ret)++;
	}
	return true;
}

static int printzoomcallback(void *user, int mode, ut64 addr, ut8 *bufz, ut64 size) {
	RzCore *core = (RzCore *)user;
	int j, ret = 0;
	struct count_pz_t u;

	switch (mode) {
	case 'a': {
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, 0);
		int value = 0;
		if (fcn) {
			value = rz_list_length(fcn->bbs);
		}
		return value;
	} break;
	case 'A': {
		RzCoreAnalStats *as = rz_core_analysis_get_stats(core, addr, addr + size * 2, size);
		int i;
		int value = 0;
		for (i = 0; i < 1; i++) {
			value += as->block[i].functions;
			value += as->block[i].in_functions;
			value += as->block[i].comments;
			value += as->block[i].symbols;
			value += as->block[i].flags;
			value += as->block[i].strings;
			value += as->block[i].blocks;
			value *= 20;
		}
		rz_core_analysis_stats_free(as);
		return value;
	} break;
	case '0': // "pz0"
		for (j = 0; j < size; j++) {
			if (bufz[j] == 0) {
				ret++;
			}
		}
		break;
	case 'e': // "pze"
		ret = (ut8)(rz_hash_entropy_fraction(bufz, size) * 255);
		break;
	case 'f': // "pzf"
		u.addr = addr;
		u.ret = &ret;
		rz_flag_foreach(core->flags, count_pzf, &u);
		break;
	case 'F': // "pzF"
		for (j = 0; j < size; j++) {
			if (bufz[j] == 0xff) {
				ret++;
			}
		}
		break;
	case 'p': // "pzp"
		for (j = 0; j < size; j++) {
			if (IS_PRINTABLE(bufz[j])) {
				ret++;
			}
		}
		break;
	case 's': // "pzs"
		u.flagspace = rz_flag_space_get(core->flags, RZ_FLAGS_FS_STRINGS);
		u.addr = addr;
		u.size = size;
		u.ret = &ret;
		rz_flag_foreach(core->flags, count_pzs, &u);
		break;
	case 'h': // "pzh" head
	default:
		ret = *bufz;
	}
	return ret;
}

RZ_API void rz_core_print_cmp(RzCore *core, ut64 from, ut64 to) {
	long int delta = 0;
	int col = core->cons->columns > 123;
	ut8 *b = malloc(core->blocksize);
	ut64 addr = core->offset;
	memset(b, 0xff, core->blocksize);
	delta = addr - from;
	rz_io_read_at(core->io, to + delta, b, core->blocksize);
	rz_print_hexdiff(core->print, core->offset, core->block,
		to + delta, b, core->blocksize, col);
	free(b);
}

static void cmd_print_pwn(const RzCore *core) {
	rz_cons_printf("easter egg license has expired\n");
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

static void cmd_print_op(RzCore *core, const char *input) {
	ut8 *buf;
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
			buf = rz_core_transform_op(core, input + 3, input[1]);
		} else { // use clipboard instead of val
			buf = rz_core_transform_op(core, NULL, input[1]);
		}
		break;
	case 'n':
		buf = rz_core_transform_op(core, "ff", 'x');
		break;
	case '\0':
	case '?':
	default:
		rz_core_cmd_help(core, help_msg_po);
		return;
	}
	if (buf) {
		rz_print_hexdump(core->print, core->offset, buf,
			core->blocksize, 16, 1, 1);
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

static void algolist(int mode) {
	int i;
	for (i = 0; i < RZ_HASH_NBITS; i++) {
		ut64 bits = 1ULL << i;
		const char *name = rz_hash_name(bits);
		if (name && *name) {
			if (mode) {
				rz_cons_println(name);
			} else {
				rz_cons_printf("%s ", name);
			}
		}
	}
	if (!mode) {
		rz_cons_newline();
	}
}

static bool cmd_print_ph(RzCore *core, const char *input) {
	char algo[128];
	ut32 osize = 0, len = core->blocksize;
	const char *ptr;
	int pos = 0, handled_cmd = false;

	if (!*input || *input == '?') {
		algolist(1);
		return true;
	}
	if (*input == '=') {
		algolist(0);
		return true;
	}
	input = rz_str_trim_head_ro(input);
	ptr = strchr(input, ' ');
	sscanf(input, "%31s", algo);
	if (ptr && ptr[1]) { // && rz_num_is_valid_input (core->num, ptr + 1)) {
		int nlen = rz_num_math(core->num, ptr + 1);
		if (nlen > 0) {
			len = nlen;
		}
		osize = core->blocksize;
		if (nlen > core->blocksize) {
			rz_core_block_size(core, nlen);
			if (nlen != core->blocksize) {
				eprintf("Invalid block size\n");
				rz_core_block_size(core, osize);
				return false;
			}
			rz_core_block_read(core);
		}
	} else if (!ptr || !*(ptr + 1)) {
		osize = len;
	}
	/* TODO: Simplify this spaguetti monster */
	while (osize > 0 && hash_handlers[pos].name) {
		if (!rz_str_ccmp(hash_handlers[pos].name, input, ' ')) {
			hash_handlers[pos].handler(core->block, len);
			handled_cmd = true;
			break;
		}
		pos++;
	}
	if (osize) {
		rz_core_block_size(core, osize);
	}
	return handled_cmd;
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
				rz_cons_printf("f pval.0x%08" PFMT64x "=%d\n", at, rz_read_ble8(b));
				break;
			case 2:
				rz_cons_printf("f pval.0x%08" PFMT64x "=%d\n", at, rz_read_ble16(b, be));
				break;
			case 4:
				rz_cons_printf("f pval.0x%08" PFMT64x "=%d\n", at, rz_read_ble32(b, be));
				break;
			case 8:
			default:
				rz_cons_printf("f pval.0x%08" PFMT64x "=%" PFMT64d "\n", at, rz_read_ble64(b, be));
				break;
			}
		}
		break;
	}
	case 'j': { // "pvj"
		PJ *pj = rz_core_pj_new(core);
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
	RzCoreAnalStats *as = NULL;
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
	//int cols = rz_cons_get_size (NULL) - 30;
	ut64 off = core->offset;
	ut64 from = UT64_MAX;
	ut64 to = 0;

	list = rz_core_get_boundaries_prot(core, -1, NULL, "search");
	if (!list) {
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
	ut64 piece = RZ_MAX((to - from) / RZ_MAX(cols, w), 1);
	as = rz_core_analysis_get_stats(core, from, to, piece);
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
	int i;
	for (i = 0; i < ((to - from) / piece); i++) {
		ut64 at = from + (piece * i);
		ut64 ate = at + piece;
		ut64 p = (at - from) / piece;
		switch (mode) {
		case 'j':
			pj_o(pj);
			if ((as->block[p].flags) || (as->block[p].functions) || (as->block[p].comments) || (as->block[p].symbols) || (as->block[p].perm) || (as->block[p].strings)) {
				pj_kn(pj, "offset", at);
				pj_kn(pj, "size", piece);
			}
			if (as->block[p].flags) {
				pj_ki(pj, "flags", as->block[p].flags);
			}
			if (as->block[p].functions) {
				pj_ki(pj, "functions", as->block[p].functions);
			}
			if (as->block[p].in_functions) {
				pj_ki(pj, "in_functions", as->block[p].in_functions);
			}
			if (as->block[p].comments) {
				pj_ki(pj, "comments", as->block[p].comments);
			}
			if (as->block[p].symbols) {
				pj_ki(pj, "symbols", as->block[p].symbols);
			}
			if (as->block[p].strings) {
				pj_ki(pj, "strings", as->block[p].strings);
			}
			if (as->block[p].perm) {
				pj_ks(pj, "perm", rz_str_rwx_i(as->block[p].perm));
			}
			pj_end(pj);
			len++;
			break;
		case 'h':
			if ((as->block[p].flags) || (as->block[p].functions) || (as->block[p].comments) || (as->block[p].symbols) || (as->block[p].strings)) {
				rz_table_add_rowf(t, "sddddd", sdb_fmt("0x%09" PFMT64x "", at), as->block[p].flags,
					as->block[p].functions, as->block[p].comments, as->block[p].symbols, as->block[p].strings);
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
							rz_cons_print(rz_cons_singleton()->context->pal.graph_trufae);
						} else {
							rz_cons_print(rz_cons_singleton()->context->pal.graph_true);
						}
					} else {
						rz_cons_print(rz_cons_singleton()->context->pal.graph_false);
					}
				}
				if (as->block[p].strings > 0) {
					rz_cons_memcat("z", 1);
				} else if (as->block[p].symbols > 0) {
					rz_cons_memcat("s", 1);
				} else if (as->block[p].functions > 0) {
					rz_cons_memcat("F", 1);
				} else if (as->block[p].comments > 0) {
					rz_cons_memcat("c", 1);
				} else if (as->block[p].flags > 0) {
					rz_cons_memcat(".", 1);
				} else if (as->block[p].in_functions > 0) {
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
		//case RZ_ANALYSIS_OP_TYPE_RJMP:
		//case RZ_ANALYSIS_OP_TYPE_UJMP:
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
	// XXX: unused memblock
	ut8 *p = malloc(blocksize);
	if (!p) {
		RZ_FREE(ptr);
		eprintf("Error: failed to malloc memory");
		return NULL;
	}
	if (type == 'A') {
		ut64 to = from + (blocksize * nblocks);
		RzCoreAnalStats *as = rz_core_analysis_get_stats(core, from, to, blocksize);
		for (i = 0; i < nblocks; i++) {
			int value = 0;
			value += as->block[i].functions;
			value += as->block[i].in_functions;
			value += as->block[i].comments;
			value += as->block[i].symbols;
			value += as->block[i].flags;
			value += as->block[i].strings;
			value += as->block[i].blocks;
			ptr[i] = RZ_MIN(255, value);
		}
		rz_core_analysis_stats_free(as);
		free(p);
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
	free(p);
	return ptr;
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
		if (rz_config_get_i(core->config, "cfg.debug")) {
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
	if (!rz_config_get_i(core->config, "cfg.debug")) {
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
				ut64 to = from + totalsize; //  (blocksize * nblocks);
				RzCoreAnalStats *as = rz_core_analysis_get_stats(core, from, to, blocksize);
				for (i = 0; i < nblocks; i++) {
					int value = 0;
					value += as->block[i].functions;
					value += as->block[i].in_functions;
					value += as->block[i].comments;
					value += as->block[i].symbols;
					value += as->block[i].flags;
					value += as->block[i].strings;
					value += as->block[i].blocks;
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
			rz_print_columns(core->print, ptr, nblocks, 14);
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
				ptr[i] = (ut8)(255 * rz_hash_entropy_fraction(p, blocksize));
			}
			free(p);
			rz_print_columns(core->print, ptr, nblocks, 14);
		} break;
		default:
			rz_print_columns(core->print, core->block, core->blocksize, 14);
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
			ptr[i] = (ut8)(255 * rz_hash_entropy_fraction(p, blocksize));
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
			rz_cons_printf("axd 0x%" PFMT64x " 0x%08" PFMT64x "\n", origin, offset);
			break;
		case '.':
			rz_meta_del(core->analysis, RZ_META_TYPE_COMMENT, origin, 1);
			rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, origin, "switch table");
			rz_core_cmdf(core, "f switch.0x%08" PFMT64x "=0x%08" PFMT64x "\n", origin, origin);
			rz_core_cmdf(core, "f jmptbl.0x%08" PFMT64x "=0x%08" PFMT64x "\n", offset, offset); //origin, origin);
			rz_analysis_xrefs_set(core->analysis, offset, origin, RZ_ANALYSIS_REF_TYPE_DATA);
			break;
		}
	} else if (mode == '.') {
		rz_meta_del(core->analysis, RZ_META_TYPE_COMMENT, origin, 1);
		rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, offset, "switch basic block");
		rz_core_cmdf(core, "f switch.0x%08" PFMT64x "=0x%08" PFMT64x "\n", offset, offset); // basic block @ 0x%08"PFMT64x "\n", offset);
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
			rz_cons_printf("ax 0x%" PFMT64x " 0x%08" PFMT64x "\n", offset, addr);
			rz_cons_printf("ax 0x%" PFMT64x " 0x%08" PFMT64x "\n", addr, offset); // wrong, but useful because forward xrefs dont work :?
			// FIXME: "aho" doesn't accept anything here after the "case" word
			rz_cons_printf("aho case 0x%" PFMT64x " 0x%08" PFMT64x " @ 0x%08" PFMT64x "\n", (ut64)i, addr, offset + i); // wrong, but useful because forward xrefs dont work :?
			rz_cons_printf("ahs %d @ 0x%08" PFMT64x "\n", step, offset + i);
		} else if (mode == '.') {
			const char *case_name = rz_str_newf("case.%d.0x%" PFMT64x, n, offset);
			rz_core_analysis_function_add(core, case_name, addr, false);
			rz_analysis_xrefs_set(core->analysis, addr, offset, RZ_ANALYSIS_REF_TYPE_NULL);
			rz_analysis_xrefs_set(core->analysis, offset, addr, RZ_ANALYSIS_REF_TYPE_NULL); // wrong, but useful because forward xrefs dont work :?
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
		? rz_core_cmdf(core, "pD %" PFMT64u " @0x%" PFMT64x, b->size, b->addr)
		: rz_core_cmdf(core, "pI %" PFMT64u " @0x%" PFMT64x, b->size, b->addr);
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
			//rz_parse_parse (core->parser, op->mnemonic, m);
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
		//rz_io_read_at (core->io, n, rbuf, 512);
		rz_analysis_op_free(op);
	}
beach:
	return;
}

static void disasm_ropchain(RzCore *core, ut64 addr, char type_print) {
	int p = 0;
	ut64 n = 0;
	ut8 *buf = calloc(core->blocksize, 1);
	(void)rz_io_read_at(core->io, addr, buf, core->blocksize);
	while (p + 4 < core->blocksize) {
		const bool be = core->print->big_endian;
		if (core->rasm->bits == 64) {
			n = rz_read_ble64(buf + p, be);
		} else {
			n = rz_read_ble32(buf + p, be);
		}
		rz_cons_printf("[0x%08" PFMT64x "] 0x%08" PFMT64x "\n", addr + p, n);
		disasm_until_ret(core, n, type_print, NULL);
		if (core->rasm->bits == 64) {
			p += 8;
		} else {
			p += 4;
		}
	}
	free(buf);
}

static void disasm_recursive(RzCore *core, ut64 addr, int count, char type_print) {
	RzAnalysisOp aop = { 0 };
	int ret;
	ut8 buf[128];
	PJ *pj = NULL;
	if (type_print == 'j') {
		pj = pj_new();
		if (!pj) {
			return;
		}
		pj_a(pj);
	}
	while (count-- > 0) {
		rz_io_read_at(core->io, addr, buf, sizeof(buf));
		rz_analysis_op_fini(&aop);
		ret = rz_analysis_op(core->analysis, &aop, addr, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC);
		if (ret < 0 || aop.size < 1) {
			addr++;
			continue;
		}
		//	rz_core_cmdf (core, "pD %d @ 0x%08"PFMT64x, aop.size, addr);
		if (type_print == 'j') {
			rz_core_print_disasm_json(core, addr, buf, sizeof(buf), 1, pj);
		} else {
			rz_core_cmdf(core, "pd 1 @ 0x%08" PFMT64x, addr);
		}
		switch (aop.type) {
		case RZ_ANALYSIS_OP_TYPE_JMP:
			addr = aop.jump;
			continue;
		case RZ_ANALYSIS_OP_TYPE_UCJMP:
			break;
		case RZ_ANALYSIS_OP_TYPE_RET:
			count = 0; // stop disassembling when hitting RET
			break;
		default:
			break;
		}
		addr += aop.size;
	}
	if (type_print == 'j') {
		pj_end(pj);
		rz_cons_printf("%s\n", pj_string(pj));
		pj_free(pj);
	}
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

static void print_json_string(RzCore *core, const char *block, int len, const char *type) {
	const char *section_name = rz_core_get_section_name(core, core->offset);
	if (section_name && strlen(section_name) < 1) {
		section_name = "unknown";
	} else {
		// cleaning useless spaces in section name in json data.
		section_name = rz_str_trim_head_ro(section_name);
		char *p;
		for (p = (char *)section_name; *p && *p != ' '; p++) {
		}
		*p = '\0';
	}
	if (!type) {
		switch (get_string_type(core->block, len)) {
		case 'w': type = "wide"; break;
		case 'a': type = "ascii"; break;
		case 'u': type = "utf"; break;
		default: type = "unknown"; break;
		}
	}
	PJ *pj = rz_core_pj_new(core);
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_k(pj, "string");
	// TODO: add pj_kd for data to pass key(string) and value(data,len) instead of pj_ks which null terminates
	char *str = rz_str_utf16_encode(block, len); // XXX just block + len should be fine, pj takes care of this
	pj_raw(pj, "\"");
	pj_raw(pj, str);
	free(str);
	pj_raw(pj, "\"");
	pj_kn(pj, "offset", core->offset);
	pj_ks(pj, "section", section_name);
	pj_ki(pj, "length", len);
	pj_ks(pj, "type", type);
	pj_end(pj);
	rz_cons_println(pj_string(pj));
	pj_free(pj);
}

static char *__op_refs(RzCore *core, RzAnalysisOp *op, int n) {
	RzStrBuf *sb = rz_strbuf_new("");
	if (n) {
		// RzList *list = rz_analysis_xrefs_get_from (core->analysis, op->addr);
		RzList *list = rz_analysis_xrefs_get(core->analysis, op->addr);
		RzAnalysisRef *ref;
		RzListIter *iter;
		rz_list_foreach (list, iter, ref) {
			rz_strbuf_appendf(sb, "0x%08" PFMT64x " ", ref->at);
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

static void rz_core_disasm_table(RzCore *core, int l, const char *input) {
	int i;
	RzTable *t = rz_core_table(core);
	char *arg = strchr(input, ' ');
	if (arg) {
		input = arg + 1;
	}
	rz_table_set_columnsf(t, "snssssss", "name", "addr", "bytes", "disasm", "comment", "esil", "refs", "xrefs");
	const int minopsz = 1;
	const int options = RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT | RZ_ANALYSIS_OP_MASK_DISASM | RZ_ANALYSIS_OP_MASK_ESIL;
	ut64 ea = core->offset;
	for (i = 0; i < l; i++) {
		RzAnalysisOp *op = rz_core_analysis_op(core, ea, options);
		if (!op || op->size < 1) {
			i += minopsz;
			ea += minopsz;
			continue;
		}
		const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, ea);
		// TODO parse/filter op->mnemonic for better disasm
		ut8 *bytes = malloc(op->size);
		if (!bytes) {
			break;
		}
		rz_io_read_at(core->io, ea, bytes, op->size); // XXX ranalop should contain the bytes like rasmop do
		char *sbytes = rz_hex_bin2strdup(bytes, op->size);
		RzFlagItem *fi = rz_flag_get_i(core->flags, ea);
		char *fn = fi ? fi->name : "";
		const char *esil = RZ_STRBUF_SAFEGET(&op->esil);
		char *refs = __op_refs(core, op, 0);
		char *xrefs = __op_refs(core, op, 1);
		rz_table_add_rowf(t, "sXssssss", fn, ea, sbytes, op->mnemonic, comment ? comment : "", esil, refs, xrefs);
		free(sbytes);
		free(bytes);
		free(xrefs);
		free(refs);
		ea += op->size;
		rz_analysis_op_free(op);
	}
	if (input && *input) {
		rz_table_query(t, input);
	}
	char *ts = rz_table_tostring(t);
	rz_cons_printf("%s", ts); // \n?
	free(ts);
	rz_table_free(t);
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
				rz_cons_printf("f pxr.%" PFMT64x "=0x%" PFMT64x "\n", val, addr);
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

RZ_IPI int rz_cmd_print(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	st64 l;
	int i, len, ret;
	ut8 *block;
	ut32 tbs = core->blocksize;
	ut64 n, off, from, to;
	ut64 tmpseek = UT64_MAX;
	const size_t addrbytes = core->io->addrbytes;
	ret = 0;
	to = 0;
	PJ *pj = NULL;

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
	case 'w': // "pw"
		if (input[1] == 'n') {
			cmd_print_pwn(core);
		} else if (input[1] == 'd') {
			char *cwd = rz_sys_getdir();
			if (cwd) {
				rz_cons_println(cwd);
				free(cwd);
			}
		} else {
			rz_cons_printf("| pwd               display current working directory\n");
		}
		break;
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
	case 'h': // "ph"
		cmd_print_ph(core, input + 1);
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
	case 'a': // "pa"
	{
		const char *arg = NULL;
		if (input[1] != '\0') {
			arg = rz_str_trim_head_ro(input + 2);
		}
		if (input[1] == 'e') { // "pae"
			if (input[2] == '?') {
				rz_cons_printf("|Usage: pae [asm]       print ESIL expression of the given assembly expression\n");
			} else {
				int printed = 0;
				int bufsz;
				RzAnalysisOp aop = { 0 };
				rz_asm_set_pc(core->rasm, core->offset);
				RzAsmCode *acode = rz_asm_massemble(core->rasm, input + 2);
				if (acode) {
					bufsz = acode->len;
					while (printed < bufsz) {
						aop.size = 0;
						if (rz_analysis_op(core->analysis, &aop, core->offset,
							    (const ut8 *)acode->bytes + printed, bufsz - printed, RZ_ANALYSIS_OP_MASK_ESIL) > 0) {
							const char *str = RZ_STRBUF_SAFEGET(&aop.esil);
							rz_cons_println(str);
						} else {
							eprintf("Cannot decode instruction\n");
							break;
						}
						if (aop.size < 1) {
							eprintf("Cannot decode instruction\n");
							break;
						}
						printed += aop.size;
						rz_analysis_op_fini(&aop);
					}
				}
			}
		} else if (input[1] == 'D') { // "paD"
			if (input[2] == '?') {
				rz_cons_printf("|Usage: paD [hex]       print assembly expression from hexpairs and show hexpairs\n");
			} else {
				rz_core_cmdf(core, "pdi@x:%s", input + 2);
			}
		} else if (input[1] == 'd') { // "pad*"
			switch (input[2]) {
			case 'e': // "pade"
				if (input[3] == '?') {
					rz_cons_printf("|Usage: pade [hex]       print ESIL expression from hexpairs\n");
				} else {
					int printed = 0;
					int bufsz;
					RzAnalysisOp aop = { 0 };
					char *hex_arg = calloc(1, strlen(arg) + 1);
					if (hex_arg) {
						bufsz = rz_hex_str2bin(arg + 1, (ut8 *)hex_arg);
						while (printed < bufsz) {
							aop.size = 0;
							if (rz_analysis_op(core->analysis, &aop, core->offset,
								    (const ut8 *)hex_arg + printed, bufsz - printed, RZ_ANALYSIS_OP_MASK_ESIL) > 0) {
								const char *str = RZ_STRBUF_SAFEGET(&aop.esil);
								rz_cons_println(str);
							} else {
								eprintf("Cannot decode instruction\n");
								break;
							}
							if (aop.size < 1) {
								eprintf("Cannot decode instruction\n");
								break;
							}
							printed += aop.size;
							rz_analysis_op_fini(&aop);
						}
						free(hex_arg);
					}
				}
				break;
			case ' ': // "pad"
				__cmd_pad(core, arg);
				break;
			case '?': // "pad?"
				rz_cons_printf("|Usage: pad [hex]       print assembly expression from hexpairs\n");
				break;
			default:
				rz_cons_printf("|Usage: pa[edD] [asm|hex]  print (dis)assembled\n");
				break;
			}
		} else if (input[1] == '?') {
			rz_core_cmd_help(core, help_msg_pa);
		} else {
			int i;
			int bytes;
			rz_asm_set_pc(core->rasm, core->offset);
			RzAsmCode *acode = rz_asm_massemble(core->rasm, input + 1);
			if (acode) {
				bytes = acode->len;
				for (i = 0; i < bytes; i++) {
					ut8 b = acode->bytes[i]; // core->print->big_endian? (bytes - 1 - i): i ];
					rz_cons_printf("%02x", b);
				}
				rz_cons_newline();
				rz_asm_code_free(acode);
			}
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
						//buf[buf_len - 1] = 0;
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
		case 'j': // "pIj" is the same as pDj
			if (l != 0) {
				if (input[2]) {
					cmd_pDj(core, input + 2);
				} else {
					cmd_pDj(core, sdb_fmt("%d", core->blocksize));
				}
			}
			break;
		case 'f': // "pIf"
		{
			const RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset,
				RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
			if (f) {
				rz_core_print_disasm_instructions(core,
					rz_analysis_function_linear_size((RzAnalysisFunction *)f), 0);
				break;
			}
		}
		case 'd': // "pId" is the same as pDi
			if (l) {
				rz_core_disasm_pdi(core, 0, l, 0);
			}
			break;
		case '?': // "pi?"
			rz_cons_printf("|Usage: p[iI][df] [len]   print N instructions/bytes"
				       "(f=func) (see pi? and pdi)\n");
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
		case 'x': // "pix"
			__cmd_pad(core, rz_str_trim_head_ro(input + 2));
			break;
		case 'a': // "pia" is like "pda", but with "pi" output
			if (l != 0) {
				rz_core_print_disasm_all(core, core->offset,
					l, len, 'i');
			}
			break;
		case 'j': // pij is the same as pdj
			if (l != 0) {
				cmd_pdj(core, input + 2, block);
			}
			break;
		case 'd': // "pid" is the same as pdi
			if (l != 0) {
				rz_core_disasm_pdi(core, l, 0, 0);
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
				RzAnalysisRef *refi;
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
					rz_list_foreach (refs, iter, refi) {
						if (pj) {
							RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, refi->addr,
								RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
							char *dst = rz_str_newf((f ? f->name : "0x%08" PFMT64x), refi->addr);
							char *dst2 = NULL;
							RzAnalysisOp *op = rz_core_analysis_op(core, refi->addr, RZ_ANALYSIS_OP_MASK_BASIC);
							RzBinReloc *rel = rz_core_getreloc(core, refi->addr, op->size);
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
							pj_kn(pj, "addr", refi->addr);
							pj_kn(pj, "at", refi->at);
							pj_end(pj);
							rz_analysis_op_free(op);
						} else {
							char *s = rz_core_cmd_strf(core, "pdi %i @ 0x%08" PFMT64x, 1, refi->at);
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
	case 'D': // "pD"
	case 'd': // "pd"
	{
		ut64 use_blocksize = core->blocksize;
		ut8 bw_disassemble = false;
		ut32 pd_result = false, processed_cmd = false;
		bool formatted_json = false;
		if (input[1] && input[2]) {
			// "pd--" // context disasm
			if (!strncmp(input + 1, "--", 2)) {
				char *offs = rz_str_newf("%s", input + 2);
				if (offs) {
					ut64 sz = rz_num_math(core->num, offs);
					char *fmt;
					if (((st64)sz * -1) > core->offset) {
						// the offset is smaller than the negative value
						// so only print -offset
						fmt = rz_str_newf("d %" PFMT64d, -1 * core->offset);
					} else {
						fmt = rz_str_newf("d %s", input + 2);
					}
					if (fmt) {
						rz_cmd_print(core, fmt);
						strcpy(fmt + 2, input + 3);
						rz_cmd_print(core, fmt);
						free(fmt);
					}
					free(offs);
				}
				ret = 0;
				goto beach;
			}
		}

		if (input[1] == 'x') { // pdx
			__cmd_pad(core, rz_str_trim_head_ro(input + 2));
			return 0;
		}

		const char *sp = NULL;
		if (input[1] == '.') {
			sp = input + 2;
		} else {
			sp = strchr(input + 1, ' ');
		}
		if (!sp && (input[1] == '-' || IS_DIGIT(input[1]))) {
			sp = input + 1;
		}
		if (sp) {
			int n = (int)rz_num_math(core->num, rz_str_trim_head_ro(sp));
			if (!n) {
				goto beach;
			}
			use_blocksize = n;
		}

		if (core->blocksize_max < use_blocksize && (int)use_blocksize < -core->blocksize_max) {
			eprintf("This block size is too big (%" PFMT64u "<%" PFMT64u "). Did you mean 'p%c @ 0x%08" PFMT64x "' instead?\n",
				(ut64)core->blocksize_max, (ut64)use_blocksize, input[0], (ut64)use_blocksize);
			goto beach;
		} else if (core->blocksize_max < use_blocksize && (int)use_blocksize > -(int)core->blocksize_max) {
			bw_disassemble = true;
			l = use_blocksize; // negative
			use_blocksize = -use_blocksize;
		} else {
			l = use_blocksize;
		}
		// may be unnecessary, fixes 'pd 1;pdj 100;pd 1' bug
		rz_core_block_read(core);

		switch (input[1]) {
		case 'C': // "pdC"
			rz_core_disasm_pdi(core, l, 0, 'C');
			pd_result = 0;
			processed_cmd = true;
			break;
		case 't': // "pdt"
			rz_core_disasm_table(core, l, rz_str_trim_head_ro(input + 2));
			pd_result = 0;
			processed_cmd = true;
			break;
		case 'k': // "pdk" -print class
		{
			int len = 0;
			ut64 at = findClassBounds(core, rz_str_trim_head_ro(input + 2), &len);
			return rz_core_cmdf(core, "pD %d @ %" PFMT64u, len, at);
		}
		case 'i': // "pdi" // "pDi"
			processed_cmd = true;
			if (*input == 'D') {
				rz_core_disasm_pdi(core, 0, l, 0);
			} else {
				rz_core_disasm_pdi(core, l, 0, 0);
			}
			pd_result = 0;
			break;
		case 'a': // "pda"
			processed_cmd = true;
			if (input[2] == '?') {
				rz_core_cmd_help(core, help_msg_pda);
				break;
			}
			rz_core_print_disasm_all(core, core->offset, l, len, input[2]);
			pd_result = true;
			break;
		case 'e': // "pde"
			processed_cmd = true;
			if (!core->fixedblock && !sp) {
				l /= 4;
			}
			int mode = RZ_MODE_PRINT;
			if (input[2] == 'j') {
				mode = RZ_MODE_JSON;
			} else if (input[2] == 'q') {
				if (input[3] == 'q') {
					mode = RZ_MODE_SIMPLEST; // Like pi
				} else {
					mode = RZ_MODE_SIMPLE; // Like pdi
				}
			}
			rz_core_disasm_pde(core, l, mode);
			pd_result = true;
			break;
		case 'R': // "pdR"
			processed_cmd = true;
			if (input[2] == 'j') {
				disasm_recursive(core, core->offset, use_blocksize, 'j');
			} else {
				disasm_recursive(core, core->offset, use_blocksize, 'D');
			}
			pd_result = true;
			break;
		case 'r': // "pdr"
			processed_cmd = true;
			{
				RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
				// RZ_ANALYSIS_FCN_TYPE_FCN|RZ_ANALYSIS_FCN_TYPE_SYM);
				if (f) {
					func_walk_blocks(core, f, input[2], 'D', input[2] == '.');
				} else {
					eprintf("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
				}
				pd_result = true;
			}
			break;
		case 'b': // "pdb"
			processed_cmd = true;
			if (input[2] == '?') {
				rz_cons_printf("Usage: pdb[j]  - disassemble basic block\n");
			} else {
				RzAnalysisBlock *b = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
				if (b) {
					ut8 *block = malloc(b->size + 1);
					if (block) {
						rz_io_read_at(core->io, b->addr, block, b->size);

						if (input[2] == 'j') {
							pj = pj_new();
							if (!pj) {
								break;
							}
							pj_a(pj);
							rz_core_print_disasm_json(core, b->addr, block, b->size, 0, pj);
							pj_end(pj);
							rz_cons_printf("%s\n", pj_string(pj));
							pj_free(pj);
						} else {
							core->num->value = rz_core_print_disasm(
								core->print, core, b->addr, block,
								b->size, 9999, 0, 2, input[2] == 'J', NULL, NULL);
						}
						free(block);
						pd_result = 0;
					}
				} else {
					eprintf("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
					core->num->value = 0;
				}
			}
			break;
		case 's': // "pds" and "pdsf"
			processed_cmd = true;
			if (input[2] == '?') {
				rz_core_cmd_help(core, help_msg_pds);
			} else {
				disasm_strings(core, input, NULL);
			}
			break;
		case 'f': // "pdf"
			processed_cmd = true;
			if (input[2] == '?') {
				rz_core_cmd_help(core, help_msg_pdf);
			} else if (input[2] == 's') { // "pdfs"
				ut64 oseek = core->offset;
				int oblock = core->blocksize;
				RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset,
					RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
				if (f) {
					ut32 rs = rz_analysis_function_realsize(f);
					ut32 fs = rz_analysis_function_linear_size(f);
					rz_core_seek(core, oseek, SEEK_SET);
					rz_core_block_size(core, RZ_MAX(rs, fs));
					disasm_strings(core, input, f);
					rz_core_block_size(core, oblock);
					rz_core_seek(core, oseek, SEEK_SET);
				}
				processed_cmd = true;
			} else {
				ut32 bsz = core->blocksize;
				RzAnalysisFunction *f = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_ROOT);
				if (!f) {
					f = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
				}
				RzListIter *locs_it = NULL;
				if (f && input[2] == 'j') { // "pdfj"
					RzAnalysisBlock *b;
					ut32 fcn_size = rz_analysis_function_realsize(f);
					const char *orig_bb_middle = rz_config_get(core->config, "asm.bb.middle");
					rz_config_set_i(core->config, "asm.bb.middle", false);
					pj = pj_new();
					if (!pj) {
						break;
					}
					pj_o(pj);
					pj_ks(pj, "name", f->name);
					pj_kn(pj, "size", fcn_size);
					pj_kn(pj, "addr", f->addr);
					pj_k(pj, "ops");
					pj_a(pj);
					rz_list_sort(f->bbs, bb_cmpaddr);
					rz_list_foreach (f->bbs, locs_it, b) {

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
					pj_end(pj);
					rz_cons_printf("%s\n", pj_string(pj));
					pj_free(pj);
					pd_result = 0;
					rz_config_set(core->config, "asm.bb.middle", orig_bb_middle);
				} else if (f) {
					ut64 linearsz = rz_analysis_function_linear_size(f);
					ut64 realsz = rz_analysis_function_realsize(f);
					if (realsz + 4096 < linearsz) {
						eprintf("Linear size differs too much from the bbsum, please use pdr instead.\n");
					} else {
						ut64 start = f->addr; // For pdf, start disassembling at the entrypoint
						ut64 end = rz_analysis_function_max_addr(f);
						if (end > start) {
							ut64 sz = end - start;
							ut8 *buf = calloc(sz, 1);
							if (buf) {
								(void)rz_io_read_at(core->io, start, buf, sz);
								core->num->value = rz_core_print_disasm(core->print, core, start, buf, sz, sz, 0, 1, 0, NULL, f);
								free(buf);
							}
						}
					}
					pd_result = 0;
				} else {
					eprintf("pdf: Cannot find function at 0x%08" PFMT64x "\n", core->offset);
					processed_cmd = true;
					core->num->value = 0;
				}
				if (bsz != core->blocksize) {
					rz_core_block_size(core, bsz);
				}
			}
			l = 0;
			break;
		case 'p': // "pdp"
			processed_cmd = true;
			disasm_ropchain(core, core->offset, 'D');
			pd_result = true;
			break;
		case 'l': // "pdl"
			processed_cmd = true;
			{
				RzAsmOp asmop;
				int j, ret;
				if (!l) {
					l = len;
				}
				rz_cons_break_push(NULL, NULL);
				for (i = j = 0; i < core->blocksize && j < l; i += ret, j++) {
					ret = rz_asm_disassemble(core->rasm, &asmop, block + i, len - i);
					if (rz_cons_is_breaked()) {
						break;
					}
					rz_cons_printf("%d\n", ret);
					if (ret < 1) {
						ret = 1;
					}
				}
				rz_cons_break_pop();
				pd_result = 0;
			}
			break;
		case 'j': // pdj
			processed_cmd = true;
			if (*input == 'D') {
				cmd_pDj(core, input + 2);
			} else {
				cmd_pdj(core, input + 2, block);
			}
			pd_result = 0;
			break;
		case 'J': // pdJ
			formatted_json = true;
			break;
		case 0: // "pd"
			/* "pd" -> will disassemble blocksize/4 instructions */
			if (!core->fixedblock && *input == 'd') {
				l /= 4;
			}
			break;
		case '?': // "pd?"
			processed_cmd = true;
			rz_core_cmd_help(core, help_msg_pd);
			pd_result = 0;
		}
		if (formatted_json) {
			if (rz_cons_singleton()->is_html) {
				rz_cons_singleton()->is_html = false;
				rz_cons_singleton()->was_html = true;
			}
		}
		if (!processed_cmd) {
			ut64 addr = core->offset;
			ut8 *block1 = NULL;
			ut64 start;

			if (bw_disassemble) {
				block1 = malloc(core->blocksize);
				if (l < 0) {
					l = -l;
				}
				if (block1) {
					if (*input == 'D') { // pD
						free(block1);
						if (!(block1 = malloc(l))) {
							break;
						}
						rz_io_read_at(core->io, addr - l, block1, l); // core->blocksize);
						core->num->value = rz_core_print_disasm(core->print, core, addr - l, block1, l, l, 0, 1, formatted_json, NULL, NULL);
					} else { // pd
						int instr_len;
						if (!rz_core_prevop_addr(core, core->offset, l, &start)) {
							start = rz_core_prevop_addr_force(core, core->offset, l);
						}
						instr_len = core->offset - start;
						ut64 prevaddr = core->offset;
						int bs = core->blocksize, bs1 = addrbytes * instr_len;
						if (bs1 > bs) {
							ut8 *tmpblock = realloc(block1, bs1);
							if (!tmpblock) {
								eprintf("Memory reallocation failed.\n");
								free(block1);
								break;
							}
							block1 = tmpblock;
						}
						rz_core_seek(core, prevaddr - instr_len, true);
						memcpy(block1, block, bs);
						if (bs1 > bs) {
							rz_io_read_at(core->io, addr + bs / addrbytes,
								block1 + (bs - bs % addrbytes),
								bs1 - (bs - bs % addrbytes));
						}
						core->num->value = rz_core_print_disasm(core->print,
							core, core->offset, block1, RZ_MAX(bs, bs1), l, 0, 1, formatted_json, NULL, NULL);
						rz_core_seek(core, prevaddr, true);
					}
				}
			} else {
				// XXX: issue with small blocks
				if (*input == 'D' && use_blocksize > 0) {
					l = use_blocksize;
					if (l > RZ_CORE_MAX_DISASM) { // pD
						eprintf("Block size too big\n");
						return 1;
					}
					block1 = malloc(addrbytes * l);
					if (block1) {
						rz_io_read_at(core->io, addr, block1, addrbytes * l);
						core->num->value = rz_core_print_disasm(core->print,
							core, addr, block1, addrbytes * l, l, 0, 1, formatted_json, NULL, NULL);
					} else {
						eprintf("Cannot allocate %" PFMT64d " byte(s)\n", addrbytes * l);
					}
				} else {
					ut8 *buf = core->block;
					const int buf_size = core->blocksize;
					if (buf) {
						if (!l) {
							l = use_blocksize;
							if (!core->fixedblock) {
								l /= 4;
							}
						}
						core->num->value = rz_core_print_disasm(core->print,
							core, addr, buf, buf_size, l,
							0, 0, formatted_json, NULL, NULL);
					}
				}
			}
			free(block1);
			if (formatted_json) {
				rz_cons_newline();
			}
		}
		if (processed_cmd) {
			ret = pd_result;
			goto beach;
		}
	} break;
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
				print_json_string(core, (const char *)core->block, len, NULL);
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
				rz_print_string(core->print, core->offset, block, len, RZ_PRINT_STRING_ESC_NL);
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
						print_json_string(core, (const char *)s, j, NULL);
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
						print_json_string(core, (const char *)core->block + 1, mylen, NULL);
					} else {
						rz_print_string(core->print, core->offset,
							core->block + 1, mylen, RZ_PRINT_STRING_ZEROEND);
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
					print_json_string(core, (const char *)core->block, len, "wide");
				} else {
					rz_print_string(core->print, core->offset, core->block, len,
						RZ_PRINT_STRING_WIDE | RZ_PRINT_STRING_ZEROEND);
				}
			}
			break;
		case 'W': // "psW"
			if (l > 0) {
				if (input[2] == 'j') { // psWj
					print_json_string(core, (const char *)core->block, len, "wide32");
				} else {
					rz_print_string(core->print, core->offset, core->block, len,
						RZ_PRINT_STRING_WIDE32 | RZ_PRINT_STRING_ZEROEND);
				}
			}
			break;
		case ' ': // "ps"
			rz_print_string(core->print, core->offset, core->block, l, 0);
			break;
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
					print_json_string(core, (const char *)core->block, len, "utf16");
				} else {
					char *str = rz_str_utf16_encode((const char *)core->block, len);
					rz_cons_println(str);
					free(str);
				}
			}
			break;
		case 'q': // "psq"
			rz_core_cmd0(core, "pqs");
			break;
		case 's': // "pss"
			if (l > 0) {
				int h, w = rz_cons_get_size(&h);
				int colwidth = rz_config_get_i(core->config, "hex.cols") * 2;
				core->print->width = (colwidth == 32) ? w : colwidth; // w;
				int bs = core->blocksize;
				if (len == bs) {
					len = (h * w) / 3;
					rz_core_block_size(core, len);
				}
				rz_print_string(core->print, core->offset, core->block,
					len, RZ_PRINT_STRING_WRAP);
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
					print_json_string(core, (const char *)core->block + 1, len, NULL);
				} else {
					rz_print_string(core->print, core->offset, core->block + 1,
						len, RZ_PRINT_STRING_ZEROEND);
				}
			}
			break;
		default:
			if (l > 0) {
				rz_print_string(core->print, core->offset, core->block,
					len, RZ_PRINT_STRING_ZEROEND);
			}
			break;
		}
		break;
	case 'm': // "pm"
		if (input[1] == '?') {
			rz_cons_printf("|Usage: pm [file|directory]\n"
				       "| rz_magic will use given file/dir as reference\n"
				       "| output of those magic can contain expressions like:\n"
				       "|   foo@0x40   # use 'foo' magic file on address 0x40\n"
				       "|   @0x40      # use current magic file on address 0x40\n"
				       "|   \\n         # append newline\n"
				       "| e dir.magic  # defaults to " RZ_JOIN_2_PATHS("{RZ_PREFIX}", RZ_SDB_MAGIC) "\n"
														    "| /m           # search for magic signatures\n");
		} else if (input[1] == 'j') { // "pmj"
			const char *filename = rz_str_trim_head_ro(input + 2);
			PJ *pj = rz_core_pj_new(core);
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
			rz_cons_printf("|Usage: pu[w] [len]       print N url"
				       "encoded bytes (w=wide)\n");
		} else {
			if (l > 0) {
				rz_print_string(core->print, core->offset, core->block, len,
					RZ_PRINT_STRING_URLENCODE |
						((input[1] == 'w') ? RZ_PRINT_STRING_WIDE : 0));
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
				rz_print_code(core->print, core->offset, core->block, len, input[1]);
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
			if (input[2] == '?') {
				rz_cons_printf("prc=e # colorblocks of entropy\n");
				rz_core_cmd0(core, "pz?");
			} else if (input[2] == '=') {
				if (input[3] == '?') {
					rz_core_cmd_help(core, help_msg_p_equal);
				} else {
					cmd_prc_zoom(core, input + 2);
				}
			} else {
				cmd_prc(core, block, len);
			}
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
		case 'j': // "pxj"
			rz_print_jsondump(core->print, core->block, core->blocksize, 8);
			break;
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
		case 'o': // "pxo"
			if (l != 0) {
				rz_print_hexdump(core->print, core->offset,
					core->block, len, 8, 1, 1);
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
		case 'd': // "pxd"
			if (input[2] == '?') {
				rz_core_cmd_help(core, help_msg_pxd);
			} else if (l != 0) {
				switch (input[2]) {
				case '1':
					// 1 byte signed words (byte)
					if (input[3] == 'j') {
						rz_print_jsondump(core->print, core->block,
							len, 8);
					} else {
						rz_print_hexdump(core->print, core->offset,
							core->block, len, -1, 4, 1);
					}
					break;
				case '2':
					// 2 byte signed words (short)
					if (input[3] == 'j') {
						rz_print_jsondump(core->print, core->block,
							len, 16);
					} else {
						rz_print_hexdump(core->print, core->offset,
							core->block, len, -10, 2, 1);
					}
					break;
				case '8':
					if (input[3] == 'j') {
						rz_print_jsondump(core->print, core->block,
							len, 64);
					} else {
						rz_print_hexdump(core->print, core->offset,
							core->block, len, -8, 4, 1);
					}
					break;
				case '4':
				case ' ':
				case 'j':
				case 0:
					// 4 byte signed words
					if (input[2] == 'j' || (input[2] && input[3] == 'j')) {
						rz_print_jsondump(core->print, core->block,
							len, 32);
					} else {
						rz_print_hexdump(core->print, core->offset,
							core->block, len, 10, 4, 1);
					}
					break;
				default:
					rz_core_cmd_help(core, help_msg_pxd);
					break;
				}
			}
			break;
		case 'w': // "pxw"
			if (l != 0) {
				if (input[2] == 'j') {
					rz_print_jsondump(core->print, core->block, len, 32);
				} else {
					rz_print_hexdump(core->print, core->offset, core->block, len, 32, 4, 1);
				}
			}
			break;
		case 'W': // "pxW"
			if (l) {
				bool printOffset = (input[2] != 'q' && rz_config_get_i(core->config, "hex.offset"));
				len = len - (len % 4);
				for (i = 0; i < len; i += 4) {
					const char *a, *b;
					char *fn;
					RzPrint *p = core->print;
					RzFlagItem *f;
					ut32 v = rz_read_ble32(core->block + i, core->print->big_endian);
					if (p && p->colorfor) {
						a = p->colorfor(p->user, v, true);
						if (a && *a) {
							b = Color_RESET;
						} else {
							a = b = "";
						}
					} else {
						a = b = "";
					}
					f = rz_flag_get_at(core->flags, v, true);
					fn = NULL;
					if (f) {
						st64 delta = (v - f->offset);
						if (delta >= 0 && delta < 8192) {
							if (v == f->offset) {
								fn = strdup(f->name);
							} else {
								fn = rz_str_newf("%s+%" PFMT64d,
									f->name, v - f->offset);
							}
						}
					}
					if (printOffset) {
						rz_print_section(core->print, core->offset + i);
						rz_cons_printf("0x%08" PFMT64x " %s0x%08" PFMT64x "%s%s%s\n",
							(ut64)core->offset + i, a, (ut64)v,
							b, fn ? " " : "", fn ? fn : "");
					} else {
						rz_cons_printf("%s0x%08" PFMT64x "%s\n", a, (ut64)v, b);
					}
					free(fn);
				}
			}
			break;
		case 'r': // "pxr"
			if (l) {
				int mode = input[2];
				int wordsize = core->analysis->bits / 8;
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
		case 'h': // "pxh"
			if (l) {
				if (input[2] == 'j') {
					rz_print_jsondump(core->print, core->block, len, 16);
				} else {
					rz_print_hexdump(core->print, core->offset,
						core->block, len, 32, 2, 1);
				}
			}
			break;
		case 'H': // "pxH"
			if (l != 0) {
				len = len - (len % 2);
				for (i = 0; i < len; i += 2) {
					const char *a, *b;
					char *fn;
					RzPrint *p = core->print;
					RzFlagItem *f;
					ut64 v = (ut64)rz_read_ble16(core->block + i, p->big_endian);
					if (p && p->colorfor) {
						a = p->colorfor(p->user, v, true);
						if (a && *a) {
							b = Color_RESET;
						} else {
							a = b = "";
						}
					} else {
						a = b = "";
					}
					f = rz_flag_get_at(core->flags, v, true);
					fn = NULL;
					if (f) {
						st64 delta = (v - f->offset);
						if (delta >= 0 && delta < 8192) {
							if (v == f->offset) {
								fn = strdup(f->name);
							} else {
								fn = rz_str_newf("%s+%" PFMT64d, f->name, v - f->offset);
							}
						}
					}
					rz_cons_printf("0x%08" PFMT64x " %s0x%04" PFMT64x "%s %s\n",
						(ut64)core->offset + i, a, v, b, fn ? fn : "");
					free(fn);
				}
			}
			break;
		case 'q': // "pxq"
			if (l) {
				if (input[2] == 'j') {
					rz_print_jsondump(core->print, core->block, len, 64);
				} else {
					rz_print_hexdump(core->print, core->offset, core->block, len, 64, 8, 1);
				}
			}
			break;
		case 'Q': // "pxQ"
			// TODO. show if flag name, or inside function
			if (l) {
				bool printOffset = (input[2] != 'q' && rz_config_get_i(core->config, "hex.offset"));
				len = len - (len % 8);
				for (i = 0; i < len; i += 8) {
					const char *a, *b;
					char *fn;
					RzPrint *p = core->print;
					RzFlagItem *f;
					ut64 v = rz_read_ble64(core->block + i, p->big_endian);
					if (p && p->colorfor) {
						a = p->colorfor(p->user, v, true);
						if (a && *a) {
							b = Color_RESET;
						} else {
							a = b = "";
						}
					} else {
						a = b = "";
					}
					f = rz_flag_get_at(core->flags, v, true);
					fn = NULL;
					if (f) {
						st64 delta = (v - f->offset);
						if (delta >= 0 && delta < 8192) {
							if (v == f->offset) {
								fn = strdup(f->name);
							} else {
								fn = rz_str_newf("%s+%" PFMT64d, f->name, v - f->offset);
							}
						}
					}
					if (printOffset) {
						rz_print_section(core->print, core->offset + i);
						rz_cons_printf("0x%08" PFMT64x " %s0x%016" PFMT64x "%s %s\n",
							(ut64)core->offset + i, a, v, b, fn ? fn : "");
					} else {
						rz_cons_printf("%s0x%016" PFMT64x "%s\n", a, v, b);
					}
					free(fn);
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
		case 'l': // "pxl"
			len = core->print->cols * len;
			/* fallthrough */
		default:
			if (l) {
				ut64 from = rz_config_get_i(core->config, "diff.from");
				ut64 to = rz_config_get_i(core->config, "diff.to");
				if (from == to && !from) {
					const char *sp = NULL;
					if (input[1] == '.') {
						sp = input + 2;
					}
					if (IS_DIGIT(input[1])) {
						sp = input + 1;
					}
					if (sp) {
						int n = (int)rz_num_math(core->num, rz_str_trim_head_ro(sp));
						if (!n) {
							goto beach;
						}
						len = n;
					}
					if (!rz_core_block_size(core, len)) {
						len = core->blocksize;
					}
					rz_core_block_read(core);
					rz_print_hexdump(core->print, rz_core_pava(core, core->offset),
						core->block, len, 16, 1, 1);
				} else {
					rz_core_print_cmp(core, from, to);
				}
				core->num->value = len;
			}
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
				rz_print_2bpp_tiles(core->print, core->block, len / 16);
			}
		}
		break;
	case '6': // "p6"
		if (l) {
			int malen = (core->blocksize * 4) + 1;
			ut8 *buf = malloc(malen);
			if (!buf) {
				break;
			}
			memset(buf, 0, malen);
			switch (input[1]) {
			case 'd': // "p6d"
				if (rz_base64_decode(buf, (const char *)block, len)) {
					rz_cons_println((const char *)buf);
				} else {
					eprintf("rz_base64_decode: invalid stream\n");
				}
				break;
			case 'e': // "p6e"
				len = len > core->blocksize ? core->blocksize : len;
				rz_base64_encode((char *)buf, block, len);
				rz_cons_println((const char *)buf);
				break;
			case '?':
			default:
				rz_core_cmd_help(core, help_msg_p6);
				break;
			}
			free(buf);
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
			RzList *pids = (core->dbg->h && core->dbg->h->pids)
				? core->dbg->h->pids(core->dbg, 0)
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
			char *s = rz_print_randomart(block, len, core->offset);
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
					s = rz_print_randomart(core->block, len, core->offset);
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
	case 'n': // easter
		eprintf("easter egg license has expired\n");
		break;
	case 't': // "pt"
		switch (input[1]) {
		case '.': {
			char nowstr[64] = { 0 };
			rz_print_date_get_now(core->print, nowstr);
			rz_cons_printf("%s\n", nowstr);
		} break;
		case ' ':
		case '\0':
			// len must be multiple of 4 since rz_mem_copyendian move data in fours - sizeof(ut32)
			if (len < sizeof(ut32)) {
				eprintf("You should change the block size: b %d\n", (int)sizeof(ut32));
			}
			if (len % sizeof(ut32)) {
				len = len - (len % sizeof(ut32));
			}
			for (l = 0; l < len; l += sizeof(ut32)) {
				rz_print_date_unix(core->print, block + l, sizeof(ut32));
			}
			break;
		case 'h': // "pth"
			// len must be multiple of 4 since rz_mem_copyendian move data in fours - sizeof(ut32)
			if (len < sizeof(ut32)) {
				eprintf("You should change the block size: b %d\n", (int)sizeof(ut32));
			}
			if (len % sizeof(ut32)) {
				len = len - (len % sizeof(ut32));
			}
			for (l = 0; l < len; l += sizeof(ut32)) {
				rz_print_date_hfs(core->print, block + l, sizeof(ut32));
			}
			break;
		case 'd': // "ptd"
			// len must be multiple of 4 since rz_print_date_dos read buf+3
			// if block size is 1 or 5 for example it reads beyond the buffer
			if (len < sizeof(ut32)) {
				eprintf("You should change the block size: b %d\n", (int)sizeof(ut32));
			}
			if (len % sizeof(ut32)) {
				len = len - (len % sizeof(ut32));
			}
			for (l = 0; l < len; l += sizeof(ut32)) {
				rz_print_date_dos(core->print, block + l, sizeof(ut32));
			}
			break;
		case 'n': // "ptn"
			if (len < sizeof(ut64)) {
				eprintf("You should change the block size: b %d\n", (int)sizeof(ut64));
			}
			if (len % sizeof(ut64)) {
				len = len - (len % sizeof(ut64));
			}
			for (l = 0; l < len; l += sizeof(ut64)) {
				rz_print_date_w32(core->print, block + l, sizeof(ut64));
			}
			break;
		case '?':
			rz_core_cmd_help(core, help_msg_pt);
			break;
		}
		break;
	case 'q': // "pq"
		switch (input[1]) {
		case '?':
			eprintf("Usage: pq[s] [len]\n");
			len = 0;
			break;
		case 's': // "pqs"
		case 'z': // for backward compat
			len = rz_str_nlen((const char *)block, core->blocksize);
			break;
		default:
			if (len < 1) {
				len = 0;
			}
			if (len > core->blocksize) {
				len = core->blocksize;
			}
			break;
		}
		if (len > 0) {
			bool inverted = (input[1] == 'i'); // pqi -- inverted colors
			char *res = rz_qrcode_gen(block, len, rz_config_get_i(core->config, "scr.utf8"), inverted);
			if (res) {
				rz_cons_printf("%s\n", res);
				free(res);
			}
		}
		break;
	case 'z': // "pz"
		if (input[1] == '?') {
			rz_core_cmd_help(core, help_msg_pz);
		} else {
			RzIOMap *map;
			RzListIter *iter;
			RzList *list = rz_core_get_boundaries_prot(core, -1, NULL, "zoom");
			if (list && rz_list_length(list) > 0) {
				RzListIter *iter1 = list->head;
				RzIOMap *map1 = iter1->data;
				from = map1->itv.addr;
				rz_list_foreach (list, iter, map) {
					to = rz_itv_end(map->itv);
				}
			} else {
				from = core->offset;
				to = from + core->blocksize;
			}
			ut64 maxsize = rz_config_get_i(core->config, "zoom.maxsz");
			int oldva = core->io->va;
			char *oldmode = NULL;
			bool do_zoom = true;

			core->io->va = 0;
			if (input[1] && input[1] != ' ') {
				oldmode = strdup(rz_config_get(core->config, "zoom.byte"));
				if (!rz_config_set(core->config, "zoom.byte", input + 1)) {
					do_zoom = false;
				}
			}
			if (do_zoom && l > 0) {
				rz_print_zoom(core->print, core, printzoomcallback,
					from, to, l, (int)maxsize);
			}
			if (oldmode) {
				rz_config_set(core->config, "zoom.byte", oldmode);
			}
			core->io->va = oldva;
			RZ_FREE(oldmode);
			rz_list_free(list);
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
