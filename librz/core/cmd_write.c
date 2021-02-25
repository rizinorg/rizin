// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_crypto.h"
#include "rz_config.h"
#include "rz_cons.h"
#include "rz_core.h"
#include "rz_io.h"

static const char *help_msg_w[] = {
	"Usage:", "w[x] [str] [<file] [<<EOF] [@addr]", "",
	"w", "[1248][+-][n]", "increment/decrement byte,word..",
	"w", " foobar", "write string 'foobar'",
	"w0", " [len]", "write 'len' bytes with value 0x00",
	"w6", "[de] base64/hex", "write base64 [d]ecoded or [e]ncoded string",
	"wa", "[?] push ebp", "write opcode, separated by ';' (use '\"' around the command)",
	"waf", " f.asm", "assemble file and write bytes",
	"waF", " f.asm", "assemble file and write bytes and show 'wx' op with hexpair bytes of assembled code",
	"wao", "[?] op", "modify opcode (change conditional of jump. nop, etc)",
	"wA", "[?] r 0", "alter/modify opcode at current seek (see wA?)",
	"wb", " 010203", "fill current block with cyclic hexpairs",
	"wB", "[-]0xVALUE", "set or unset bits with given value",
	"wc", "", "list all write changes",
	"wc", "[?][jir+-*?]", "write cache undo/commit/reset/list (io.cache)",
	"wd", " [off] [n]", "duplicate N bytes from offset at current seek (memcpy) (see y?)",
	"we", "[?] [nNsxX] [arg]", "extend write operations (insert instead of replace)",
	"wf", "[fs] -|file", "write contents of file at current offset",
	"wh", " rizin", "whereis/which shell command",
	"wm", " f0ff", "set binary mask hexpair to be used as cyclic write mask",
	"wo", "[?] hex", "write in block with operation. 'wo?' fmi",
	"wp", "[?] -|file", "apply rizin patch file. See wp? fmi",
	"wr", " 10", "write 10 random bytes",
	"ws", " pstring", "write 1 byte for length and then the string",
	"wt[f]", "[?] file [sz]", "write to file (from current seek, blocksize or sz bytes)",
	"wts", " host:port [sz]", "send data to remote host:port via tcp://",
	"ww", " foobar", "write wide string 'f\\x00o\\x00o\\x00b\\x00a\\x00r\\x00'",
	"wx", "[?][fs] 9090", "write two intel nops (from wxfile or wxseek)",
	"wv", "[?] eip+34", "write 32-64 bit value honoring cfg.bigendian",
	"wz", " string", "write zero terminated string (like w + \\x00)",
	NULL
};

static const char *help_msg_wa[] = {
	"Usage:", "wa[of*] [arg]", "",
	"wa", " nop", "write nopcode using asm.arch and asm.bits",
	"wai", " jmp 0x8080", "write inside this op (fill with nops or error if doesnt fit)",
	"wa*", " mov eax, 33", "show 'wx' op with hexpair bytes of assembled opcode",
	"\"wa nop;nop\"", "", "assemble more than one instruction (note the quotes)",
	"waf", " f.asm", "assemble file and write bytes",
	"waF", " f.asm", "assemble file and write bytes and show 'wx' op with hexpair bytes of assembled code",
	"waF*", " f.asm", "assemble file and show 'wx' op with hexpair bytes of assembled code",
	"wao?", "", "show help for assembler operation on current opcode (hack)",
	NULL
};

static const char *help_msg_wA[] = {
	"Usage:", " wA", "[type] [value]",
	"Types", "", "",
	"r", "", "raw write value",
	"v", "", "set value (taking care of current address)",
	"d", "", "destination register",
	"0", "", "1st src register",
	"1", "", "2nd src register",
	"Example:", "wA r 0", "# e800000000",
	NULL
};

static const char *help_msg_wc[] = {
	"Usage:", "wc[jir+-*?]", "  # NOTE: Uses io.cache=true",
	"wc", "", "list all write changes",
	"wcj", "", "list all write changes in JSON",
	"wc-", " [from] [to]", "remove write op at curseek or given addr",
	"wc+", " [from] [to]", "commit change from cache to io",
	"wc*", "", "\"\" in rizin commands",
	"wcr", "", "reset all write changes in cache",
	"wci", "", "commit write cache",
	"wcp", " [fd]", "list all cached write-operations on p-layer for specified fd or current fd",
	"wcp*", " [fd]", "list all cached write-operations on p-layer in rizin commands",
	"wcpi", " [fd]", "commit and invalidate pcache for specified fd or current fd",
	NULL
};

static const char *help_msg_we[] = {
	"Usage", "", "write extend # resize the file",
	"wen", " <num>", "extend the underlying file inserting NUM null bytes at current offset",
	"weN", " <addr> <len>", "extend current file and insert bytes at address",
	"wes", " <addr>  <dist> <block_size>", "shift a blocksize left or write in the editor",
	"wex", " <hex_bytes>", "insert bytes at current offset by extending the file",
	"weX", " <addr> <hex_bytes>", "insert bytes at address by extending the file",
	NULL
};

static const char *help_msg_wo[] = {
	"Usage:", "wo[asmdxoArl24]", " [hexpairs] @ addr[!bsize]",
	"wo[24aAdlmorwx]", "", "without hexpair values, clipboard is used",
	"wo2", " [val]", "2=  2 byte endian swap (word)",
	"wo4", " [val]", "4=  4 byte endian swap (dword)",
	"wo8", " [val]", "8=  8 byte endian swap (qword)",
	"woa", " [val]", "+=  addition (f.ex: woa 0102)",
	"woA", " [val]", "&=  and",
	"wod", " [val]", "/=  divide",
	"woD", "[algo] [key] [IV]", "decrypt current block with given algo and key",
	"woe", " [from to] [step] [wsz=1]", "..  create sequence",
	"woE", " [algo] [key] [IV]", "encrypt current block with given algo and key",
	"wol", " [val]", "<<= shift left",
	"wom", " [val]", "*=  multiply",
	"woo", " [val]", "|=  or",
	"wop[DO]", " [arg]", "De Bruijn Patterns",
	"wor", " [val]", ">>= shift right",
	"woR", "", "random bytes (alias for 'wr $b')",
	"wos", " [val]", "-=  substraction",
	"wow", " [val]", "==  write looped value (alias for 'wb')",
	"wox", " [val]", "^=  xor  (f.ex: wox 0x90)",
	NULL
};

static const char *help_msg_wop[] = {
	"Usage:", "wop[DO]", " len @ addr | value",
	"wopD", " len [@ addr]", "Write a De Bruijn Pattern of length 'len' at address 'addr'",
	"wopD*", " len [@ addr]", "Show wx command that creates a debruijn pattern of a specific length",
	"wopO", " value", "Finds the given value into a De Bruijn Pattern at current offset",
	NULL
};

static const char *help_msg_wt[] = {
	"Usage:", "wt[a] file [size]", " Write 'size' bytes in current block to 'file'",
	"wta", " [filename]", "append to 'filename'",
	"wtf", " [filename] [size]", "write to file (see also 'wxf' and 'wf?')",
	"wtf!", " [filename]", "write to file from current address to eof",
	"wtff", " [prefix]", "write block from current seek to [prefix]-[offset]",
	"wts", " host:port [sz]", "send data to remote host:port via tcp://",
	NULL
};

static const char *help_msg_wf[] = {
	"Usage:", "wf[fs] [-|args ..]", " Write from (file, swap, offset)",
	"wf", " 10 20", "write 20 bytes from offset 10 into current seek",
	"wff", " file [len]", "write contents of file into current offset",
	"wfs", " host:port [len]", "write from socket (tcp listen in port for N bytes)",
	"wfx", " 10 20", "exchange 20 bytes betweet current offset and 10",
	NULL
};

static const char *help_msg_wv[] = {
	"Usage:", "wv[size] [value]", " Write value of given size",
	"wv", " 0x834002", "write dword with this value",
	"wv1", " 234", "write one byte with this value",
	"Supported sizes are:", "1, 2, 4, 8", "",
	NULL
};

static const char *help_msg_wx[] = {
	"Usage:", "wx[f] [arg]", "",
	"wx", " 9090", "write two intel nops",
	"wxf", " -|file", "write contents of hexpairs file here",
	"wxs", " 9090", "write hexpairs and seek at the end",
	NULL
};

static void cmd_write_fail(RzCore *core) {
	eprintf("Failed to write\n");
	core->num->value = 1;
}

static bool encrypt_or_decrypt_block(RzCore *core, const char *algo, const char *key, int direction, const char *iv) {
	//TODO: generalise no_key_mode for all non key encoding/decoding.
	int keylen = 0;
	bool no_key_mode = !strcmp("base64", algo) || !strcmp("base91", algo) || !strcmp("punycode", algo);
	ut8 *binkey = NULL;
	if (!strncmp(key, "s:", 2)) {
		binkey = (ut8 *)strdup(key + 2);
		keylen = strlen(key + 2);
	} else {
		binkey = (ut8 *)strdup(key);
		keylen = rz_hex_str2bin(key, binkey);
	}
	if (!no_key_mode && keylen < 1) {
		eprintf("%s key not defined. Use -S [key]\n", ((!direction) ? "Encryption" : "Decryption"));
		free(binkey);
		return false;
	}
	RzCrypto *cry = rz_crypto_new();
	if (rz_crypto_use(cry, algo)) {
		if (!binkey) {
			eprintf("Cannot allocate %d byte(s)\n", keylen);
			rz_crypto_free(cry);
			return false;
		}
		if (rz_crypto_set_key(cry, binkey, keylen, 0, direction)) {
			if (iv) {
				ut8 *biniv = malloc(strlen(iv) + 1);
				int ivlen = rz_hex_str2bin(iv, biniv);
				if (ivlen < 1) {
					ivlen = strlen(iv);
					strcpy((char *)biniv, iv);
				}
				if (!rz_crypto_set_iv(cry, biniv, ivlen)) {
					eprintf("Invalid IV.\n");
					return 0;
				}
			}
			rz_crypto_update(cry, (const ut8 *)core->block, core->blocksize);
			rz_crypto_final(cry, NULL, 0);

			int result_size = 0;
			ut8 *result = rz_crypto_get_output(cry, &result_size);
			if (result) {
				if (!rz_core_write_at(core, core->offset, result, result_size)) {
					eprintf("rz_core_write_at failed at 0x%08" PFMT64x "\n", core->offset);
				}
				eprintf("Written %d byte(s)\n", result_size);
				free(result);
			}
		} else {
			eprintf("Invalid key\n");
		}
		free(binkey);
		rz_crypto_free(cry);
		return 0;
	} else {
		eprintf("Unknown %s algorithm '%s'\n", ((!direction) ? "encryption" : "decryption"), algo);
	}
	rz_crypto_free(cry);
	return 1;
}

static void cmd_write_bits(RzCore *core, int set, ut64 val) {
	ut64 ret, orig;
	// used to set/unset bit in current address
	rz_io_read_at(core->io, core->offset, (ut8 *)&orig, sizeof(orig));
	if (set) {
		ret = orig | val;
	} else {
		ret = orig & (~(val));
	}
	if (!rz_core_write_at(core, core->offset, (const ut8 *)&ret, sizeof(ret))) {
		cmd_write_fail(core);
	}
}

static void cmd_write_inc(RzCore *core, int size, st64 num) {
	ut64 *v64;
	ut32 *v32;
	ut16 *v16;
	ut8 *v8;
	switch (size) {
	case 1:
		v8 = (ut8 *)core->block;
		*v8 += num;
		break;
	case 2:
		v16 = (ut16 *)core->block;
		*v16 += num;
		break;
	case 4:
		v32 = (ut32 *)core->block;
		*v32 += num;
		break;
	case 8:
		v64 = (ut64 *)core->block;
		*v64 += num;
		break;
	}
	// TODO: obey endian here
	if (!rz_core_write_at(core, core->offset, core->block, size)) {
		cmd_write_fail(core);
	}
}

RZ_IPI int rz_wo_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	ut8 *buf;
	int len;
	int value;
	switch (input[0]) {
	case 'e':
		if (input[1] != ' ') {
			rz_cons_printf("Usage: 'woe from-to step'\n");
			return -1;
		}
		/* fallthru */
	case 'a':
	case 's':
	case 'A':
	case 'x':
	case 'r':
	case 'l':
	case 'm':
	case 'd':
	case 'o':
	case 'w':
	case '2': // "wo2"
	case '4': // "wo4"
	case '8': // "wo8"
		if (input[1]) { // parse val from arg
			rz_core_write_op(core, input + 2, input[0]);
		} else { // use clipboard instead of val
			rz_core_write_op(core, NULL, input[0]);
		}
		rz_core_block_read(core);
		break;
	case 'R':
		rz_core_cmd0(core, "wr $b");
		break;
	case 'n':
		rz_core_write_op(core, "ff", 'x');
		rz_core_block_read(core);
		break;
	case 'E': // "woE" encrypt
	case 'D': // "woD" decrypt
	{
		int direction = (input[0] == 'E') ? 0 : 1;
		const char *algo = NULL;
		const char *key = NULL;
		const char *iv = NULL;
		char *space, *args = strdup(rz_str_trim_head_ro(input + 1));
		space = strchr(args, ' ');
		if (space) {
			*space++ = 0;
			key = space;
			space = strchr(key, ' ');
			if (space) {
				*space++ = 0;
				iv = space;
			}
		}
		algo = args;
		if (algo && *algo && key) {
			encrypt_or_decrypt_block(core, algo, key, direction, iv);
		} else {
			eprintf("Usage: wo%c [algo] [key] [IV]\n", ((!direction) ? 'E' : 'D'));
			eprintf("Currently supported hashes:\n");
			ut64 bits;
			int i;
			for (i = 0;; i++) {
				bits = ((ut64)1) << i;
				const char *name = rz_hash_name(bits);
				if RZ_STR_ISEMPTY (name) {
					break;
				}
				printf("  %s\n", name);
			}
			eprintf("Available Encoders/Decoders: \n");
			for (i = 0;; i++) {
				bits = (1ULL) << i;
				const char *name = rz_crypto_codec_name((const RzCryptoSelector)bits);
				if (RZ_STR_ISEMPTY(name)) {
					break;
				}
				printf("  %s\n", name);
			}
			eprintf("Currently supported crypto algos:\n");
			for (i = 0;; i++) {
				bits = (1ULL) << i;
				const char *name = rz_crypto_name((const RzCryptoSelector)bits);
				if RZ_STR_ISEMPTY (name) {
					break;
				}
				printf("  %s\n", name);
			}
		}
		free(args);
	} break;
	case 'p': // debrujin patterns
		switch (input[1]) {
		case 'D': // "wopD"
		{
			char *sp = strchr(input, ' ');
			len = sp ? rz_num_math(core->num, sp + 1) : core->blocksize;
		}
			if (len > 0) {
				/* XXX This seems to fail at generating long patterns (wopD 512K) */
				buf = (ut8 *)rz_debruijn_pattern(len, 0, NULL); //debruijn_charset);
				if (buf) {
					const ut8 *ptr = buf;
					ut64 addr = core->offset;
					if (input[2] == '*') {
						int i;
						rz_cons_printf("wx ");
						for (i = 0; i < len; i++) {
							rz_cons_printf("%02x", buf[i]);
						}
						rz_cons_newline();
					} else {
						if (!rz_core_write_at(core, addr, ptr, len)) {
							cmd_write_fail(core);
						}
					}
					free(buf);
				} else {
					eprintf("Couldn't generate pattern of length %d\n", len);
				}
			}
			break;
		case 'O': // "wopO"
			if (strlen(input) > 3 && strncmp(input + 3, "0x", 2)) {
				eprintf("Need hex value with `0x' prefix e.g. 0x41414142\n");
			} else if (input[2] == ' ') {
				value = rz_num_get(core->num, input + 3);
				core->num->value = rz_debruijn_offset(value, rz_config_get_i(core->config, "cfg.bigendian"));
				rz_cons_printf("%" PFMT64d "\n", core->num->value);
			}
			break;
		case '\0':
		case '?':
		default:
			rz_core_cmd_help(core, help_msg_wop);
			break;
		}
		break;
	case '\0':
	case '?':
	default:
		rz_core_cmd_help(core, help_msg_wo);
		break;
	}
	return 0;
}

#define WSEEK(x, y) \
	if (wseek) \
	rz_core_seek_delta(x, y, true)
static void rz_cmd_write_value(RzCore *core, const char *input) {
	int type = 0;
	ut64 off = 0LL;
	ut8 buf[sizeof(ut64)];
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	bool be = rz_config_get_i(core->config, "cfg.bigendian");

	core->num->value = 0;

	switch (input[0]) {
	case '?':
		rz_core_cmd_help(core, help_msg_wv);
		return;
	case '1': type = 1; break;
	case '2': type = 2; break;
	case '4': type = 4; break;
	case '8': type = 8; break;
	}
	if (input[0] && input[1]) {
		off = rz_num_math(core->num, input + 1);
	}
	if (core->file) {
		rz_io_use_fd(core->io, core->file->fd);
	}
	ut64 res = rz_io_seek(core->io, core->offset, RZ_IO_SEEK_SET);
	if (res == UT64_MAX)
		return;
	if (type == 0)
		type = (off & UT64_32U) ? 8 : 4;
	switch (type) {
	case 1:
		rz_write_ble8(buf, (ut8)(off & UT8_MAX));
		if (!rz_io_write(core->io, buf, 1)) {
			cmd_write_fail(core);
		} else {
			WSEEK(core, 1);
		}
		break;
	case 2:
		rz_write_ble16(buf, (ut16)(off & UT16_MAX), be);
		if (!rz_io_write(core->io, buf, 2)) {
			cmd_write_fail(core);
		} else {
			WSEEK(core, 2);
		}
		break;
	case 4:
		rz_write_ble32(buf, (ut32)(off & UT32_MAX), be);
		if (!rz_io_write(core->io, buf, 4)) {
			cmd_write_fail(core);
		} else {
			WSEEK(core, 4);
		}
		break;
	case 8:
		rz_write_ble64(buf, off, be);
		if (!rz_io_write(core->io, buf, 8)) {
			cmd_write_fail(core);
		} else {
			WSEEK(core, 8);
		}
		break;
	}
}

static RzCmdStatus common_wv_handler(RzCore *core, int argc, const char **argv, int type) {
	ut64 off = 0LL;
	ut8 buf[sizeof(ut64)];
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	bool be = rz_config_get_i(core->config, "cfg.bigendian");

	core->num->value = 0;
	off = rz_num_math(core->num, argv[1]);
	if (core->file) {
		rz_io_use_fd(core->io, core->file->fd);
	}

	ut64 res = rz_io_seek(core->io, core->offset, RZ_IO_SEEK_SET);
	if (res == UT64_MAX) {
		return RZ_CMD_STATUS_ERROR;
	}
	if (type == 0) {
		type = off & UT64_32U ? 8 : 4;
	}

	switch (type) {
	case 1:
		rz_write_ble8(buf, (ut8)(off & UT8_MAX));
		break;
	case 2:
		rz_write_ble16(buf, (ut16)(off & UT16_MAX), be);
		break;
	case 4:
		rz_write_ble32(buf, (ut32)(off & UT32_MAX), be);
		break;
	case 8:
		rz_write_ble64(buf, off, be);
		break;
	}

	if (!rz_io_write(core->io, buf, type)) {
		cmd_write_fail(core);
	} else if (wseek) {
		rz_core_seek_delta(core, type, true);
	}

	rz_core_block_read(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_write_value_handler(RzCore *core, int argc, const char **argv) {
	return common_wv_handler(core, argc, argv, 0);
}

RZ_IPI RzCmdStatus rz_write_value1_handler(RzCore *core, int argc, const char **argv) {
	return common_wv_handler(core, argc, argv, 1);
}

RZ_IPI RzCmdStatus rz_write_value2_handler(RzCore *core, int argc, const char **argv) {
	return common_wv_handler(core, argc, argv, 2);
}

RZ_IPI RzCmdStatus rz_write_value4_handler(RzCore *core, int argc, const char **argv) {
	return common_wv_handler(core, argc, argv, 4);
}

RZ_IPI RzCmdStatus rz_write_value8_handler(RzCore *core, int argc, const char **argv) {
	return common_wv_handler(core, argc, argv, 8);
}

RZ_IPI RzCmdStatus rz_write_base64_encode_handler(RzCore *core, int argc, const char **argv) {
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	const char *str = argv[1];
	size_t str_len = strlen(str) + 1;
	ut8 *bin_buf = malloc(str_len);
	if (!bin_buf) {
		eprintf("Error: failed to malloc memory");
		return RZ_CMD_STATUS_ERROR;
	}

	const int bin_len = rz_hex_str2bin(str, bin_buf);
	if (bin_len <= 0) {
		free(bin_buf);
		return RZ_CMD_STATUS_ERROR;
	}

	ut8 *buf = calloc(str_len + 1, 4);
	int len = rz_base64_encode((char *)buf, bin_buf, bin_len);
	free(bin_buf);
	if (len == 0) {
		free(buf);
		return RZ_CMD_STATUS_ERROR;
	}

	if (!rz_core_write_at(core, core->offset, buf, len)) {
		cmd_write_fail(core);
		free(buf);
		return RZ_CMD_STATUS_ERROR;
	}
	WSEEK(core, len);
	rz_core_block_read(core);

	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_write_base64_decode_handler(RzCore *core, int argc, const char **argv) {
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	const char *str = argv[1];
	size_t str_len = strlen(str) + 1;
	ut8 *buf = malloc(str_len);
	int len = rz_base64_decode(buf, str, -1);
	if (len < 0) {
		free(buf);
		return RZ_CMD_STATUS_ERROR;
	}

	if (!rz_core_write_at(core, core->offset, buf, len)) {
		cmd_write_fail(core);
		free(buf);
		return RZ_CMD_STATUS_ERROR;
	}
	WSEEK(core, len);
	rz_core_block_read(core);

	free(buf);
	return RZ_CMD_STATUS_OK;
}

static bool cmd_wff(RzCore *core, const char *input) {
	ut8 *buf;
	size_t size;
	// XXX: file names cannot contain spaces
	const char *arg = input + ((input[0] == ' ') ? 1 : 0);
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	char *p, *a = rz_str_trim_dup(arg);
	p = strchr(a, ' ');
	if (p) {
		*p++ = 0;
	}

	if (*arg == '?' || !*arg) {
		eprintf("Usage: wf [file] ([size] ([offset]))\n");
	}
	if (!strcmp(arg, "-")) {
		char *out = rz_core_editor(core, NULL, NULL);
		if (out) {
			if (!rz_io_write_at(core->io, core->offset,
				    (ut8 *)out, strlen(out))) {
				eprintf("rz_io_write_at failed at 0x%08" PFMT64x "\n", core->offset);
			}
			rz_core_block_read(core);
			free(out);
		}
	}
	if ((buf = (ut8 *)rz_file_slurp(a, &size))) {
		int u_offset = 0;
		ut64 u_size = rz_num_math(core->num, p);
		if (u_size < 1)
			u_size = (ut64)size;
		if (p) {
			*p++ = 0;
			u_offset = rz_num_math(core->num, p);
			if (u_offset > size) {
				eprintf("Invalid offset\n");
				free(buf);
				return false;
			}
		}
		rz_io_use_fd(core->io, core->file->fd);
		if (!rz_io_write_at(core->io, core->offset, buf + u_offset, (int)u_size)) {
			eprintf("rz_io_write_at failed at 0x%08" PFMT64x "\n", core->offset);
		}
		WSEEK(core, size);
		free(buf);
		rz_core_block_read(core);
	} else {
		eprintf("Cannot open file '%s'\n", arg);
	}
	return true;
}

static bool ioMemcpy(RzCore *core, ut64 dst, ut64 src, int len) {
	bool ret = false;
	if (len > 0) {
		ut8 *buf = calloc(1, len);
		if (buf) {
			if (rz_io_read_at(core->io, src, buf, len)) {
				if (rz_io_write_at(core->io, dst, buf, len)) {
					rz_core_block_read(core);
					ret = true;
				} else {
					eprintf("rz_io_write_at failed at 0x%08" PFMT64x "\n", dst);
				}
			} else {
				eprintf("rz_io_read_at failed at 0x%08" PFMT64x "\n", src);
			}
			free(buf);
		}
	}
	return ret;
}

static bool cmd_wfx(RzCore *core, const char *input) {
	char *args = rz_str_trim_dup(input);
	char *arg = strchr(args, ' ');
	int len = core->blocksize;
	if (arg) {
		*arg = 0;
		len = rz_num_math(core->num, arg + 1);
	}
	ut64 dst = core->offset;
	ut64 src = rz_num_math(core->num, args);
	if (len > 0) {
		// cache dest, memcpy, write cache
		ut8 *buf = calloc(1, len);
		if (buf) {
			if (rz_io_read_at(core->io, dst, buf, len)) {
				ioMemcpy(core, core->offset, src, len);
				if (rz_io_write_at(core->io, src, buf, len)) {
					rz_core_block_read(core);
				} else {
					eprintf("Failed to write at 0x%08" PFMT64x "\n", src);
				}
			} else {
				eprintf("cmd_wfx: failed to read at 0x%08" PFMT64x "\n", dst);
			}
			free(buf);
		}
	}
	free(args);
	return true;
}

static bool cmd_wfs(RzCore *core, const char *input) {
	char *str = strdup(input);
	if (str[0] != ' ') {
		eprintf("Usage wfs host:port [sz]\n");
		free(str);
		return false;
	}
	ut64 addr = 0;
	char *host = str + 1;
	char *port = strchr(host, ':');
	if (!port) {
		eprintf("Usage wfs host:port [sz]\n");
		free(str);
		return false;
	}
	ut64 sz = core->blocksize;
	*port++ = 0;
	char *space = strchr(port, ' ');
	if (space) {
		*space++ = 0;
		sz = rz_num_math(core->num, space);
		addr = core->offset;
	}
	ut8 *buf = calloc(1, sz);
	if (!buf) {
		free(str);
		return false;
	}
	rz_io_read_at(core->io, addr, buf, sz);
	RzSocket *s = rz_socket_new(false);
	if (!rz_socket_listen(s, port, NULL)) {
		eprintf("Cannot listen on port %s\n", port);
		rz_socket_free(s);
		free(str);
		free(buf);
		return false;
	}
	int done = 0;
	RzSocket *c = rz_socket_accept(s);
	if (c) {
		eprintf("Receiving data from client...\n");
		while (done < sz) {
			int rc = rz_socket_read(c, buf + done, sz - done);
			if (rc < 1) {
				eprintf("oops\n");
				break;
			}
			done += rc;
		}
		rz_socket_free(c);
		if (rz_io_write_at(core->io, core->offset, buf, done)) {
			eprintf("Written %d bytes\n", done);
		} else {
			eprintf("Cannot write\n");
		}
	}
	rz_socket_free(s);
	free(buf);
	free(str);
	return true;
}

RZ_IPI int rz_wf_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	if (!core || !*input) {
		return -1;
	}
	if (input[0] == '?') {
		eprintf("Usage: wf [file] ([size] ([offset]))\n");
		rz_core_cmd_help(core, help_msg_wf);
		return -1;
	}
	if (input[0] == 's') { // "wfs"
		return cmd_wfs(core, input + 1);
	}
	if (input[0] == 'x') { // "wfx"
		return cmd_wfx(core, input + 1);
	}
	if (input[0] == 'f') { // "wff"
		return cmd_wff(core, input + 1);
	}
	char *args = rz_str_trim_dup(input);
	char *arg = strchr(args, ' ');
	int len = core->blocksize;
	if (arg) {
		*arg++ = 0;
		len = rz_num_math(core->num, arg);
	}
	ut64 addr = rz_num_math(core->num, args);
	ioMemcpy(core, core->offset, addr, len);
	free(args);
	rz_core_block_read(core);
	return 0;
}

static void cmd_write_pcache(RzCore *core, const char *input) {
	RzIODesc *desc;
	RzIOCache *c;
	RzList *caches;
	RzListIter *iter;
	int fd, i;
	bool rad = false;
	if (core && core->io && core->io->p_cache && core->print && core->print->cb_printf) {
		switch (input[0]) {
		case 'i':
			if (input[1]) {
				fd = (int)rz_num_math(core->num, input + 1);
				desc = rz_io_desc_get(core->io, fd);
			} else {
				desc = core->io->desc;
			}
			rz_io_desc_cache_commit(desc);
			break;
		case '*':
			rad = true;
		case ' ': //fall-o-through
		case '\0':
			if (input[0] && input[1]) {
				fd = (int)rz_num_math(core->num, input + 1);
				desc = rz_io_desc_get(core->io, fd);
			} else {
				desc = core->io->desc;
			}
			if ((caches = rz_io_desc_cache_list(desc))) {
				if (rad) {
					core->print->cb_printf("e io.va = false\n");
					rz_list_foreach (caches, iter, c) {
						core->print->cb_printf("wx %02x", c->data[0]);
						const int cacheSize = rz_itv_size(c->itv);
						for (i = 1; i < cacheSize; i++) {
							core->print->cb_printf("%02x", c->data[i]);
						}
						core->print->cb_printf(" @ 0x%08" PFMT64x " \n", rz_itv_begin(c->itv));
					}
				} else {
					rz_list_foreach (caches, iter, c) {
						core->print->cb_printf("0x%08" PFMT64x ": %02x",
							rz_itv_begin(c->itv), c->odata[0]);
						const int cacheSize = rz_itv_size(c->itv);
						for (i = 1; i < cacheSize; i++) {
							core->print->cb_printf("%02x", c->odata[i]);
						}
						core->print->cb_printf(" -> %02x", c->data[0]);
						for (i = 1; i < cacheSize; i++) {
							core->print->cb_printf("%02x", c->data[i]);
						}
						core->print->cb_printf("\n");
					}
				}
				rz_list_free(caches);
			}
			break;
		default:
			break;
		}
	}
}

RZ_IPI int rz_wB_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	switch (input[0]) {
	case ' ':
		cmd_write_bits(core, 1, rz_num_math(core->num, input + 1));
		break;
	case '-':
		cmd_write_bits(core, 0, rz_num_math(core->num, input + 1));
		break;
	default:
		eprintf("Usage: wB 0x2000  # or wB-0x2000\n");
		break;
	}
	return 0;
}

RZ_IPI RzCmdStatus rz_write_bits_handler(RzCore *core, int argc, const char **argv) {
	cmd_write_bits(core, 1, rz_num_math(core->num, argv[1]));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_write_unset_bits_handler(RzCore *core, int argc, const char **argv) {
	cmd_write_bits(core, 0, rz_num_math(core->num, argv[1]));
	return RZ_CMD_STATUS_OK;
}

static int w0_handler_common(RzCore *core, ut64 len) {
	int res = 0;
	if (len > 0) {
		ut8 *buf = calloc(1, len);
		if (buf) {
			if (!rz_io_write_at(core->io, core->offset, buf, len)) {
				eprintf("rz_io_write_at failed at 0x%08" PFMT64x "\n", core->offset);
				res = -1;
			}
			rz_core_block_read(core);
			free(buf);
		} else {
			eprintf("Cannot allocate %d byte(s)\n", (int)len);
			res = -1;
		}
	}
	return res;
}

RZ_IPI int rz_w0_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	ut64 len = rz_num_math(core->num, input);
	return w0_handler_common(core, len);
}

RZ_IPI RzCmdStatus rz_write_zero_handler(RzCore *core, int argc, const char **argv) {
	ut64 len = rz_num_math(core->num, argv[1]);
	return rz_cmd_int2status(w0_handler_common(core, len));
}

static int rz_w_incdec_handler_old(void *data, const char *input, int inc) {
	RzCore *core = (RzCore *)data;
	st64 num = 1;
	if (input[0] && input[1]) {
		num = rz_num_math(core->num, input + 1);
	}
	switch (input[0]) {
	case '+':
		cmd_write_inc(core, inc, num);
		break;
	case '-':
		cmd_write_inc(core, inc, -num);
		break;
	default:
		eprintf("Usage: w[1248][+-][num]   # inc/dec byte/word/..\n");
	}
	return 0;
}

static RzCmdStatus w_incdec_handler(RzCore *core, int argc, const char **argv, int inc_size) {
	st64 num = argc > 1 ? rz_num_math(core->num, argv[1]) : 1;
	const char *command = argv[0];
	if (command[strlen(command) - 1] == '-') {
		num *= -1;
	}
	cmd_write_inc(core, inc_size, num);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_write_1_inc_handler(RzCore *core, int argc, const char **argv) {
	return w_incdec_handler(core, argc, argv, 1);
}
RZ_IPI RzCmdStatus rz_write_1_dec_handler(RzCore *core, int argc, const char **argv) {
	return w_incdec_handler(core, argc, argv, 1);
}

RZ_IPI RzCmdStatus rz_write_2_inc_handler(RzCore *core, int argc, const char **argv) {
	return w_incdec_handler(core, argc, argv, 2);
}
RZ_IPI RzCmdStatus rz_write_2_dec_handler(RzCore *core, int argc, const char **argv) {
	return w_incdec_handler(core, argc, argv, 2);
}

RZ_IPI RzCmdStatus rz_write_4_inc_handler(RzCore *core, int argc, const char **argv) {
	return w_incdec_handler(core, argc, argv, 4);
}
RZ_IPI RzCmdStatus rz_write_4_dec_handler(RzCore *core, int argc, const char **argv) {
	return w_incdec_handler(core, argc, argv, 4);
}

RZ_IPI RzCmdStatus rz_write_8_inc_handler(RzCore *core, int argc, const char **argv) {
	return w_incdec_handler(core, argc, argv, 8);
}
RZ_IPI RzCmdStatus rz_write_8_dec_handler(RzCore *core, int argc, const char **argv) {
	return w_incdec_handler(core, argc, argv, 8);
}

RZ_IPI int rz_w6_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	int fail = 0;
	ut8 *buf = NULL;
	int len = 0, str_len;
	const char *str;

	if (input[0] && input[1] != ' ')
		fail = 1;

	if (input[0] && input[1] && input[2])
		str = input + 2;
	else
		str = "";
	str_len = strlen(str) + 1;
	if (!fail) {
		switch (input[0]) {
		case 'd': // "w6d"
			buf = malloc(str_len);
			if (!buf) {
				eprintf("Error: failed to malloc memory");
				break;
			}
			len = rz_base64_decode(buf, str, -1);
			if (len < 0) {
				free(buf);
				fail = 1;
			}
			break;
		case 'e': { // "w6e"
			ut8 *bin_buf = malloc(str_len);
			if (!bin_buf) {
				eprintf("Error: failed to malloc memory");
				break;
			}
			const int bin_len = rz_hex_str2bin(str, bin_buf);
			if (bin_len <= 0) {
				fail = 1;
			} else {
				buf = calloc(str_len + 1, 4);
				len = rz_base64_encode((char *)buf, bin_buf, bin_len);
				if (len == 0) {
					free(buf);
					fail = 1;
				}
			}
			free(bin_buf);
			break;
		}
		default:
			fail = 1;
			break;
		}
	}
	if (!fail) {
		if (!rz_core_write_at(core, core->offset, buf, len)) {
			cmd_write_fail(core);
		}
		WSEEK(core, len);
		rz_core_block_read(core);
		free(buf);
	} else {
		eprintf("Usage: w6[de] base64/hex\n");
	}
	return 0;
}

RZ_IPI int rz_wh_handler_old(void *data, const char *input) {
	char *p = strchr(input, ' ');
	if (p) {
		while (*p == ' ')
			p++;
		p = rz_file_path(p);
		if (p) {
			rz_cons_println(p);
			free(p);
		}
	}
	return 0;
}

RZ_IPI int rz_we_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	ut64 addr = 0, len = 0, b_size = 0;
	st64 dist = 0;
	ut8 *bytes = NULL;
	int cmd_suc = false;
	char *input_shadow = NULL, *p = NULL;

	switch (input[0]) {
	case 'n': // "wen"
		if (input[1] == ' ') {
			len = *input ? rz_num_math(core->num, input + 2) : 0;
			if (len > 0) {
				const ut64 cur_off = core->offset;
				cmd_suc = rz_core_extend_at(core, core->offset, len);
				if (cmd_suc) {
					core->offset = cur_off;
					rz_core_block_read(core);
				} else {
					eprintf("rz_io_extend failed\n");
					cmd_suc = true;
				}
			}
		} else {
			eprintf("Usage: wen [len]\n");
			cmd_suc = true;
		}
		break;
	case 'N': // "weN"
		if (input[1] == ' ') {
			input += 2;
			while (*input && *input == ' ')
				input++;
			addr = rz_num_math(core->num, input);
			while (*input && *input != ' ')
				input++;
			input++;
			len = *input ? rz_num_math(core->num, input) : 0;
			if (len > 0) {
				ut64 cur_off = core->offset;
				cmd_suc = rz_core_extend_at(core, addr, len);
				if (cmd_suc) {
					rz_core_seek(core, cur_off, true);
					core->offset = addr;
					rz_core_block_read(core);
				} else {
					eprintf("rz_io_extend failed\n");
				}
			}
			cmd_suc = true;
		}
		break;
	case 'x': // "wex"
		if (input[1] == ' ') {
			input += 1;
			len = *input ? strlen(input) : 0;
			bytes = len > 1 ? malloc(len + 1) : NULL;
			len = bytes ? rz_hex_str2bin(input, bytes) : 0;
			if (len > 0) {
				ut64 cur_off = core->offset;
				cmd_suc = rz_core_extend_at(core, cur_off, len);
				if (cmd_suc) {
					if (!rz_core_write_at(core, cur_off, bytes, len)) {
						cmd_write_fail(core);
					}
				}
				core->offset = cur_off;
				rz_core_block_read(core);
			}
			free(bytes);
		}
		break;
	case 's': // "wes"
		input += 2;
		while (*input && *input == ' ') {
			input++;
		}
		len = strlen(input);

		// since the distance can be negative,
		// the rz_num_math will perform an unwanted operation
		// the solution is to tokenize the string :/
		if (len > 0) {
			input_shadow = strdup(input);
			p = strtok(input_shadow, " ");
			addr = p && *p ? rz_num_math(core->num, p) : 0;

			p = strtok(NULL, " ");
			dist = p && *p ? rz_num_math(core->num, p) : 0;

			p = strtok(NULL, " ");
			b_size = p && *p ? rz_num_math(core->num, p) : 0;
			if (dist != 0) {
				rz_core_shift_block(core, addr, b_size, dist);
				rz_core_seek(core, addr, true);
				cmd_suc = true;
			}
		}
		free(input_shadow);
		break;
	case 'X': // "weX"
		if (input[1] == ' ') {
			addr = rz_num_math(core->num, input + 2);
			input += 2;
			while (*input && *input != ' ')
				input++;
			input++;
			len = *input ? strlen(input) : 0;
			bytes = len > 1 ? malloc(len + 1) : NULL;
			len = bytes ? rz_hex_str2bin(input, bytes) : 0;
			if (len > 0) {
				//ut64 cur_off = core->offset;
				cmd_suc = rz_core_extend_at(core, addr, len);
				if (cmd_suc) {
					if (!rz_core_write_at(core, addr, bytes, len)) {
						cmd_write_fail(core);
					}
				} else {
					eprintf("rz_io_extend failed\n");
				}
				core->offset = addr;
				rz_core_block_read(core);
			}
			free(bytes);
		}
		break;
	case '?': // "we?"
	default:
		cmd_suc = false;
		break;
	}
	if (cmd_suc == false) {
		rz_core_cmd_help(core, help_msg_we);
	}
	return 0;
}

RZ_IPI int rz_wu_handler_old(void *data, const char *input) {
	// TODO: implement it in an API RzCore.write_unified_hexpatch() is ETOOLONG
	if (input[0] == ' ') {
		char *data = rz_file_slurp(input + 1, NULL);
		if (data) {
			int i;
			char sign = ' ';
			int line = 0, offs = 0, hexa = 0;
			int newline = 1;
			for (i = 0; data[i]; i++) {
				switch (data[i]) {
				case '+':
					if (newline)
						sign = 1;
					break;
				case '-':
					if (newline) {
						sign = 0;
						offs = i + ((data[i + 1] == ' ') ? 2 : 1);
					}
					break;
				case ' ':
					data[i] = 0;
					if (sign) {
						if (!line)
							line = i + 1;
						else if (!hexa)
							hexa = i + 1;
					}
					break;
				case '\r':
					break;
				case '\n':
					newline = 1;
					if (sign == ' ') {
						offs = 0;
						line = 0;
						hexa = 0;
					} else if (sign) {
						if (offs && hexa) {
							rz_cons_printf("wx %s @ %s\n", data + hexa, data + offs);
						} else
							eprintf("food\n");
						offs = 0;
						line = 0;
					} else
						hexa = 0;
					sign = -1;
					continue;
				}
				newline = 0;
			}
			free(data);
		}
	} else {
		eprintf("|Usage: wu [unified-diff-patch]    # see 'cu'\n");
	}
	return 0;
}

RZ_IPI int rz_wr_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	ut64 off = rz_num_math(core->num, input);
	int len = (int)off;
	if (len > 0) {
		ut8 *buf = malloc(len);
		if (buf != NULL) {
			int i;
			rz_num_irand();
			for (i = 0; i < len; i++)
				buf[i] = rz_num_rand(256);
			if (!rz_core_write_at(core, core->offset, buf, len)) {
				cmd_write_fail(core);
			}
			WSEEK(core, len);
			free(buf);
		} else
			eprintf("Cannot allocate %d byte(s)\n", len);
	}
	return 0;
}

RZ_IPI int rz_wA_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	int len;
	switch (input[0]) {
	case ' ':
		if (input[1] && input[2] == ' ') {
			rz_asm_set_pc(core->rasm, core->offset);
			eprintf("modify (%c)=%s\n", input[1], input + 3);
			len = rz_asm_modify(core->rasm, core->block, input[1],
				rz_num_math(core->num, input + 3));
			eprintf("len=%d\n", len);
			if (len > 0) {
				if (!rz_core_write_at(core, core->offset, core->block, len)) {
					cmd_write_fail(core);
				}
				WSEEK(core, len);
			} else
				eprintf("rz_asm_modify = %d\n", len);
		} else
			eprintf("Usage: wA [type] [value]\n");
		break;
	case '?':
	default:
		rz_core_cmd_help(core, help_msg_wA);
		break;
	}
	return 0;
}

RZ_IPI int rz_wc_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	switch (input[0]) {
	case '\0': // "wc"
		//if (!rz_config_get_i (core->config, "io.cache"))
		//	eprintf ("[warning] e io.cache must be true\n");
		rz_io_cache_list(core->io, 0);
		break;
	case '?': // "wc?"
		rz_core_cmd_help(core, help_msg_wc);
		break;
	case '*': // "wc*"
		rz_io_cache_list(core->io, 1);
		break;
	case '+': // "wc+"
		if (input[1] == '*') { // "wc+*"
			//rz_io_cache_reset (core->io, core->io->cached);
			eprintf("TODO\n");
		} else if (input[1] == ' ') { // "wc+ "
			char *p = strchr(input + 2, ' ');
			ut64 to, from;
			from = rz_num_math(core->num, input + 2);
			if (p) {
				*p = 0;
				to = rz_num_math(core->num, input + 2);
				if (to < from) {
					eprintf("Invalid range (from>to)\n");
					return 0;
				}
			} else {
				to = from + core->blocksize;
			}
			rz_io_cache_commit(core->io, from, to);
		} else {
			eprintf("Invalidate write cache at 0x%08" PFMT64x "\n", core->offset);
			rz_io_cache_commit(core->io, core->offset, core->offset + 1);
		}
		break;
	case '-': { // "wc-"
		if (input[1] == '*') { // "wc-*"
			rz_io_cache_reset(core->io, core->io->cached);
			break;
		}
		ut64 from, to;
		if (input[1] == ' ') { // "wc- "
			char *p = strchr(input + 2, ' ');
			if (p) {
				*p = 0;
				from = rz_num_math(core->num, input + 2);
				to = rz_num_math(core->num, p + 1);
				if (to < from) {
					eprintf("Invalid range (from>to)\n");
					return 0;
				}
			} else {
				from = rz_num_math(core->num, input + 2);
				to = from + core->blocksize;
			}
		} else {
			eprintf("Invalidate write cache at 0x%08" PFMT64x "\n", core->offset);
			from = core->offset;
			to = core->offset + core->blocksize;
		}
		eprintf("invalidated %d cache(s)\n",
			rz_io_cache_invalidate(core->io, from, to));
		rz_core_block_read(core);
		break;
	}
	case 'i': // "wci"
		rz_io_cache_commit(core->io, 0, UT64_MAX);
		rz_core_block_read(core);
		break;
	case 'j': // "wcj"
		rz_io_cache_list(core->io, 2);
		break;
	case 'p': // "wcp"
		cmd_write_pcache(core, &input[1]);
		break;
	case 'r': // "wcr"
		rz_io_cache_reset(core->io, core->io->cached);
		/* Before loading the core block we have to make sure that if
			* the cache wrote past the original EOF these changes are no
			* longer displayed. */
		memset(core->block, 0xff, core->blocksize);
		rz_core_block_read(core);
		break;
	}
	return 0;
}

static void w_handler_common(RzCore *core, const char *input) {
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	char *str = strdup(input);
	/* write string */
	int len = rz_str_unescape(str);
	if (!rz_core_write_at(core, core->offset, (const ut8 *)str, len)) {
		cmd_write_fail(core);
	}
	free(str);
	WSEEK(core, len);
	rz_core_block_read(core);
}

RZ_IPI int rz_w_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	w_handler_common(core, input);
	return 0;
}

RZ_IPI RzCmdStatus rz_write_handler(RzCore *core, int argc, const char **argv) {
	char *s = rz_str_array_join(argv + 1, argc - 1, " ");
	w_handler_common(core, s);
	free(s);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI int rz_wz_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	char *str = strdup(input);
	/* write zero-terminated string */
	int len = rz_str_unescape(str);
	if (!rz_core_write_at(core, core->offset, (const ut8 *)str + 1, len)) {
		cmd_write_fail(core);
	}
	if (len > 0) {
		core->num->value = len;
	} else {
		core->num->value = 0;
	}
#if 0
		rz_io_use_desc (core->io, core->file->desc);
#endif
	WSEEK(core, len + 1);
	rz_core_block_read(core);
	return 0;
}

RZ_IPI int rz_wt_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	char *str = strdup(input);
	char *ostr = str;
	const char *filename = "";
	char _fn[32];
	_fn[0] = 0;
	char *tmp;
	if (*str == 's') { // "wts"
		if (str[1] == ' ') {
			eprintf("Write to server\n");
			st64 sz = rz_io_size(core->io);
			if (sz > 0) {
				ut64 addr = 0;
				char *host = str + 2;
				char *port = strchr(host, ':');
				if (port) {
					*port++ = 0;
					char *space = strchr(port, ' ');
					if (space) {
						*space++ = 0;
						sz = rz_num_math(core->num, space);
						addr = core->offset;
					}
					ut8 *buf = calloc(1, sz);
					rz_io_read_at(core->io, addr, buf, sz);
					RzSocket *s = rz_socket_new(false);
					if (rz_socket_connect(s, host, port, RZ_SOCKET_PROTO_TCP, 0)) {
						int done = 0;
						eprintf("Transfering file to the end-point...\n");
						while (done < sz) {
							int rc = rz_socket_write(s, buf + done, sz - done);
							if (rc < 1) {
								eprintf("oops\n");
								break;
							}
							done += rc;
						}
					} else {
						eprintf("Cannot connect\n");
					}
					rz_socket_free(s);
					free(buf);
				} else {
					eprintf("Usage wts host:port [sz]\n");
				}
			} else {
				eprintf("Unknown file size\n");
			}
		} else {
			eprintf("Usage wts host:port [sz]\n");
		}
	} else if (*str == '?' || *str == '\0') {
		rz_core_cmd_help(core, help_msg_wt);
		free(ostr);
		return 0;
	} else {
		bool append = false;
		bool toend = false;
		st64 sz = core->blocksize;
		ut64 poff = core->offset;
		if (*str == 'f') { // "wtf"
			str++;
			if (*str == '?') {
				rz_core_cmd_help(core, help_msg_wt);
				return 0;
			}
			if (*str == '!') {
				if (str[1] == '?') {
					rz_core_cmd_help(core, help_msg_wt);
					return 0;
				}
				RzIOMap *map = rz_io_map_get(core->io, poff);
				toend = true;
				//use physical address
				poff = map ? poff - map->itv.addr + map->delta : poff;
				str++;
			}
			if (*str == 'f') { // "wtff"
				if (str[1] == '?') {
					rz_core_cmd_help(core, help_msg_wt);
					return 0;
				}
				const char *prefix = rz_str_trim_head_ro(str + 2);
				if (!*prefix) {
					prefix = "dump";
				}
				str++;
				filename = rz_str_newf("%s-0x%08" PFMT64x, prefix, core->offset);
			} else {
				if (*str) {
					if (str[1] == '?') {
						rz_core_cmd_help(core, help_msg_wt);
						return 0;
					}
					filename = rz_str_trim_head_ro(str);
				} else {
					filename = "";
				}
			}
		} else if (*str == 'a') { // "wta"
			append = 1;
			str++;
			if (str[0] == ' ') {
				filename = str + 1;
			} else {
				const char *prefix = rz_config_get(core->config, "cfg.prefixdump");
				snprintf(_fn, sizeof(_fn), "%s.0x%08" PFMT64x, prefix, poff);
				filename = _fn;
			}
		} else if (*str != ' ') {
			const char *prefix = rz_config_get(core->config, "cfg.prefixdump");
			snprintf(_fn, sizeof(_fn), "%s.0x%08" PFMT64x, prefix, poff);
			filename = _fn;
		} else {
			filename = str + 1;
		}
		tmp = *str ? strchr(str + 1, ' ') : NULL;
		if (!filename || !*filename) {
			const char *prefix = rz_config_get(core->config, "cfg.prefixdump");
			snprintf(_fn, sizeof(_fn), "%s.0x%08" PFMT64x, prefix, poff);
			filename = _fn;
		}
		if (tmp) {
			if (toend) {
				sz = rz_io_fd_size(core->io, core->file->fd) - core->offset;
				if (sz < 0) {
					eprintf("Warning: File size is unknown.");
				}
			} else {
				sz = (st64)rz_num_math(core->num, tmp + 1);
				*tmp = 0;
			}
			if ((st64)sz < 1) {
				sz = 0;
			} else if (!rz_core_dump(core, filename, poff, (ut64)sz, append)) {
				sz = -1;
			}
		} else {
			if (toend) {
				sz = rz_io_fd_size(core->io, core->file->fd);
				if (sz < 0) {
					eprintf("Warning: File size is unknown.");
				}
				if (sz != -1 && core->offset <= sz) {
					sz -= core->offset;
					if (!rz_core_dump(core, filename, core->offset, (ut64)sz, append)) {
						sz = -1;
					}
				} else {
					sz = -1;
				}
			} else {
				sz = core->blocksize;
				if (!rz_file_dump(filename, core->block, sz, append)) {
					sz = -1;
				}
			}
		}
		if (sz >= 0) {
			eprintf("Dumped %" PFMT64d " bytes from 0x%08" PFMT64x " into %s\n",
				sz, poff, filename);
		}
	}
	return 0;
}

RZ_IPI int rz_ww_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	char *str = strdup(input);
	int len = rz_str_unescape(str);
	if (len < 1) {
		return 0;
	}
	len++;
	str++;
	len = (len - 1) << 1;
	char *tmp = (len > 0) ? malloc(len + 1) : NULL;
	if (tmp) {
		int i;
		for (i = 0; i < len; i++) {
			if (i % 2)
				tmp[i] = 0;
			else
				tmp[i] = str[i >> 1];
		}
		str = tmp;
		if (core->file) {
			rz_io_use_fd(core->io, core->file->fd);
		}
		if (!rz_io_write_at(core->io, core->offset, (const ut8 *)str, len)) {
			eprintf("rz_io_write_at failed at 0x%08" PFMT64x "\n", core->offset);
		}
		WSEEK(core, len);
		rz_core_block_read(core);
		free(tmp);
	} else {
		eprintf("Cannot malloc %d\n", len);
	}
	return 0;
}

RZ_IPI int rz_wx_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	const char *arg;
	ut8 *buf;
	int size;
	switch (input[0]) {
	case ' ': // "wx "
		rz_core_write_hexpair(core, core->offset, input + 0);
		break;
	case 'f': // "wxf"
		arg = (const char *)(input + ((input[1] == ' ') ? 2 : 1));
		if (!strcmp(arg, "-")) {
			int len;
			ut8 *out;
			char *in = rz_core_editor(core, NULL, NULL);
			if (in) {
				out = (ut8 *)strdup(in);
				if (out) {
					len = rz_hex_str2bin(in, out);
					if (len > 0) {
						if (!rz_io_write_at(core->io, core->offset, out, len)) {
							eprintf("rz_io_write_at failed at 0x%08" PFMT64x "\n", core->offset);
						}
						core->num->value = len;
					} else {
						core->num->value = 0;
					}
					free(out);
				}
				free(in);
			}
		} else if (rz_file_exists(arg)) {
			if ((buf = rz_file_slurp_hexpairs(arg, &size))) {
				rz_io_use_fd(core->io, core->file->fd);
				if (rz_io_write_at(core->io, core->offset, buf, size) > 0) {
					core->num->value = size;
					WSEEK(core, size);
				} else {
					eprintf("rz_io_write_at failed at 0x%08" PFMT64x "\n", core->offset);
				}
				free(buf);
				rz_core_block_read(core);
			} else {
				eprintf("This file doesnt contains hexpairs\n");
			}
		} else {
			eprintf("Cannot open file '%s'\n", arg);
		}
		break;
	case 's': // "wxs"
	{
		int len = rz_core_write_hexpair(core, core->offset, input + 1);
		if (len > 0) {
			rz_core_seek_delta(core, len, true);
			core->num->value = len;
		} else {
			core->num->value = 0;
		}
	} break;
	default:
		rz_core_cmd_help(core, help_msg_wx);
		break;
	}
	return 0;
}

RZ_IPI int rz_wa_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	switch (input[0]) {
	case 'o': // "wao"
		if (input[1] == ' ') {
			char *op = rz_str_trim_dup(input + 2);
			if (op) {
				rz_core_hack(core, op);
				free(op);
			}
		} else {
			rz_core_hack_help(core);
		}
		break;
	case ' ':
	case 'i':
	case '*': {
		bool pad = input[0] == 'i'; // "wai"
		bool pretend = input[0] == '*'; // "wa*"
		const char *instructions = rz_str_trim_head_ro(input + 1);
		rz_core_write_assembly(core, core->offset, instructions, pretend, pad);
	} break;
	case 'f': // "waf"
		if ((input[1] == ' ' || input[1] == '*')) {
			const char *file = input + ((input[1] == '*') ? 3 : 2);
			rz_asm_set_pc(core->rasm, core->offset);

			char *src = rz_file_slurp(file, NULL);
			if (src) {
				ut64 addr = core->offset, nextaddr = addr;
				char *a, *b = src;
				do {
					a = strstr(b, ".offset ");
					if (a) {
						*a = 0;
						a += strlen(".offset ");
						nextaddr = rz_num_math(core->num, a);
						char *nl = strchr(a, '\n');
						if (nl) {
							*nl = 0;
							a = nl + 1;
						} else {
							break;
						}
					}
					if (*b) {
						RzAsmCode *ac = rz_asm_massemble(core->rasm, b);
						if (ac) {
							rz_io_write_at(core->io, addr, ac->bytes, ac->len);
							rz_asm_code_free(ac);
						}
					}
					b = a;
					addr = nextaddr;
				} while (a);
				free(src);
			} else {
				eprintf("Cannot open '%s'\n", file);
			}
		} else {
			eprintf("Wrong argument\n");
		}
		break;
	case 'F': // "waF"
		if ((input[1] == ' ' || input[1] == '*')) {
			const char *file = input + ((input[1] == '*') ? 3 : 2);
			rz_asm_set_pc(core->rasm, core->offset);
			char *f = rz_file_slurp(file, NULL);
			if (f) {
				RzAsmCode *acode = rz_asm_massemble(core->rasm, f);
				if (acode) {
					char *hex = rz_asm_code_get_hex(acode);
					if (input[1] == '*') {
						rz_cons_printf("wx %s\n", hex);
					} else {
						if (rz_config_get_i(core->config, "scr.prompt")) {
							eprintf("Written %d byte(s) (%s)=wx %s\n", acode->len, input, hex);
						}
						if (!rz_core_write_at(core, core->offset, acode->bytes, acode->len)) {
							cmd_write_fail(core);
						} else {
							WSEEK(core, acode->len);
						}
						rz_core_block_read(core);
					}
					free(hex);
					rz_asm_code_free(acode);
				} else {
					eprintf("Cannot assemble file\n");
				}
			} else {
				eprintf("Cannot slurp '%s'\n", file);
			}
		} else {
			eprintf("Wrong argument\n");
		}
		break;
	default:
		rz_core_cmd_help(core, help_msg_wa);
		break;
	}
	return 0;
}

RZ_IPI int rz_wb_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	int len = strlen(input);
	ut8 *buf = malloc(len + 2);
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	if (buf) {
		len = rz_hex_str2bin(input, buf);
		if (len > 0) {
			rz_mem_copyloop(core->block, buf, core->blocksize, len);
			if (!rz_core_write_at(core, core->offset, core->block, core->blocksize)) {
				cmd_write_fail(core);
			} else {
				WSEEK(core, core->blocksize);
			}
			rz_core_block_read(core);
		} else
			eprintf("Wrong argument\n");
		free(buf);
	} else {
		eprintf("Cannot malloc %d\n", len + 1);
	}
	return 0;
}

RZ_IPI int rz_wm_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	char *str = strdup(input);
	int size = rz_hex_str2bin(input, (ut8 *)str);
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	switch (input[0]) {
	case '\0':
		eprintf("TODO: Display current write mask");
		break;
	case '?':
		break;
	case '-':
		rz_io_set_write_mask(core->io, 0, 0);
		eprintf("Write mask disabled\n");
		break;
	case ' ':
		if (size > 0) {
			rz_io_use_fd(core->io, core->file->fd);
			rz_io_set_write_mask(core->io, (const ut8 *)str, size);
			WSEEK(core, size);
			eprintf("Write mask set to '");
			size_t i;
			for (i = 0; i < size; i++) {
				eprintf("%02x", str[i]);
			}
			eprintf("'\n");
		} else {
			eprintf("Invalid string\n");
		}
		break;
	}
	return 0;
}

RZ_IPI int rz_wd_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	if (input[0] && input[0] == ' ') {
		char *arg, *inp = strdup(input + 1);
		arg = strchr(inp, ' ');
		if (arg) {
			*arg = 0;
			ut64 addr = rz_num_math(core->num, input + 1);
			ut64 len = rz_num_math(core->num, arg + 1);
			ut8 *data = malloc(len);
			rz_io_read_at(core->io, addr, data, len);
			if (!rz_io_write_at(core->io, core->offset, data, len)) {
				eprintf("rz_io_write_at failed at 0x%08" PFMT64x "\n", core->offset);
			}
			free(data);
		} else {
			eprintf("See wd?\n");
		}
		free(inp);
	} else
		eprintf("Usage: wd [source-offset] [length] @ [dest-offset]\n");
	return 0;
}

RZ_IPI int rz_ws_handler_old(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	char *str = strdup(input);
	if (str && *str && str[1]) {
		int len = rz_str_unescape(str + 1);
		if (len > 255) {
			eprintf("Too large\n");
		} else {
			ut8 ulen = (ut8)len;
			if (!rz_core_write_at(core, core->offset, &ulen, 1) ||
				!rz_core_write_at(core, core->offset + 1, (const ut8 *)str + 1, len)) {
				cmd_write_fail(core);
			} else {
				WSEEK(core, len);
			}
			rz_core_block_read(core);
		}
	} else {
		eprintf("Too short.\n");
	}
	return 0;
}

/* TODO: simplify using rz_write */
RZ_IPI int rz_cmd_write(void *data, const char *input) {
	RzCore *core = (RzCore *)data;

	if (!input) {
		return 0;
	}

	switch (*input) {
	case 'B': // "wB"
		rz_wB_handler_old(data, input + 1);
		break;
	case '0': // "w0"
		rz_w0_handler_old(data, input + 1);
		break;
	case '1': // "w1"
	case '2': // "w2"
	case '4': // "w4"
	case '8': // "w8"
		rz_w_incdec_handler_old(data, input + 1, *input - '0');
		break;
	case '6': // "w6"
		rz_w6_handler_old(core, input + 1);
		break;
	case 'h': // "wh"
		rz_wh_handler_old(core, input + 1);
		break;
	case 'e': // "we"
		rz_we_handler_old(core, input + 1);
		break;
	case 'u': // "wu"
		rz_wu_handler_old(core, input + 1);
		break;
	case 'r': // "wr"
		rz_wr_handler_old(core, input + 1);
		break;
	case 'A': // "wA"
		rz_wA_handler_old(core, input + 1);
		break;
	case 'c': // "wc"
		rz_wc_handler_old(core, input + 1);
		break;
	case ' ': // "w"
		rz_w_handler_old(core, input + 1);
		break;
	case 'z': // "wz"
		rz_wz_handler_old(core, input + 1);
		break;
	case 't': // "wt"
		rz_wt_handler_old(core, input + 1);
		break;
	case 'f': // "wf"
		rz_wf_handler_old(core, input + 1);
		break;
	case 'w': // "ww"
		rz_ww_handler_old(core, input + 1);
		break;
	case 'x': // "wx"
		rz_wx_handler_old(core, input + 1);
		break;
	case 'a': // "wa"
		rz_wa_handler_old(core, input + 1);
		break;
	case 'b': // "wb"
		rz_wb_handler_old(core, input + 1);
		break;
	case 'm': // "wm"
		rz_wm_handler_old(core, input + 1);
		break;
	case 'v': // "wv"
		rz_cmd_write_value(core, input + 1);
		break;
	case 'o': // "wo"
		rz_wo_handler_old(core, input + 1);
		break;
	case 'd': // "wd"
		rz_wd_handler_old(core, input + 1);
		break;
	case 's': // "ws"
		rz_ws_handler_old(core, input + 1);
		break;
	default:
	case '?': // "w?"
		rz_core_cmd_help(core, help_msg_w);
		break;
	}
	return 0;
}
