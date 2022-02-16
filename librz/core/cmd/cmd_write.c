// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
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

static void cmd_write_fail(RzCore *core) {
	eprintf("Failed to write\n");
	core->num->value = 1;
}

static bool encrypt_or_decrypt_block(RzCore *core, const char *algo, const char *key, int direction, const char *iv) {
	// TODO: generalise no_key_mode for all non key encoding/decoding.
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
			const ut8 *result = rz_crypto_get_output(cry, &result_size);
			if (result) {
				if (!rz_core_write_at(core, core->offset, result, result_size)) {
					eprintf("rz_core_write_at failed at 0x%08" PFMT64x "\n", core->offset);
				}
				eprintf("Written %d byte(s)\n", result_size);
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

static void wo_show_algorithms(char c) {
	char flags[5] = { 0 };

	eprintf("Usage: wo%c [algo] [key] [IV]\n", c);
	eprintf(" flags algorithm      license    author\n");

	const RzCryptoPlugin *rcp;
	for (size_t i = 0; (rcp = rz_crypto_plugin_by_index(i)); i++) {
		if (!strncmp("base", rcp->name, 4) || !strcmp("punycode", rcp->name)) {
			snprintf(flags, sizeof(flags), "__ed");
		} else if (!strcmp("rol", rcp->name)) {
			snprintf(flags, sizeof(flags), "E___");
		} else if (!strcmp("ror", rcp->name)) {
			snprintf(flags, sizeof(flags), "_D__");
		} else {
			snprintf(flags, sizeof(flags), "ED__");
		}
		eprintf(" %-5s %-14s %-10s %s\n", flags, rcp->name, rcp->license, rcp->author);
	}
	eprintf(
		"\n"
		"flags legenda:\n"
		"    E = encryption, D = decryption\n"
		"    e = encoding, d = encoding\n");
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
			if (input[1] == '?') {
				wo_show_algorithms(input[0]);
			} else {
				eprintf("Usage: wo%c [algo] [key] [IV] (use wo%c? for the algorithms list)\n", input[0], input[0]);
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
				buf = (ut8 *)rz_debruijn_pattern(len, 0, NULL); // debruijn_charset);
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

static RzCmdStatus common_write_value_handler(RzCore *core, const char *valstr, size_t sz) {
	ut64 value = rz_num_math(core->num, valstr);
	if (core->num->nc.errors) {
		RZ_LOG_ERROR("Could not convert argument to number");
		return RZ_CMD_STATUS_ERROR;
	}

	return rz_core_write_value_at(core, core->offset, value, sz) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_write_value_handler(RzCore *core, int argc, const char **argv) {
	return common_write_value_handler(core, argv[1], 0);
}

RZ_IPI RzCmdStatus rz_write_value1_handler(RzCore *core, int argc, const char **argv) {
	return common_write_value_handler(core, argv[1], 1);
}

RZ_IPI RzCmdStatus rz_write_value2_handler(RzCore *core, int argc, const char **argv) {
	return common_write_value_handler(core, argv[1], 2);
}

RZ_IPI RzCmdStatus rz_write_value4_handler(RzCore *core, int argc, const char **argv) {
	return common_write_value_handler(core, argv[1], 4);
}

RZ_IPI RzCmdStatus rz_write_value8_handler(RzCore *core, int argc, const char **argv) {
	return common_write_value_handler(core, argv[1], 8);
}

RZ_IPI RzCmdStatus rz_write_base64_encode_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_write_base64_at(core, core->offset, argv[1]) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_write_base64_decode_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_write_base64d_at(core, core->offset, argv[1]) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
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

RZ_IPI RzCmdStatus rz_write_from_io_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = rz_num_math(core->num, argv[1]);
	ut64 len = rz_num_math(core->num, argv[2]);
	bool res = ioMemcpy(core, core->offset, addr, len);
	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_write_from_io_xchg_handler(RzCore *core, int argc, const char **argv) {
	ut64 dst = core->offset;
	ut64 src = rz_num_math(core->num, argv[1]);
	ut64 len = rz_num_math(core->num, argv[2]);
	if (len < 0) {
		return RZ_CMD_STATUS_ERROR;
	}

	ut8 *buf = RZ_NEWS0(ut8, len);
	if (!buf) {
		return RZ_CMD_STATUS_ERROR;
	}

	RzCmdStatus res = RZ_CMD_STATUS_ERROR;
	if (!rz_io_read_at(core->io, dst, buf, len)) {
		eprintf("cmd_wfx: failed to read at 0x%08" PFMT64x "\n", dst);
		goto err;
	}

	ioMemcpy(core, core->offset, src, len);
	if (!rz_io_write_at(core->io, src, buf, len)) {
		eprintf("Failed to write at 0x%08" PFMT64x "\n", src);
		goto err;
	}

	rz_core_block_read(core);
	res = RZ_CMD_STATUS_OK;
err:
	free(buf);
	return res;
}

RZ_IPI RzCmdStatus rz_write_from_file_handler(RzCore *core, int argc, const char **argv) {
	int wseek = rz_config_get_i(core->config, "cfg.wseek");
	ut64 user_size = argc > 2 ? rz_num_math(core->num, argv[2]) : UT64_MAX;
	ut64 offset = argc > 3 ? rz_num_math(core->num, argv[3]) : 0;
	const char *filename = argv[1];

	RzCmdStatus res = RZ_CMD_STATUS_ERROR;
	char *data = NULL;
	size_t size, w_size;
	if (!strcmp(filename, "-")) {
		data = rz_core_editor(core, NULL, NULL);
		if (!data) {
			eprintf("No data from editor\n");
			return RZ_CMD_STATUS_ERROR;
		}
		size = strlen(data);
	} else {
		data = rz_file_slurp(filename, &size);
		if (!data) {
			eprintf("Cannot open file '%s'\n", filename);
			return RZ_CMD_STATUS_ERROR;
		}
	}

	w_size = RZ_MIN(size, user_size);
	if (offset > size) {
		eprintf("Invalid offset provided\n");
		goto err;
	}
	if (UT64_ADD_OVFCHK(offset, w_size) || offset + w_size > size) {
		eprintf("Invalid offset/size provided\n");
		goto err;
	}

	rz_io_use_fd(core->io, core->file->fd);
	if (!rz_io_write_at(core->io, core->offset, (ut8 *)data + offset, w_size)) {
		eprintf("rz_io_write_at failed at 0x%08" PFMT64x "\n", core->offset);
		goto err;
	}
	WSEEK(core, w_size);
	rz_core_block_read(core);
	res = RZ_CMD_STATUS_OK;

err:
	free(data);
	return res;
}

RZ_IPI RzCmdStatus rz_write_from_socket_handler(RzCore *core, int argc, const char **argv) {
	RzCmdStatus res = RZ_CMD_STATUS_ERROR;
	char *address = strdup(argv[1]);
	ut64 sz = argc > 2 ? rz_num_math(core->num, argv[2]) : core->blocksize;

	size_t n_split = rz_str_split(address, ':');
	if (n_split != 2) {
		eprintf("Wrong format for <host:port>\n");
		goto err;
	}
	char *host = address;
	char *port = host + strlen(host) + 1;

	ut8 *buf = RZ_NEWS0(ut8, sz);
	if (!buf) {
		goto err;
	}

	RzSocket *s = rz_socket_new(false);
	if (!rz_socket_listen(s, port, NULL)) {
		eprintf("Cannot listen on port %s\n", port);
		goto socket_err;
	}
	int done = 0;
	RzSocket *c = rz_socket_accept(s);
	if (!c) {
		eprintf("Failing to accept socket\n");
		goto socket_err;
	}

	eprintf("Receiving data from client...\n");
	while (done < sz) {
		int rc = rz_socket_read(c, buf + done, sz - done);
		if (rc < 0) {
			eprintf("Failing to read data from socket: %d\n", rc);
			goto socket_err;
		} else if (rc == 0) {
			break;
		}
		done += rc;
	}
	if (!rz_io_write_at(core->io, core->offset, buf, done)) {
		eprintf("Cannot write\n");
		goto socket_err;
	}
	eprintf("Written %d bytes\n", done);
	res = RZ_CMD_STATUS_OK;

socket_err:
	rz_socket_free(s);
err:
	free(address);
	return res;
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
	ut8 *buf = RZ_NEWS0(ut8, len);
	if (!buf) {
		RZ_LOG_ERROR("Cannot allocate %" PFMT64d " bytes", len);
		return RZ_CMD_STATUS_ERROR;
	}

	bool res = rz_core_write_at(core, core->offset, buf, len);
	free(buf);

	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

static RzCmdStatus w_incdec_handler(RzCore *core, int argc, const char **argv, int inc_size) {
	st64 num = argc > 1 ? rz_num_math(core->num, argv[1]) : 1;
	const char *command = argv[0];
	if (command[strlen(command) - 1] == '-') {
		num *= -1;
	}
	return rz_core_write_value_inc_at(core, core->offset, num, inc_size) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
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

RZ_IPI RzCmdStatus rz_write_random_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_num_is_valid_input(core->num, argv[1])) {
		RZ_LOG_ERROR("Invalid length '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	size_t length = rz_num_math(core->num, argv[1]);
	return rz_core_write_random_at(core, core->offset, length) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
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
	return rz_core_write_string_at(core, core->offset, argv[1]) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
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
				// use physical address
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

RZ_IPI RzCmdStatus rz_write_hex_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_write_hexpair(core, core->offset, argv[1]) > 0 ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_write_hex_from_file_handler(RzCore *core, int argc, const char **argv) {
	char *buf;
	if (!strcmp(argv[1], "-")) {
		buf = rz_core_editor(core, NULL, NULL);
		if (!buf) {
			RZ_LOG_ERROR("Could not get anything from editor\n");
			return RZ_CMD_STATUS_ERROR;
		}
	} else {
		if (!rz_file_exists(argv[1])) {
			RZ_LOG_ERROR("File '%s' does not exist\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}

		buf = rz_file_slurp(argv[1], NULL);
		if (!buf) {
			RZ_LOG_ERROR("Cannot open file '%s'\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
	}

	int res = rz_core_write_hexpair(core, core->offset, buf);
	free(buf);
	if (res < 0) {
		RZ_LOG_ERROR("Could not write hexpairs to 0x%" PFMT64x "\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_write_assembly_handler(RzCore *core, int argc, const char **argv) {
	char *instructions = rz_str_array_join(argv + 1, argc - 1, "\n");
	if (!instructions) {
		return RZ_CMD_STATUS_ERROR;
	}
	int res = rz_core_write_assembly(core, core->offset, instructions);
	free(instructions);
	return res >= 0 ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_write_assembly_inside_handler(RzCore *core, int argc, const char **argv) {
	char *instructions = rz_str_array_join(argv + 1, argc - 1, "\n");
	if (!instructions) {
		return RZ_CMD_STATUS_ERROR;
	}
	int res = rz_core_write_assembly_fill(core, core->offset, instructions);
	free(instructions);
	return res >= 0 ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_write_assembly_file_handler(RzCore *core, int argc, const char **argv) {
	char *instructions = rz_file_slurp(argv[1], NULL);
	if (!instructions) {
		RZ_LOG_ERROR("Cannot read file '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	int res = rz_core_write_assembly(core, core->offset, instructions);
	free(instructions);
	return res >= 0 ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_write_assembly_opcode_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_hack(core, argv[1]));
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

RZ_IPI RzCmdStatus rz_write_length_string_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_write_length_string_at(core, core->offset, argv[1]) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

/* TODO: simplify using rz_write */
RZ_IPI int rz_cmd_write(void *data, const char *input) {
	RzCore *core = (RzCore *)data;

	if (!input) {
		return 0;
	}

	switch (*input) {
	case 'u': // "wu"
		rz_wu_handler_old(core, input + 1);
		break;
	case 'z': // "wz"
		rz_wz_handler_old(core, input + 1);
		break;
	case 't': // "wt"
		rz_wt_handler_old(core, input + 1);
		break;
	case 'w': // "ww"
		rz_ww_handler_old(core, input + 1);
		break;
	case 'b': // "wb"
		rz_wb_handler_old(core, input + 1);
		break;
	case 'm': // "wm"
		rz_wm_handler_old(core, input + 1);
		break;
	case 'o': // "wo"
		rz_wo_handler_old(core, input + 1);
		break;
	case 'd': // "wd"
		rz_wd_handler_old(core, input + 1);
		break;
	default:
	case '?': // "w?"
		rz_core_cmd_help(core, help_msg_w);
		break;
	}
	return 0;
}

RZ_IPI RzCmdStatus rz_write_cache_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_core_io_cache_print(core, state);
}

RZ_IPI RzCmdStatus rz_write_cache_remove_handler(RzCore *core, int argc, const char **argv) {
	ut64 from = argc > 1 ? rz_num_math(core->num, argv[1]) : core->offset;
	ut64 to = argc > 2 ? rz_num_math(core->num, argv[2]) : from + core->blocksize;
	int ninvalid = rz_io_cache_invalidate(core->io, from, to);
	RZ_LOG_INFO("Invalidated %d cache(s)\n", ninvalid);
	rz_core_block_read(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_write_cache_remove_all_handler(RzCore *core, int argc, const char **argv) {
	rz_io_cache_reset(core->io, core->io->cached);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_write_cache_commit_handler(RzCore *core, int argc, const char **argv) {
	ut64 from = argc > 1 ? rz_num_math(core->num, argv[1]) : core->offset;
	ut64 to = argc > 2 ? rz_num_math(core->num, argv[2]) : from + core->blocksize;
	rz_io_cache_commit(core->io, from, to);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_write_cache_commit_all_handler(RzCore *core, int argc, const char **argv) {
	rz_io_cache_commit(core->io, 0, UT64_MAX);
	rz_core_block_read(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_write_pcache_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzIODesc *desc = NULL;
	if (argc > 1) {
		int fd = (int)rz_num_math(core->num, argv[1]);
		if (fd < 0) {
			RZ_LOG_ERROR("Invalid fd argument %d.\n", fd);
			return RZ_CMD_STATUS_ERROR;
		}
		desc = rz_io_desc_get(core->io, fd);
	} else {
		desc = core->io->desc;
	}
	if (!desc) {
		RZ_LOG_ERROR("Cannot retrieve valid file.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return rz_core_io_pcache_print(core, desc, state);
}

RZ_IPI RzCmdStatus rz_write_pcache_commit_handler(RzCore *core, int argc, const char **argv) {
	RzIODesc *desc = NULL;
	if (argc > 1) {
		int fd = (int)rz_num_math(core->num, argv[1]);
		if (fd < 0) {
			RZ_LOG_ERROR("Invalid fd argument %d.\n", fd);
			return RZ_CMD_STATUS_ERROR;
		}
		desc = rz_io_desc_get(core->io, fd);
	} else {
		desc = core->io->desc;
	}
	if (!desc) {
		RZ_LOG_ERROR("Cannot retrieve valid file.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return bool2status(rz_io_desc_cache_commit(desc));
}

RZ_IPI RzCmdStatus rz_write_extend_zero_handler(RzCore *core, int argc, const char **argv) {
	ut64 len = rz_num_math(core->num, argv[1]);
	ut64 addr = argc > 2 ? rz_num_math(core->num, argv[2]) : core->offset;
	return bool2status(rz_core_extend_at(core, addr, len));
}

RZ_IPI RzCmdStatus rz_write_extend_shift_handler(RzCore *core, int argc, const char **argv) {
	ut64 dist = rz_num_math(core->num, argv[1]);
	ut64 block_size = argc > 2 ? rz_num_math(core->num, argv[2]) : 0;
	if (dist == 0) {
		RZ_LOG_ERROR("Cannot use '%s' as a distance.\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	return bool2status(rz_core_shift_block(core, core->offset, block_size, dist));
}

RZ_IPI RzCmdStatus rz_write_extend_hexbytes_handler(RzCore *core, int argc, const char **argv) {
	ut8 *bytes = RZ_NEWS(ut8, (strlen(argv[1]) + 1) / 2);
	if (!bytes) {
		return RZ_CMD_STATUS_ERROR;
	}

	int len = rz_hex_str2bin(argv[1], bytes);
	if (len <= 0) {
		RZ_LOG_ERROR("Cannot convert '%s' to bytes values.\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}

	ut64 addr = argc > 2 ? rz_num_math(core->num, argv[2]) : core->offset;
	bool res = rz_core_extend_at(core, addr, len);
	if (!res) {
		RZ_LOG_ERROR("Cannot extend the file.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return bool2status(rz_core_write_at(core, addr, bytes, len));
}
