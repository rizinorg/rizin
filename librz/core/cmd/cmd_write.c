// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_crypto.h>
#include <rz_config.h>
#include <rz_cons.h>
#include <rz_core.h>
#include <rz_io.h>
#include <rz_socket.h>
#include "../core_private.h"

static void cmd_write_fail(RzCore *core) {
	RZ_LOG_ERROR("core: Failed to write\n");
	core->num->value = 1;
}

static bool encrypt_or_decrypt_block(RzCore *core, const char *algo, const char *key, int direction, const char *iv) {
	// TODO: generalise no_key_mode for all non key encoding/decoding.
	int keylen = 0;
	bool no_key_mode = !strcmp("base64", algo) || !strcmp("base91", algo) || !strcmp("punycode", algo);
	ut8 *binkey = NULL;
	if (!strncmp(key, "s:", 2)) {
		binkey = (ut8 *)rz_str_dup(key + 2);
		keylen = strlen(key + 2);
	} else {
		binkey = (ut8 *)rz_str_dup(key);
		keylen = rz_hex_str2bin(key, binkey);
	}
	if (!no_key_mode && keylen < 1) {
		RZ_LOG_ERROR("core: %s key not defined. Use -S [key]\n", ((!direction) ? "Encryption" : "Decryption"));
		free(binkey);
		return false;
	}
	rz_crypto_reset(core->crypto);
	if (!rz_crypto_use(core->crypto, algo)) {
		RZ_LOG_ERROR("core: Unknown %s algorithm '%s'\n", ((!direction) ? "encryption" : "decryption"), algo);
		free(binkey);
		return false;
	}
	if (!binkey) {
		RZ_LOG_ERROR("core: Cannot allocate %d byte(s)\n", keylen);
		return false;
	}
	if (rz_crypto_set_key(core->crypto, binkey, keylen, 0, direction)) {
		if (iv) {
			ut8 *biniv = malloc(strlen(iv) + 1);
			int ivlen = rz_hex_str2bin(iv, biniv);
			if (ivlen < 1) {
				ivlen = strlen(iv);
				strcpy((char *)biniv, iv);
			}
			if (!rz_crypto_set_iv(core->crypto, biniv, ivlen)) {
				RZ_LOG_ERROR("core: Invalid IV.\n");
				return 0;
			}
		}
		rz_crypto_update(core->crypto, (const ut8 *)core->block, core->blocksize);
		rz_crypto_final(core->crypto, NULL, 0);

		int result_size = 0;
		const ut8 *result = rz_crypto_get_output(core->crypto, &result_size);
		if (result) {
			if (!rz_core_write_at(core, core->offset, result, result_size)) {
				RZ_LOG_ERROR("core: rz_core_write_at failed at 0x%08" PFMT64x "\n", core->offset);
			}
			RZ_LOG_WARN("core: Written %d byte(s)\n", result_size);
		}
	} else {
		RZ_LOG_ERROR("core: Invalid key\n");
	}
	free(binkey);
	return 0;
}

static void cmd_write_bits(RzCore *core, int set, ut64 val) {
	bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");
	ut8 buf[sizeof(ut64)];
	ut64 ret, orig;
	// used to set/unset bit in current address
	if (!rz_io_read_at(core->io, core->offset, buf, sizeof(buf))) {
		cmd_write_fail(core);
		return;
	}
	orig = rz_read_ble64(buf, big_endian);
	if (set) {
		ret = orig | val;
	} else {
		ret = orig & (~(val));
	}
	rz_write_ble64(buf, ret, big_endian);
	if (!rz_core_write_at(core, core->offset, buf, sizeof(buf))) {
		cmd_write_fail(core);
	}
}

#define WSEEK(x, y) \
	if (wseek) \
	rz_core_seek_delta(x, y, true)

static RzCmdStatus common_write_value_handler(RzCore *core, const char *valstr, size_t sz) {
	ut64 value = rz_num_math(core->num, valstr);
	if (core->num->nc.errors) {
		RZ_LOG_ERROR("Could not convert argument to number\n");
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
					RZ_LOG_ERROR("core: rz_io_write_at failed at 0x%08" PFMT64x "\n", dst);
				}
			} else {
				RZ_LOG_ERROR("core: rz_io_read_at failed at 0x%08" PFMT64x "\n", src);
			}
			free(buf);
		}
	}
	return ret;
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
		RZ_LOG_ERROR("core: cmd_wfx: failed to read at 0x%08" PFMT64x "\n", dst);
		goto err;
	}

	ioMemcpy(core, core->offset, src, len);
	if (!rz_io_write_at(core->io, src, buf, len)) {
		RZ_LOG_ERROR("core: Failed to write at 0x%08" PFMT64x "\n", src);
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
			RZ_LOG_ERROR("core: No data from editor\n");
			return RZ_CMD_STATUS_ERROR;
		}
		size = strlen(data);
	} else {
		data = rz_file_slurp(filename, &size);
		if (!data) {
			RZ_LOG_ERROR("core: Cannot open file '%s'\n", filename);
			return RZ_CMD_STATUS_ERROR;
		}
	}

	w_size = RZ_MIN(size, user_size);
	if (offset > size) {
		RZ_LOG_ERROR("core: Invalid offset provided\n");
		goto err;
	}
	if (UT64_ADD_OVFCHK(offset, w_size) || offset + w_size > size) {
		RZ_LOG_ERROR("core: Invalid offset/size provided\n");
		goto err;
	}

	rz_io_use_fd(core->io, core->file->fd);
	if (!rz_io_write_at(core->io, core->offset, (ut8 *)data + offset, w_size)) {
		RZ_LOG_ERROR("core: rz_io_write_at failed at 0x%08" PFMT64x "\n", core->offset);
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
	char *address = rz_str_dup(argv[1]);
	ut64 sz = argc > 2 ? rz_num_math(core->num, argv[2]) : core->blocksize;

	size_t n_split = rz_str_split(address, ':');
	if (n_split != 2) {
		RZ_LOG_ERROR("core: Wrong format for <host:port>\n");
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
		RZ_LOG_ERROR("core: Cannot listen on port %s\n", port);
		goto socket_err;
	}
	int done = 0;
	RzSocket *c = rz_socket_accept(s);
	if (!c) {
		RZ_LOG_ERROR("core: Failing to accept socket\n");
		goto socket_err;
	}

	RZ_LOG_INFO("core: Receiving data from client...\n");
	while (done < sz) {
		int rc = rz_socket_read(c, buf + done, sz - done);
		if (rc < 0) {
			RZ_LOG_ERROR("core: Failing to read data from socket: %d\n", rc);
			goto socket_err;
		} else if (rc == 0) {
			break;
		}
		done += rc;
	}
	if (!rz_io_write_at(core->io, core->offset, buf, done)) {
		RZ_LOG_ERROR("core: Cannot write\n");
		goto socket_err;
	}
	RZ_LOG_WARN("core: Written %d bytes\n", done);
	res = RZ_CMD_STATUS_OK;

socket_err:
	rz_socket_free(s);
err:
	free(address);
	return res;
}

RZ_IPI RzCmdStatus rz_write_bits_handler(RzCore *core, int argc, const char **argv) {
	cmd_write_bits(core, 1, rz_num_math(core->num, argv[1]));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_write_unset_bits_handler(RzCore *core, int argc, const char **argv) {
	cmd_write_bits(core, 0, rz_num_math(core->num, argv[1]));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_write_zero_handler(RzCore *core, int argc, const char **argv) {
	ut64 len = rz_num_math(core->num, argv[1]);
	ut8 *buf = RZ_NEWS0(ut8, len);
	if (!buf) {
		RZ_LOG_ERROR("Cannot allocate %" PFMT64d " bytes\n", len);
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

RZ_IPI RzCmdStatus rz_write_unified_patch_handler(RzCore *core, int argc, const char **argv) {
	// TODO: implement it in an API RzCore.write_unified_hexpatch() is ETOOLONG
	char *data = rz_file_slurp(argv[1], NULL);
	if (!data) {
		RZ_LOG_ERROR("Cannot read data from %s.\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
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
					ut64 dst = rz_num_math(core->num, data + offs);
					ut8 *buf = RZ_NEWS(ut8, strlen(data + hexa));
					if (buf) {
						int len = rz_hex_str2bin(data + hexa, buf);
						rz_core_write_at(core, dst, buf, len);
					}
				}
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
	return 0;
}

RZ_IPI RzCmdStatus rz_write_random_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_num_is_valid_input(core->num, argv[1])) {
		RZ_LOG_ERROR("Invalid length '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	size_t length = rz_num_math(core->num, argv[1]);
	return bool2status(rz_core_write_random_at(core, core->offset, length));
}

RZ_IPI RzCmdStatus rz_write_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_write_string_at(core, core->offset, argv[1]));
}

RZ_IPI RzCmdStatus rz_write_zero_string_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_write_string_zero_at(core, core->offset, argv[1]));
}

RZ_IPI RzCmdStatus rz_write_wide_string_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_write_string_wide_at(core, core->offset, argv[1]));
}

RZ_IPI RzCmdStatus rz_write_hex_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_write_hexpair(core, core->offset, argv[1]) > 0);
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

RZ_IPI RzCmdStatus rz_write_block_handler(RzCore *core, int argc, const char **argv) {
	ut8 *hex = RZ_NEWS0(ut8, (strlen(argv[1]) + 1) / 2);
	if (!hex) {
		return RZ_CMD_STATUS_ERROR;
	}

	int len = rz_hex_str2bin(argv[1], hex);
	if (len <= 0) {
		free(hex);
		RZ_LOG_ERROR("Cannot convert '%s' to hex data.\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}

	return bool2status(rz_core_write_block(core, core->offset, hex, len));
}

RZ_IPI RzCmdStatus rz_write_mask_set_handler(RzCore *core, int argc, const char **argv) {
	ut8 *buf = RZ_NEWS(ut8, strlen(argv[1]) / 2);
	if (!buf) {
		return RZ_CMD_STATUS_ERROR;
	}
	int size = rz_hex_str2bin(argv[1], buf);
	bool result = rz_io_set_write_mask(core->io, buf, size);
	free(buf);
	return bool2status(result);
}

RZ_IPI RzCmdStatus rz_write_mask_reset_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_io_set_write_mask(core->io, NULL, 0));
}

RZ_IPI RzCmdStatus rz_write_duplicate_handler(RzCore *core, int argc, const char **argv) {
	ut64 src = rz_num_math(core->num, argv[1]);
	int len = (int)rz_num_math(core->num, argv[2]);
	if (len < 0) {
		RZ_LOG_ERROR("Negative length is not valid.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return bool2status(rz_core_write_duplicate_at(core, core->offset, src, len));
}

RZ_IPI RzCmdStatus rz_write_length_string_handler(RzCore *core, int argc, const char **argv) {
	return rz_core_write_length_string_at(core, core->offset, argv[1]) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
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
		free(bytes);
		return RZ_CMD_STATUS_ERROR;
	}

	ut64 addr = argc > 2 ? rz_num_math(core->num, argv[2]) : core->offset;
	bool res = rz_core_extend_at(core, addr, len);
	if (!res) {
		RZ_LOG_ERROR("Cannot extend the file.\n");
		free(bytes);
		return RZ_CMD_STATUS_ERROR;
	}
	bool result = rz_core_write_at(core, addr, bytes, len);
	free(bytes);
	return bool2status(result);
}

RZ_IPI RzCmdStatus rz_write_op_2byteswap_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_write_block_op_at(core, core->offset, RZ_CORE_WRITE_OP_BYTESWAP2, NULL, 0));
}

RZ_IPI RzCmdStatus rz_write_op_4byteswap_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_write_block_op_at(core, core->offset, RZ_CORE_WRITE_OP_BYTESWAP4, NULL, 0));
}

RZ_IPI RzCmdStatus rz_write_op_8byteswap_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_core_write_block_op_at(core, core->offset, RZ_CORE_WRITE_OP_BYTESWAP8, NULL, 0));
}

static RzCmdStatus write_op_val(RzCore *core, int argc, const char **argv, RzCoreWriteOp op) {
	rz_return_val_if_fail(argc > 1, RZ_CMD_STATUS_WRONG_ARGS);

	ut8 *hex = RZ_NEWS(ut8, (strlen(argv[1]) + 1) / 2);
	if (!hex) {
		return RZ_CMD_STATUS_ERROR;
	}

	int hexlen = rz_hex_str2bin(argv[1], hex);
	RzCmdStatus res = bool2status(rz_core_write_block_op_at(core, core->offset, op, hex, hexlen));
	free(hex);
	return res;
}

RZ_IPI RzCmdStatus rz_write_op_add_handler(RzCore *core, int argc, const char **argv) {
	return write_op_val(core, argc, argv, RZ_CORE_WRITE_OP_ADD);
}

RZ_IPI RzCmdStatus rz_write_op_sub_handler(RzCore *core, int argc, const char **argv) {
	return write_op_val(core, argc, argv, RZ_CORE_WRITE_OP_SUB);
}

RZ_IPI RzCmdStatus rz_write_op_mul_handler(RzCore *core, int argc, const char **argv) {
	return write_op_val(core, argc, argv, RZ_CORE_WRITE_OP_MUL);
}

RZ_IPI RzCmdStatus rz_write_op_div_handler(RzCore *core, int argc, const char **argv) {
	return write_op_val(core, argc, argv, RZ_CORE_WRITE_OP_DIV);
}

RZ_IPI RzCmdStatus rz_write_op_xor_handler(RzCore *core, int argc, const char **argv) {
	return write_op_val(core, argc, argv, RZ_CORE_WRITE_OP_XOR);
}

RZ_IPI RzCmdStatus rz_write_op_and_handler(RzCore *core, int argc, const char **argv) {
	return write_op_val(core, argc, argv, RZ_CORE_WRITE_OP_AND);
}

RZ_IPI RzCmdStatus rz_write_op_or_handler(RzCore *core, int argc, const char **argv) {
	return write_op_val(core, argc, argv, RZ_CORE_WRITE_OP_OR);
}

RZ_IPI RzCmdStatus rz_write_op_shl_handler(RzCore *core, int argc, const char **argv) {
	return write_op_val(core, argc, argv, RZ_CORE_WRITE_OP_SHIFT_LEFT);
}

RZ_IPI RzCmdStatus rz_write_op_shr_handler(RzCore *core, int argc, const char **argv) {
	return write_op_val(core, argc, argv, RZ_CORE_WRITE_OP_SHIFT_RIGHT);
}

RZ_IPI RzCmdStatus rz_write_op_encrypt_handler(RzCore *core, int argc, const char **argv) {
	const char *algo = argv[1];
	const char *key = argv[2];
	const char *iv = argv[3];
	return bool2status(encrypt_or_decrypt_block(core, algo, key, 0, iv));
}

RZ_IPI RzCmdStatus rz_write_op_decrypt_handler(RzCore *core, int argc, const char **argv) {
	const char *algo = argv[1];
	const char *key = argv[2];
	const char *iv = argv[3];
	return bool2status(encrypt_or_decrypt_block(core, algo, key, 1, iv));
}

RZ_IPI RzCmdStatus rz_write_op_sequence_handler(RzCore *core, int argc, const char **argv) {
	ut64 from = rz_num_math(NULL, argv[1]);
	ut64 to = rz_num_math(NULL, argv[2]);
	ut64 step = rz_num_math(NULL, argv[3]);
	int value_size = (int)rz_num_math(NULL, argv[4]);
	if (step < 1) {
		RZ_LOG_ERROR("Invalid <step> value: %" PFMT64d "\n", step);
		return RZ_CMD_STATUS_ERROR;
	}
	if (value_size != 1 && value_size != 2 && value_size != 4 && value_size != 8) {
		RZ_LOG_ERROR("Invalid <value_size> value: %d\n", value_size);
		return RZ_CMD_STATUS_ERROR;
	}
	ut64 max_val = (1ULL << (8 * value_size));
	if (from >= max_val) {
		RZ_LOG_ERROR("Invalid <from> value: %" PFMT64d "\n", from);
		return RZ_CMD_STATUS_ERROR;
	}
	if (to >= max_val) {
		RZ_LOG_ERROR("Invalid <to> value: %" PFMT64d "\n", to);
		return RZ_CMD_STATUS_ERROR;
	}

	return bool2status(rz_core_write_seq_at(core, core->offset, from, to, step, value_size));
}

RZ_IPI RzCmdStatus rz_write_debruijn_handler(RzCore *core, int argc, const char **argv) {
	int len = (int)rz_num_math(core->num, argv[1]);
	if (len < 0) {
		RZ_LOG_ERROR("Invalid length: %d\n", len);
		return RZ_CMD_STATUS_ERROR;
	}
	char *p = rz_debruijn_pattern(len, 0, NULL);
	if (!p) {
		RZ_LOG_ERROR("Cannot create Debrujn sequence of length %d\n", len);
		return RZ_CMD_STATUS_ERROR;
	}
	bool res = rz_core_write_string_at(core, core->offset, p);
	free(p);
	return bool2status(res);
}

RZ_IPI RzCmdStatus rz_write_debruijn_find_handler(RzCore *core, int argc, const char **argv) {
	ut64 value = rz_num_math(core->num, argv[1]);
	int offset = rz_debruijn_offset(0, NULL, value, rz_config_get_b(core->config, "cfg.bigendian"));
	if (offset < 0) {
		RZ_LOG_ERROR("Could not find value %" PFMT64x " in Debruijn sequence.\n", value);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%d\n", offset);
	return RZ_CMD_STATUS_OK;
}
