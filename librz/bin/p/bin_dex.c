// SPDX-FileCopyrightText: 2011-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2011-2021 h4ng3r
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include "../i/private.h"
#include "dex/dex.h"
#define rz_hash_adler32 __adler32
#include "../../hash/adler32.c"

// globals to be removed
extern struct rz_bin_dbginfo_t rz_bin_dbginfo_dex;
static bool dexdump = false;
static Sdb *mdb = NULL;
static const char *dexSubsystem = NULL;
static bool simplifiedDemangling = false; // depends on asm.pseudo

static ut64 get_method_flags(ut64 MA) {
	ut64 flags = 0;
	if (MA & RZ_DEX_METH_PUBLIC) {
		flags |= RZ_BIN_METH_PUBLIC;
	}
	if (MA & RZ_DEX_METH_PRIVATE) {
		flags |= RZ_BIN_METH_PRIVATE;
	}
	if (MA & RZ_DEX_METH_PROTECTED) {
		flags |= RZ_BIN_METH_PROTECTED;
	}
	if (MA & RZ_DEX_METH_STATIC) {
		flags |= RZ_BIN_METH_STATIC;
	}
	if (MA & RZ_DEX_METH_FINAL) {
		flags |= RZ_BIN_METH_FINAL;
	}
	if (MA & RZ_DEX_METH_SYNCHRONIZED) {
		flags |= RZ_BIN_METH_SYNCHRONIZED;
	}
	if (MA & RZ_DEX_METH_BRIDGE) {
		flags |= RZ_BIN_METH_BRIDGE;
	}
	if (MA & RZ_DEX_METH_VARARGS) {
		flags |= RZ_BIN_METH_VARARGS;
	}
	if (MA & RZ_DEX_METH_NATIVE) {
		flags |= RZ_BIN_METH_NATIVE;
	}
	if (MA & RZ_DEX_METH_ABSTRACT) {
		flags |= RZ_BIN_METH_ABSTRACT;
	}
	if (MA & RZ_DEX_METH_STRICT) {
		flags |= RZ_BIN_METH_STRICT;
	}
	if (MA & RZ_DEX_METH_SYNTHETIC) {
		flags |= RZ_BIN_METH_SYNTHETIC;
	}
	if (MA & RZ_DEX_METH_MIRANDA) {
		flags |= RZ_BIN_METH_MIRANDA;
	}
	if (MA & RZ_DEX_METH_CONSTRUCTOR) {
		flags |= RZ_BIN_METH_CONSTRUCTOR;
	}
	if (MA & RZ_DEX_METH_DECLARED_SYNCHRONIZED) {
		flags |= RZ_BIN_METH_DECLARED_SYNCHRONIZED;
	}
	return flags;
}

static ut64 offset_of_method_idx(RzBinFile *bf, struct rz_bin_dex_obj_t *dex, int idx) {
	// ut64 off = dex->header.method_offset + idx;
	return sdb_num_get(mdb, sdb_fmt("method.%d", idx), 0);
}

static ut64 dex_field_offset(RzBinDexObj *bin, int fid) {
	return bin->header.fields_offset + (fid * 8); // (sizeof (DexField) * fid);
}

static const char *getstr(RzBinDexObj *dex, int idx) {
	ut8 buf[LEB_MAX_SIZE];
	if (idx < 0 || idx >= dex->header.strings_size || !dex->strings) {
		return NULL;
	}
	if (dex->cal_strings) {
		const char *p = dex->cal_strings[idx];
		if (!RZ_STR_ISEMPTY(p)) {
			return p;
		}
	} else {
		dex->cal_strings = RZ_NEWS0(char *, dex->header.strings_size);
	}
	const ut32 string_index = dex->strings[idx];
	if (string_index >= dex->size) {
		return NULL;
	}
	if (rz_buf_read_at(dex->b, string_index, buf, sizeof(buf)) != sizeof(buf)) {
		return NULL;
	}
	ut64 len;
	int uleblen = rz_uleb128(buf, sizeof(buf), &len, NULL) - buf;
	if (!uleblen || uleblen >= dex->size || uleblen >= dex->header.strings_size) {
		return NULL;
	}
	if (!len || len >= dex->size) {
		return NULL;
	}
	ut8 *ptr = malloc(len + 1);
	if (ptr) {
		rz_buf_read_at(dex->b, string_index + uleblen, ptr, len);
		ptr[len] = 0;
		dex->cal_strings[idx] = (char *)ptr;
		return (const char *)ptr;
	}
	return NULL;
}

//  TODO move to util
static int countOnes(ut32 val) {
	if (!val) {
		return 0;
	}
	/* visual studio doesnt supports __buitin_clz */
#if defined(_MSC_VER) || defined(__TINYC__)
	int count = 0;
	val = val - ((val >> 1) & 0x55555555);
	val = (val & 0x33333333) + ((val >> 2) & 0x33333333);
	count = (((val + (val >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
	return count;
#else
	return __builtin_clz(val);
#endif
}

typedef enum {
	kAccessForClass = 0,
	kAccessForMethod = 1,
	kAccessForField = 2,
	kAccessForMAX
} AccessFor;

static char *createAccessFlagStr(ut32 flags, AccessFor forWhat) {
#define NUM_FLAGS 18
	static const char *kAccessStrings[kAccessForMAX][NUM_FLAGS] = {
		{
			/* class, inner class */
			"PUBLIC", /* 0x0001 */
			"PRIVATE", /* 0x0002 */
			"PROTECTED", /* 0x0004 */
			"STATIC", /* 0x0008 */
			"FINAL", /* 0x0010 */
			"?", /* 0x0020 */
			"?", /* 0x0040 */
			"?", /* 0x0080 */
			"?", /* 0x0100 */
			"INTERFACE", /* 0x0200 */
			"ABSTRACT", /* 0x0400 */
			"?", /* 0x0800 */
			"SYNTHETIC", /* 0x1000 */
			"ANNOTATION", /* 0x2000 */
			"ENUM", /* 0x4000 */
			"?", /* 0x8000 */
			"VERIFIED", /* 0x10000 */
			"OPTIMIZED", /* 0x20000 */
		},
		{
			/* method */
			"PUBLIC", /* 0x0001 */
			"PRIVATE", /* 0x0002 */
			"PROTECTED", /* 0x0004 */
			"STATIC", /* 0x0008 */
			"FINAL", /* 0x0010 */
			"SYNCHRONIZED", /* 0x0020 */
			"BRIDGE", /* 0x0040 */
			"VARARGS", /* 0x0080 */
			"NATIVE", /* 0x0100 */
			"?", /* 0x0200 */
			"ABSTRACT", /* 0x0400 */
			"STRICT", /* 0x0800 */
			"SYNTHETIC", /* 0x1000 */
			"?", /* 0x2000 */
			"?", /* 0x4000 */
			"MIRANDA", /* 0x8000 */
			"CONSTRUCTOR", /* 0x10000 */
			"DECLARED_SYNCHRONIZED", /* 0x20000 */
		},
		{
			/* field */
			"PUBLIC", /* 0x0001 */
			"PRIVATE", /* 0x0002 */
			"PROTECTED", /* 0x0004 */
			"STATIC", /* 0x0008 */
			"FINAL", /* 0x0010 */
			"?", /* 0x0020 */
			"VOLATILE", /* 0x0040 */
			"TRANSIENT", /* 0x0080 */
			"?", /* 0x0100 */
			"?", /* 0x0200 */
			"?", /* 0x0400 */
			"?", /* 0x0800 */
			"SYNTHETIC", /* 0x1000 */
			"?", /* 0x2000 */
			"ENUM", /* 0x4000 */
			"?", /* 0x8000 */
			"?", /* 0x10000 */
			"?", /* 0x20000 */
		},
	};
	size_t i, count = countOnes(flags);
	const int kLongest = 21;
	const int maxSize = (count + 1) * (kLongest + 1);
	char *str, *cp;
	// produces a huge number????
	if (count < 1 || (count * (kLongest + 1)) < 1) {
		return NULL;
	}
	cp = str = (char *)calloc(count + 1, (kLongest + 1));
	if (!str) {
		return NULL;
	}
	for (i = 0; i < NUM_FLAGS; i++) {
		if (flags & 0x01) {
			const char *accessStr = kAccessStrings[forWhat][i];
			int len = strlen(accessStr);
			if (cp != str) {
				*cp++ = ' ';
			}
			if (((cp - str) + len) >= maxSize) {
				free(str);
				return NULL;
			}
			memcpy(cp, accessStr, len);
			cp += len;
		}
		flags >>= 1;
	}
	*cp = '\0';
	return str;
}

static const char *dex_type_descriptor(RzBinDexObj *bin, int type_idx) {
	if (type_idx < 0 || type_idx >= bin->header.types_size) {
		return NULL;
	}
	return getstr(bin, bin->types[type_idx].descriptor_id);
}

static ut16 type_desc(RzBinDexObj *bin, ut16 type_idx) {
	if (type_idx >= bin->header.types_size || type_idx >= bin->size) {
		return UT16_MAX;
	}
	return bin->types[type_idx].descriptor_id;
}

static char *dex_get_proto(RzBinDexObj *bin, int proto_id) {
	if (proto_id >= bin->header.prototypes_size) {
		return NULL;
	}
	ut32 params_off = bin->protos[proto_id].parameters_off;
	if (params_off >= bin->size) {
		return NULL;
	}
	ut32 type_id = bin->protos[proto_id].return_type_id;
	if (type_id >= bin->header.types_size) {
		return NULL;
	}
	const char *return_type = getstr(bin, bin->types[type_id].descriptor_id);
	if (!return_type) {
		return NULL;
	}
	if (!params_off) {
		return rz_str_newf("()%s", return_type);
		;
	}
	ut8 params_buf[sizeof(ut32)];
	if (!rz_buf_read_at(bin->b, params_off, params_buf, sizeof(params_buf))) {
		return NULL;
	}
	// size of the list, in 16 bit entries
	ut32 list_size = rz_read_le32(params_buf);
	if (list_size >= ST32_MAX) {
		eprintf("Warning: function prototype contains too many parameters (> 2 million).\n");
		list_size = ST32_MAX;
	}
	size_t typeidx_bufsize = (list_size * sizeof(ut16));
	if (params_off + typeidx_bufsize > bin->size) {
		typeidx_bufsize = bin->size - params_off;
		eprintf("Warning: truncated typeidx buffer\n");
	}
	RzStrBuf *sig = rz_strbuf_new("(");
	if (typeidx_bufsize > 0) {
		ut8 *typeidx_buf = malloc(typeidx_bufsize);
		if (!typeidx_buf || !rz_buf_read_at(bin->b, params_off + 4, typeidx_buf, typeidx_bufsize)) {
			rz_strbuf_free(sig);
			return NULL;
		}
		size_t off;
		for (off = 0; off + 1 < typeidx_bufsize; off += 2) {
			ut16 type_idx = rz_read_le16(typeidx_buf + off);
			ut16 type_desc_id = type_desc(bin, type_idx);
			if (type_desc_id == UT16_MAX) {
				rz_strbuf_append(sig, "?;");
			} else {
				const char *buff = getstr(bin, type_desc_id);
				rz_strbuf_append(sig, buff ? buff : "?;");
			}
		}
		free(typeidx_buf);
	}
	rz_strbuf_appendf(sig, ")%s", return_type);
	return rz_strbuf_drain(sig);
}

static char *dex_method_signature(RzBinDexObj *bin, int method_idx) {
	if (method_idx < 0 || method_idx >= bin->header.method_size) {
		return NULL;
	}
	return dex_get_proto(bin, bin->methods[method_idx].proto_id);
}

static ut32 read32(RzBuffer *b, ut64 addr) {
	ut32 n = 0;
	rz_buf_read_at(b, addr, (ut8 *)&n, sizeof(n));
	return rz_read_le32(&n);
}

static ut16 read16(RzBuffer *b, ut64 addr) {
	ut16 n = 0;
	rz_buf_read_at(b, addr, (ut8 *)&n, sizeof(n));
	return rz_read_le16(&n);
}

static RzList *dex_method_signature2(RzBinDexObj *bin, int method_idx) {
	ut32 proto_id, params_off, list_size;
	ut16 type_idx;
	size_t i;

	RzList *params = rz_list_new();
	if (!params) {
		return NULL;
	}
	if (method_idx < 0 || method_idx >= bin->header.method_size) {
		goto out_error;
	}
	proto_id = bin->methods[method_idx].proto_id;
	if (proto_id >= bin->header.prototypes_size) {
		goto out_error;
	}
	params_off = bin->protos[proto_id].parameters_off;
	if (params_off >= bin->size) {
		goto out_error;
	}
	if (!params_off) {
		return params;
	}
	list_size = read32(bin->b, params_off);
	for (i = 0; i < list_size; i++) {
		ut64 of = params_off + 4 + (i * 2);
		if (of >= bin->size || of < params_off) {
			break;
		}
		type_idx = read16(bin->b, of);
		if (type_idx >= bin->header.types_size || type_idx > bin->size) {
			break;
		}
		const char *buff = getstr(bin, bin->types[type_idx].descriptor_id);
		if (!buff) {
			break;
		}
		rz_list_append(params, (void *)buff);
	}
	return params;
out_error:
	rz_list_free(params);
	return NULL;
}

// TODO: fix this, now has more registers that it should
// XXX. this is using binfile->buf directly :(
// https://github.com/android/platform_dalvik/blob/0641c2b4836fae3ee8daf6c0af45c316c84d5aeb/libdex/DexDebugInfo.cpp#L312
// https://github.com/android/platform_dalvik/blob/0641c2b4836fae3ee8daf6c0af45c316c84d5aeb/libdex/DexDebugInfo.cpp#L141
static void dex_parse_debug_item(RzBinFile *bf, RzBinDexClass *c, int MI, int MA, int paddr, int ins_size, int insns_size, char *class_name, int regsz, int debug_info_off, RzBinSourceLineInfoBuilder *bob) {
	RzBin *rbin = bf->rbin;
	RzBinDexObj *dex = bf->o->bin_obj; //  bin .. unnecessary arg
	// runtime error: pointer index expression with base 0x000000004402 overflowed to 0xffffffffff0043fc
	if (debug_info_off >= rz_buf_size(bf->buf)) {
		return;
	}
	ut64 line_start;
	ut64 parameters_size;
	ut64 param_type_idx;
	ut16 argReg = regsz - ins_size;
	ut64 source_file_idx = c->source_file;
	RzList *params, *debug_positions, *emitted_debug_locals = NULL;
	bool keep = true;
	if (argReg > regsz) {
		return; // this return breaks tests
	}
	rz_buf_seek(bf->buf, debug_info_off, RZ_BUF_SET);
	ut64 res;
	rz_buf_uleb128(bf->buf, &res);
	line_start = res;
	rz_buf_uleb128(bf->buf, &res);
	parameters_size = res;

	// TODO: check when we should use source_file
	// The state machine consists of five registers
	ut32 address = 0;
	ut32 line = line_start;
	if (!(debug_positions = rz_list_newf((RzListFree)free))) {
		return;
	}
	if (!(emitted_debug_locals = rz_list_newf((RzListFree)free))) {
		free(debug_positions);
		return;
	}

	struct dex_debug_local_t *debug_locals = calloc(sizeof(struct dex_debug_local_t), regsz + 1);
	if (!(MA & 0x0008)) {
		debug_locals[argReg].name = "this";
		debug_locals[argReg].descriptor = rz_str_newf("%s;", class_name);
		debug_locals[argReg].startAddress = 0;
		debug_locals[argReg].signature = NULL;
		debug_locals[argReg].live = true;
		argReg++;
	}
	if (!(params = dex_method_signature2(dex, MI))) {
		goto beach;
	}

	RzListIter *iter;
	const char *name;
	char *type;
	int reg;

	rz_list_foreach (params, iter, type) {
		if ((argReg >= regsz) || !type || parameters_size <= 0) {
			goto beach;
		}
		(void)rz_buf_uleb128(bf->buf, &res);
		param_type_idx = res - 1;
		name = getstr(dex, param_type_idx);
		reg = argReg;
		switch (type[0]) {
		case 'D':
		case 'J':
			argReg += 2;
			break;
		default:
			argReg += 1;
			break;
		}
		if (!name || !*name) {
			debug_locals[reg].name = name;
			debug_locals[reg].descriptor = type;
			debug_locals[reg].signature = NULL;
			debug_locals[reg].startAddress = address;
			debug_locals[reg].live = true;
		}
		parameters_size--;
	}
	ut8 opcode = 0;
	if (rz_buf_read(bf->buf, &opcode, 1) != 1) {
		goto beach;
	}
	while (keep) {
		switch (opcode) {
		case 0x0: // DBG_END_SEQUENCE
			keep = false;
			break;
		case 0x1: // DBG_ADVANCE_PC
		{
			ut64 addr_diff;
			rz_buf_uleb128(bf->buf, &addr_diff);
			address += addr_diff;
		} break;
		case 0x2: // DBG_ADVANCE_LINE
		{
			st64 line_diff;
			rz_buf_sleb128(bf->buf, &line_diff);
			line += line_diff;
		} break;
		case 0x3: // DBG_START_LOCAL
		{
			ut64 register_num, name_idx, type_idx;
			rz_buf_uleb128(bf->buf, &register_num);
			rz_buf_uleb128(bf->buf, &name_idx);
			rz_buf_uleb128(bf->buf, &type_idx);
			name_idx--;
			type_idx--;
			if (register_num >= regsz) {
				goto beach;
			}
			// Emit what was previously there, if anything
			// emitLocalCbIfLive
			if (debug_locals[register_num].live) {
				struct dex_debug_local_t *local = malloc(
					sizeof(struct dex_debug_local_t));
				if (!local) {
					keep = false;
					break;
				}
				local->name = debug_locals[register_num].name;
				local->descriptor = debug_locals[register_num].descriptor;
				local->startAddress = debug_locals[register_num].startAddress;
				local->signature = debug_locals[register_num].signature;
				local->live = true;
				local->reg = register_num;
				local->endAddress = address;
				rz_list_append(emitted_debug_locals, local);
			}
			debug_locals[register_num].name = getstr(dex, name_idx);
			debug_locals[register_num].descriptor = dex_type_descriptor(dex, type_idx);
			debug_locals[register_num].startAddress = address;
			debug_locals[register_num].signature = NULL;
			debug_locals[register_num].live = true;
			//eprintf("DBG_START_LOCAL %x %x %x\n", register_num, name_idx, type_idx);
		} break;
		case 0x4: //DBG_START_LOCAL_EXTENDED
		{
			ut64 register_num, name_idx, type_idx, sig_idx;
			rz_buf_uleb128(bf->buf, &register_num);
			rz_buf_uleb128(bf->buf, &name_idx);
			rz_buf_uleb128(bf->buf, &type_idx);
			rz_buf_uleb128(bf->buf, &sig_idx);
			sig_idx--;
			type_idx--;
			name_idx--;
			if (register_num >= regsz) {
				goto beach;
			}

			// Emit what was previously there, if anything
			// emitLocalCbIfLive
			if (debug_locals[register_num].live) {
				struct dex_debug_local_t *local = malloc(
					sizeof(struct dex_debug_local_t));
				if (!local) {
					keep = false;
					break;
				}
				local->name = debug_locals[register_num].name;
				local->descriptor = debug_locals[register_num].descriptor;
				local->startAddress = debug_locals[register_num].startAddress;
				local->signature = debug_locals[register_num].signature;
				local->live = true;
				local->reg = register_num;
				local->endAddress = address;
				rz_list_append(emitted_debug_locals, local);
			}
			debug_locals[register_num].name = getstr(dex, name_idx);
			debug_locals[register_num].descriptor = dex_type_descriptor(dex, type_idx);
			debug_locals[register_num].startAddress = address;
			debug_locals[register_num].signature = getstr(dex, sig_idx);
			debug_locals[register_num].live = true;
		} break;
		case 0x5: // DBG_END_LOCAL
		{
			ut64 register_num;
			rz_buf_uleb128(bf->buf, &register_num);
			// emitLocalCbIfLive
			if (register_num >= regsz) {
				goto beach;
			}
			if (debug_locals[register_num].live) {
				struct dex_debug_local_t *local = malloc(
					sizeof(struct dex_debug_local_t));
				if (!local) {
					keep = false;
					break;
				}
				local->name = debug_locals[register_num].name;
				local->descriptor = debug_locals[register_num].descriptor;
				local->startAddress = debug_locals[register_num].startAddress;
				local->signature = debug_locals[register_num].signature;
				local->live = true;
				local->reg = register_num;
				local->endAddress = address;
				rz_list_append(emitted_debug_locals, local);
			}
			debug_locals[register_num].live = false;
		} break;
		case 0x6: // DBG_RESTART_LOCAL
		{
			ut64 register_num;
			rz_buf_uleb128(bf->buf, &register_num);
			if (register_num >= regsz) {
				goto beach;
			}
			if (!debug_locals[register_num].live) {
				debug_locals[register_num].startAddress = address;
				debug_locals[register_num].live = true;
			}
		} break;
		case 0x7: //DBG_SET_PROLOGUE_END
			break;
		case 0x8: //DBG_SET_PROLOGUE_BEGIN
			break;
		case 0x9: {
			ut64 res;
			rz_buf_uleb128(bf->buf, &res);
			source_file_idx = res - 1;
		} break;
		default: {
			int adjusted_opcode = opcode - 10;
			address += (adjusted_opcode / 15);
			line += -4 + (adjusted_opcode % 15);
			struct dex_debug_position_t *position =
				RZ_NEW0(struct dex_debug_position_t);
			if (!position) {
				keep = false;
				break;
			}
			position->source_file_idx = source_file_idx;
			position->address = address;
			position->line = line;
			rz_list_append(debug_positions, position);
		} break;
		}
		if (rz_buf_read(bf->buf, &opcode, 1) != 1) {
			break;
		}
	}

	RzListIter *iter1;
	struct dex_debug_position_t *pos;
	if (bob) {
		rz_list_foreach (debug_positions, iter1, pos) {
			const char *file = getstr(dex, pos->source_file_idx);
			if (!file || !*file) {
				continue;
			}
			rz_bin_source_line_info_builder_push_sample(bob, pos->address + paddr, pos->line, 0, file);
		}
	}
	if (!dexdump) {
		goto beach;
	}

	RzListIter *iter2;
	struct dex_debug_position_t *position;

	rbin->cb_printf("      positions     :\n");
	rz_list_foreach (debug_positions, iter2, position) {
		rbin->cb_printf("        0x%04" PFMT64x " line=%llu\n",
			position->address, position->line);
	}

	rbin->cb_printf("      locals        :\n");

	RzListIter *iter3;
	struct dex_debug_local_t *local;
	rz_list_foreach (emitted_debug_locals, iter3, local) {
		if (local->signature) {
			rbin->cb_printf(
				"        0x%04x - 0x%04x reg=%d %s %s %s\n",
				local->startAddress, local->endAddress,
				local->reg, local->name, local->descriptor,
				local->signature);
		} else {
			rbin->cb_printf(
				"        0x%04x - 0x%04x reg=%d %s %s\n",
				local->startAddress, local->endAddress,
				local->reg, local->name, local->descriptor);
		}
	}

	for (reg = 0; reg < regsz; reg++) {
		if (!debug_locals[reg].name) {
			continue;
		}
		if (debug_locals[reg].live) {
			if (debug_locals[reg].signature) {
				rbin->cb_printf(
					"        0x%04x - 0x%04x reg=%d %s %s %s\n",
					debug_locals[reg].startAddress,
					insns_size, reg, debug_locals[reg].name,
					debug_locals[reg].descriptor,
					debug_locals[reg].signature);
			} else {
				rbin->cb_printf(
					"        0x%04x - 0x%04x reg=%d %s %s\n",
					debug_locals[reg].startAddress,
					insns_size, reg, debug_locals[reg].name,
					debug_locals[reg].descriptor);
			}
		}
	}
beach:
	rz_list_free(debug_positions);
	rz_list_free(emitted_debug_locals);
	rz_list_free(params);
	free(debug_locals);
}

static Sdb *get_sdb(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	RzBinObject *o = bf->o;
	rz_return_val_if_fail(o && o->bin_obj, NULL);
	struct rz_bin_dex_obj_t *bin = (struct rz_bin_dex_obj_t *)o->bin_obj;
	return bin->kv;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	*bin_obj = rz_bin_dex_new_buf(buf);
	return *bin_obj != NULL;
}

static ut64 baddr(RzBinFile *bf) {
	return 0;
}

static bool check_buffer(RzBuffer *buf) {
	ut8 tmp[8];
	int r = rz_buf_read_at(buf, 0, tmp, sizeof(tmp));
	if (r < sizeof(tmp)) {
		return false;
	}
	// Non-extended opcode dex file
	if (!memcmp(tmp, "dex\n035\0", 8)) {
		return true;
	}
	// Extended (jumnbo) opcode dex file, ICS+ only (sdk level 14+)
	if (!memcmp(tmp, "dex\n036\0", 8)) {
		return true;
	}
	// Two new opcodes: invoke-polymorphic and invoke-custom (sdk level 26+)
	if (!memcmp(tmp, "dex\n038\0", 8)) {
		return true;
	}
	// M3 (Nov-Dec 07)
	if (!memcmp(tmp, "dex\n009\0", 8)) {
		return true;
	}
	// M5 (Feb-Mar 08)
	if (!memcmp(tmp, "dex\n009\0", 8)) {
		return true;
	}
	// Default fall through, should still be a dex file
	if (!memcmp(tmp, "dex\n", 4)) {
		return true;
	}
	return false;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinHash *h;
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = bf->file ? strdup(bf->file) : NULL;
	ret->type = strdup("DEX CLASS");
	ret->has_va = true;
	ret->bclass = rz_bin_dex_get_version(bf->o->bin_obj);
	ret->rclass = strdup("class");
	ret->os = strdup("linux");
	ret->subsystem = strdup(dexSubsystem ? dexSubsystem : "java");
	ret->machine = strdup("Dalvik VM");
	h = &ret->sum[0];
	h->type = "sha1";
	h->len = 20;
	h->addr = 12;
	h->from = 12;
	h->to = rz_buf_size(bf->buf) - 32;
	rz_buf_read_at(bf->buf, 12, h->buf, 20);
	h = &ret->sum[1];
	h->type = "adler32";
	h->len = 4;
	h->addr = 8;
	h->from = 12;
	h->to = rz_buf_size(bf->buf) - h->from;
	rz_buf_read_at(bf->buf, 8, h->buf, 12);
	h = &ret->sum[2];
	h->type = 0;
	rz_buf_read_at(bf->buf, 8, h->buf, 4);
	// this is slow but computed once, so we can use rz_buf_data or just do rz_buf_read()
	// not sure if we want to expose the computed checksum everytime we open the file
	// also the checksum is computed by other methods in RzBin, so maybe good to generalize
	{
		ut32 fc = rz_buf_read_le32_at(bf->buf, 8);
		ut64 tmpsz;
		const ut8 *tmp = rz_buf_data(bf->buf, &tmpsz);
		ut32 cc = __adler32(tmp + 12, tmpsz - 12);
		if (fc != cc) {
			eprintf("# adler32 checksum doesn't match. Type this to fix it:\n");
			eprintf("wx `ph sha1 $s-32 @32` @12 ; wx `ph adler32 $s-12 @12` @8\n");
		}
	}
	ret->arch = strdup("dalvik");
	ret->lang = "dalvik";
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0; //1 | 4 | 8; /* Stripped | LineNums | Syms */
	return ret;
}

static RzList *strings(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o, NULL);
	RzBinString *ptr = NULL;
	RzList *ret = NULL;
	int i;
	ut64 len;
	ut8 buf[LEB_MAX_SIZE];
	ut64 off;
	struct rz_bin_dex_obj_t *bin = (struct rz_bin_dex_obj_t *)bf->o->bin_obj;
	if (!bin || !bin->strings) {
		return NULL;
	}
	if (bin->header.strings_size > bin->size) {
		bin->strings = NULL;
		return NULL;
	}
	if (!(ret = rz_list_newf(free))) {
		return NULL;
	}
	for (i = 0; i < bin->header.strings_size; i++) {
		if (!(ptr = RZ_NEW0(RzBinString))) {
			break;
		}
		if (bin->strings[i] > bin->size || bin->strings[i] + 6 > bin->size) {
			goto out_error;
		}
		rz_buf_read_at(bin->b, bin->strings[i], buf, sizeof(buf));
		rz_uleb128(buf, sizeof(buf), &len, NULL);

		if (len > 5 && len < RZ_BIN_SIZEOF_STRINGS) {
			ptr->string = malloc(len + 1);
			if (!ptr->string) {
				goto out_error;
			}
			off = bin->strings[i] + rz_uleb128_len(buf, sizeof(buf));
			if (off + len >= bin->size || off + len < len) {
				free(ptr->string);
				goto out_error;
			}
			rz_buf_read_at(bin->b, off, (ut8 *)ptr->string, len);
			ptr->string[len] = 0;
			if ((ptr->string[0] == 'L' && strchr(ptr->string, '/')) || !strncmp(ptr->string, "[L", 2)) {
				free(ptr->string);
				free(ptr);
				continue;
			}
			ptr->vaddr = ptr->paddr = bin->strings[i];
			ptr->size = len;
			ptr->length = len;
			ptr->ordinal = i + 1;
			rz_list_append(ret, ptr);
		} else {
			free(ptr);
		}
	}
	return ret;
out_error:
	rz_list_free(ret);
	free(ptr);
	return NULL;
}

static const char *dex_method_name(RzBinDexObj *bin, int idx) {
	if (idx < 0 || idx >= bin->header.method_size) {
		return NULL;
	}
	ut16 cid = bin->methods[idx].class_id;
	if (cid >= bin->header.strings_size) {
		return NULL;
	}
	int tid = bin->methods[idx].name_id;
	if (tid < 0 || tid >= bin->header.strings_size) {
		return NULL;
	}
	return getstr(bin, tid);
}

static char *simplify(char *s) {
	char *p = (char *)rz_str_rchr(s, NULL, '/');
	if (p) {
		rz_str_cpy(s, p + 1);
	}
	rz_str_replace_char(s, '/', '.');
	return s;
}

static char *dex_class_name_byid(RzBinDexObj *bin, int cid) {
	rz_return_val_if_fail(bin && bin->types, NULL);
	if (cid < 0 || cid >= bin->header.types_size) {
		return NULL;
	}
	int tid = bin->types[cid].descriptor_id;
	const char *s = getstr(bin, tid);
	if (s) {
		char *r = strdup(s);
		if (simplifiedDemangling) {
			simplify(r);
		}
		return r;
	}
	return NULL;
}

static char *dex_class_name(RzBinDexObj *bin, RzBinDexClass *c) {
	char *s = dex_class_name_byid(bin, c->class_id);
	if (simplifiedDemangling) {
		simplify(s);
		if (*s == 'L') {
			rz_str_cpy(s, s + 1);
		}
	}
	return s;
}

static char *dex_field_name(RzBinDexObj *bin, int fid) {
	int tid;
	ut16 cid, type_id;
	rz_return_val_if_fail(bin && bin->fields, NULL);

	if (fid < 0 || fid >= bin->header.fields_size) {
		return NULL;
	}
	cid = bin->fields[fid].class_id;
	if (cid >= bin->header.types_size) {
		return NULL;
	}
	type_id = bin->fields[fid].type_id;
	if (type_id >= bin->header.types_size) {
		return NULL;
	}
	tid = bin->fields[fid].name_id;
	const char *a = getstr(bin, bin->types[cid].descriptor_id);
	const char *b = getstr(bin, tid);
	const char *c = getstr(bin, bin->types[type_id].descriptor_id);
	if (simplifiedDemangling) {
		if (a && b && c) {
			char *_a = simplify(strdup(a));
			char *_b = simplify(strdup(b));
			char *_c = simplify(strdup(c));
			char *str = rz_str_newf("(%s) %s.%s", _c, _a, _b);
			free(_a);
			free(_b);
			free(_c);
			return str;
		}
		return rz_str_newf("(%d) %d.%d",
			bin->types[type_id].descriptor_id,
			tid,
			bin->types[cid].descriptor_id);
	}
	return (a && b && c)
		? rz_str_newf("%s->%s %s", a, b, c)
		: rz_str_newf("%d->%d %d", bin->types[cid].descriptor_id, tid, bin->types[type_id].descriptor_id);
}

static char *dex_method_fullname(RzBinDexObj *bin, int method_idx) {
	rz_return_val_if_fail(bin && bin->types, NULL);
	if (method_idx < 0 || method_idx >= bin->header.method_size) {
		return NULL;
	}
	ut16 cid = bin->methods[method_idx].class_id;
	if (cid >= bin->header.types_size) {
		return NULL;
	}
	const char *name = dex_method_name(bin, method_idx);
	if (!name) {
		return NULL;
	}
	char *flagname = NULL;

	char *class_name = dex_class_name_byid(bin, cid);
	if (!class_name) {
		class_name = strdup("???");
	}
	rz_str_replace_char(class_name, ';', 0);
	char *signature = dex_method_signature(bin, method_idx);
	if (signature) {
		flagname = rz_str_newf("%s.%s%s", class_name, name, signature);
		free(signature);
	} else {
		flagname = rz_str_newf("%s.%s%s", class_name, name, "???");
	}
	free(class_name);
	if (flagname && simplifiedDemangling) {
		char *p = strchr(flagname, '(');
		if (p) {
			*p = 0;
			char *q = strchr(p + 1, ')');
			if (q) {
				simplify(q + 1);
				rz_str_cpy(p, q + 1);
			}
			simplify(flagname);
		}
	}
	return flagname;
}

static ut64 dex_get_type_offset(RzBinFile *bf, int type_idx) {
	RzBinDexObj *bin = (RzBinDexObj *)bf->o->bin_obj;
	if (!bin || !bin->types) {
		return 0;
	}
	if (type_idx < 0 || type_idx >= bin->header.types_size) {
		return 0;
	}
	return bin->header.types_offset + type_idx * 0x04; //&bin->types[type_idx];
}

static const char *dex_class_super_name(RzBinDexObj *bin, RzBinDexClass *c) {
	rz_return_val_if_fail(bin && bin->types && c, NULL);

	int cid = c->super_class;
	if (cid < 0 || cid >= bin->header.types_size) {
		return NULL;
	}
	int tid = bin->types[cid].descriptor_id;
	return getstr(bin, tid);
}

static ut64 peek_uleb(RzBuffer *b, bool *err, size_t *nn) {
	ut64 n = UT64_MAX;
	int len = rz_buf_uleb128(b, &n);
	if (len < 1) {
		if (err) {
			*err |= true;
		}
	} else {
		*nn += len;
	}
	return n;
}

static void parse_dex_class_fields(RzBinFile *bf, RzBinDexClass *c, RzBinClass *cls,
	int *sym_count, ut64 fields_count, bool is_sfield) {
	RzBinDexObj *dex = bf->o->bin_obj;
	RzBin *bin = bf->rbin;
	ut64 lastIndex = 0;
	ut8 ff[sizeof(DexField)] = { 0 };
	int total, tid;
	DexField field;
	size_t i, skip = 0;

	for (i = 0; i < fields_count; i++) {
		bool err = false;
		ut64 fieldIndex = peek_uleb(bf->buf, &err, &skip);
		ut64 accessFlags = peek_uleb(bf->buf, &err, &skip);
		if (err) {
			break;
		}
		fieldIndex += lastIndex;
		total = dex->header.fields_offset + (sizeof(DexField) * fieldIndex);
		if (total >= dex->size || total < dex->header.fields_offset) {
			break;
		}
		if (rz_buf_read_at(bf->buf, total, ff, sizeof(DexField)) != sizeof(DexField)) {
			break;
		}
		field.class_id = rz_read_le16(ff);
		field.type_id = rz_read_le16(ff + 2);
		field.name_id = rz_read_le32(ff + 4);
		const char *fieldName = getstr(dex, field.name_id);
		if (field.type_id >= dex->header.types_size) {
			break;
		}
		tid = dex->types[field.type_id].descriptor_id;
		const char *type_str = getstr(dex, tid);
		RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
		if (!sym) {
			break;
		}
		if (is_sfield) {
			sym->name = rz_str_newf("%s.sfield_%s:%s", cls->name, fieldName, type_str);
			sym->type = "STATIC";
		} else {
			sym->name = rz_str_newf("%s.ifield_%s:%s", cls->name, fieldName, type_str);
			sym->type = "FIELD";
		}
		sym->name = rz_str_replace(sym->name, "method.", "", 0);
		rz_str_replace_char(sym->name, ';', 0);
		sym->paddr = sym->vaddr = total;
		sym->ordinal = (*sym_count)++;

		if (dexdump) {
			char *accessStr = createAccessFlagStr(
				accessFlags, kAccessForField);
			bin->cb_printf("    #%zu              : (in %s;)\n", i,
				cls->name);
			bin->cb_printf("      name          : '%s'\n", fieldName);
			bin->cb_printf("      type          : '%s'\n", type_str);
			bin->cb_printf("      access        : 0x%04x (%s)\n",
				(ut32)accessFlags, accessStr ? accessStr : "");
			free(accessStr);
		}
		rz_list_append(dex->methods_list, sym);

		RzBinField *field = RZ_NEW0(RzBinField);
		if (field) {
			field->vaddr = field->paddr = sym->paddr;
			field->name = strdup(sym->name);
			field->flags = get_method_flags(accessFlags);
			rz_list_append(cls->fields, field);
		}
		lastIndex = fieldIndex;
	}
}

// TODO: refactor this method
// XXX it needs a lot of love!!!
static void parse_dex_class_method(RzBinFile *bf, RzBinDexClass *c, RzBinClass *cls,
	int *sym_count, ut64 DM, int *methods, bool is_direct, RzBinSourceLineInfoBuilder *bob) {
	PrintfCallback cb_printf = bf->rbin->cb_printf;
	RzBinDexObj *dex = bf->o->bin_obj;
	bool bin_dbginfo = bf->rbin->want_dbginfo;
	int i;
	ut64 omi = 0;
	bool catchAll;
	ut16 regsz = 0, ins_size = 0, outs_size = 0, tries_size = 0;
	ut16 start_addr, insn_count = 0;
	ut32 debug_info_off = 0, insns_size = 0;

	if (!dex->trycatch_list) {
		dex->trycatch_list = rz_list_newf((RzListFree)rz_bin_trycatch_free);
	}
	size_t skip = 0;
	ut64 bufsz = rz_buf_size(bf->buf);
	ut64 encoded_method_addr;
	bool err = false;
	ut64 MI, MA, MC;
	for (i = 0; i < DM; i++) {
		err = false;
		skip = 0;
		// Needed because theres another rbufseek call inside this loop. must be fixed
		encoded_method_addr = rz_buf_tell(bf->buf);
		MI = peek_uleb(bf->buf, &err, &skip);
		if (err) {
			eprintf("Error\n");
			break;
		}
		MI += omi;
		omi = MI;
		MA = peek_uleb(bf->buf, &err, &skip);
		if (err) {
			eprintf("Error\n");
			break;
		}
		MC = peek_uleb(bf->buf, &err, &skip);
		if (err) {
			eprintf("Error\n");
			break;
		}
		// TODO: MOVE CHECKS OUTSIDE!
		if (MI < dex->header.method_size) {
			if (methods) {
				methods[MI] = 1;
			}
		}
		const char *method_name = dex_method_name(dex, MI);
		char *signature = dex_method_signature(dex, MI);
		if (!method_name) {
			method_name = strdup("unknown");
		}
		char *flag_name = rz_str_newf("%s.method.%s%s", cls->name, method_name, signature);
		if (!flag_name || !*flag_name) {
			RZ_FREE(flag_name);
			RZ_FREE(signature);
			continue;
		}
		// TODO: check size
		// ut64 prolog_size = 2 + 2 + 2 + 2 + 4 + 4;
		ut64 v2, handler_type, handler_addr;
		int t = 0;
		if (MC > 0) {
			// TODO: parse debug info
			// XXX why bf->buf->base???
			if (MC + 16 >= dex->size || MC + 16 < MC) {
				RZ_FREE(flag_name);
				RZ_FREE(signature);
				continue;
			}
			if (bufsz < MC || bufsz < MC + 16) {
				RZ_FREE(flag_name);
				RZ_FREE(signature);
				continue;
			}
			regsz = rz_buf_read_le16_at(bf->buf, MC);
			if (regsz == UT16_MAX) {
				RZ_FREE(flag_name);
				RZ_FREE(signature);
				break;
			}
			ins_size = rz_buf_read_le16_at(bf->buf, MC + 2);
			if (ins_size == UT16_MAX) {
				RZ_FREE(flag_name);
				RZ_FREE(signature);
				break;
			}
			outs_size = rz_buf_read_le16_at(bf->buf, MC + 4);
			tries_size = rz_buf_read_le16_at(bf->buf, MC + 6);
			if (tries_size == UT16_MAX) {
				RZ_FREE(flag_name);
				RZ_FREE(signature);
				break;
			}
			debug_info_off = rz_buf_read_le32_at(bf->buf, MC + 8);
			insns_size = rz_buf_read_le32_at(bf->buf, MC + 12);
			int padd = 0;
			if (tries_size > 0 && insns_size % 2) {
				padd = 2;
			}
			t = 16 + 2 * insns_size + padd;
		}
		if (dexdump) {
			const char *accessStr = createAccessFlagStr(MA, kAccessForMethod);
			cb_printf("    #%d              : (in %s;)\n", i, cls->name);
			cb_printf("      name          : '%s'\n", method_name);
			cb_printf("      type          : '%s'\n", signature);
			cb_printf("      access        : 0x%04x (%s)\n", (ut32)MA, accessStr);
		}

		if (MC > 0) {
			if (dexdump) {
				cb_printf("      code          -\n");
				cb_printf("      registers     : %d\n", regsz);
				cb_printf("      ins           : %d\n", ins_size);
				cb_printf("      outs          : %d\n", outs_size);
				cb_printf(
					"      insns size    : %d 16-bit code "
					"units\n",
					insns_size);
			}
			if (tries_size > 0) {
				if (dexdump) {
					cb_printf("      catches       : %d\n", tries_size);
				}
				int j, m = 0;
				//XXX bucle controlled by tainted variable it could produces huge loop
				ut64 offorig = rz_buf_tell(bf->buf);
				for (j = 0; j < tries_size; j++) {
					ut64 offset = MC + t + j * 8;
					if (offset >= dex->size || offset < MC) {
						RZ_FREE(signature);
						break;
					}
					if (bufsz < offset || bufsz < offset + 8) {
						RZ_FREE(signature);
						break;
					}
					// start address of the block of code covered by this entry.
					// The address is a count of 16-bit code units to the start of the first covered instruction.
					start_addr = rz_buf_read_le32_at(bf->buf, offset);
					// number of 16-bit code units covered by this entry.
					// The last code unit covered (inclusive) is start_addr + insn_count - 1.
					insn_count = rz_buf_read_le16_at(bf->buf, offset + 4);
					// offset in bytes from the start of the associated encoded_catch_hander_list
					// to the encoded_catch_handler for this entry.
					// This must be an offset to the start of an encoded_catch_handler.
					ut64 handler_off = rz_buf_read_le16_at(bf->buf, offset + 6);

					ut64 method_offset = MC + 16;
					ut64 try_from = (start_addr * 2) + method_offset;
					ut64 try_to = (start_addr * 2) + (insn_count * 2) + method_offset + 2;
					ut64 try_catch = try_to + handler_off - 1;
					if (dexdump) {
						cb_printf("        0x%04x - 0x%04x\n", start_addr, (start_addr + insn_count));
					}
					RzBinTrycatch *tc = rz_bin_trycatch_new(method_offset, try_from, try_to, try_catch, 0);
					rz_list_append(dex->trycatch_list, tc);

					//XXX tries_size is tainted and oob here
					int off = MC + t + tries_size * 8 + handler_off;
					if (off >= dex->size || off < tries_size) {
						RZ_FREE(signature);
						break;
					}
					// TODO: catch left instead of null
					st64 size;
					if (rz_buf_seek(bf->buf, off, RZ_BUF_SET) == -1) {
						break;
					}
					int r = rz_buf_sleb128(bf->buf, &size);
					if (r <= 0) {
						break;
					}
					if (size <= 0) {
						catchAll = true;
						size = -size;
						// XXX this is probably wrong
					} else {
						catchAll = false;
					}

					for (m = 0; m < size; m++) {
						r = rz_buf_uleb128(bf->buf, &handler_type);
						if (r <= 0) {
							break;
						}
						r = rz_buf_uleb128(bf->buf, &handler_addr);
						if (r <= 0) {
							break;
						}
						if (handler_type > 0 && handler_type < dex->header.types_size) {
							const char *s = getstr(dex, dex->types[handler_type].descriptor_id);
							if (dexdump) {
								cb_printf(
									"          %s "
									"-> 0x%04" PFMT64x "\n",
									s,
									handler_addr);
							}
						} else {
							if (dexdump) {
								cb_printf("          (error) -> 0x%04" PFMT64x "\n", handler_addr);
							}
						}
					}
					if (catchAll) {
						r = rz_buf_uleb128(bf->buf, &v2);
						if (r <= 0) {
							break;
						}
						if (dexdump) {
							cb_printf("          <any> -> 0x%04" PFMT64x "\n", v2);
						}
					}
				}
				rz_buf_seek(bf->buf, offorig, RZ_BUF_SET);
			} else {
				if (dexdump) {
					cb_printf(
						"      catches       : "
						"(none)\n");
				}
			}
		} else {
			if (dexdump) {
				cb_printf("      code          : (none)\n");
			}
		}
		if (*flag_name) {
			RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
			if (!sym) {
				RZ_FREE(flag_name);
				break;
			}
			sym->name = flag_name;
			// is_direct is no longer used
			// if method has code *addr points to code
			// otherwise it points to the encoded method
			if (MC > 0) {
				sym->type = RZ_BIN_TYPE_FUNC_STR;
				sym->paddr = MC; // + 0x10;
				sym->vaddr = MC; // + 0x10;
			} else {
				sym->type = RZ_BIN_TYPE_METH_STR;
				sym->paddr = encoded_method_addr;
				sym->vaddr = encoded_method_addr;
			}
			dex->code_from = RZ_MIN(dex->code_from, sym->paddr);
			sym->bind = ((MA & 1) == 1) ? RZ_BIN_BIND_GLOBAL_STR : RZ_BIN_BIND_LOCAL_STR;
			sym->method_flags = get_method_flags(MA);
			sym->ordinal = (*sym_count)++;
			if (MC > 0) {
				if (bufsz < MC || bufsz < MC + 16) {
					RZ_FREE(sym);
					RZ_FREE(signature);
					continue;
				}
				ut16 tries_size = rz_buf_read_le16_at(bf->buf, MC + 6);
				ut32 insns_size = rz_buf_read_le32_at(bf->buf, MC + 12);
				ut64 prolog_size = 2 + 2 + 2 + 2 + 4 + 4;
				if (tries_size > 0) {
					//prolog_size += 2 + 8*tries_size; // we need to parse all so the catch info...
				}
				// TODO: prolog_size
				sym->paddr = MC + prolog_size; // + 0x10;
				sym->vaddr = MC + prolog_size; // + 0x10;
				//if (is_direct) {
				sym->size = insns_size * 2;
				//}
				//eprintf("%s (0x%x-0x%x) size=%d\nregsz=%d\ninsns_size=%d\nouts_size=%d\ntries_size=%d\ninsns_size=%d\n", flag_name, sym->vaddr, sym->vaddr+sym->size, prolog_size, regsz, ins_size, outs_size, tries_size, insns_size);
				rz_list_append(dex->methods_list, sym);
				rz_list_append(cls->methods, sym);

				if (dex->code_from == UT64_MAX || dex->code_from > sym->paddr) {
					dex->code_from = sym->paddr;
				}
				if (dex->code_to < sym->paddr) {
					dex->code_to = sym->paddr + sym->size;
				}

				if (!mdb) {
					mdb = sdb_new0();
				}
				sdb_num_set(mdb, sdb_fmt("method.%" PFMT64d, MI), sym->paddr, 0);
				// -----------------
				// WORK IN PROGRESS
				// -----------------
#if 0
				if (0) {
					if (MA & 0x10000) { //ACC_CONSTRUCTOR
						if (!cdb) {
							cdb = sdb_new0 ();
						}
						sdb_num_set (cdb, sdb_fmt ("%d", c->class_id), sym->paddr, 0);
					}
				}
#endif
			} else {
				sym->size = 0;
				rz_list_append(dex->methods_list, sym);
				rz_list_append(cls->methods, sym);
			}
			if (MC > 0 && debug_info_off > 0 && dex->header.data_offset < debug_info_off &&
				debug_info_off < dex->header.data_offset + dex->header.data_size) {
				if (bin_dbginfo) {
					ut64 addr = rz_buf_tell(bf->buf);
					dex_parse_debug_item(bf, c, MI, MA, sym->paddr, ins_size,
						insns_size, cls->name, regsz, debug_info_off, bob);
					rz_buf_seek(bf->buf, addr, RZ_BUF_SET);
				}
			} else if (MC > 0) {
				if (dexdump) {
					cb_printf("      positions     :\n");
					cb_printf("      locals        :\n");
				}
			}
		} else {
			RZ_FREE(flag_name);
		}
		RZ_FREE(signature);
	}
}

static void parse_class(RzBinFile *bf, RzBinDexClass *c, int class_index, int *methods, int *sym_count, RzBinSourceLineInfoBuilder *bob) {
	rz_return_if_fail(bf && bf->o && c);

	RzBinDexObj *dex = bf->o->bin_obj;
	RzBin *rbin = bf->rbin;
	int z;
	RzBinClass *cls = RZ_NEW0(RzBinClass);
	if (!cls) {
		goto beach;
	}
	cls->name = dex_class_name(dex, c);
	if (!cls->name) {
		goto beach;
	}
	rz_str_replace_char(cls->name, ';', 0);
	cls->index = class_index;
	cls->addr = dex->header.class_offset + (class_index * DEX_CLASS_SIZE);
	cls->methods = rz_list_new();
	const char *super = dex_class_super_name(dex, c);
	cls->super = super ? strdup(super) : NULL;
	if (!cls->methods) {
		free(cls);
		goto beach;
	}
	cls->fields = rz_list_new();
	if (!cls->fields) {
		rz_list_free(cls->methods);
		free(cls);
		goto beach;
	}
	char *str = createAccessFlagStr(c->access_flags, kAccessForClass);
	cls->visibility_str = str ? str : strdup("");
	rz_list_append(dex->classes_list, cls);
	if (dexdump) {
		rbin->cb_printf("  Class descriptor  : '%s;'\n", cls->name);
		rbin->cb_printf("  Access flags      : 0x%04x (%s)\n", c->access_flags,
			createAccessFlagStr(c->access_flags, kAccessForClass));
		rbin->cb_printf("  Superclass        : '%s'\n", cls->super);
		rbin->cb_printf("  Interfaces        -\n");
	}

	if (c->interfaces_offset > 0 &&
		dex->header.data_offset < c->interfaces_offset &&
		c->interfaces_offset < dex->header.data_offset + dex->header.data_size) {
		int types_list_size = rz_buf_read_le32_at(bf->buf, c->interfaces_offset);
		if (types_list_size < 0 || types_list_size >= dex->header.types_size) {
			goto beach;
		}
		for (z = 0; z < types_list_size; z++) {
			ut16 le16;
			ut32 off = c->interfaces_offset + 4 + (z * 2);
			rz_buf_read_at(bf->buf, off, (ut8 *)&le16, sizeof(le16));
			int t = rz_read_le16(&le16);
			if (t > 0 && t < dex->header.types_size) {
				int tid = dex->types[t].descriptor_id;
				if (dexdump) {
					const char *cn = getstr(dex, tid);
					rbin->cb_printf("    #%d              : '%s'\n", z, cn);
				}
			}
		}
	}
	// TODO: this is quite ugly
	if (!c || !c->class_data_offset) {
		if (dexdump) {
			rbin->cb_printf(
				"  Static fields     -\n"
				"  Instance fields   -\n"
				"  Direct methods    -\n"
				"  Virtual methods   -\n");
		}
	} else {
		// TODO: move to func, def or inline
		// class_data_offset => [class_offset, class_defs_off+class_defs_size*32]
		if (dex->header.class_offset > c->class_data_offset ||
			c->class_data_offset <
				dex->header.class_offset +
					dex->header.class_size * DEX_CLASS_SIZE) {
			goto beach;
		}

		RzBinDexClassData *dc = RZ_NEW0(RzBinDexClassData);
		if (!dc) {
			goto beach;
		}

		bool err = false;
		size_t skip = 0;
		rz_buf_seek(bf->buf, c->class_data_offset, RZ_BUF_SET);
		dc->static_fields_size = peek_uleb(bf->buf, &err, &skip);
		dc->instance_fields_size = peek_uleb(bf->buf, &err, &skip);
		dc->direct_methods_size = peek_uleb(bf->buf, &err, &skip);
		dc->virtual_methods_size = peek_uleb(bf->buf, &err, &skip);
		if (err) {
			free(dc);
			goto beach;
		}
		c->class_data = dc;

		if (dexdump) {
			rbin->cb_printf("  Static fields     -\n");
		}
		parse_dex_class_fields(bf, c, cls, sym_count, dc->static_fields_size, true);

		if (dexdump) {
			rbin->cb_printf("  Instance fields   -\n");
		}
		parse_dex_class_fields(bf, c, cls, sym_count, dc->instance_fields_size, false);

		if (dexdump) {
			rbin->cb_printf("  Direct methods    -\n");
		}
		parse_dex_class_method(bf, c, cls, sym_count,
			c->class_data->direct_methods_size, methods, true, bob);

		if (dexdump) {
			rbin->cb_printf("  Virtual methods   -\n");
		}
		parse_dex_class_method(bf, c, cls, sym_count,
			c->class_data->virtual_methods_size, methods, false, bob);
	}

	if (dexdump) {
		const char *source_file = getstr(dex, c->source_file);
		if (!source_file) {
			rbin->cb_printf(
				"  source_file_idx   : %d (unknown)\n\n",
				c->source_file);
		} else {
			rbin->cb_printf("  source_file_idx   : %d (%s)\n\n",
				c->source_file, source_file);
		}
	}
	cls = NULL;
beach:
	return;
}

static bool is_class_idx_in_code_classes(RzBinDexObj *bin, int class_idx) {
	int i;
	for (i = 0; i < bin->header.class_size; i++) {
		if (class_idx == bin->classes[i].class_id) {
			return true;
		}
	}
	return false;
}

static bool dex_loadcode(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, false);

	PrintfCallback cb_printf = bf->rbin->cb_printf;
	RzBinDexObj *bin = bf->o->bin_obj;
	size_t i;
	int *methods = NULL;
	int sym_count = 0;

	// doublecheck??
	if (bin->methods_list) {
		return false;
	}
	bin->version = rz_bin_dex_get_version(bin);
	bin->code_from = UT64_MAX;
	bin->code_to = 0;
	bin->methods_list = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!bin->methods_list) {
		return false;
	}
	bin->imports_list = rz_list_newf((RzListFree)rz_bin_import_free);
	if (!bin->imports_list) {
		rz_list_free(bin->methods_list);
		return false;
	}
	bin->classes_list = rz_list_newf((RzListFree)rz_bin_class_free);
	if (!bin->classes_list) {
		rz_list_free(bin->methods_list);
		rz_list_free(bin->imports_list);
		return false;
	}

	if (bin->header.method_size > bin->size) {
		bin->header.method_size = 0;
		return false;
	}

	/* WrapDown the header sizes to avoid huge allocations */
	bin->header.method_size = RZ_MIN(bin->header.method_size, bin->size);
	bin->header.class_size = RZ_MIN(bin->header.class_size, bin->size);
	bin->header.strings_size = RZ_MIN(bin->header.strings_size, bin->size);

	// TODO: is this posible after RZ_MIN ??
	if (bin->header.strings_size > bin->size) {
		eprintf("Invalid strings size\n");
		return false;
	}
	dexSubsystem = NULL;

	RzBinSourceLineInfoBuilder bob;
	rz_bin_source_line_info_builder_init(&bob);

	if (bin->classes) {
		ut64 amount = sizeof(int) * bin->header.method_size;
		if (amount > UT32_MAX || amount < bin->header.method_size) {
			rz_bin_source_line_info_builder_fini(&bob);
			return false;
		}
		methods = calloc(1, amount + 1);
		for (i = 0; i < bin->header.class_size; i++) {
			struct dex_class_t *c = &bin->classes[i];
			if (dexdump) {
				cb_printf("Class #%zu            -\n", i);
			}
			parse_class(bf, c, i, methods, &sym_count, &bob);
		}
	}

	bin->lines = rz_bin_source_line_info_builder_build_and_fini(&bob);

	if (methods) {
		int import_count = 0;
		int sym_count = bin->methods_list->length;

		for (i = 0; i < bin->header.method_size; i++) {
			int len = 0;
			if (methods[i]) {
				continue;
			}
			if (bin->methods[i].class_id >= bin->header.types_size) {
				continue;
			}
			if (is_class_idx_in_code_classes(bin, bin->methods[i].class_id)) {
				continue;
			}
			const char *className = getstr(bin, bin->types[bin->methods[i].class_id].descriptor_id);
			if (!className) {
				continue;
			}
			char *class_name = strdup(className);
			if (!class_name) {
				free(class_name);
				continue;
			}
			if (!dexSubsystem) {
				if (strstr(class_name, "wearable/view")) {
					dexSubsystem = "android-wear";
				} else if (strstr(class_name, "android/view/View")) {
					dexSubsystem = "android";
				}
			}
			len = strlen(class_name);
			if (len < 1) {
				free(class_name);
				continue;
			}
			rz_str_replace_char(class_name, ';', 0);
			const char *method_name = dex_method_name(bin, i);
			char *signature = dex_method_signature(bin, i);
			if (!RZ_STR_ISEMPTY(method_name)) {
				RzBinImport *imp = RZ_NEW0(RzBinImport);
				if (!imp) {
					free(methods);
					free(signature);
					free(class_name);
					return false;
				}
				imp->name = rz_str_newf("%s.method.%s%s", class_name, method_name, signature);
				imp->type = "FUNC";
				imp->bind = "NONE";
				imp->ordinal = import_count++;
				rz_list_append(bin->imports_list, imp);

				RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
				if (!sym) {
					free(methods);
					free(signature);
					free(class_name);
					return false;
				}
				sym->name = strdup(imp->name);
				sym->is_imported = true;
				sym->type = RZ_BIN_TYPE_FUNC_STR;
				sym->bind = "NONE";
				//XXX so unsafe check buffer boundaries!!!!
				//XXX use rz_buf API!!
				sym->paddr = sym->vaddr = bin->header.method_offset + (sizeof(struct dex_method_t) * i);
				sym->ordinal = sym_count++;
				rz_list_append(bin->methods_list, sym);
				const char *mname = sdb_fmt("method.%" PFMT64d, (ut64)i);
				sdb_num_set(mdb, mname, sym->paddr, 0);
			}
			free(signature);
			free(class_name);
		}
		free(methods);
	}
	return true;
}

static RzList *imports(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinDexObj *bin = (RzBinDexObj *)bf->o->bin_obj;
	if (!bin->imports_list) {
		dex_loadcode(bf);
	}
	return bin->imports_list;
}

static RzList *trycatch(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinDexObj *bin = (RzBinDexObj *)bf->o->bin_obj;
	if (!bin->trycatch_list) {
		dex_loadcode(bf);
	}
	return bin->trycatch_list;
}

static RzList *methods(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinDexObj *bin = (RzBinDexObj *)bf->o->bin_obj;
	if (!bin->methods_list) {
		dex_loadcode(bf);
	}
	return bin->methods_list;
}

static RzList *classes(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinDexObj *bin = (RzBinDexObj *)bf->o->bin_obj;
	if (!bin->classes_list) {
		dex_loadcode(bf);
	}
	return bin->classes_list;
}

static bool already_entry(RzList *entries, ut64 vaddr) {
	RzBinAddr *e;
	RzListIter *iter;
	rz_list_foreach (entries, iter, e) {
		if (e->vaddr == vaddr) {
			return true;
		}
	}
	return false;
}

static RzList *entries(RzBinFile *bf) {
	RzListIter *iter;
	RzBinSymbol *m;
	RzBinAddr *ptr;

	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	RzBinDexObj *bin = (RzBinDexObj *)bf->o->bin_obj;
	RzList *ret = rz_list_newf((RzListFree)free);

	if (!bin->methods_list) {
		dex_loadcode(bf);
	}

	// STEP 1. ".onCreate(Landroid/os/Bundle;)V"
	rz_list_foreach (bin->methods_list, iter, m) {
		if (strlen(m->name) > 30 && m->bind &&
			(!strcmp(m->bind, RZ_BIN_BIND_LOCAL_STR) || !strcmp(m->bind, RZ_BIN_BIND_GLOBAL_STR)) &&
			!strcmp(m->name + strlen(m->name) - 31,
				".onCreate(Landroid/os/Bundle;)V")) {
			if (!already_entry(ret, m->paddr)) {
				if ((ptr = RZ_NEW0(RzBinAddr))) {
					ptr->paddr = ptr->vaddr = m->paddr;
					rz_list_append(ret, ptr);
				}
			}
		}
	}

	// STEP 2. ".main([Ljava/lang/String;)V"
	if (rz_list_empty(ret)) {
		rz_list_foreach (bin->methods_list, iter, m) {
			if (strlen(m->name) > 26 &&
				!strcmp(m->name + strlen(m->name) - 27,
					".main([Ljava/lang/String;)V")) {
				if (!already_entry(ret, m->paddr)) {
					if ((ptr = RZ_NEW0(RzBinAddr))) {
						ptr->paddr = ptr->vaddr = m->paddr;
						rz_list_append(ret, ptr);
					}
				}
			}
		}
	}
#if 0
	// this is now done by rizin in a generic way
	// STEP 3. NOTHING FOUND POINT TO CODE_INIT
	if (rz_list_empty (ret)) {
		if (!already_entry (ret, bin->code_from)) {
			ptr = RZ_NEW0 (RzBinAddr);
			if (ptr) {
				ptr->paddr = ptr->vaddr = bin->code_from;
				rz_list_append (ret, ptr);
			}
		}
	}
#endif
	return ret;
}

static int getoffset(RzBinFile *bf, int type, int idx) {
	struct rz_bin_dex_obj_t *dex = bf->o->bin_obj;
	switch (type) {
	case 'm': // methods
		// TODO: ADD CHECK
		return offset_of_method_idx(bf, dex, idx);
	case 'f':
		return dex_field_offset(dex, idx);
	case 'o': // objects
		eprintf("TODO: getoffset object\n");
		return 0; // //chdex_object_offset (dex, idx);
	case 's': // strings
		if (dex->header.strings_size > idx) {
			if (dex->strings) {
				return dex->strings[idx];
			}
		}
		break;
	case 't': // type
		return dex_get_type_offset(bf, idx);
	case 'c': // class
		return dex_get_type_offset(bf, idx);
	}
	return -1;
}

static char *getname(RzBinFile *bf, int type, int idx, bool sd) {
	simplifiedDemangling = sd; // XXX remove globals
	struct rz_bin_dex_obj_t *dex = bf->o->bin_obj;
	switch (type) {
	case 'm': // methods
		return dex_method_fullname(dex, idx);
	case 'c': // classes
		return dex_class_name_byid(dex, idx);
	case 'f': // fields
		return dex_field_name(dex, idx);
	case 'p': // proto
		return dex_get_proto(dex, idx);
	}
	return NULL;
}

typedef struct {
	ut64 addr;
	ut64 size;
} Section;

static RzBinSection *add_section(RzList *ret, const char *name, Section s, int perm, char *format) {
	rz_return_val_if_fail(ret && name, NULL);
	rz_return_val_if_fail(s.addr < UT32_MAX, NULL);
	rz_return_val_if_fail(s.size > 0 && s.size < UT32_MAX, NULL);
	RzBinSection *ptr = RZ_NEW0(RzBinSection);
	if (ptr) {
		ptr->name = strdup(name);
		ptr->paddr = ptr->vaddr = s.addr;
		ptr->size = ptr->vsize = s.size;
		ptr->perm = perm;
		if (format) {
			ptr->format = format;
		}
		rz_list_append(ret, ptr);
	}
	return ptr;
}

static bool validate_section(const char *name, Section *pre, Section *cur, Section *nex, Section *all) {
	rz_return_val_if_fail(cur && all, false);
	if (pre && cur->addr < (pre->addr + pre->size)) {
		eprintf("Warning: %s Section starts before the previous.\n", name);
	}
	if (cur->addr >= all->size) {
		eprintf("Warning: %s section starts beyond the end of the file.\n", name);
		return false;
	}
	if (cur->addr == UT64_MAX) {
		eprintf("Warning: %s invalid region size.\n", name);
		return false;
	}
	if ((cur->addr + cur->size) > all->size) {
		eprintf("Warning: %s truncated section because of file size.\n", name);
		cur->size = all->size - cur->addr;
	}
	if (nex) {
		if (cur->addr >= nex->addr) {
			eprintf("Warning: invalid %s section address.\n", name);
			return false;
		}
		if ((cur->addr + cur->size) > nex->addr) {
			eprintf("Warning: truncated %s with next section size.\n", name);
			cur->size = nex->addr - cur->addr;
		}
	}
	return cur->size > 0;
}

static void calculate_code_size(RzBinFile *bf) {
	struct rz_bin_dex_obj_t *bin = bf->o->bin_obj;
	if (bin->code_from && bin->code_to) {
		// already done
		return;
	}
	const size_t bs = rz_buf_size(bf->buf);
	ut64 ns;
	ut64 fsym = 0LL;
	ut64 fsymsz = 0LL;
	RzListIter *iter;
	RzBinSymbol *m;
	RzList *ml = methods(bf);
	rz_list_foreach (ml, iter, m) {
		if (!fsym || m->paddr < fsym) {
			fsym = m->paddr;
		}
		ns = m->paddr + m->size;
		if (ns > bs || m->paddr > bs || m->size > bs) {
			continue;
		}
		if (ns > fsymsz) {
			fsymsz = ns;
		}
	}
	bin->code_from = fsym;
	bin->code_to = fsymsz;
}

static RzList *maps(RzBinFile *bf) {
	struct rz_bin_dex_obj_t *bin = bf->o->bin_obj;
	const ut64 bs = rz_buf_size(bf->buf);
	calculate_code_size(bf);
	RzList *ret = rz_list_newf((RzListFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}
	// map code specifically with r-x perms
	ut64 addr = bin->code_from;
	if (addr < bs) {
		// don't map after file and and also not beyond file end
		ut64 size = RZ_MIN(bs, bin->code_to) - addr;
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			return ret;
		}
		map->paddr = map->vaddr = addr;
		map->psize = map->vsize = size;
		map->perm = RZ_PERM_RX;
		map->name = strdup("code");
		rz_list_push(ret, map);
	}
	// map the entire rest of the file with r-- perms and lower prio
	RzBinMap *map = RZ_NEW0(RzBinMap);
	if (!map) {
		return ret;
	}
	map->psize = map->vsize = bs;
	map->perm = RZ_PERM_R;
	map->name = strdup("file");
	rz_list_push(ret, map);
	return ret;
}

static RzList *sections(RzBinFile *bf) {
	struct rz_bin_dex_obj_t *bin = bf->o->bin_obj;
	RzList *ret = NULL;

	const ut64 bs = rz_buf_size(bf->buf);
	calculate_code_size(bf);
	if (!(ret = rz_list_newf((RzListFree)rz_bin_section_free))) {
		return NULL;
	}

	/* initial section boundary assumptions */
	Section s_head = { 0, sizeof(struct dex_header_t) };
	Section s_pool = { s_head.size, bin->code_from - sizeof(struct dex_header_t) };
	Section s_code = { bin->code_from, bin->code_to - bin->code_from };
	Section s_data = { bin->code_to, bs - bin->code_to };
	Section s_file = { 0, bs };

	/* sanity bound checks and section registrations */
	if (validate_section("header", NULL, &s_head, NULL, &s_file)) {
		add_section(ret, "header", s_head, RZ_PERM_R, NULL);
	}
	if (validate_section("constpool", &s_head, &s_pool, &s_code, &s_file)) {
		char *s_pool_format = rz_str_newf("Cd %d[%" PFMT64d "]", 4, (ut64)s_pool.size / 4);
		add_section(ret, "constpool", s_pool, RZ_PERM_R, s_pool_format);
	}
	if (validate_section("code", &s_pool, &s_code, &s_data, &s_file)) {
		add_section(ret, "code", s_code, RZ_PERM_RX, NULL);
	}
	if (validate_section("data", &s_code, &s_data, NULL, &s_file)) {
		add_section(ret, "data", s_data, RZ_PERM_RX, NULL);
	}
	add_section(ret, "file", s_file, RZ_PERM_R, NULL);
	return ret;
}

// iH
static void dex_header(RzBinFile *bf) {
	RzBinDexObj *dex = bf->o->bin_obj;
	DexHeader *hdr = &dex->header;
	PrintfCallback cb_printf = bf->rbin->cb_printf;

	cb_printf("DEX file header:\n");
	cb_printf("magic               : 'dex\\n035\\0'\n");
	cb_printf("checksum            : %x\n", hdr->checksum);
	cb_printf("signature           : %02x%02x...%02x%02x\n",
		hdr->signature[0], hdr->signature[1], hdr->signature[18], hdr->signature[19]);
	cb_printf("file_size           : %d\n", hdr->size);
	cb_printf("header_size         : %d\n", hdr->header_size);
	cb_printf("link_size           : %d\n", hdr->linksection_size);
	cb_printf("link_off            : %d (0x%06x)\n", hdr->linksection_offset, hdr->linksection_offset);
	cb_printf("string_ids_size     : %d\n", hdr->strings_size);
	cb_printf("string_ids_off      : %d (0x%06x)\n", hdr->strings_offset, hdr->strings_offset);
	cb_printf("type_ids_size       : %d\n", hdr->types_size);
	cb_printf("type_ids_off        : %d (0x%06x)\n", hdr->types_offset, hdr->types_offset);
	cb_printf("proto_ids_size      : %d\n", hdr->prototypes_size);
	cb_printf("proto_ids_off       : %d (0x%06x)\n", hdr->prototypes_offset, hdr->prototypes_offset);
	cb_printf("field_ids_size      : %d\n", hdr->fields_size);
	cb_printf("field_ids_off       : %d (0x%06x)\n", hdr->fields_offset, hdr->fields_offset);
	cb_printf("method_ids_size     : %d\n", hdr->method_size);
	cb_printf("method_ids_off      : %d (0x%06x)\n", hdr->method_offset, hdr->method_offset);
	cb_printf("class_defs_size     : %d\n", hdr->class_size);
	cb_printf("class_defs_off      : %d (0x%06x)\n", hdr->class_offset, hdr->class_offset);
	cb_printf("data_size           : %d\n", hdr->data_size);
	cb_printf("data_off            : %d (0x%06x)\n\n", hdr->data_offset, hdr->data_offset);

	// TODO: print information stored in the RBIN not this ugly fix
	dex->methods_list = NULL;
	dexdump = true; /// XXX convert this global into an argument or field in RzBinFile or so
	dex_loadcode(bf);
	dexdump = false;
}

static ut64 size(RzBinFile *bf) {
	ut8 u32s[sizeof(ut32)] = { 0 };

	int ret = rz_buf_read_at(bf->buf, 108, u32s, 4);
	if (ret != 4) {
		return 0;
	}
	ut32 off = rz_read_le32(u32s);
	ret = rz_buf_read_at(bf->buf, 104, u32s, 4);
	if (ret != 4) {
		return 0;
	}
	return off + rz_read_le32(u32s);
}

static RzBinSourceLineInfo *lines(RzBinFile *bf) {
	struct rz_bin_dex_obj_t *dex = bf->o->bin_obj;
	RzBinSourceLineInfo *r = dex->lines;
	dex->lines = NULL;
	return r;
}

// iH*
static RzList *dex_fields(RzBinFile *bf) {
	RzList *ret = rz_list_newf((RzListFree)rz_bin_field_free);
	if (!ret) {
		return NULL;
	}
	ut64 addr = 0;

#define ROW(nam, siz, val, fmt) \
	rz_list_append(ret, rz_bin_field_new(addr, addr, siz, nam, sdb_fmt("0x%08" PFMT64x, (ut64)val), fmt, false)); \
	addr += siz;

	rz_buf_seek(bf->buf, 0, RZ_BUF_SET);
	ut64 magic = rz_buf_read_le64(bf->buf);
	ROW("dex_magic", 8, magic, "[8]c");
	ut32 checksum = rz_buf_read_le32(bf->buf);
	ROW("dex_checksum", 4, checksum, "x");
	ut8 signature[20];
	ROW("dex_signature", 8, signature, "[20]c");
	ut32 size = rz_buf_read_le32(bf->buf);
	ROW("dex_size", 4, size, "x");
	ut32 header_size = rz_buf_read_le32(bf->buf);
	ROW("dex_header_size", 4, header_size, "x");
	ut32 endian = rz_buf_read_le32(bf->buf);
	ROW("dex_endian", 4, endian, "x");
	/*
	ROW ("hdr.cputype", 4, mh->cputype, "x");
	ROW ("hdr.cpusubtype", 4, mh->cpusubtype, "x");
	ROW ("hdr.filetype", 4, mh->filetype, "x");
	ROW ("hdr.nbcmds", 4, mh->ncmds, "x");
	ROW ("hdr.sizeofcmds", 4, mh->sizeofcmds, "x");
*/
	return ret;
}

static int cmp_path(const void *a, const void *b) {
	if (!a || !b) {
		return 0;
	}
	return strcmp((const char *)a, (const char *)b);
}

static bool is_classes_dex(const char *filename) {
	return rz_str_startswith(filename, "classes") && rz_str_endswith(filename, ".dex");
}

static RzList *libs(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	char *path = rz_file_dirname(bf->file);
	if (rz_str_startswith(path, "./")) {
		// avoids stuff like .//.//.//.//.//
		free(path);
		return NULL;
	}
	RzList *files = rz_sys_dir(path);
	if (!files) {
		free(path);
		return NULL;
	}
	RzList *ret = rz_list_newf(free);
	if (!ret) {
		free(path);
		rz_list_free(files);
		return NULL;
	}
	/* opening dex files in order. */
	rz_list_sort(files, cmp_path);
	RzListIter *iter;
	char *file;
	rz_list_foreach (files, iter, file) {
		if (is_classes_dex(file)) {
			char *n = rz_str_newf("%s%s%s", path, RZ_SYS_DIR, file);
			if (strcmp(n, bf->file)) {
				rz_list_append(ret, n);
			} else {
				free(n);
			}
		}
	}
	rz_list_free(files);
	free(path);
	return ret;
}

static void destroy(RzBinFile *bf) {
	rz_return_if_fail(bf && bf->o);
	RzBinDexObj *obj = bf->o->bin_obj;
	rz_bin_dex_free(obj);
}

RzBinPlugin rz_bin_plugin_dex = {
	.name = "dex",
	.desc = "dex format bin plugin",
	.license = "LGPL3",
	.destroy = &destroy,
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.check_buffer = check_buffer,
	.baddr = baddr,
	.entries = entries,
	.classes = classes,
	.maps = maps,
	.sections = sections,
	.symbols = methods,
	.trycatch = trycatch,
	.imports = imports,
	.strings = strings,
	.info = &info,
	.header = dex_header,
	.fields = dex_fields,
	.libs = &libs,
	.size = &size,
	.get_offset = &getoffset,
	.get_name = &getname,
	.lines = lines
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_dex,
	.version = RZ_VERSION
};
#endif
