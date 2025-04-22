// SPDX-FileCopyrightText: 2011-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_egg.h>
#include "rz_egg_plugins.h"

RZ_LIB_VERSION(rz_egg);

// TODO: must be plugins
extern RzEggEmit emit_x86;
extern RzEggEmit emit_x64;
extern RzEggEmit emit_arm;
extern RzEggEmit emit_trace;

static RzEggPlugin *egg_static_plugins[] = { RZ_EGG_STATIC_PLUGINS };

struct egg_patch_t {
	RzBuffer *b;
	int off;
};

void egg_patch_free(void *p) {
	struct egg_patch_t *ep = (struct egg_patch_t *)p;
	rz_buf_free(ep->b);
	free(ep);
}

RZ_API const char *rz_egg_os_as_string(int os) {
	switch (os) {
	case RZ_EGG_OS_LINUX: return "linux";
	case RZ_EGG_OS_OSX: return "osx";
	case RZ_EGG_OS_DARWIN: return "darwin";
	case RZ_EGG_OS_WATCHOS: return "watchos";
	case RZ_EGG_OS_IOS: return "ios";
	case RZ_EGG_OS_MACOS: return "macos";
	case RZ_EGG_OS_W32: return "win32";
	case RZ_EGG_OS_WINDOWS: return "windows";
	case RZ_EGG_OS_BEOS: return "beos";
	case RZ_EGG_OS_FREEBSD: return "freebsd";
	default: return "linux";
	}
}

RZ_API RzEgg *rz_egg_new(void) {
	int i;
	RzEgg *egg = RZ_NEW0(RzEgg);
	if (!egg) {
		return NULL;
	}
	egg->src = rz_buf_new_with_bytes(NULL, 0);
	if (!egg->src) {
		goto beach;
	}
	egg->buf = rz_buf_new_with_bytes(NULL, 0);
	if (!egg->buf) {
		goto beach;
	}
	egg->bin = rz_buf_new_with_bytes(NULL, 0);
	if (!egg->bin) {
		goto beach;
	}
	egg->remit = &emit_x86;
	egg->syscall = rz_syscall_new();
	if (!egg->syscall) {
		goto beach;
	}
	egg->rasm = rz_asm_new();
	if (!egg->rasm) {
		goto beach;
	}
	egg->bits = 0;
	egg->endian = 0;
	egg->db = sdb_new(NULL, NULL, 0);
	if (!egg->db) {
		goto beach;
	}
	egg->patches = rz_list_newf(egg_patch_free);
	if (!egg->patches) {
		goto beach;
	}
	egg->plugins = ht_sp_new(HT_STR_DUP, NULL, NULL);
	for (i = 0; i < RZ_ARRAY_SIZE(egg_static_plugins); i++) {
		rz_egg_plugin_add(egg, egg_static_plugins[i]);
	}
	return egg;

beach:
	rz_egg_free(egg);
	return NULL;
}

RZ_API bool rz_egg_plugin_add(RzEgg *a, RZ_NONNULL RzEggPlugin *plugin) {
	rz_return_val_if_fail(a && plugin && plugin->name, false);
	if (!ht_sp_insert(a->plugins, plugin->name, plugin)) {
		RZ_LOG_WARN("Plugin '%s' was already added.\n", plugin->name);
	}
	return true;
}

RZ_API bool rz_egg_plugin_del(RzEgg *a, RZ_NONNULL RzEggPlugin *plugin) {
	rz_return_val_if_fail(a && plugin, false);
	return ht_sp_delete(a->plugins, plugin->name);
}

RZ_API char *rz_egg_to_string(RzEgg *egg) {
	return rz_buf_to_string(egg->buf);
}

RZ_API void rz_egg_free(RzEgg *egg) {
	if (!egg) {
		return;
	}
	rz_buf_free(egg->src);
	rz_buf_free(egg->buf);
	rz_buf_free(egg->bin);
	rz_asm_free(egg->rasm);
	rz_syscall_free(egg->syscall);
	sdb_free(egg->db);
	ht_sp_free(egg->plugins);
	rz_list_free(egg->patches);
	rz_egg_lang_free(egg);
	free(egg);
}

RZ_API void rz_egg_reset(RzEgg *egg) {
	rz_egg_lang_include_init(egg);
	rz_buf_free(egg->src);
	rz_buf_free(egg->buf);
	rz_buf_free(egg->bin);
	egg->src = rz_buf_new_with_bytes(NULL, 0);
	egg->buf = rz_buf_new_with_bytes(NULL, 0);
	egg->bin = rz_buf_new_with_bytes(NULL, 0);
	rz_list_purge(egg->patches);
}

RZ_API bool rz_egg_setup(RzEgg *egg, const char *arch, int bits, int endian, const char *os) {
	const char *asmcpu = NULL; // TODO
	egg->remit = NULL;

	egg->os = os ? rz_str_djb2_hash(os) : RZ_EGG_OS_DEFAULT;
	if (!strcmp(arch, "x86")) {
		egg->arch = RZ_SYS_ARCH_X86;
		switch (bits) {
		case 32:
			rz_syscall_setup(egg->syscall, arch, bits, asmcpu, os);
			egg->remit = &emit_x86;
			egg->bits = bits;
			break;
		case 64:
			rz_syscall_setup(egg->syscall, arch, bits, asmcpu, os);
			egg->remit = &emit_x64;
			egg->bits = bits;
			break;
		}
	} else if (!strcmp(arch, "arm")) {
		egg->arch = RZ_SYS_ARCH_ARM;
		switch (bits) {
		case 16:
		case 32:
		case 64:
			rz_syscall_setup(egg->syscall, arch, bits, asmcpu, os);
			egg->remit = &emit_arm;
			egg->bits = bits;
			egg->endian = endian;
			break;
		}
	} else if (!strcmp(arch, "trace")) {
		// rz_syscall_setup (egg->syscall, arch, os, bits);
		egg->remit = &emit_trace;
		egg->bits = bits;
		egg->endian = endian;
	} else {
		return false;
	}
	return true;
}

RZ_API int rz_egg_include(RzEgg *egg, const char *file, int format) {
	size_t sz;
	const ut8 *foo = (const ut8 *)rz_file_slurp(file, &sz);
	if (!foo) {
		return 0;
	}
	// XXX: format breaks compiler layers
	switch (format) {
	case 'r': // raw
		rz_egg_raw(egg, foo, (int)sz);
		break;
	case 'a': // assembly
		rz_buf_append_bytes(egg->buf, foo, (ut64)sz);
		break;
	default:
		rz_buf_append_bytes(egg->src, foo, (ut64)sz);
	}
	free((void *)foo);
	return 1;
}

RZ_API void rz_egg_load(RzEgg *egg, const char *code, int format) {
	rz_return_if_fail(code);
	switch (format) {
	case 'a': // assembly
		rz_buf_append_bytes(egg->buf, (const ut8 *)code, strlen(code));
		break;
	default:
		rz_buf_append_bytes(egg->src, (const ut8 *)code, strlen(code));
		break;
	}
}

RZ_API bool rz_egg_load_file(RzEgg *egg, const char *file) {
	rz_return_val_if_fail(file, false);
	// We have to reset the RzEgg state first
	rz_egg_reset(egg);
	if (rz_str_endswith(file, ".c")) {
		char *fileSanitized = rz_str_dup(file);
		rz_str_sanitize(fileSanitized);
		const char *arch = rz_sys_arch_str(egg->arch);
		const char *os = rz_egg_os_as_string(egg->os);
		char *textFile = rz_egg_Cfile_parser(fileSanitized, arch, os, egg->bits);
		if (!textFile) {
			RZ_LOG_ERROR("egg: failure while parsing '%s'\n", fileSanitized);
			free(fileSanitized);
			return false;
		}
		size_t l;
		char *buf = rz_file_slurp(textFile, &l);
		if (buf && l > 0) {
			rz_egg_raw(egg, (const ut8 *)buf, (int)l);
		} else {
			RZ_LOG_ERROR("egg: error loading '%s'\n", textFile);
		}
		rz_file_rm(textFile);
		free(fileSanitized);
		free(textFile);
		free(buf);
	} else {
		int fmt;
		if (rz_str_endswith(file, ".s") || rz_str_endswith(file, ".asm")) {
			fmt = 'a';
		} else {
			fmt = 0;
		}
		if (!rz_egg_include(egg, file, fmt)) {
			RZ_LOG_ERROR("egg: cannot open '%s'\n", file);
			return false;
		}
	}
	return true;
}

RZ_API void rz_egg_syscall(RzEgg *egg, const char *arg, ...) {
	RzSyscallItem *item = rz_syscall_get(egg->syscall,
		rz_syscall_get_num(egg->syscall, arg), -1);
	if (!strcmp(arg, "close")) {
		// egg->remit->syscall_args ();
	}
	if (!item) {
		return;
	}
	egg->remit->syscall(egg, item->num);
	rz_syscall_item_free(item);
}

RZ_API void rz_egg_alloc(RzEgg *egg, int n) {
	// add esp, n
}

RZ_API void rz_egg_label(RzEgg *egg, const char *name) {
	rz_egg_printf(egg, "%s:\n", name);
}

RZ_API void rz_egg_math(RzEgg *egg) { //, char eq, const char *vs, char type, const char *sr
	// TODO
	// e->mathop (egg, op, type, eq, p);
}

RZ_API int rz_egg_raw(RzEgg *egg, const ut8 *b, int len) {
	int outlen = len * 2; // two hexadecimal digits per byte
	char *out = malloc(outlen + 1);
	if (!out) {
		return false;
	}
	(void)rz_hex_bin2str(b, len, out);
	rz_buf_append_bytes(egg->buf, (const ut8 *)".hex ", 5);
	rz_buf_append_bytes(egg->buf, (const ut8 *)out, outlen);
	rz_buf_append_bytes(egg->buf, (const ut8 *)"\n", 1);
	free(out);
	return true;
}

static int rz_egg_raw_prepend(RzEgg *egg, const ut8 *b, int len) {
	int outlen = len * 2; // two hexadecimal digits per byte
	char *out = malloc(outlen + 1);
	if (!out) {
		return false;
	}
	rz_hex_bin2str(b, len, out);
	rz_buf_prepend_bytes(egg->buf, (const ut8 *)"\n", 1);
	rz_buf_prepend_bytes(egg->buf, (const ut8 *)out, outlen);
	rz_buf_prepend_bytes(egg->buf, (const ut8 *)".hex ", 5);
	free(out);
	return true;
}

static int rz_egg_prepend_bytes(RzEgg *egg, const ut8 *b, int len) {
	if (!rz_egg_raw_prepend(egg, b, len)) {
		return false;
	}
	if (!rz_buf_prepend_bytes(egg->bin, b, len)) {
		return false;
	}
	return true;
}

static int rz_egg_append_bytes(RzEgg *egg, const ut8 *b, int len) {
	if (!rz_egg_raw(egg, b, len)) {
		return false;
	}

	if (!rz_buf_append_bytes(egg->bin, b, len)) {
		return false;
	}

	return true;
}

// rz_egg_block (egg, FRAME | IF | ELSE | ENDIF | FOR | WHILE, sz)
RZ_API void rz_egg_if(RzEgg *egg, const char *reg, char cmp, int v) {
	//	egg->depth++;
}

RZ_API void rz_egg_printf(RzEgg *egg, const char *fmt, ...) {
	va_list ap;
	int len;
	char buf[1024];
	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	rz_buf_append_bytes(egg->buf, (const ut8 *)buf, len);
	va_end(ap);
}

RZ_API bool rz_egg_assemble_asm(RzEgg *egg, char **asm_list) {
	RzAsmCode *asmcode = NULL;
	char *code = NULL;
	char *asm_name = NULL;

	if (asm_list) {
		char **asm_;

		for (asm_ = asm_list; *asm_; asm_ += 2) {
			if (!strcmp(egg->remit->arch, asm_[0])) {
				asm_name = asm_[1];
				break;
			}
		}
	}
	if (!asm_name) {
		if (egg->remit == &emit_x86 || egg->remit == &emit_x64) {
			asm_name = "x86.nz";
		} else if (egg->remit == &emit_arm) {
			asm_name = "arm";
		}
	}
	if (asm_name) {
		rz_asm_use(egg->rasm, asm_name);
		rz_asm_set_bits(egg->rasm, egg->bits);
		rz_asm_set_big_endian(egg->rasm, egg->endian);
		rz_asm_set_syntax(egg->rasm, RZ_ASM_SYNTAX_INTEL);
		code = rz_buf_to_string(egg->buf);
		asmcode = rz_asm_massemble(egg->rasm, code);
		if (asmcode) {
			if (asmcode->len > 0) {
				rz_buf_append_bytes(egg->bin, asmcode->bytes, asmcode->len);
			}
			// LEAK rz_asm_code_free (asmcode);
		} else {
			RZ_LOG_ERROR("egg: fail assembling\n");
		}
	}
	bool ret = code ? asmcode != NULL : true;
	free(code);
	rz_asm_code_free(asmcode);
	return ret;
}

RZ_API bool rz_egg_assemble(RzEgg *egg) {
	return rz_egg_assemble_asm(egg, NULL);
}

RZ_API int rz_egg_compile(RzEgg *egg) {
	rz_buf_seek(egg->src, 0, RZ_BUF_SET);
	char b;
	int r = rz_buf_read(egg->src, (ut8 *)&b, sizeof(b));
	if (r != sizeof(b) || !egg->remit) {
		return true;
	}
	// only emit begin if code is found
	rz_egg_lang_init(egg);
	for (; b;) {
		rz_egg_lang_parsechar(egg, b);
		if (egg->lang.elem_n >= sizeof(egg->lang.elem)) {
			RZ_LOG_ERROR("egg: elem too large.\n");
			break;
		}
		int r = rz_buf_read(egg->src, (ut8 *)&b, sizeof(b));
		if (r != sizeof(b)) {
			break;
		}
		// XXX: some parse fail errors are false positives :(
	}
	if (egg->context > 0) {
		RZ_LOG_ERROR("egg: expected '}' at the end of the file. %d left\n", egg->context);
		return false;
	}
	// TODO: handle errors here
	return true;
}

RZ_API RzBuffer *rz_egg_get_bin(RzEgg *egg) {
	// TODO increment reference
	return egg->bin;
}

// RZ_API int rz_egg_dump (RzEgg *egg, const char *file) { }

RZ_API char *rz_egg_get_source(RzEgg *egg) {
	return rz_buf_to_string(egg->src);
}

RZ_API char *rz_egg_get_assembly(RzEgg *egg) {
	return rz_buf_to_string(egg->buf);
}

RZ_API void rz_egg_append(RzEgg *egg, const char *src) {
	rz_buf_append_bytes(egg->src, (const ut8 *)src, strlen(src));
}

/* JIT : TODO: accept arguments here */
RZ_API int rz_egg_run(RzEgg *egg) {
	ut64 tmpsz;
	const ut8 *tmp = rz_buf_data(egg->bin, &tmpsz);
	bool res = rz_sys_run(tmp, tmpsz);
	return res;
}

RZ_API int rz_egg_run_rop(RzEgg *egg) {
	ut64 sz;
	const ut8 *tmp = rz_buf_data(egg->bin, &sz);
	return rz_sys_run_rop(tmp, sz);
}

#define RZ_EGG_FILL_TYPE_TRAP
#define RZ_EGG_FILL_TYPE_NOP
#define RZ_EGG_FILL_TYPE_CHAR
#define RZ_EGG_FILL_TYPE_SEQ
#define RZ_EGG_FILL_TYPE_SEQ

static inline char *eon(char *n) {
	while (*n && (*n >= '0' && *n <= '9')) {
		n++;
	}
	return n;
}

/* padding looks like:
  ([snatSNAT][0-9]+)*
*/
RZ_API int rz_egg_padding(RzEgg *egg, const char *pad) {
	int number;
	ut8 *buf, padding_byte;
	char *p, *o = rz_str_dup(pad);

	for (p = o; *p;) { // parse pad string
		const char f = *p++;
		number = strtol(p, NULL, 10);

		if (number < 1) {
			RZ_LOG_ERROR("egg: invalid padding length at %d\n", number);
			free(o);
			return false;
		}
		p = eon(p);

		switch (f) {
		case 's':
		case 'S': padding_byte = 0; break;
		case 'n':
		case 'N': padding_byte = 0x90; break;
		case 'a':
		case 'A': padding_byte = 'A'; break;
		case 't':
		case 'T': padding_byte = 0xcc; break;
		default:
			RZ_LOG_ERROR("Invalid padding format (%c)\nValid ones are:\n"
				     "	s S : NULL byte\n"
				     "	n N : nop\n"
				     "	a A : 0x41\n"
				     "	t T : trap (0xcc)\n",
				*p ? *p : ' ');
			free(o);
			return false;
		}

		buf = malloc(number);
		if (!buf) {
			free(o);
			return false;
		}

		memset(buf, padding_byte, number);
		if (f >= 'a' && f <= 'z') {
			rz_egg_prepend_bytes(egg, buf, number);
		} else {
			rz_egg_append_bytes(egg, buf, number);
		}
		free(buf);
	}
	free(o);
	return true;
}

RZ_API void rz_egg_fill(RzEgg *egg, int pos, int type, int argc, int length) {
	// TODO
}

RZ_API void rz_egg_option_set(RzEgg *egg, const char *key, const char *val) {
	sdb_set(egg->db, key, val);
}

RZ_API char *rz_egg_option_get(RzEgg *egg, const char *key) {
	return sdb_get(egg->db, key);
}

RZ_API int rz_egg_shellcode(RZ_NONNULL RZ_BORROW RzEgg *egg, const char *name) {
	rz_return_val_if_fail(egg && name, false);
	RzIterator *iter = ht_sp_as_iter(egg->plugins);
	RzEggPlugin **val;
	RzBuffer *b;
	rz_iterator_foreach(iter, val) {
		RzEggPlugin *p = *val;
		if (p->type == RZ_EGG_PLUGIN_SHELLCODE && !strcmp(name, p->name)) {
			b = p->build(egg);
			if (!b) {
				RZ_LOG_ERROR("egg: %s Shellcode has failed\n", p->name);
				rz_iterator_free(iter);
				return false;
			}
			ut64 tmpsz;
			const ut8 *tmp = rz_buf_data(b, &tmpsz);
			rz_egg_raw(egg, tmp, tmpsz);
			rz_iterator_free(iter);
			return true;
		}
	}
	rz_iterator_free(iter);
	return false;
}

RZ_API int rz_egg_encode(RZ_NONNULL RZ_BORROW RzEgg *egg, const char *name) {
	rz_return_val_if_fail(egg && name, false);
	RzIterator *iter = ht_sp_as_iter(egg->plugins);
	RzEggPlugin **val;
	RzBuffer *b;
	rz_iterator_foreach(iter, val) {
		RzEggPlugin *p = *val;
		if (p->type == RZ_EGG_PLUGIN_ENCODER && !strcmp(name, p->name)) {
			b = p->build(egg);
			if (!b) {
				rz_iterator_free(iter);
				return false;
			}
			rz_buf_free(egg->bin);
			egg->bin = b;
			rz_iterator_free(iter);
			return true;
		}
	}
	rz_iterator_free(iter);
	return false;
}

RZ_API int rz_egg_patch(RzEgg *egg, int off, const ut8 *buf, int len) {
	struct egg_patch_t *ep = RZ_NEW(struct egg_patch_t);
	if (!ep) {
		return false;
	}
	ep->b = rz_buf_new_with_bytes(buf, len);
	if (!ep->b) {
		egg_patch_free(ep);
		return false;
	}
	ep->off = off;
	rz_list_append(egg->patches, ep);
	return true;
}

RZ_API bool rz_egg_patch_num(RzEgg *egg, int off, ut64 num, ut32 bits) {
	rz_return_val_if_fail(egg && bits <= 64, false);
	ut8 buf[8] = { 0 };
	rz_write_ble(buf, num, egg->endian, bits);
	return rz_egg_patch(egg, off, buf, bits / 8);
}

RZ_API void rz_egg_finalize(RzEgg *egg) {
	struct egg_patch_t *ep;
	RzListIter *iter;
	if (!egg->bin) {
		rz_buf_free(egg->bin);
		egg->bin = rz_buf_new_with_bytes(NULL, 0);
	}
	rz_list_foreach (egg->patches, iter, ep) {
		if (ep->off < 0) {
			ut64 sz;
			const ut8 *buf = rz_buf_data(ep->b, &sz);
			rz_egg_append_bytes(egg, buf, sz);
		} else if (ep->off < rz_buf_size(egg->bin)) {
			ut64 sz;
			const ut8 *buf = rz_buf_data(ep->b, &sz);
			int r = rz_buf_write_at(egg->bin, ep->off, buf, sz);
			if (r < sz) {
				RZ_LOG_ERROR("egg: error during patch\n");
				return;
			}
		} else {
			RZ_LOG_ERROR("egg: cannot patch outside\n");
			return;
		}
	}
}

RZ_API bool rz_egg_pattern(RzEgg *egg, int size) {
	bool ok = false;

	char *ret = rz_debruijn_pattern((int)size, 0, NULL);
	if (ret) {
		ok = rz_egg_prepend_bytes(egg, (const ut8 *)ret, strlen(ret));
	} else {
		RZ_LOG_ERROR("egg: invalid debruijn pattern length.\n");
	}

	free(ret);
	return ok;
}
