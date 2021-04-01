// SPDX-FileCopyrightText: 2011-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_egg.h>
#include <config.h>

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

RZ_API RzEgg *rz_egg_new(void) {
	int i;
	RzEgg *egg = RZ_NEW0(RzEgg);
	if (!egg) {
		return NULL;
	}
	egg->src = rz_buf_new();
	if (!egg->src) {
		goto beach;
	}
	egg->buf = rz_buf_new();
	if (!egg->buf) {
		goto beach;
	}
	egg->bin = rz_buf_new();
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
	egg->plugins = rz_list_new();
	for (i = 0; egg_static_plugins[i]; i++) {
		rz_egg_add(egg, egg_static_plugins[i]);
	}
	return egg;

beach:
	rz_egg_free(egg);
	return NULL;
}

RZ_API int rz_egg_add(RzEgg *a, RzEggPlugin *foo) {
	RzListIter *iter;
	RzAsmPlugin *h;
	// TODO: cache foo->name length and use memcmp instead of strcmp
	if (!foo->name) {
		return false;
	}
	rz_list_foreach (a->plugins, iter, h) {
		if (!strcmp(h->name, foo->name)) {
			return false;
		}
	}
	rz_list_append(a->plugins, foo);
	return true;
}

RZ_API char *rz_egg_to_string(RzEgg *egg) {
	return rz_buf_to_string(egg->buf);
}

RZ_API void rz_egg_free(RzEgg *egg) {
	if (egg) {
		rz_buf_free(egg->src);
		rz_buf_free(egg->buf);
		rz_buf_free(egg->bin);
		rz_list_free(egg->list);
		rz_asm_free(egg->rasm);
		rz_syscall_free(egg->syscall);
		sdb_free(egg->db);
		rz_list_free(egg->plugins);
		rz_list_free(egg->patches);
		rz_egg_lang_free(egg);
		free(egg);
	}
}

RZ_API void rz_egg_reset(RzEgg *egg) {
	rz_egg_lang_include_init(egg);
	// TODO: use rz_list_purge instead of free/new here
	rz_buf_free(egg->src);
	rz_buf_free(egg->buf);
	rz_buf_free(egg->bin);
	egg->src = rz_buf_new();
	egg->buf = rz_buf_new();
	egg->bin = rz_buf_new();
	rz_list_purge(egg->patches);
}

RZ_API int rz_egg_setup(RzEgg *egg, const char *arch, int bits, int endian, const char *os) {
	const char *asmcpu = NULL; // TODO
	egg->remit = NULL;

	egg->os = os ? rz_str_hash(os) : RZ_EGG_OS_DEFAULT;
	//eprintf ("%s -> %x (linux=%x) (darwin=%x)\n", os, egg->os, RZ_EGG_OS_LINUX, RZ_EGG_OS_DARWIN);
	// TODO: setup egg->arch for all archs
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
		//rz_syscall_setup (egg->syscall, arch, os, bits);
		egg->remit = &emit_trace;
		egg->bits = bits;
		egg->endian = endian;
	}
	return 0;
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
	switch (format) {
	case 'a': // assembly
		rz_buf_append_bytes(egg->buf, (const ut8 *)code, strlen(code));
		break;
	default:
		rz_buf_append_bytes(egg->src, (const ut8 *)code, strlen(code));
		break;
	}
}

RZ_API void rz_egg_syscall(RzEgg *egg, const char *arg, ...) {
	RzSyscallItem *item = rz_syscall_get(egg->syscall,
		rz_syscall_get_num(egg->syscall, arg), -1);
	if (!strcmp(arg, "close")) {
		//egg->remit->syscall_args ();
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
	//e->mathop (egg, op, type, eq, p);
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
			eprintf("fail assembling\n");
		}
	}
	free(code);
	bool ret = (asmcode != NULL);
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
			eprintf("ERROR: elem too large.\n");
			break;
		}
		int r = rz_buf_read(egg->src, (ut8 *)&b, sizeof(b));
		if (r != sizeof(b)) {
			break;
		}
		// XXX: some parse fail errors are false positives :(
	}
	if (egg->context > 0) {
		eprintf("ERROR: expected '}' at the end of the file. %d left\n", egg->context);
		return false;
	}
	// TODO: handle errors here
	return true;
}

RZ_API RzBuffer *rz_egg_get_bin(RzEgg *egg) {
	// TODO increment reference
	return egg->bin;
}

//RZ_API int rz_egg_dump (RzEgg *egg, const char *file) { }

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
	char *p, *o = strdup(pad);

	for (p = o; *p;) { // parse pad string
		const char f = *p++;
		number = strtol(p, NULL, 10);

		if (number < 1) {
			eprintf("Invalid padding length at %d\n", number);
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
			eprintf("Invalid padding format (%c)\n", *p);
			eprintf("Valid ones are:\n");
			eprintf("	s S : NULL byte");
			eprintf("	n N : nop");
			eprintf("	a A : 0x41");
			eprintf("	t T : trap (0xcc)");
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
	sdb_set(egg->db, key, val, 0);
}

RZ_API char *rz_egg_option_get(RzEgg *egg, const char *key) {
	return sdb_get(egg->db, key, NULL);
}

RZ_API int rz_egg_shellcode(RzEgg *egg, const char *name) {
	RzEggPlugin *p;
	RzListIter *iter;
	RzBuffer *b;
	rz_list_foreach (egg->plugins, iter, p) {
		if (p->type == RZ_EGG_PLUGIN_SHELLCODE && !strcmp(name, p->name)) {
			b = p->build(egg);
			if (!b) {
				eprintf("%s Shellcode has failed\n", p->name);
				return false;
			}
			ut64 tmpsz;
			const ut8 *tmp = rz_buf_data(b, &tmpsz);
			rz_egg_raw(egg, tmp, tmpsz);
			return true;
		}
	}
	return false;
}

RZ_API int rz_egg_encode(RzEgg *egg, const char *name) {
	RzEggPlugin *p;
	RzListIter *iter;
	RzBuffer *b;
	rz_list_foreach (egg->plugins, iter, p) {
		if (p->type == RZ_EGG_PLUGIN_ENCODER && !strcmp(name, p->name)) {
			b = p->build(egg);
			if (!b) {
				return false;
			}
			rz_buf_free(egg->bin);
			egg->bin = b;
			return true;
		}
	}
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

RZ_API void rz_egg_finalize(RzEgg *egg) {
	struct egg_patch_t *ep;
	RzListIter *iter;
	if (!egg->bin) {
		rz_buf_free(egg->bin);
		egg->bin = rz_buf_new();
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
				eprintf("Error during patch\n");
				return;
			}
		} else {
			eprintf("Cannot patch outside\n");
			return;
		}
	}
}

RZ_API void rz_egg_pattern(RzEgg *egg, int size) {
	char *ret = rz_debruijn_pattern((int)size, 0, NULL);
	if (ret) {
		rz_egg_prepend_bytes(egg, (const ut8 *)ret, strlen(ret));
		free(ret);
	} else {
		eprintf("Invalid debruijn pattern length.\n");
	}
}
