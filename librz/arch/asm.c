// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2021 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util/rz_print.h"
#include <rz_vector.h>
#include <rz_util/rz_strbuf.h>
#include <rz_util/rz_regex.h>
#include <rz_util/rz_assert.h>
#include <rz_list.h>
#include <stdio.h>
#include <rz_core.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>
#define USE_RZ_UTIL 1
#include <spp.h>

/**
 * \brief Checks if the first character of \p c is a digit character
 * OR if the first two chars are a hex prefix.
 *
 * \param c The character string.
 * \return true First char is a digit or the first two chars are a hex prefix.
 * \return false Otherwise.
 */
static bool is_num(const char *c) {
	rz_return_val_if_fail(c, false);
	if (!isascii(*c)) {
		return false; // UTF-8
	}
	return rz_num_is_hex_prefix(c) || isxdigit(c[0]);
}

/**
 * \brief Checks if the first character of \p c is an alphanumeric character OR if it is a hex prefix.
 *
 * \param c The character string.
 * \return true If it is alphanumeric or a hex prefix.
 * \return false Otherwise.
 */
static bool is_alpha_num(const char *c) {
	rz_return_val_if_fail(c, false);
	if (!isascii(*c)) {
		return false; // UTF-8
	}
	return is_num(c) || isalpha(c[0]);
}

static bool is_separator(const char *c) {
	if (!isascii(*c)) {
		return false; // UTF-8
	}
	return (*c == '(' || *c == ')' || *c == '[' || *c == ']' || *c == '{' || *c == '}' || *c == ',' || *c == '.' || *c == '#' || *c == ':' || *c == ' ' ||
		(c[0] == '|' && c[1] == '|') ||
		(c[0] == '=' && c[1] == '=') ||
		(c[0] == '<' && c[1] == '=') ||
		(c[0] == ':' && c[1] == ':'));
}

static bool is_operator(const char *c) {
	if (!isascii(*c)) {
		return false; // UTF-8
	}
	return (*c == '+' || *c == '-' || *c == '/' || *c == '>' || *c == '<' || *c == '*' || *c == '%' || *c == '|' || *c == '&' || *c == '=' || *c == '!');
}

static bool is_register(const char *name, RZ_BORROW const RzRegSet *regset) {
	rz_return_val_if_fail(name, false);
	if (!regset) {
		return false;
	}

	bool found = false;
	for (ut32 i = 0; i < RZ_REG_TYPE_LAST; ++i) {
		if (regset[i].ht_regs) {
			ht_sp_find(regset[i].ht_regs, name, &found);
			if (found) {
				return true;
			}
		}
	}
	return false;
}

/**
 * \brief Checks if the provided token string fits in any known asm token type.
 *
 * If the prev byte is not an operator or a separator and next byte is NULL(eg: "push rsp") , don't consider it as unknown
 * If the prev byte or next byte is not an operator or a separator, don't consider it as unknown.
 *
 * \param str The parsed asm token.
 * \param prev index of the prev byte of the token
 * \param next index of the next byte of the token
 * \return true The given token cannot be parsed to any known asm token type.
 * \return false Otherwise.
 */
static bool is_not_unknown(const char *str, size_t prev, size_t next) {
	rz_return_val_if_fail(str, false);
	return (is_operator(str + prev - 1) || is_separator(str + prev - 1)) &&
		(!*(str + next) || (is_operator(str + next) || is_separator(str + next)));
}

static char *directives[] = {
	".include", ".error", ".warning",
	".echo", ".if", ".ifeq", ".endif",
	".else", ".set", ".get", NULL
};

static void parseHeap(RzParse *p, RzStrBuf *s) {
	char *op_buf_asm = rz_strbuf_get(s);
	char *out = rz_parse_pseudocode(p, op_buf_asm);
	if (out) {
		rz_strbuf_set(s, out);
		free(out);
	}
}

/* pseudo.c - private api */
static int rz_asm_pseudo_align(RzAsmCode *acode, RzAsmOp *op, char *input) {
	acode->code_align = rz_num_math(NULL, input);
	return 0;
}

static int rz_asm_pseudo_string(RzAsmOp *op, char *input, int zero) {
	int len = strlen(input) - 1;
	if (len < 1) {
		return 0;
	}
	// TODO: if not starting with '"'.. give up
	if (input[len] == '"') {
		input[len] = 0;
	}
	if (*input == '"') {
		input++;
	}
	len = rz_str_unescape(input) + zero;
	rz_strbuf_set(&op->buf, input); // uh?
	return len;
}

static inline int rz_asm_pseudo_arch(RzAsm *a, char *input) {
	if (!rz_asm_use(a, input)) {
		RZ_LOG_ERROR("Unknown asm plugin name '%s'\n", input);
		return -1;
	}
	return 0;
}

static inline int rz_asm_pseudo_bits(RzAsm *a, char *input) {
	if (!(rz_asm_set_bits(a, rz_num_math(NULL, input)))) {
		RZ_LOG_ERROR("Unsupported bits (%s) value for the selected asm plugin.\n", input);
		return -1;
	}
	return 0;
}

static inline int rz_asm_pseudo_org(RzAsm *a, char *input) {
	rz_asm_set_pc(a, rz_num_math(NULL, input));
	return 0;
}

static inline int rz_asm_pseudo_intN(RzAsm *a, RzAsmOp *op, char *input, int n) {
	ut16 s;
	ut32 i;
	ut64 s64 = rz_num_math(NULL, input);
	if (n != 8 && s64 >> (n * 8)) {
		RZ_LOG_ERROR("Cannot write a number that does not fit within a int%d type.\n", (n * 8));
		return 0;
	}
	// XXX honor endian here
	ut8 *buf = (ut8 *)rz_strbuf_get(&op->buf);
	if (!buf) {
		return 0;
	}
	if (n == 2) {
		s = (ut16)(st16)s64;
		rz_write_ble16(buf, s, a->big_endian);
	} else if (n == 4) {
		i = (ut32)(st32)s64;
		rz_write_ble32(buf, i, a->big_endian);
	} else if (n == 8) {
		rz_write_ble64(buf, (ut64)s64, a->big_endian);
	} else {
		return 0;
	}
	return n;
}

static inline int rz_asm_pseudo_int16(RzAsm *a, RzAsmOp *op, char *input) {
	return rz_asm_pseudo_intN(a, op, input, 2);
}

static inline int rz_asm_pseudo_int32(RzAsm *a, RzAsmOp *op, char *input) {
	return rz_asm_pseudo_intN(a, op, input, 4);
}

static inline int rz_asm_pseudo_int64(RzAsm *a, RzAsmOp *op, char *input) {
	return rz_asm_pseudo_intN(a, op, input, 8);
}

static inline int rz_asm_pseudo_byte(RzAsmOp *op, char *input) {
	int i, len = 0;
	rz_str_replace_char(input, ',', ' ');
	len = rz_str_word_count(input);
	rz_str_word_set0(input);
	ut8 *buf = malloc(len);
	if (!buf) {
		return 0;
	}
	for (i = 0; i < len; i++) {
		const char *word = rz_str_word_get0(input, i);
		int num = (int)rz_num_math(NULL, word);
		buf[i] = num;
	}
	rz_asm_op_set_buf(op, buf, len);
	free(buf);
	return len;
}

static inline int rz_asm_pseudo_fill(RzAsmOp *op, char *input) {
	int i, repeat = 0, size = 0, value = 0;
	sscanf(input, "%d,%d,%d", &repeat, &size, &value); // use rz_num?
	size *= (sizeof(value) * repeat);
	if (size > 0) {
		ut8 *buf = malloc(size);
		if (buf) {
			for (i = 0; i < size; i += sizeof(value)) {
				memcpy(&buf[i], &value, sizeof(value));
			}
			rz_asm_op_set_buf(op, buf, size);
			free(buf);
		}
	} else {
		size = 0;
	}
	return size;
}

static inline int rz_asm_pseudo_incbin(RzAsmOp *op, char *input) {
	size_t bytes_read = 0;
	rz_str_replace_char(input, ',', ' ');
	// int len = rz_str_word_count (input);
	rz_str_word_set0(input);
	// const char *filename = rz_str_word_get0 (input, 0);
	size_t skip = (size_t)rz_num_math(NULL, rz_str_word_get0(input, 1));
	size_t count = (size_t)rz_num_math(NULL, rz_str_word_get0(input, 2));
	char *content = rz_file_slurp(input, &bytes_read);
	if (!content) {
		RZ_LOG_ERROR("Could not open '%s'.\n", input);
		return -1;
	}
	if (skip > 0) {
		skip = skip > bytes_read ? bytes_read : skip;
	}
	if (count > 0) {
		count = count > bytes_read ? 0 : count;
	} else {
		count = bytes_read;
	}
	// Need to handle arbitrary amount of data
	rz_buf_free(op->buf_inc);
	op->buf_inc = rz_buf_new_with_string(content + skip);
	// Terminate the original buffer
	free(content);
	return count;
}

static void plugin_fini(RzAsm *a) {
	if (a->cur && a->cur->fini && !a->cur->fini(a->plugin_data)) {
		RZ_LOG_ERROR("asm plugin '%s' failed to terminate.\n", a->cur->name);
	}
	a->plugin_data = NULL;
}

RZ_API RzAsm *rz_asm_new(void) {
	RzAsm *a = RZ_NEW0(RzAsm);
	if (!a) {
		return NULL;
	}
	a->dataalign = 1;
	a->bits = RZ_SYS_BITS;
	a->bitshift = 0;
	a->syntax = RZ_ASM_SYNTAX_INTEL;
	a->plugins = rz_list_new();
	if (!a->plugins) {
		free(a);
		return NULL;
	}

	const size_t n_plugins = rz_arch_get_n_plugins();
	for (size_t i = 0; i < n_plugins; i++) {
		RzAsmPlugin *plugin = rz_arch_get_asm_plugin(i);
		if (!plugin) {
			continue;
		}
		rz_asm_plugin_add(a, plugin);
	}
	return a;
}

RZ_API bool rz_asm_setup(RzAsm *a, const char *arch, int bits, int big_endian) {
	rz_return_val_if_fail(a && arch, false);
	bool ret = !rz_asm_use(a, arch);
	return ret | !rz_asm_set_bits(a, bits);
}

// TODO: spagueti
RZ_API int rz_asm_sub_names_input(RzAsm *a, const char *f) {
	rz_return_val_if_fail(a && f, false);
	if (!a->ifilter) {
		a->ifilter = rz_parse_new();
	}
	if (!rz_parse_use(a->ifilter, f)) {
		rz_parse_free(a->ifilter);
		a->ifilter = NULL;
		return false;
	}
	return true;
}

RZ_API int rz_asm_sub_names_output(RzAsm *a, const char *f) {
	if (!a->ofilter) {
		a->ofilter = rz_parse_new();
	}
	if (!rz_parse_use(a->ofilter, f)) {
		rz_parse_free(a->ofilter);
		a->ofilter = NULL;
		return false;
	}
	return true;
}

RZ_API void rz_asm_free(RzAsm *a) {
	if (!a) {
		return;
	}
	plugin_fini(a);
	if (a->plugins) {
		rz_list_free(a->plugins);
		a->plugins = NULL;
	}
	rz_syscall_free(a->syscall);
	free(a->cpu);
	free(a->features);
	sdb_free(a->pair);
	ht_ss_free(a->flags);
	a->pair = NULL;
	free(a);
}

RZ_API bool rz_asm_plugin_add(RzAsm *a, RZ_NONNULL RzAsmPlugin *p) {
	rz_return_val_if_fail(a && p, false);
	if (!p->name) {
		return false;
	}
	if (rz_asm_is_valid(a, p->name)) {
		return false;
	}
	RZ_PLUGIN_CHECK_AND_ADD(a->plugins, p, RzAsmPlugin);
	return true;
}

RZ_API bool rz_asm_plugin_del(RzAsm *a, RZ_NONNULL RzAsmPlugin *p) {
	rz_return_val_if_fail(a && p, false);
	if (a->cur == p) {
		plugin_fini(a);
		a->cur = NULL;
	}
	if (a->acur == p) {
		a->acur = NULL;
	}
	return rz_list_delete_data(a->plugins, p);
}

RZ_API bool rz_asm_is_valid(RzAsm *a, const char *name) {
	RzAsmPlugin *h;
	RzListIter *iter;
	if (!name || !*name) {
		return false;
	}
	rz_list_foreach (a->plugins, iter, h) {
		if (!strcmp(h->name, name)) {
			return true;
		}
	}
	return false;
}

RZ_API bool rz_asm_use_assembler(RzAsm *a, const char *name) {
	RzAsmPlugin *h;
	RzListIter *iter;
	if (a) {
		if (name && *name) {
			rz_list_foreach (a->plugins, iter, h) {
				if (h->assemble && !strcmp(h->name, name)) {
					a->acur = h;
					return true;
				}
			}
		}
		a->acur = NULL;
	}
	return false;
}

/**
 * \brief Copies all config nodes in \p pcfg to the config in \p rz_asm.
 *
 * \param rz_asm Pointer to RzAsm struct.
 * \param pcfg Pointer to the plugins RzConfig struct.
 */
static void set_plugin_configs(RZ_BORROW RzAsm *rz_asm, RZ_BORROW RzConfig *pcfg) {
	rz_return_if_fail(pcfg && rz_asm);

	RzConfig *conf = ((RzCore *)(rz_asm->core))->config;
	RzConfigNode *n;
	RzListIter *it;
	rz_list_foreach (pcfg->nodes, it, n) {
		if (!rz_config_add_node(conf, rz_config_node_clone(n))) {
			RZ_LOG_WARN("Failed to add \"%s\" to the global config.\n", n->name)
		}
	}
}

/**
 * \brief Deletes all copies of \p pcfg nodes in the RzConfig from \p rz_asm.
 *
 * \param rz_asm Pointer to RzAsm struct.
 * \param pcfg Pointer to the plugins RzConfig struct.
 */
static void unset_plugins_config(RZ_BORROW RzAsm *rz_asm, RZ_BORROW RzConfig *pcfg) {
	rz_return_if_fail(pcfg && rz_asm && rz_asm->core);

	RzConfig *conf = ((RzCore *)(rz_asm->core))->config;
	RzConfigNode *n;
	RzListIter *it;
	rz_list_foreach (pcfg->nodes, it, n) {
		if (!rz_config_rm(conf, n->name)) {
			RZ_LOG_WARN("Failed to remove \"%s\" from the global config.\n", n->name)
		}
	}
}

// TODO: this can be optimized using rz_str_hash()
/**
 * \brief Puts an Asm plugin in use and disables the previous one.
 *
 * \param a Current RzAsm struct.
 * \param name Name of the asm plugin to enable.
 * \return true Put Asm plugin successfully in use.
 * \return false Asm plugin failed to be enabled.
 */
RZ_API bool rz_asm_use(RzAsm *a, const char *name) {
	RzAsmPlugin *h;
	RzListIter *iter;
	if (!a || !name) {
		return false;
	}
	RzCore *core = a->core;
	if (a->cur && !strcmp(a->cur->arch, name)) {
		return true;
	}
	rz_list_foreach (a->plugins, iter, h) {
		if (h->arch && h->name && !strcmp(h->name, name)) {
			if (!a->cur || (a->cur && strcmp(a->cur->arch, h->arch))) {
				plugin_fini(a);
				char *opcodes_dir = rz_path_system(RZ_SDB_OPCODES);
				char *file = rz_str_newf("%s/%s.sdb", opcodes_dir, h->arch);
				if (file) {
					rz_asm_set_cpu(a, NULL);
					sdb_free(a->pair);
					a->pair = sdb_new(NULL, file, 0);
					free(file);
				}
				free(opcodes_dir);
			}
			if (h->init && !h->init(&a->plugin_data)) {
				RZ_LOG_ERROR("asm plugin '%s' failed to initialize.\n", h->name);
				return false;
			}

			if (a->cur && a->cur->get_config && core) {
				rz_config_lock(core->config, false);
				unset_plugins_config(a, a->cur->get_config());
				rz_config_lock(core->config, true);
			}
			if (h->get_config && core) {
				rz_config_lock(core->config, false);
				set_plugin_configs(a, h->get_config());
				rz_config_lock(core->config, true);
			}
			a->cur = h;
			return true;
		}
	}
	sdb_free(a->pair);
	a->pair = NULL;
	return false;
}

RZ_DEPRECATE RZ_API void rz_asm_set_cpu(RzAsm *a, const char *cpu) {
	if (a) {
		free(a->cpu);
		a->cpu = rz_str_dup(cpu);
	}
}

static bool has_bits(RzAsmPlugin *h, int bits) {
	return (h && h->bits && (bits & h->bits));
}

RZ_DEPRECATE RZ_API int rz_asm_set_bits(RzAsm *a, int bits) {
	if (has_bits(a->cur, bits)) {
		if (a->bits != bits) {
			a->bits = bits; // TODO : use OR? :)
		}
		return true;
	}
	return false;
}

RZ_API bool rz_asm_set_big_endian(RzAsm *a, bool b) {
	rz_return_val_if_fail(a && a->cur, false);
	a->big_endian = false; // little endian by default
	switch (a->cur->endian) {
	case RZ_SYS_ENDIAN_NONE:
	case RZ_SYS_ENDIAN_BI:
		// TODO: not yet implemented
		a->big_endian = b;
		break;
	case RZ_SYS_ENDIAN_LITTLE:
		a->big_endian = false;
		break;
	case RZ_SYS_ENDIAN_BIG:
		a->big_endian = true;
		break;
	default:
		RZ_LOG_DEBUG("The asm plugin doesn't specify endianness.\n");
		break;
	}
	return a->big_endian;
}

RZ_API bool rz_asm_set_syntax(RzAsm *a, int syntax) {
	// TODO: move into rz_arch ?
	switch (syntax) {
	case RZ_ASM_SYNTAX_REGNUM:
	case RZ_ASM_SYNTAX_INTEL:
	case RZ_ASM_SYNTAX_MASM:
	case RZ_ASM_SYNTAX_ATT:
	case RZ_ASM_SYNTAX_JZ:
		a->syntax = syntax;
		return true;
	default:
		return false;
	}
}

RZ_API int rz_asm_set_pc(RzAsm *a, ut64 pc) {
	a->pc = pc;
	return true;
}

static bool __isInvalid(RzAsmOp *op) {
	const char *buf_asm = rz_strbuf_get(&op->buf_asm);
	return (buf_asm && *buf_asm && !strcmp(buf_asm, "invalid"));
}

RZ_API int rz_asm_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	rz_asm_op_init(op);
	rz_return_val_if_fail(a && buf && op, -1);
	if (len < 1) {
		return 0;
	}

	int ret = op->payload = 0;
	op->size = 4;
	op->bitsize = 0;
	rz_asm_op_set_asm(op, "");
	if (a->pcalign) {
		const int mod = a->pc % a->pcalign;
		if (mod) {
			op->size = a->pcalign - mod;
			rz_strbuf_set(&op->buf_asm, "unaligned");
			return -1;
		}
	}
	if (a->cur && a->cur->disassemble) {
		// shift buf N bits
		if (a->bitshift > 0) {
			ut8 *tmp = calloc(len, 1);
			if (tmp) {
				rz_mem_copybits_delta(tmp, 0, buf, a->bitshift, (len * 8) - a->bitshift);
				ret = a->cur->disassemble(a, op, tmp, len);
				free(tmp);
			}
		} else {
			ret = a->cur->disassemble(a, op, buf, len);
		}
	}
	if (ret < 0) {
		ret = 0;
	}
	if (op->bitsize > 0) {
		op->size = op->bitsize / 8;
		a->bitshift += op->bitsize % 8;
		int count = a->bitshift / 8;
		if (count > 0) {
			op->size = op->size + count;
			a->bitshift %= 8;
		}
	}

	if (op->size < 1 || __isInvalid(op)) {
		if (a->invhex) {
			if (a->bits == 16) {
				ut16 b = rz_read_le16(buf);
				rz_asm_op_setf_asm(op, ".word 0x%04x", b);
			} else {
				ut32 b = rz_read_le32(buf);
				rz_asm_op_setf_asm(op, ".dword 0x%08x", b);
			}
			// TODO: something for 64bits too?
		} else {
			rz_asm_op_set_asm(op, "invalid");
		}
	}
	if (a->ofilter) {
		parseHeap(a->ofilter, &op->buf_asm);
	}
	int opsz = (op->size > 0) ? RZ_MAX(0, RZ_MIN(len, op->size)) : 1;
	rz_asm_op_set_buf(op, buf, opsz);
	return ret;
}

typedef int (*Ase)(RzAsm *a, RzAsmOp *op, const char *buf);

static bool assemblerMatches(RzAsm *a, RzAsmPlugin *h) {
	if (!a || !h->arch || !h->assemble || !has_bits(h, a->bits)) {
		return false;
	}
	return (!strncmp(a->cur->arch, h->arch, strlen(a->cur->arch)));
}

static Ase findAssembler(RzAsm *a, const char *kw) {
	Ase ase = NULL;
	RzAsmPlugin *h;
	RzListIter *iter;
	if (a->acur && a->acur->assemble) {
		return a->acur->assemble;
	}
	rz_list_foreach (a->plugins, iter, h) {
		if (assemblerMatches(a, h)) {
			if (kw) {
				if (strstr(h->name, kw)) {
					return h->assemble;
				}
			} else {
				ase = h->assemble;
			}
		}
	}
	return ase;
}

static char *replace_directives_for(char *str, char *token) {
	RzStrBuf *sb = rz_strbuf_new("");
	char *p = NULL;
	char *q = str;
	bool changes = false;
	for (;;) {
		if (q) {
			p = strstr(q, token);
		}
		if (p) {
			char *nl = strchr(p, '\n');
			if (nl) {
				*nl++ = 0;
			}
			char _ = *p;
			*p = 0;
			rz_strbuf_append(sb, q);
			*p = _;
			rz_strbuf_appendf(sb, "<{%s}>\n", p + 1);
			q = nl;
			changes = true;
		} else {
			if (q) {
				rz_strbuf_append(sb, q);
			}
			break;
		}
	}
	if (changes) {
		free(str);
		return rz_strbuf_drain(sb);
	}
	rz_strbuf_free(sb);
	return str;
}

static char *replace_directives(char *str) {
	int i = 0;
	char *dir = directives[i++];
	char *o = replace_directives_for(str, dir);
	while (dir) {
		o = replace_directives_for(o, dir);
		dir = directives[i++];
	}
	return o;
}

RZ_API void rz_asm_list_directives(void) {
	int i = 0;
	char *dir = directives[i++];
	while (dir) {
		printf("%s\n", dir);
		dir = directives[i++];
	}
}

// returns instruction size
RZ_API int rz_asm_assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
	rz_return_val_if_fail(a && op && buf, 0);
	int ret = 0;
	char *b = rz_str_dup(buf);
	if (!b) {
		return 0;
	}
	if (a->ifilter) {
		char *tmp = rz_parse_pseudocode(a->ifilter, buf);
		if (tmp) {
			free(b);
			b = tmp;
		}
	}
	rz_str_case(b, 0); // to-lower
	memset(op, 0, sizeof(RzAsmOp));
	if (a->cur) {
		Ase ase = NULL;
		if (!a->cur->assemble) {
			// Check if the syntax is GAS/AT&T.
			if (a->syntax == RZ_ASM_SYNTAX_ATT) {
				ase = findAssembler(a, ".as");
			} else {
				/* find callback if no assembler support in current plugin */
				ase = findAssembler(a, ".ks");
				if (!ase) {
					ase = findAssembler(a, ".nz");
				}
				if (!ase) {
					ase = findAssembler(a, NULL);
				}
			}
		} else {
			ase = a->cur->assemble;
		}
		if (ase) {
			ret = ase(a, op, b);
		}
	}
	// XXX delete this block, the ase thing should be setting asm, buf and hex
	if (op && ret > 0) {
		op->size = ret; // XXX shouldn't be necessary
		rz_asm_op_set_asm(op, b); // XXX ase should be updating this already, isn't?
		ut8 *opbuf = (ut8 *)rz_strbuf_get(&op->buf);
		rz_asm_op_set_buf(op, opbuf, ret);
	}
	free(b);
	return ret;
}

// TODO: Use RzStrBuf api here pls
RZ_API RzAsmCode *rz_asm_mdisassemble(RzAsm *a, const ut8 *buf, int len) {
	rz_return_val_if_fail(a && buf && len >= 0, NULL);

	RzStrBuf *buf_asm;
	RzAsmCode *acode;
	ut64 pc = a->pc;
	ut64 idx;
	size_t ret;
	const size_t addrbytes = a->core ? ((RzCore *)a->core)->io->addrbytes : 1;

	if (!(acode = rz_asm_code_new())) {
		return NULL;
	}
	if (!(acode->bytes = malloc(1 + len))) {
		return rz_asm_code_free(acode);
	}
	memcpy(acode->bytes, buf, len);
	if (!(buf_asm = rz_strbuf_new(NULL))) {
		return rz_asm_code_free(acode);
	}
	RzAsmOp op;
	rz_asm_op_init(&op);
	for (idx = 0; idx + addrbytes <= len; idx += (addrbytes * ret)) {
		rz_asm_set_pc(a, pc + idx);
		ret = rz_asm_disassemble(a, &op, buf + idx, len - idx);
		if (ret < 1) {
			ret = 1;
		}
		if (a->ofilter) {
			parseHeap(a->ofilter, &op.buf_asm);
		}
		rz_strbuf_append(buf_asm, rz_strbuf_get(&op.buf_asm));
		rz_strbuf_append(buf_asm, "\n");
	}
	rz_asm_op_fini(&op);
	acode->assembly = rz_strbuf_drain(buf_asm);
	acode->len = idx;
	return acode;
}

RZ_API RzAsmCode *rz_asm_mdisassemble_hexstr(RzAsm *a, RzParse *p, const char *hexstr) {
	ut8 *buf = malloc(strlen(hexstr) + 1);
	if (!buf) {
		return NULL;
	}
	int len = rz_hex_str2bin(hexstr, buf);
	if (len < 1) {
		free(buf);
		return NULL;
	}
	RzAsmCode *ret = rz_asm_mdisassemble(a, buf, (ut64)len);
	if (ret && p) {
		char *tmp = rz_parse_pseudocode(p, ret->assembly);
		if (tmp) {
			free(ret->assembly);
			ret->assembly = tmp;
		}
	}
	free(buf);
	return ret;
}

RZ_API RzAsmCode *rz_asm_massemble(RzAsm *a, const char *assembly) {
	int num, stage, ret, idx, ctr, i, linenum = 0;
	char *lbuf = NULL, *ptr2, *ptr = NULL, *ptr_start = NULL;
	const char *asmcpu = NULL;
	RzAsmCode *acode = NULL;
	RzAsmOp op = { 0 };
	ut64 off, pc;

	char *buf_token = NULL;
	size_t tokens_size = 32;
	char **tokens = calloc(sizeof(char *), tokens_size);
	if (!tokens) {
		return NULL;
	}
	if (!assembly) {
		free(tokens);
		return NULL;
	}
	ht_ss_free(a->flags);
	if (!(a->flags = ht_ss_new(HT_STR_DUP, HT_STR_DUP))) {
		free(tokens);
		return NULL;
	}
	if (!(acode = rz_asm_code_new())) {
		free(tokens);
		return NULL;
	}
	if (!(acode->assembly = malloc(strlen(assembly) + 16))) {
		free(tokens);
		return rz_asm_code_free(acode);
	}
	rz_str_ncpy(acode->assembly, assembly, sizeof(acode->assembly) - 1);
	if (!(acode->bytes = calloc(1, 64))) {
		free(tokens);
		return rz_asm_code_free(acode);
	}
	lbuf = rz_str_dup(assembly);
	acode->code_align = 0;

	/* consider ,, an alias for a newline */
	lbuf = rz_str_replace(lbuf, ",,", "\n", true);
	/* accept ';' as comments when input is multiline */
	{
		char *nl = strchr(lbuf, '\n');
		if (nl) {
			if (strchr(nl + 1, '\n')) {
				rz_str_replace_char(lbuf, ';', '#');
			}
		}
	}
	// XXX: ops like mov eax, $pc+33 fail coz '+' is not a valid number!!!
	// XXX: must be handled here to be global.. and not arch-specific
	{
		char val[32];
		snprintf(val, sizeof(val), "0x%" PFMT64x, a->pc);
		lbuf = rz_str_replace(lbuf, "$$", val, 1);
	}
	if (a->syscall) {
		char val[32];
		char *aa, *p = strstr(lbuf, "$sys.");
		while (p) {
			char *sp = (char *)rz_str_closer_chr(p, " \n\r#");
			if (sp) {
				char osp = *sp;
				*sp = 0;
				aa = rz_str_dup(p);
				*sp = osp;
				num = rz_syscall_get_num(a->syscall, aa + 5);
				snprintf(val, sizeof(val), "%d", num);
				lbuf = rz_str_replace(lbuf, aa, val, 1);
				free(aa);
			}
			p = strstr(p + 5, "$sys.");
		}
	}
	bool labels = !!strchr(lbuf, ':');

	/* Tokenize */
	for (tokens[0] = lbuf, ctr = 0;
		((ptr = strchr(tokens[ctr], ';')) ||
			(ptr = strchr(tokens[ctr], '\n')) ||
			(ptr = strchr(tokens[ctr], '\r')));) {
		if (ctr + 1 >= tokens_size) {
			const size_t new_tokens_size = tokens_size * 2;
			if (sizeof(char *) * new_tokens_size <= sizeof(char *) * tokens_size) {
				// overflow
				RZ_LOG_ERROR("Too many tokens while assembling (overflow).\n");
				goto fail;
			}
			char **new_tokens = realloc(tokens, sizeof(char *) * new_tokens_size);
			if (!new_tokens) {
				RZ_LOG_ERROR("Cannot reallocate meory for tokens while assembling.\n");
				goto fail;
			}
			tokens_size = new_tokens_size;
			tokens = new_tokens;
		}
		ctr++;
		*ptr = '\0';
		tokens[ctr] = ptr + 1;
	}

#define isavrseparator(x) ((x) == ' ' || (x) == '\t' || (x) == '\n' || (x) == '\r' || (x) == ' ' || \
	(x) == ',' || (x) == ';' || (x) == '[' || (x) == ']' || \
	(x) == '(' || (x) == ')' || (x) == '{' || (x) == '}')

	/* Stage 0-2: Parse labels*/
	/* Stage 3: Assemble */
// XXX: stages must be dynamic. until all equs have been resolved
#define STAGES 5
	pc = a->pc;
	bool inComment = false;
	for (stage = 0; stage < STAGES; stage++) {
		if (stage < 2 && !labels) {
			continue;
		}
		inComment = false;
		rz_asm_set_pc(a, pc);
		for (idx = ret = i = 0; i <= ctr; i++, idx += ret) {
			buf_token = tokens[i];
			if (!buf_token) {
				continue;
			}
			if (inComment) {
				if (!strncmp(ptr_start, "*/", 2)) {
					inComment = false;
				}
				continue;
			}
			// XXX TODO remove arch-specific hacks
			if (!strncmp(a->cur->arch, "avr", 3)) {
				for (ptr_start = buf_token; *ptr_start && isavrseparator(*ptr_start); ptr_start++)
					;
			} else {
				for (ptr_start = buf_token; *ptr_start && IS_SEPARATOR(*ptr_start); ptr_start++)
					;
			}
			if (!strncmp(ptr_start, "/*", 2)) {
				if (!strstr(ptr_start + 2, "*/")) {
					inComment = true;
				}
				continue;
			}
			/* Comments */ {
				bool likely_comment = true;
				char *cptr = strchr(ptr_start, ',');
				ptr = strchr(ptr_start, '#');
				// a comma is probably not followed by a comment
				// 8051 often uses #symbol notation as 2nd arg
				if (cptr && ptr && cptr < ptr) {
					likely_comment = false;
					for (cptr += 1; cptr < ptr; cptr += 1) {
						if (!isspace(*cptr)) {
							likely_comment = true;
							break;
						}
					}
				}
				// # followed by number literal also
				// isn't likely to be a comment
				likely_comment = likely_comment && ptr && !RZ_BETWEEN('0', ptr[1], '9') && ptr[1] != '-';
				if (likely_comment) {
					*ptr = '\0';
				}
			}
			rz_asm_set_pc(a, a->pc + ret);
			off = a->pc;
			ret = 0;
			if (!*ptr_start) {
				continue;
			}
			linenum++;
			/* labels */
			if (labels && (ptr = strchr(ptr_start, ':'))) {
				bool is_a_label = true;
				char *q = ptr_start;
				while (*q) {
					if (*q == ' ') {
						is_a_label = false;
						break;
					}
					q++;
				}
				if (is_a_label) {
					// if (stage != 2) {
					if (ptr_start[1] && ptr_start[1] != ' ') {
						*ptr = 0;
						char *p = rz_str_dup(ptr_start);
						*ptr = ':';
						if (acode->code_align) {
							off += (acode->code_align - (off % acode->code_align));
						}
						char *food = rz_str_newf("0x%" PFMT64x, off);
						ht_ss_insert(a->flags, ptr_start, food);
						rz_asm_code_set_equ(acode, p, food);
						free(p);
						free(food);
					}
					//}
					ptr_start = ptr + 1;
				}
			}
			if (!*ptr_start) {
				ret = 0;
				continue;
			}
			if (*ptr_start == '.') { /* pseudo */
				/* TODO: move into a separate function */
				ptr = ptr_start;
				rz_str_trim(ptr);
				if (!strncmp(ptr, ".intel_syntax", 13)) {
					a->syntax = RZ_ASM_SYNTAX_INTEL;
				} else if (!strncmp(ptr, ".att_syntax", 11)) {
					a->syntax = RZ_ASM_SYNTAX_ATT;
				} else if (!strncmp(ptr, ".endian", 7)) {
					rz_asm_set_big_endian(a, atoi(ptr + 7));
				} else if (!strncmp(ptr, ".big_endian", 7 + 4)) {
					rz_asm_set_big_endian(a, true);
				} else if (!strncmp(ptr, ".lil_endian", 7 + 4) || !strncmp(ptr, "little_endian", 7 + 6)) {
					rz_asm_set_big_endian(a, false);
				} else if (!strncmp(ptr, ".asciz", 6)) {
					rz_str_trim(ptr + 8);
					ret = rz_asm_pseudo_string(&op, ptr + 8, 1);
				} else if (!strncmp(ptr, ".string ", 8)) {
					rz_str_trim(ptr + 8);
					char *str = rz_str_dup(ptr + 8);
					ret = rz_asm_pseudo_string(&op, str, 1);
					free(str);
				} else if (!strncmp(ptr, ".ascii", 6)) {
					ret = rz_asm_pseudo_string(&op, ptr + 7, 0);
				} else if (!strncmp(ptr, ".align", 6)) {
					ret = rz_asm_pseudo_align(acode, &op, ptr + 7);
				} else if (!strncmp(ptr, ".arm", 4)) {
					rz_asm_use(a, "arm");
					rz_asm_set_bits(a, 32);
					ret = 0;
				} else if (!strncmp(ptr, ".thumb", 6)) {
					rz_asm_use(a, "arm");
					rz_asm_set_bits(a, 16);
					ret = 0;
				} else if (!strncmp(ptr, ".arch ", 6)) {
					ret = rz_asm_pseudo_arch(a, ptr + 6);
				} else if (!strncmp(ptr, ".bits ", 6)) {
					ret = rz_asm_pseudo_bits(a, ptr + 6);
				} else if (!strncmp(ptr, ".fill ", 6)) {
					ret = rz_asm_pseudo_fill(&op, ptr + 6);
				} else if (!strncmp(ptr, ".kernel ", 8)) {
					rz_syscall_setup(a->syscall, a->cur->arch, a->bits, asmcpu, ptr + 8);
				} else if (!strncmp(ptr, ".cpu ", 5)) {
					rz_asm_set_cpu(a, ptr + 5);
				} else if (!strncmp(ptr, ".os ", 4)) {
					rz_syscall_setup(a->syscall, a->cur->arch, a->bits, asmcpu, ptr + 4);
				} else if (!strncmp(ptr, ".hex ", 5)) {
					ret = rz_asm_op_set_hex(&op, ptr + 5);
				} else if ((!strncmp(ptr, ".int16 ", 7)) || !strncmp(ptr, ".short ", 7)) {
					ret = rz_asm_pseudo_int16(a, &op, ptr + 7);
				} else if (!strncmp(ptr, ".int32 ", 7)) {
					ret = rz_asm_pseudo_int32(a, &op, ptr + 7);
				} else if (!strncmp(ptr, ".int64 ", 7)) {
					ret = rz_asm_pseudo_int64(a, &op, ptr + 7);
				} else if (!strncmp(ptr, ".size", 5)) {
					ret = true; // do nothing, ignored
				} else if (!strncmp(ptr, ".section", 8)) {
					ret = true; // do nothing, ignored
				} else if ((!strncmp(ptr, ".byte ", 6)) || (!strncmp(ptr, ".int8 ", 6))) {
					ret = rz_asm_pseudo_byte(&op, ptr + 6);
				} else if (!strncmp(ptr, ".glob", 5)) { // .global .globl
					RZ_LOG_DEBUG(".global directive not yet implemented\n");
					ret = 0;
					continue;
				} else if (!strncmp(ptr, ".equ ", 5)) {
					ptr2 = strchr(ptr + 5, ',');
					if (!ptr2) {
						ptr2 = strchr(ptr + 5, '=');
					}
					if (!ptr2) {
						ptr2 = strchr(ptr + 5, ' ');
					}
					if (ptr2) {
						*ptr2 = '\0';
						rz_asm_code_set_equ(acode, ptr + 5, ptr2 + 1);
					} else {
						RZ_LOG_ERROR("Invalid syntax for '.equ': Use '.equ <word> <word>'\n");
					}
				} else if (!strncmp(ptr, ".org ", 5)) {
					ret = rz_asm_pseudo_org(a, ptr + 5);
				} else if (rz_str_startswith(ptr, ".offset ")) {
					RZ_LOG_ERROR("Invalid use of the .offset directory. This directive is only supported in rizin -c 'waf'.\n");
				} else if (!strncmp(ptr, ".text", 5)) {
					acode->code_offset = a->pc;
				} else if (!strncmp(ptr, ".data", 5)) {
					acode->data_offset = a->pc;
				} else if (!strncmp(ptr, ".incbin", 7)) {
					if (ptr[7] != ' ') {
						RZ_LOG_ERROR("Invalid syntax for '.incbin': Use '.incbin <filename>'\n");
						continue;
					}
					ret = rz_asm_pseudo_incbin(&op, ptr + 8);
				} else {
					RZ_LOG_ERROR("Unknown directive named '%s'\n", ptr);
					goto fail;
				}
				if (!ret) {
					continue;
				}
				if (ret < 0) {
					RZ_LOG_ERROR("Something went wrong when handling the directive '%s'.\n", ptr);
					goto fail;
				}
			} else { /* Instruction */
				char *str = ptr_start;
				rz_str_trim(str);
				if (acode->equs) {
					if (!*ptr_start) {
						continue;
					}
					str = rz_asm_code_equ_replace(acode, rz_str_dup(ptr_start));
					rz_asm_op_fini(&op);
					rz_asm_op_init(&op);
					ret = rz_asm_assemble(a, &op, str);
					free(str);
				} else {
					if (!*ptr_start) {
						continue;
					}
					rz_asm_op_fini(&op);
					rz_asm_op_init(&op);
					ret = rz_asm_assemble(a, &op, ptr_start);
				}
			}
			if (stage == STAGES - 1) {
				if (ret < 1) {
					RZ_LOG_ERROR("Cannot assemble '%s' at line %d\n", ptr_start, linenum);
					goto fail;
				}
				acode->len = idx + ret;
				char *newbuf = realloc(acode->bytes, (idx + ret) * 2);
				if (!newbuf) {
					goto fail;
				}
				acode->bytes = (ut8 *)newbuf;
				memcpy(acode->bytes + idx, rz_strbuf_get(&op.buf), rz_strbuf_length(&op.buf));
				memset(acode->bytes + idx + ret, 0, idx + ret);
				if (op.buf_inc && rz_buf_size(op.buf_inc) > 1) {
					char *inc = rz_buf_to_string(op.buf_inc);
					rz_buf_free(op.buf_inc);
					op.buf_inc = NULL;
					if (inc) {
						ret += rz_hex_str2bin(inc, acode->bytes + idx + ret);
						free(inc);
					}
				}
			}
		}
	}
	rz_asm_op_fini(&op);
	free(lbuf);
	free(tokens);
	return acode;
fail:
	rz_asm_op_fini(&op);
	free(lbuf);
	free(tokens);
	return rz_asm_code_free(acode);
}

RZ_API int rz_asm_get_offset(RzAsm *a, int type, int idx) { // link to rbin
	if (a && a->binb.bin && a->binb.get_offset) {
		return a->binb.get_offset(a->binb.bin, type, idx);
	}
	return -1;
}

RZ_API char *rz_asm_describe(RzAsm *a, const char *str) {
	return (a && a->pair) ? sdb_get(a->pair, str) : NULL;
}

RZ_API RzList /*<RzAsmPlugin *>*/ *rz_asm_get_plugins(RzAsm *a) {
	return a->plugins;
}

RZ_API bool rz_asm_set_arch(RzAsm *a, const char *name, int bits) {
	return rz_asm_use(a, name) ? rz_asm_set_bits(a, bits) : false;
}

/* to ease the use of the native bindings (not used in rizin) */
RZ_API char *rz_asm_to_string(RzAsm *a, ut64 addr, const ut8 *b, int l) {
	rz_return_val_if_fail(a && b && l >= 0, NULL);
	rz_asm_set_pc(a, addr);
	RzAsmCode *code = rz_asm_mdisassemble(a, b, l);
	if (code) {
		char *buf_asm = code->assembly;
		code->assembly = NULL;
		rz_asm_code_free(code);
		return buf_asm;
	}
	return NULL;
}

RZ_API ut8 *rz_asm_from_string(RzAsm *a, ut64 addr, const char *b, int *l) {
	rz_asm_set_pc(a, addr);
	RzAsmCode *code = rz_asm_massemble(a, b);
	if (code) {
		ut8 *buf = code->bytes;
		if (l) {
			*l = code->len;
		}
		rz_asm_code_free(code);
		return buf;
	}
	return NULL;
}

RZ_API int rz_asm_syntax_from_string(const char *name) {
	rz_return_val_if_fail(name, -1);
	if (!strcmp(name, "regnum")) {
		return RZ_ASM_SYNTAX_REGNUM;
	}
	if (!strcmp(name, "jz")) {
		return RZ_ASM_SYNTAX_JZ;
	}
	if (!strcmp(name, "intel")) {
		return RZ_ASM_SYNTAX_INTEL;
	}
	if (!strcmp(name, "masm")) {
		return RZ_ASM_SYNTAX_MASM;
	}
	if (!strcmp(name, "att")) {
		return RZ_ASM_SYNTAX_ATT;
	}
	return -1;
}

RZ_API char *rz_asm_mnemonics(RzAsm *a, int id, bool json) {
	rz_return_val_if_fail(a && a->cur, NULL);
	if (a->cur->mnemonics) {
		return a->cur->mnemonics(a, id, json);
	}
	return NULL;
}

RZ_API int rz_asm_mnemonics_byname(RzAsm *a, const char *name) {
	rz_return_val_if_fail(a && a->cur, 0);
	if (a->cur->mnemonics) {
		int i;
		for (i = 0; i < 1024; i++) {
			char *n = a->cur->mnemonics(a, i, false);
			if (n && !strcmp(n, name)) {
				return i;
			}
			free(n);
		}
	}
	return 0;
}

RZ_API RzAsmCode *rz_asm_rasm_assemble(RzAsm *a, const char *buf, bool use_spp) {
	rz_return_val_if_fail(a && buf, NULL);
	char *lbuf = rz_str_dup(buf);
	if (!lbuf) {
		return NULL;
	}
	RzAsmCode *acode;
	if (use_spp) {
		Output out;
		out.fout = NULL;
		out.cout = rz_strbuf_new("");
		rz_strbuf_init(out.cout);
		struct Proc proc;
		spp_proc_set(&proc, "spp", 1);

		lbuf = replace_directives(lbuf);
		spp_eval(lbuf, &out);
		free(lbuf);
		lbuf = rz_str_dup(rz_strbuf_get(out.cout));
	}
	acode = rz_asm_massemble(a, lbuf);
	free(lbuf);
	return acode;
}

RZ_API RZ_OWN RzAsmTokenString *rz_asm_token_string_new(const char *asm_str) {
	RzAsmTokenString *s = RZ_NEW0(RzAsmTokenString);
	if (!s) {
		return NULL;
	}
	s->tokens = rz_vector_new(sizeof(RzAsmToken), NULL, NULL);
	s->str = rz_strbuf_new(asm_str);
	if (!s->tokens || !s->str) {
		rz_asm_token_string_free(s);
		return NULL;
	}
	return s;
}

RZ_API void rz_asm_token_string_free(RZ_OWN RzAsmTokenString *toks) {
	if (!toks) {
		return;
	}
	rz_strbuf_free(toks->str);
	rz_vector_free(toks->tokens);
	free(toks);
}

RZ_API RZ_OWN RzAsmTokenString *rz_asm_token_string_clone(RZ_OWN RZ_NONNULL RzAsmTokenString *toks) {
	rz_return_val_if_fail(toks, NULL);

	RzAsmTokenString *newt = RZ_NEW0(RzAsmTokenString);
	if (!newt) {
		return NULL;
	}
	newt->tokens = rz_vector_clone(toks->tokens);
	newt->str = rz_strbuf_new(rz_strbuf_get(toks->str));
	newt->op_type = toks->op_type;

	if (!(newt->tokens && newt->str)) {
		free(newt);
		return NULL;
	}
	return newt;
}

RZ_API void rz_asm_token_pattern_free(void *p) {
	if (!p) {
		return;
	}
	RzAsmTokenPattern *pat = (RzAsmTokenPattern *)p;
	free(pat->pattern);
	rz_regex_free(pat->regex);
	free(p);
}

/**
 * \brief Creates a token and returns it.
 *
 * \param start Index in the asm string of the token.
 * \param len The length in bytes of the token.
 * \param type The token type.
 * \param val The value of the token (should be 0 if token has no value).
 * \return RzAsmToken* Pointer to the newly created token or NULL in case of failure.
 */
static RZ_OWN RzAsmToken *asm_token_create(const size_t start, const size_t len, const RzAsmTokenType type, const ut64 val) {
	rz_return_val_if_fail(len > 0, NULL);
	RzAsmToken *t = RZ_NEW0(RzAsmToken);
	if (!t) {
		return NULL;
	}

	t->start = start;
	t->type = type;
	t->len = len;
	switch (type) {
	default:
		break;
	case RZ_ASM_TOKEN_NUMBER:
		t->val.number = val;
		break;
	}
	return t;
}

/**
 * \brief Creates a token and adds it to the token string vector \p toks.
 *
 * \param toks The token string to which the token is added.
 * \param i The start index if the token.
 * \param l The length of the token.
 * \param type The type of the token.
 * \param token_val The token value if it was a number otherwise should be 0.
 */
static void add_token(RZ_OUT RzAsmTokenString *toks, const size_t i, const size_t l, const RzAsmTokenType type, const ut64 token_val) {
	rz_return_if_fail(toks);
	RzAsmToken *t = asm_token_create(i, l, type, token_val);
	if (!t) {
		RZ_LOG_WARN("Failed to create token. Asm strings will be flawed.\n");
		rz_warn_if_reached();
		return;
	}

	rz_vector_push(toks->tokens, t);
	free(t);
}

/**
 * \brief Checks if indicies s, e overlap with other tokens start/end.
 *
 * \param toks Tokens to compare to.
 * \param s Start index of token into asm string.
 * \param e End index of token into asm string (points to last char of token).
 * \return true Overlaps with token from token vector.
 * \return false Does not overap with other token.
 */
static bool overlaps_with_token(RZ_BORROW RzVector /*<RzAsmTokenString>*/ *toks, const size_t s, const size_t e) {
	rz_return_val_if_fail(toks, false);
	size_t x, y; // Other tokens start/end
	RzAsmToken *it;
	rz_vector_foreach (toks, it) {
		x = it->start;
		y = it->start + it->len - 1;
		if (!(s > y || e < x)) { // s:e not outside of x:y
			return true;
		}
	}
	return false;
}

/**
 * \brief Compare two RzAsmTokens.
 *
 * \param a Token a to compare.
 * \param b Token b to compare.
 *
 * \return -1 If a.start < b.start
 * \return 1 If a.start > b.start
 * \return 0 If a.start == b.start
 */
static int cmp_tokens(const RzAsmToken *a, const RzAsmToken *b, void *user) {
	rz_return_val_if_fail(a && b, 0);
	if (a->start < b->start) {
		return -1;
	} else if (a->start > b->start) {
		return 1;
	}
	return 0;
}

static const char *token_str(RzAsmToken *t) {
	static const char *token_strings[] = {
		[RZ_ASM_TOKEN_MNEMONIC] = "MNEMONIC", ///< Asm mnemonics like: mov, push, lea...
		[RZ_ASM_TOKEN_OPERATOR] = "OPERATOR", ///< Arithmetic operators: +,-,<< etc.
		[RZ_ASM_TOKEN_NUMBER] = "NUMBER", ///< Numbers
		[RZ_ASM_TOKEN_REGISTER] = "REGISTER", ///< Registers
		[RZ_ASM_TOKEN_SEPARATOR] = "SEPARATOR", ///< Brackets, comma etc.
		[RZ_ASM_TOKEN_META] = "META", ///< Meta information (e.g Hexagon packet prefix, ARM & Hexagon number prefix).
	};
	if (!t) {
		return NULL;
	}
	if (t->type < RZ_ASM_TOKEN_MNEMONIC || t->type > RZ_ASM_TOKEN_META) {
		return "UNKNOWN";
	}
	return token_strings[t->type];
}

/**
 * \brief Checks a token string if any token in it overlaps with another or a part of the asm string is not covered.
 * It prints a warning if this is the case.
 *
 * \param toks The token string to check.
 */
static void check_token_coverage(RzAsmTokenString *toks) {
	rz_return_if_fail(toks);
	if (rz_vector_len(toks->tokens) == 0) {
		RZ_LOG_WARN("No tokens given.\n");
		return;
	}
	bool error = false;
	// Check if all characters belong to a token.
	RzAsmToken *cur, *prev = NULL;
	int i = 0;
	ut32 ci, cj, pi, pj; // Current and previous token indices.
	rz_vector_foreach (toks->tokens, cur) {
		if (i == cur->start) {
			prev = cur;
			i = cur->start + cur->len;
			continue;
		}
		ci = cur->start;
		cj = cur->start + cur->len;
		pi = prev ? prev->start : 0;
		pj = prev ? prev->start + prev->len : 0;
		if (i > cur->start) {
			RZ_LOG_WARN("i = %" PFMT32d " Token at %" PFMT32d ":%" PFMT32d " overlaps with token %" PFMT32d ":%" PFMT32d "\n",
				i, pi, pj, ci, cj);
			error = true;
		} else {
			RZ_LOG_WARN("i = %" PFMT32d ", Part of asm string is not covered by a token."
				    " Empty range between token[%s] %" PFMT32d ":%" PFMT32d " and token[%s] %" PFMT32d ":%" PFMT32d "\n",
				i, token_str(prev), pi, pj, token_str(cur), ci, cj);
			error = true;
		}
		i = cur->start + cur->len;
		prev = cur;
	}
	if (error) {
		RZ_LOG_WARN("Parsing errors in asm str: %s\n", rz_strbuf_get(toks->str));
	}
}

/**
 * \brief Compiles the regex patterns of a vector of RzAsmTokenPatterns.
 *
 * \param patterns The token patterns to compile the regex for.
 */
RZ_API void rz_asm_compile_token_patterns(RZ_INOUT RzPVector /*<RzAsmTokenPattern *>*/ *patterns) {
	rz_return_if_fail(patterns);

	void **it;
	rz_pvector_foreach (patterns, it) {
		RzAsmTokenPattern *pat = *it;
		if (!pat->regex) {
			pat->regex = rz_regex_new(pat->pattern, RZ_REGEX_EXTENDED, 0);
			if (!pat->regex) {
				RZ_LOG_WARN("Did not compile regex pattern %s.\n", pat->pattern);
				rz_warn_if_reached();
			}
		}
	}
}

/**
 * \brief Splits an asm string into tokens by using the given regex patterns.
 *
 * \param str The asm string.
 * \param patterns RzList<RzAsmTokenPattern> with the regex patterns describing each token type.
 * \return RzAsmTokenString* The tokens.
 */
RZ_API RZ_OWN RzAsmTokenString *rz_asm_tokenize_asm_regex(RZ_BORROW RzStrBuf *asm_string, RzPVector /*<RzAsmTokenPattern *>*/ *patterns) {
	rz_return_val_if_fail(asm_string && patterns, NULL);

	const char *asm_str = rz_strbuf_get(asm_string);
	RzAsmTokenString *toks = rz_asm_token_string_new(asm_str);

	void **it;
	// Iterate over each pattern and search for it in str
	rz_pvector_foreach (patterns, it) {
		RzAsmTokenPattern *pattern = *it;
		if (!pattern) {
			rz_asm_token_string_free(toks);
			return NULL;
		}
		if (!pattern->regex) {
			// Pattern was not compiled.
			rz_asm_compile_token_patterns(patterns);
			if (!pattern->regex) {
				rz_warn_if_reached();
				return NULL;
			}
		}

		// Search for token pattern.
		RzPVector *match_sets = rz_regex_match_all(pattern->regex, asm_str, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
		void **grouped_match;
		rz_pvector_foreach (match_sets, grouped_match) {
			if (rz_pvector_empty(*grouped_match)) {
				continue;
			}
			RzRegexMatch *match = rz_pvector_at(*grouped_match, 0);
			st64 match_start = match->start; // Token start
			st64 len = match->len; // Length of token
			st64 tok_offset = match_start; // Token offset in str
			if (overlaps_with_token(toks->tokens, tok_offset, tok_offset + len - 1)) {
				// If this is true a token with higher priority was matched before.
				continue;
			}

			// New token found, add it.
			if (!is_num(asm_str + tok_offset)) {
				add_token(toks, tok_offset, len, pattern->type, 0);
				continue;
			}
			ut64 number = strtoull(asm_str + tok_offset, NULL, 0);
			add_token(toks, tok_offset, len, pattern->type, number);
		}
		rz_pvector_free(match_sets);
	}

	rz_vector_sort(toks->tokens, (RzVectorComparator)cmp_tokens, false, NULL);
	check_token_coverage(toks);

	return toks;
}

/**
 * \brief Seeks from \p str + \p i for a token of the given \p type.
 * If any was found it returns the length of it. Or 0 if non was found.
 *
 * \param str The asm string.
 * \param i Index into \p str where the token starts.
 * \param type Type of the token.
 * \return size_t Length of token
 */
static size_t seek_to_end_of_token(const char *str, size_t i, RzAsmTokenType type) {
	rz_return_val_if_fail(str, 0);
	size_t j = i;

	switch (type) {
	default:
		rz_warn_if_reached();
		break;
	case RZ_ASM_TOKEN_MNEMONIC:
	case RZ_ASM_TOKEN_REGISTER:
		do {
			++j;
		} while (is_alpha_num(str + j));
		break;
	case RZ_ASM_TOKEN_NUMBER:
		do {
			if (rz_num_is_hex_prefix(str + j)) {
				j += 2;
			} else {
				++j;
			}
		} while (is_num(str + j));
		break;
	case RZ_ASM_TOKEN_SEPARATOR:
		do {
			++j;
		} while (is_separator(str + j));
		break;
	case RZ_ASM_TOKEN_OPERATOR:
		do {
			++j;
		} while (is_operator(str + j));
		break;
	case RZ_ASM_TOKEN_UNKNOWN:
		do {
			++j;
		} while (!isascii(*(str + j)) && !is_operator(str + j) && !is_separator(str + j) && !is_alpha_num(str + j));
		break;
	}
	return j - i;
}

/**
 * \brief Parses an asm string into tokens.
 *
 * \p param->regsets must be set if this function is expected to detect register names.
 *
 * \param asm_str The asm string.
 * \param param Several parameter which alter the parsing.
 * \return RzAsmTokenString* The asm tokens.
 */
static RZ_OWN RzAsmTokenString *tokenize_asm_generic(RZ_BORROW RzStrBuf *asm_str, RZ_NULLABLE const RzAsmParseParam *param) {
	rz_return_val_if_fail(asm_str, NULL);
	if (rz_strbuf_is_empty(asm_str)) {
		return NULL;
	}
	// Splitting the asm string into tokens is relatively straight forward.
	//
	// The target is to split an asm string into separate tokens of a given type.
	// For example:
	//
	// Asm string: `mov eax, 0x122`
	//
	// is split into:
	//   `mov`   : Mnemonic token
	//   ` `     : Separator token
	//   `eax`   : Register token
	//   `, `    : Separator token
	//   `0x122` : Number token
	//
	// In order to do this we associated a certain characters with a token type.
	//
	// E.g. alphanumeric characters are associated with numbers, registers and mnemonics.
	// Comma and brackets are interpreted as separators.
	// Plus, minus and pipe are associated with the operator token type and so forth.
	//
	// A sequence of characters of the same type are interpreted as a token.
	//
	// For example: `lr` could be a mnemonic or a special register.
	//
	// In this generic method we ignore these ambiguities and parse the first alphabetic token always as mnemonic
	// and alphabetic tokens after that as registers/unknowns.
	//
	// To extract the tokens we set the following variables:
	// `i = 0`				// Start of token
	// `l = 0`				// Length of token.
	// `i + l`				// Is the start of the next token.
	//
	// Parsing is done sequentially:
	// - The character at `str[i]` determines the token type.
	// - Iterate over characters from `i` on and stop if a character of another token type appears (char at `str[l]`).
	// - Create token from `i` to `l-1` with length `l`.
	// - Start again from `i + l`

	const char *str = rz_strbuf_get(asm_str);
	if (!str) {
		return NULL;
	}
	RzAsmTokenString *toks = rz_asm_token_string_new(str);
	if (!toks) {
		return NULL;
	}
	// Start of token.
	size_t i = 0;
	// Length of token.
	size_t l = 0;
	// Set flag once the mnemonic was parsed
	// The mnemonic is the first token in our string which ends with an ' '
	// Some mnemonics are not at the beginning of the string
	// and have only hexadecimal digits. It is too complicated to handle those.
	// In this case the plugin should build its own token strings.
	bool mnemonic_parsed = false;

	while (str[i]) {
		// Alphanumeric tokens
		if (is_alpha_num(str + i)) {
			bool is_number = false;
			bool prefix_less_hex = false;
			if (isxdigit(*(str + i)) && mnemonic_parsed) {
				// Registers, mnemonics and hexadecimal numbers can be ambiguous.
				// E.g. "eax" could be parsed as hex number token "ea".
				//      "ac0" could be a prefixless hexnumber or a register.
				// To solve this we do:
				//
				// Step 1:
				// Here we check try to parse a number and check:
				//    A. the character after the number token
				//    B. if the number token starts with the hex prefix "0x"
				// Step 2:
				// A: If the char after the number token is an alphabetic char (like the "x" in "eax"),
				//    the token isn't a number.
				// B: If it could be a hex number but has no prefix, a flag is set.
				//    In this case we only mark it as number if it is not in the register profile.

				// Handles cases where the string can be of: sym.foo_bar_ADC_dfg, sym_foo_bar_0x80
				// 1) If the next byte after seek is not an operator or a separator and
				// 2) if the hex string is not unknown then we can consider it as a number.
				l = seek_to_end_of_token(str, i, RZ_ASM_TOKEN_NUMBER);
				if ((!str[i + l] || is_separator(str + i + l) || is_operator(str + i + l)) && is_not_unknown(str, i, i + l)) {
					prefix_less_hex = !rz_num_is_hex_prefix(str + i);
					is_number = true;
				}
			}

			if (is_number && !prefix_less_hex) {
				// Parse numbers which are defintly a number.
				add_token(toks, i, l, RZ_ASM_TOKEN_NUMBER, strtoull(str + i, NULL, 0));
			} else if (mnemonic_parsed) {
				l = seek_to_end_of_token(str, i, RZ_ASM_TOKEN_REGISTER);
				char *op_name = rz_str_ndup(str + i, l);
				if (param && is_register(op_name, param->reg_sets) && is_not_unknown(str, i, i + l)) {
					add_token(toks, i, l, RZ_ASM_TOKEN_REGISTER, 0);
				} else if (prefix_less_hex) {
					// It wasn't a register but still could be a prefixless hex number.
					add_token(toks, i, l, RZ_ASM_TOKEN_NUMBER, strtoull(str + i, NULL, 0));
				} else {
					// Didn't match any of the before. Mark as unknown.
					add_token(toks, i, l, RZ_ASM_TOKEN_UNKNOWN, 0);
				}
				free(op_name);
			} else {
				mnemonic_parsed = true;
				l = seek_to_end_of_token(str, i, RZ_ASM_TOKEN_MNEMONIC);
				if (*(str + i + l) != ' ') {
					// Mnemonics can contain dots and other separators.
					// Example ARM asm string: "adc.w r8, sb, sl, ror 31"
					// Here we seek past the first separator.
					l += seek_to_end_of_token(str, l + i, RZ_ASM_TOKEN_MNEMONIC);
				}
				add_token(toks, i, l, RZ_ASM_TOKEN_MNEMONIC, 0);
			}
		} else if (is_operator(str + i)) {
			l = seek_to_end_of_token(str, i, RZ_ASM_TOKEN_OPERATOR);
			add_token(toks, i, l, RZ_ASM_TOKEN_OPERATOR, 0);
		} else if (is_separator(str + i)) {
			l = seek_to_end_of_token(str, i, RZ_ASM_TOKEN_SEPARATOR);
			add_token(toks, i, l, RZ_ASM_TOKEN_SEPARATOR, 0);
		} else {
			// Unknown tokens. UTF-8 and others.
			l = seek_to_end_of_token(str, i, RZ_ASM_TOKEN_UNKNOWN);
			add_token(toks, i, l, RZ_ASM_TOKEN_UNKNOWN, 0);
		}
		i = i + l;
	}
	return toks;
}

/**
 * \brief Parses an asm string generically. It parses the string like: <mnemmonic> <op>, <op>.
 * Every <op> (which is not a number) is parsed as a register. Unless a register profile is given.
 * In this case <op> is only parsed as register if it occurs in the register profile. Otherwise as UNKNOWN.
 *
 * DEPRECATED: Please implement your custom parsing method and set RzAsmOp.asm_toks.
 * Check out the Hexagon plugin for an example implementation.
 *
 */
RZ_DEPRECATE RZ_API RZ_OWN RzAsmTokenString *rz_asm_tokenize_asm_string(RZ_BORROW RzStrBuf *asm_str, RZ_NULLABLE const RzAsmParseParam *param) {
	rz_return_val_if_fail(asm_str, NULL);

	return tokenize_asm_generic(asm_str, param);
}

/**
 * \brief Colors a given asm string and returns it. If \p toks is not NULL it uses the tokens to color the asm string accordingly.
 * If \p toks is NULL it parses the asm string generically into tokens and colorizes it afterwards.
 * \p param can be set to alter the generic parsing method.
 *
 * DEPRECATED: This is only a helper method until all plugins set RzAsmOp.asm_toks.
 * Please check if this is already the case before using this function.
 * If you want to implement the token parsing of the asm string take a look at the Hexagon plugin
 * for an example.
 *
 * \param asm_str The plain asm string.
 * \param p The RzPrint object which holds the color palette to use.
 * \param param Parsing parameter for the generic parsing method (can be NULL).
 * \param toks Already present token string for \p asm_str (can be NULL).
 * \return RzStrBuf* String buffer with the colorized asm string.
 */
RZ_DEPRECATE RZ_API RZ_OWN RzStrBuf *
rz_asm_colorize_asm_str(RZ_BORROW RzStrBuf *asm_str, RZ_BORROW RzPrint *p, RZ_NULLABLE const RzAsmParseParam *param, RZ_NULLABLE const RzAsmTokenString *toks) {
	RzStrBuf *colored_asm;
	if (toks) {
		colored_asm = rz_print_colorize_asm_str(p, toks);
	} else {
		RzAsmTokenString *ts = rz_asm_tokenize_asm_string(asm_str, param);
		if (!ts) {
			return NULL;
		}
		ts->op_type = param ? param->ana_op_type : 0;
		colored_asm = rz_print_colorize_asm_str(p, ts);
		rz_asm_token_string_free(ts);
	}
	return colored_asm;
}

/**
 * \brief Free a RzAsmParseParam
 *
 * \param p The parameter struct.
 */
RZ_API void rz_asm_parse_param_free(RZ_OWN RZ_NULLABLE RzAsmParseParam *p) {
	free(p);
}

/**
 * \brief Does all kinds of NULL checks on the parameters and returns an initialized RzAsmParseParam or NULL on failure.
 *
 * \param reg The RzReg which holds the reg_set.
 * \return RzAsmParseParam* Pointer to the RzAsmParseParam struct or NULL.
 */
RZ_API RZ_OWN RzAsmParseParam *rz_asm_get_parse_param(RZ_NULLABLE const RzReg *reg, ut32 ana_op_type) {
	if (!reg) {
		return NULL;
	}
	RzAsmParseParam *param = RZ_NEW(RzAsmParseParam);
	param->reg_sets = reg->regset;
	param->ana_op_type = ana_op_type;
	return param;
}
