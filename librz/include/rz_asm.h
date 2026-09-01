// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ASM_H
#define RZ_ASM_H

#include <rz_util/rz_print.h>
#include <rz_util/ht_ss.h>
#include <rz_types.h>
#include <rz_bin.h> // only for binding, no hard dep required
#include <rz_util.h>
#include <rz_parse.h>
#include <rz_bind.h>
#include <rz_config.h>

#ifdef __cplusplus
extern "C" {
#endif

/* backward compatibility */
#define RZ_ASM_ARCH_NONE  RZ_SYS_ARCH_NONE
#define RZ_ASM_ARCH_X86   RZ_SYS_ARCH_X86
#define RZ_ASM_ARCH_ARM   RZ_SYS_ARCH_ARM
#define RZ_ASM_ARCH_PPC   RZ_SYS_ARCH_PPC
#define RZ_ASM_ARCH_M68K  RZ_SYS_ARCH_M68K
#define RZ_ASM_ARCH_JAVA  RZ_SYS_ARCH_JAVA
#define RZ_ASM_ARCH_LM32  RZ_SYS_ARCH_LM32
#define RZ_ASM_ARCH_MIPS  RZ_SYS_ARCH_MIPS
#define RZ_ASM_ARCH_SPARC RZ_SYS_ARCH_SPARC
#define RZ_ASM_ARCH_XAP   RZ_SYS_ARCH_XAP
#define RZ_ASM_ARCH_MSIL  RZ_SYS_ARCH_MSIL
#define RZ_ASM_ARCH_OBJD  RZ_SYS_ARCH_OBJD
#define RZ_ASM_ARCH_BF    RZ_SYS_ARCH_BF
#define RZ_ASM_ARCH_SH    RZ_SYS_ARCH_SH
#define RZ_ASM_ARCH_Z80   RZ_SYS_ARCH_Z80
#define RZ_ASM_ARCH_I8080 RZ_SYS_ARCH_I8080
#define RZ_ASM_ARCH_ARC   RZ_SYS_ARCH_ARC
#define RZ_ASM_ARCH_HPPA  RZ_SYS_ARCH_HPPA

#define RZ_ASM_GET_OFFSET(x, y, z) \
	(x && x->binb.bin && x->binb.get_offset) ? x->binb.get_offset(x->binb.bin, y, z) : -1

#define RZ_ASM_GET_NAME(x, y, z) \
	(x && x->binb.bin && x->binb.get_name) ? x->binb.get_name(x->binb.bin, y, z) : NULL

typedef enum {
	RZ_ASM_SYNTAX_NONE = 0,
	RZ_ASM_SYNTAX_INTEL,
	RZ_ASM_SYNTAX_ATT,
	RZ_ASM_SYNTAX_MASM,
	RZ_ASM_SYNTAX_REGNUM, // alias for capstone's NOREGNAME
	RZ_ASM_SYNTAX_JZ, // hack to use jz instead of je on x86
	/* The value below is used for runtime checks */
	RZ_ASM_ENUM_SIZE
} RzAsmSyntax;

enum {
	RZ_ASM_MOD_RAWVALUE = 'r',
	RZ_ASM_MOD_VALUE = 'v',
	RZ_ASM_MOD_DSTREG = 'd',
	RZ_ASM_MOD_SRCREG0 = '0',
	RZ_ASM_MOD_SRCREG1 = '1',
	RZ_ASM_MOD_SRCREG2 = '2'
};

typedef struct rz_asm_op_t {
	int size; // instruction size (must be deprecated. just use buf.len
	int bitsize; // instruction size in bits (or 0 if fits in 8bit bytes) // why this field is dup?
	int payload; // size of payload (opsize = (size-payload))
	// But this is pretty slow..so maybe we should add some accessors
	RzStrBuf buf;
	RzStrBuf buf_asm;
	RzBuffer *buf_inc; // must die
	RzAsmTokenString *asm_toks; ///< Tokenized asm string.
} RzAsmOp;

typedef struct rz_asm_code_t {
	int len;
	ut8 *bytes;
	char *assembly;
	RzList /*<RzAsmEqu *>*/ *equs; // TODO: must be a hash
	ut64 code_offset;
	ut64 data_offset;
	int code_align;
} RzAsmCode;

// TODO: Must use Hashtable instead of this hack
typedef struct {
	char *key;
	char *value;
} RzAsmEqu;

typedef struct rz_asm_t RzAsm;

typedef struct rz_asm_plugin_t {
	const char *name;
	const char *arch;
	const char *author;
	const char *version;
	const char *cpus;
	const char *desc;
	const char *license;
	int bits;
	int endian;
	bool (*init)(void **user);
	bool (*fini)(void *user);
	int (*disassemble)(const RzAsm *a, RzAsmOp *op, const ut8 *buf, int len);
	int (*assemble)(const RzAsm *a, RzAsmOp *op, const char *buf);
	char *(*mnemonics)(const RzAsm *a, int id, bool json);
	RZ_OWN RzConfig *(*get_config)(void *plugin_data);
	const char *features;
	const char *platforms;
	char **(*get_cpu_desc)();
	bool (*sw_breakpoint)(const RzAsm *a, ut64 addr, const RzAsmOp *original, RzAsmOp *breakpoint);
} RzAsmPlugin;

/**
 * \brief Compare plugins by name (via strcmp).
 */
static inline int rz_asm_plugin_cmp(RZ_NULLABLE const RzAsmPlugin *a, RZ_NULLABLE const RzAsmPlugin *b) {
	if (!a && !b) {
		return 0;
	} else if (!a) {
		return -1;
	} else if (!b) {
		return 1;
	}
	return rz_str_cmp(a->name, b->name, -1);
}

#ifdef RZ_API
/* asm.c */
RZ_API RzAsm *rz_asm_new(void);
RZ_API void rz_asm_free(RzAsm *a);
RZ_API char *rz_asm_mnemonics(const RzAsm *a, int id, bool json);
RZ_API int rz_asm_mnemonics_byname(const RzAsm *a, const char *name);
RZ_API bool rz_asm_plugin_add(RzAsm *a, RZ_NONNULL RzAsmPlugin *foo);
RZ_API bool rz_asm_plugin_del(RzAsm *a, RZ_NONNULL RzAsmPlugin *foo);
RZ_API RZ_OWN RzIterator *rz_asm_plugin_iterator(RZ_NONNULL const RzAsm *a);
RZ_API const RzAsmPlugin *rz_asm_plugin_current(RZ_NONNULL const RzAsm *a);
RZ_API const RzAsmPlugin *rz_asm_plugin_find(RZ_NONNULL const RzAsm *a, RZ_NONNULL const char *name);
RZ_API bool rz_asm_setup(RzAsm *a, const char *arch, int bits, int big_endian);
RZ_API bool rz_asm_is_valid(const RzAsm *a, const char *name);
RZ_API bool rz_asm_use(RzAsm *a, RZ_NULLABLE const char *name);
RZ_API bool rz_asm_use_assembler(RzAsm *a, const char *name);
RZ_API bool rz_asm_set_arch(RzAsm *a, const char *name, int bits);
RZ_API const char *rz_asm_get_arch(RZ_NONNULL const RzAsm *a);
RZ_API bool rz_asm_is_arch(RZ_NONNULL const RzAsm *a, RZ_NONNULL const char *name);
RZ_DEPRECATE RZ_API void rz_asm_set_core(RZ_NONNULL RzAsm *a, RZ_NULLABLE void *core);
RZ_DEPRECATE RZ_API RZ_BORROW const RzBinBind *rz_asm_get_bin_bind(const RzAsm *a);
RZ_DEPRECATE RZ_API int rz_asm_set_bits(RzAsm *a, int bits);
RZ_DEPRECATE RZ_API int rz_asm_get_bits(RZ_NONNULL const RzAsm *a);
RZ_DEPRECATE RZ_API bool rz_asm_is_bits(const RzAsm *a, int bits);
RZ_DEPRECATE RZ_API int rz_asm_get_plugin_bits(RZ_NONNULL const RzAsm *a);
RZ_DEPRECATE RZ_API const char *rz_asm_get_plugin_cpus(RZ_NONNULL const RzAsm *a);
RZ_DEPRECATE RZ_API const char *rz_asm_get_plugin_platforms(RZ_NONNULL const RzAsm *a);
RZ_DEPRECATE RZ_API const char *rz_asm_get_plugin_features(RZ_NONNULL const RzAsm *a);
RZ_API RZ_OWN RzConfig *rz_asm_get_new_config(RZ_NONNULL const RzAsm *a);
RZ_API RZ_OWN char *rz_asm_get_sys_opcode_path(RZ_NONNULL const RzAsm *a, RZ_NONNULL const char *path);
RZ_DEPRECATE RZ_API void rz_asm_set_cpu(RzAsm *a, const char *cpu);
RZ_API const char *rz_asm_get_cpu(RZ_NONNULL const RzAsm *a);
RZ_API void rz_asm_set_platforms(RZ_NONNULL RzAsm *a, RZ_NULLABLE const char *platforms);
RZ_API const char *rz_asm_get_platforms(RZ_NONNULL const RzAsm *a);
RZ_API void rz_asm_set_features(RZ_NONNULL RzAsm *a, RZ_NULLABLE const char *features);
RZ_API const char *rz_asm_get_features(RZ_NONNULL const RzAsm *a);
RZ_API void rz_asm_set_pseudo(RZ_NONNULL RzAsm *a, bool enable);
RZ_API bool rz_asm_get_pseudo(RZ_NONNULL const RzAsm *a);
RZ_API void rz_asm_set_utf8(RZ_NONNULL RzAsm *a, bool utf8);
RZ_API bool rz_asm_get_utf8(RZ_NONNULL const RzAsm *a);
RZ_API void rz_asm_set_segment_granularity(RZ_NONNULL RzAsm *a, int seggrn);
RZ_API int rz_asm_get_segment_granularity(RZ_NONNULL const RzAsm *a);
RZ_API void rz_asm_set_pc_align(RZ_NONNULL RzAsm *a, ut32 pc_align);
RZ_API ut32 rz_asm_get_pc_align(RZ_NONNULL const RzAsm *a);
RZ_API void rz_asm_set_syscall(RZ_NONNULL RzAsm *a, RzSyscall *syscall);
RZ_API RzSyscall *rz_asm_get_syscall(RZ_NONNULL const RzAsm *a);
RZ_API void rz_asm_set_invalid_as_hex_flag(RZ_NONNULL RzAsm *a, bool invhex);
RZ_API bool rz_asm_get_invalid_as_hex_flag(RZ_NONNULL const RzAsm *a);
RZ_API void rz_asm_set_show_immediate_hashtag(RZ_NONNULL RzAsm *a, bool show);
RZ_API bool rz_asm_get_show_immediate_hashtag(RZ_NONNULL const RzAsm *a);
RZ_API ut32 rz_asm_get_endianness(const RzAsm *a);
RZ_API bool rz_asm_is_big_endian_set(RZ_NONNULL const RzAsm *a);
RZ_API bool rz_asm_support_endianness(const RzAsm *a, ut32 endian);
RZ_API bool rz_asm_set_big_endian(RzAsm *a, bool big_endian);
RZ_API void rz_asm_set_syntax(RZ_NONNULL RzAsm *a, RzAsmSyntax syntax);
RZ_API RzAsmSyntax rz_asm_get_syntax(RZ_NONNULL const RzAsm *a);
RZ_API bool rz_asm_is_syntax(RZ_NONNULL const RzAsm *a, RzAsmSyntax syntax);
RZ_API int rz_asm_syntax_from_string(const char *name);
RZ_API void rz_asm_set_pc(RZ_NONNULL RzAsm *a, ut64 pc);
RZ_API ut64 rz_asm_get_pc(RZ_NONNULL const RzAsm *a);
RZ_API int rz_asm_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len);
RZ_API int rz_asm_assemble(const RzAsm *a, RzAsmOp *op, const char *buf);
RZ_API bool rz_asm_software_breakpoint(RZ_NONNULL const RzAsm *a, ut64 addr, const RZ_NONNULL RzAsmOp *original, RZ_NONNULL RzAsmOp *breakpoint);
RZ_API RzAsmCode *rz_asm_mdisassemble(RzAsm *a, const ut8 *buf, int len);
RZ_API RzAsmCode *rz_asm_mdisassemble_hexstr(RzAsm *a, RzParse *p, const char *hexstr);
RZ_API RzAsmCode *rz_asm_massemble(RzAsm *a, const char *buf);
RZ_API RzAsmCode *rz_asm_rasm_assemble(RzAsm *a, const char *buf, bool use_spp);
RZ_API char *rz_asm_to_string(RzAsm *a, ut64 addr, const ut8 *b, int l);
/* to ease the use of the native bindings (not used in r2) */
RZ_API ut8 *rz_asm_from_string(RzAsm *a, ut64 addr, const char *b, int *l);
RZ_API int rz_asm_sub_names_input(RzAsm *a, const char *f);
RZ_API int rz_asm_sub_names_output(RzAsm *a, const char *f);
RZ_API char *rz_asm_describe(const RzAsm *a, const char *str);
RZ_API void rz_asm_describe_iterate(RZ_NONNULL const RzAsm *a, RZ_NONNULL SdbForeachCallback cb, RZ_NULLABLE void *user);
RZ_API RZ_BORROW HtSP /*<RzAsmPlugin *>*/ *rz_asm_get_plugins(RZ_BORROW RZ_NONNULL const RzAsm *a);
RZ_API void rz_asm_list_directives(void);

/* code.c */
RZ_API RzAsmCode *rz_asm_code_new(void);
RZ_API void *rz_asm_code_free(RzAsmCode *acode);
RZ_API void rz_asm_equ_item_free(RzAsmEqu *equ);
RZ_API bool rz_asm_code_set_equ(RzAsmCode *code, const char *key, const char *value);
RZ_API char *rz_asm_code_equ_replace(RzAsmCode *code, char *str);
RZ_API char *rz_asm_code_get_hex(RzAsmCode *acode);

/* op.c */
RZ_API RZ_OWN RzAsmOp *rz_asm_op_new(void);
RZ_API void rz_asm_op_init(RZ_NULLABLE RzAsmOp *op);
RZ_API void rz_asm_op_free(RZ_NULLABLE RzAsmOp *op);
RZ_API void rz_asm_op_fini(RZ_NULLABLE RzAsmOp *op);
RZ_API RZ_OWN char *rz_asm_op_get_hex(RZ_NONNULL RzAsmOp *op);
RZ_API RZ_BORROW char *rz_asm_op_get_asm(RZ_NONNULL RzAsmOp *op);
RZ_API int rz_asm_op_get_size(RZ_NONNULL RzAsmOp *op);
RZ_API void rz_asm_op_set_asm(RZ_NONNULL RzAsmOp *op, RZ_NONNULL const char *str);
RZ_API void rz_asm_op_setf_asm(RZ_NONNULL RzAsmOp *op, RZ_NONNULL const char *fmt, ...);
RZ_API int rz_asm_op_set_hex(RZ_NONNULL RzAsmOp *op, RZ_NONNULL const char *str);
RZ_API int rz_asm_op_set_hexbuf(RZ_NONNULL RzAsmOp *op, RZ_NONNULL const ut8 *buf, int len);
RZ_API void rz_asm_op_set_buf(RZ_NONNULL RzAsmOp *op, RZ_NONNULL const ut8 *str, int len);
RZ_API RZ_BORROW ut8 *rz_asm_op_get_buf(RZ_NONNULL RzAsmOp *op);

// String tokenizing
RZ_API RZ_OWN RzAsmTokenString *rz_asm_token_string_new(const char *asm_str);
RZ_API void rz_asm_token_string_free(RZ_OWN RzAsmTokenString *toks);
RZ_API RZ_OWN RzAsmTokenString *rz_asm_token_string_clone(RZ_OWN RZ_NONNULL RzAsmTokenString *toks);
RZ_API void rz_asm_token_pattern_free(void *p);
RZ_API void rz_asm_compile_token_patterns(RZ_INOUT RzPVector /*<RzAsmTokenPattern *>*/ *patterns);
RZ_API RZ_OWN RzAsmTokenString *rz_asm_tokenize_asm_regex(RZ_BORROW RzStrBuf *asm_str, RzPVector /*<RzAsmTokenPattern *>*/ *patterns);
RZ_API RZ_OWN RzAsmParseParam *rz_asm_get_parse_param(RZ_NULLABLE const RzReg *reg, ut32 ana_op_type);
RZ_API void rz_asm_parse_param_free(RZ_OWN RZ_NULLABLE RzAsmParseParam *p);
RZ_DEPRECATE RZ_API RZ_OWN RzAsmTokenString *rz_asm_tokenize_asm_string(RZ_BORROW RzStrBuf *asm_str, RZ_NULLABLE const RzAsmParseParam *param);
RZ_DEPRECATE RZ_API RZ_OWN RzStrBuf *rz_asm_colorize_asm_str(RZ_BORROW RzStrBuf *asm_str, RZ_BORROW RzPrint *p, RZ_NULLABLE const RzAsmParseParam *param, RZ_NULLABLE const RzAsmTokenString *toks);

#endif

#ifdef __cplusplus
}
#endif

#endif
