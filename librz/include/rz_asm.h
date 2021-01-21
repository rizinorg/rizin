// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ASM_H
#define RZ_ASM_H

#include <rz_types.h>
#include <rz_bin.h> // only for binding, no hard dep required
#include <rz_util.h>
#include <rz_parse.h>
#include <rz_bind.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_asm);

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
	(x && x->binb.bin && x->binb.get_name) ? x->binb.get_name(x->binb.bin, y, z, x->pseudo) : NULL

enum {
	RZ_ASM_SYNTAX_NONE = 0,
	RZ_ASM_SYNTAX_INTEL,
	RZ_ASM_SYNTAX_ATT,
	RZ_ASM_SYNTAX_MASM,
	RZ_ASM_SYNTAX_REGNUM, // alias for capstone's NOREGNAME
	RZ_ASM_SYNTAX_JZ, // hack to use jz instead of je on x86
};

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
} RzAsmOp;

typedef struct rz_asm_code_t {
#if 1
	int len;
	ut8 *bytes;
	char *assembly;
#else
	RzAsmOp op; // we have those fields already inside RzAsmOp
#endif
	RzList *equs; // TODO: must be a hash
	ut64 code_offset;
	ut64 data_offset;
	int code_align;
} RzAsmCode;

// TODO: Must use Hashtable instead of this hack
typedef struct {
	char *key;
	char *value;
} RzAsmEqu;

#define _RzAsmPlugin struct rz_asm_plugin_t
typedef struct rz_asm_t {
	char *cpu;
	int bits;
	int big_endian;
	int syntax;
	ut64 pc;
	void *user;
	_RzAsmPlugin *cur;
	_RzAsmPlugin *acur;
	RzList *plugins;
	RzBinBind binb;
	RzParse *ifilter;
	RzParse *ofilter;
	Sdb *pair;
	RzSyscall *syscall;
	RNum *num;
	char *features;
	int invhex; // invalid instructions displayed in hex
	int pcalign;
	int dataalign;
	int bitshift;
	bool immdisp; // Display immediates with # symbol (for arm stuff).
	HtPP *flags;
	int seggrn;
	bool pseudo;
} RzAsm;

typedef bool (*RzAsmModifyCallback)(RzAsm *a, ut8 *buf, int field, ut64 val);

typedef struct rz_asm_plugin_t {
	const char *name;
	const char *arch;
	const char *author;
	const char *version;
	const char *cpus;
	const char *desc;
	const char *license;
	void *user; // user data pointer
	int bits;
	int endian;
	bool (*init)(void *user);
	bool (*fini)(void *user);
	int (*disassemble)(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len);
	int (*assemble)(RzAsm *a, RzAsmOp *op, const char *buf);
	RzAsmModifyCallback modify;
	char *(*mnemonics)(RzAsm *a, int id, bool json);
	const char *features;
} RzAsmPlugin;

#ifdef RZ_API
/* asm.c */
RZ_API RzAsm *rz_asm_new(void);
RZ_API void rz_asm_free(RzAsm *a);
RZ_API bool rz_asm_modify(RzAsm *a, ut8 *buf, int field, ut64 val);
RZ_API char *rz_asm_mnemonics(RzAsm *a, int id, bool json);
RZ_API int rz_asm_mnemonics_byname(RzAsm *a, const char *name);
RZ_API void rz_asm_set_user_ptr(RzAsm *a, void *user);
RZ_API bool rz_asm_add(RzAsm *a, RzAsmPlugin *foo);
RZ_API bool rz_asm_setup(RzAsm *a, const char *arch, int bits, int big_endian);
RZ_API bool rz_asm_is_valid(RzAsm *a, const char *name);
RZ_API bool rz_asm_use(RzAsm *a, const char *name);
RZ_API bool rz_asm_use_assembler(RzAsm *a, const char *name);
RZ_API bool rz_asm_set_arch(RzAsm *a, const char *name, int bits);
RZ_API int rz_asm_set_bits(RzAsm *a, int bits);
RZ_API void rz_asm_set_cpu(RzAsm *a, const char *cpu);
RZ_API bool rz_asm_set_big_endian(RzAsm *a, bool big_endian);
RZ_API bool rz_asm_set_syntax(RzAsm *a, int syntax);
RZ_API int rz_asm_syntax_from_string(const char *name);
RZ_API int rz_asm_set_pc(RzAsm *a, ut64 pc);
RZ_API int rz_asm_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len);
RZ_API int rz_asm_assemble(RzAsm *a, RzAsmOp *op, const char *buf);
RZ_API RzAsmCode *rz_asm_mdisassemble(RzAsm *a, const ut8 *buf, int len);
RZ_API RzAsmCode *rz_asm_mdisassemble_hexstr(RzAsm *a, RzParse *p, const char *hexstr);
RZ_API RzAsmCode *rz_asm_massemble(RzAsm *a, const char *buf);
RZ_API RzAsmCode *rz_asm_rasm_assemble(RzAsm *a, const char *buf, bool use_spp);
RZ_API char *rz_asm_to_string(RzAsm *a, ut64 addr, const ut8 *b, int l);
/* to ease the use of the native bindings (not used in r2) */
RZ_API ut8 *rz_asm_from_string(RzAsm *a, ut64 addr, const char *b, int *l);
RZ_API int rz_asm_sub_names_input(RzAsm *a, const char *f);
RZ_API int rz_asm_sub_names_output(RzAsm *a, const char *f);
RZ_API char *rz_asm_describe(RzAsm *a, const char *str);
RZ_API RzList *rz_asm_get_plugins(RzAsm *a);
RZ_API void rz_asm_list_directives(void);

/* code.c */
RZ_API RzAsmCode *rz_asm_code_new(void);
RZ_API void *rz_asm_code_free(RzAsmCode *acode);
RZ_API void rz_asm_equ_item_free(RzAsmEqu *equ);
RZ_API bool rz_asm_code_set_equ(RzAsmCode *code, const char *key, const char *value);
RZ_API char *rz_asm_code_equ_replace(RzAsmCode *code, char *str);
RZ_API char *rz_asm_code_get_hex(RzAsmCode *acode);

/* op.c */
RZ_API RzAsmOp *rz_asm_op_new(void);
RZ_API void rz_asm_op_init(RzAsmOp *op);
RZ_API void rz_asm_op_free(RzAsmOp *op);
RZ_API void rz_asm_op_fini(RzAsmOp *op);
RZ_API char *rz_asm_op_get_hex(RzAsmOp *op);
RZ_API char *rz_asm_op_get_asm(RzAsmOp *op);
RZ_API int rz_asm_op_get_size(RzAsmOp *op);
RZ_API void rz_asm_op_set_asm(RzAsmOp *op, const char *str);
RZ_API int rz_asm_op_set_hex(RzAsmOp *op, const char *str);
RZ_API int rz_asm_op_set_hexbuf(RzAsmOp *op, const ut8 *buf, int len);
RZ_API void rz_asm_op_set_buf(RzAsmOp *op, const ut8 *str, int len);
RZ_API ut8 *rz_asm_op_get_buf(RzAsmOp *op);

/* plugin pointers */
extern RzAsmPlugin rz_asm_plugin_6502;
extern RzAsmPlugin rz_asm_plugin_6502_cs;
extern RzAsmPlugin rz_asm_plugin_8051;
extern RzAsmPlugin rz_asm_plugin_amd29k;
extern RzAsmPlugin rz_asm_plugin_arc;
extern RzAsmPlugin rz_asm_plugin_arm_as;
extern RzAsmPlugin rz_asm_plugin_arm_cs;
extern RzAsmPlugin rz_asm_plugin_arm_gnu;
extern RzAsmPlugin rz_asm_plugin_arm_winedbg;
extern RzAsmPlugin rz_asm_plugin_avr;
extern RzAsmPlugin rz_asm_plugin_bf;
extern RzAsmPlugin rz_asm_plugin_null;
extern RzAsmPlugin rz_asm_plugin_chip8;
extern RzAsmPlugin rz_asm_plugin_cr16;
extern RzAsmPlugin rz_asm_plugin_cris_gnu;
extern RzAsmPlugin rz_asm_plugin_dalvik;
extern RzAsmPlugin rz_asm_plugin_dcpu16;
extern RzAsmPlugin rz_asm_plugin_ebc;
extern RzAsmPlugin rz_asm_plugin_gb;
extern RzAsmPlugin rz_asm_plugin_h8300;
extern RzAsmPlugin rz_asm_plugin_hexagon;
extern RzAsmPlugin rz_asm_plugin_hexagon_gnu;
extern RzAsmPlugin rz_asm_plugin_hppa_gnu;
extern RzAsmPlugin rz_asm_plugin_i4004;
extern RzAsmPlugin rz_asm_plugin_i8080;
extern RzAsmPlugin rz_asm_plugin_java;
extern RzAsmPlugin rz_asm_plugin_lanai_gnu;
extern RzAsmPlugin rz_asm_plugin_lh5801;
extern RzAsmPlugin rz_asm_plugin_lm32;
extern RzAsmPlugin rz_asm_plugin_m68k_cs;
extern RzAsmPlugin rz_asm_plugin_m680x_cs;
extern RzAsmPlugin rz_asm_plugin_malbolge;
extern RzAsmPlugin rz_asm_plugin_mcore;
extern RzAsmPlugin rz_asm_plugin_mcs96;
extern RzAsmPlugin rz_asm_plugin_mips_cs;
extern RzAsmPlugin rz_asm_plugin_mips_gnu;
extern RzAsmPlugin rz_asm_plugin_msp430;
extern RzAsmPlugin rz_asm_plugin_nios2;
extern RzAsmPlugin rz_asm_plugin_or1k;
extern RzAsmPlugin rz_asm_plugin_pic;
extern RzAsmPlugin rz_asm_plugin_ppc_as;
extern RzAsmPlugin rz_asm_plugin_ppc_cs;
extern RzAsmPlugin rz_asm_plugin_ppc_gnu;
extern RzAsmPlugin rz_asm_plugin_propeller;
extern RzAsmPlugin rz_asm_plugin_riscv;
extern RzAsmPlugin rz_asm_plugin_riscv_cs;
extern RzAsmPlugin rz_asm_plugin_rsp;
extern RzAsmPlugin rz_asm_plugin_sh;
extern RzAsmPlugin rz_asm_plugin_snes;
extern RzAsmPlugin rz_asm_plugin_sparc_cs;
extern RzAsmPlugin rz_asm_plugin_sparc_gnu;
extern RzAsmPlugin rz_asm_plugin_spc700;
extern RzAsmPlugin rz_asm_plugin_sysz;
extern RzAsmPlugin rz_asm_plugin_tms320;
extern RzAsmPlugin rz_asm_plugin_tms320c64x;
extern RzAsmPlugin rz_asm_plugin_tricore;
extern RzAsmPlugin rz_asm_plugin_v810;
extern RzAsmPlugin rz_asm_plugin_v850;
extern RzAsmPlugin rz_asm_plugin_vax;
extern RzAsmPlugin rz_asm_plugin_wasm;
extern RzAsmPlugin rz_asm_plugin_ws;
extern RzAsmPlugin rz_asm_plugin_x86_as;
extern RzAsmPlugin rz_asm_plugin_x86_cs;
extern RzAsmPlugin rz_asm_plugin_x86_nasm;
extern RzAsmPlugin rz_asm_plugin_x86_nz;
extern RzAsmPlugin rz_asm_plugin_xap;
extern RzAsmPlugin rz_asm_plugin_xcore_cs;
extern RzAsmPlugin rz_asm_plugin_xtensa;
extern RzAsmPlugin rz_asm_plugin_z80;
extern RzAsmPlugin rz_asm_plugin_pyc;

#endif

#ifdef __cplusplus
}
#endif

#endif
