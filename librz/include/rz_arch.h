// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ARCH_H
#define RZ_ARCH_H

#include <rz_types.h>
#include <rz_vector.h>
#include <rz_util.h>

// Deprecated includes.
#include <rz_analysis.h>
#include <rz_asm.h>
#include <rz_parse.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_arch);

typedef enum {
	RZ_ARCH_XCODE_MEMBER_BYTES = 0, ///< Member is raw bytes
	RZ_ARCH_XCODE_MEMBER_ASSEMBLY, ///< Member is assembly
	RZ_ARCH_XCODE_MEMBER_PACKET, ///< Member is RzArchPacket
	RZ_ARCH_XCODE_MEMBER_HINT, ///< Member is RzArchHint
	RZ_ARCH_XCODE_MEMBER_DETAIL, ///< Member is RzArchDetail
	RZ_ARCH_XCODE_MEMBER_IL, ///< Member is RzIL
	RZ_ARCH_XCODE_MEMBER_PARSE, ///< [Deprecated] Member is parsed string (pseudo code)
	RZ_ARCH_XCODE_MEMBER_ESIL, ///< [Deprecated] Member is ESIL
} RzArchXCodeMember;

#define RZ_ARCH_BUFFER_SIZE 128

typedef struct rz_arch_xcode_t {
	RzArchXCodeMember member; ///< Describes the content of array
	void *array; ///< Array of variable size, containing one or more structures of type member.
	size_t length; ///< Length of the data as an array
} RzArchXCode;

/// This needs to be redone, copied for reference from RzAnalysisOp
typedef struct rz_arch_packet_t {
	char *mnemonic; /* mnemonic.. it actually contains the args too, we should replace rasm with this */
	ut64 addr; /* address */
	ut32 type; /* type of opcode */
	RzAnalysisOpPrefix prefix; /* type of opcode prefix (rep,lock,..) */
	ut32 type2; /* used by java */
	RzAnalysisStackOp stackop; /* operation on stack? */
	RzTypeCond cond; /* condition type */
	int size; /* size in bytes of opcode */
	int nopcode; /* number of bytes representing the opcode (not the arguments) TODO: find better name */
	int cycles; /* cpu-cycles taken by instruction */
	int failcycles; /* conditional cpu-cycles */
	RzAnalysisOpFamily family; /* family of opcode */
	int id; /* instruction id */
	bool eob; /* end of block (boolean) */
	bool sign; /* operates on signed values, false by default */
	/* Run N instructions before executing the current one */
	int delay; /* delay N slots (mips, ..)*/
	ut64 jump; /* true jmp */
	ut64 fail; /* false jmp */
	RzAnalysisOpDirection direction;
	st64 ptr; /* reference to memory */ /* XXX signed? */
	ut64 val; /* reference to value */ /* XXX signed? */
	RzAnalysisValue analysis_vals[6]; /* Analyzable values */
	int ptrsize; /* f.ex: zero extends for 8, 16 or 32 bits only */
	st64 stackptr; /* stack pointer */
	int refptr; /* if (0) ptr = "reference" else ptr = "load memory of refptr bytes" */
	ut64 mmio_address; // mmio address
	RzAnalysisValue *src[6];
	RzAnalysisValue *dst;
	RzList /*<RzAnalysisValue *>*/ *access; /* RzAnalysisValue access information */
	RzStrBuf esil;
	RzStrBuf opex;
	RzAnalysisLiftedILOp il_op;
	const char *reg; /* destination register */
	const char *ireg; /* register used for indirect memory computation*/
	int scale;
	ut64 disp;
	RzAnalysisSwitchOp *switch_op;
	RzAnalysisHint hint;
	RzAnalysisDataType datatype;
} RzArchPacket;

/// This needs to be redone, copied for reference from RzAnalysisHint
typedef struct rz_arch_hint_t {
	ut64 addr;
	ut64 ptr;
	ut64 val; // used to hint jmp rax
	ut64 jump;
	ut64 fail;
	ut64 ret; // hint for function ret values
	char *arch;
	char *opcode;
	char *syntax;
	char *esil;
	char *offset;
	ut32 type;
	ut64 size;
	int bits;
	int new_bits; // change asm.bits after evaluating this instruction
	int immbase;
	bool high; // highlight hint
	int nword;
	ut64 stackframe;
} RzArchHint;

typedef enum {
	RZ_ARCH_DETAIL_ACCESS_UNDEF = 0, ///< Undefined access
	RZ_ARCH_DETAIL_ACCESS_READ, ///< Read access
	RZ_ARCH_DETAIL_ACCESS_WRITE, ///< Write access
} RzArchDetailAccess;

typedef enum {
	RZ_ARCH_DETAIL_MEMBER_REGISTER = 0, ///< Member is raw bytes
	RZ_ARCH_DETAIL_MEMBER_UNSIGNED, ///< Member is assembly
	RZ_ARCH_DETAIL_MEMBER_SIGNED, ///< Member is RzArchPacket
} RzArchDetailMember;

typedef struct rz_arch_detail_value_t {
	RzArchDetailMember member;
	union {
		size_t register_id;
		ut64 imm_unsigned;
		st64 imm_signed;
	};
} RzArchDetailValue;

typedef struct rz_arch_detail_t {
	RzArchDetailValue source[6];
	RzArchDetailValue destination;
} RzArchDetail;

typedef void RzArchPluginContext;

typedef struct rz_arch_plugin_t {
	RZ_DEPRECATE RzAsmPlugin *p_asm; ///< [Deprecated] Assembly Plugin
	RZ_DEPRECATE RzAnalysisPlugin *p_analysis; ///< [Deprecated] Analysis Plugin
	RZ_DEPRECATE RzParsePlugin *p_parse; ///< [Deprecated] Parse Plugin

    bool (*init)(RZ_NONNULL RzConfig *config); ///< Global constructor for the plugin to fill the configuration values.
    bool (*fini)(); ///< Global destructor for the plugin
	bool (*can_xcode_in)(RZ_NONNULL RzArchXCodeMember input); ///< Returns true if the plugin can support the given RzArchXCodeMember in input.
	bool (*can_xcode_out)(RZ_NONNULL RzArchXCodeMember output); ///< Returns true if the plugin can support the given RzArchXCodeMember in ouput.
	bool (*context_init)(RZ_NONNULL RzConfig *config, RZ_OUT RzArchPluginContext** context); ///< Create a new context for a given configuration
	void (*context_fini)(RZ_NULLABLE RzArchPluginContext *context); ///< Free the given context
	void (*context_update)(RZ_NULLABLE RzArchPluginContext *context, RZ_NONNULL RzConfig *config); ///< Updates the given context with the given configuration.
	bool (*context_xcode)(RZ_NULLABLE RzArchPluginContext *context, RZ_NONNULL RzArchXCode *input, RZ_NONNULL RzArchXCode *output); ///< Updates the given context with the given configuration.
} RzArchPlugin;

typedef struct rz_arch_t {
	RzPVector /*<RzArchPlugin*>*/ *plugins;
	HtSP /*<char*, RzConfig*>*/ plugins_config;
} RzArch;

RZ_DEPRECATE RZ_API const size_t rz_arch_get_n_plugins();
RZ_DEPRECATE RZ_API RZ_BORROW RzAsmPlugin *rz_arch_get_asm_plugin(size_t index);
RZ_DEPRECATE RZ_API RZ_BORROW RzAnalysisPlugin *rz_arch_get_analysis_plugin(size_t index);
RZ_DEPRECATE RZ_API RZ_BORROW RzParsePlugin *rz_arch_get_parse_plugin(size_t index);

#ifdef __cplusplus
}
#endif

#endif /* RZ_ARCH_H */
