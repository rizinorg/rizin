// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ARCH_H
#define RZ_ARCH_H

#include <rz_config.h>
#include <rz_flag.h>
#include <rz_il.h>
#include <sdb.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_arch_profile_t {
	ut64 rom_size;
	ut64 ram_size;
	ut64 rom_address;
	ut64 eeprom_size;
	ut64 io_size;
	ut64 sram_start;
	ut64 sram_size;
	ut64 pc;
	ut64 page_size;
	ut64 interrupt_vector_size;
	HtUP /* <ut64 , char *> */ *registers_mmio;
	HtUP /* <ut64 , char *> */ *registers_extended;
} RzArchProfile;

typedef struct rz_arch_target_t {
	char *cpu;
	char *arch;
	RzArchProfile *profile;
} RzArchTarget;

typedef struct rz_platform_item_t {
	char *name;
	char *comment;
} RzArchPlatformItem;

typedef struct rz_platform_target_t {
	HtUP /* <ut64 , RzArchPlatformItem> */ *platforms;
} RzArchPlatformTarget;

RZ_API RZ_OWN RzArchProfile *rz_arch_profile_new();
RZ_API RZ_OWN RzArchTarget *rz_arch_target_new();
RZ_API void rz_arch_profile_free(RzArchProfile *profile);
RZ_API void rz_arch_target_free(RzArchTarget *target);
RZ_API bool rz_arch_profiles_init(RzArchTarget *c, const char *cpu, const char *arch, const char *cpus_dir);
RZ_API void rz_arch_profile_add_flag_every_io(RzArchProfile *profile, RzFlag *flags);
RZ_API bool rz_arch_load_profile_sdb(RzArchTarget *t, const char *path);
RZ_API RZ_BORROW const char *rz_arch_profile_resolve_mmio(RZ_NONNULL RzArchProfile *profile, ut64 address);
RZ_API RZ_BORROW const char *rz_arch_profile_resolve_extended_register(RZ_NONNULL RzArchProfile *profile, ut64 address);

RZ_API RZ_OWN RzArchPlatformItem *rz_arch_platform_item_new(RZ_NULLABLE const char *name);
RZ_API RZ_OWN RzArchPlatformTarget *rz_arch_platform_target_new();
RZ_API void rz_arch_platform_target_free(RzArchPlatformTarget *target);
RZ_API void rz_arch_platform_item_free(RzArchPlatformItem *item);
RZ_API bool rz_arch_load_platform_sdb(RZ_NONNULL RzArchPlatformTarget *t, RZ_NONNULL const char *path);
RZ_API bool rz_arch_platform_init(RzArchPlatformTarget *t, RZ_NONNULL const char *arch, RZ_NONNULL const char *cpu,
	const char *platform, RZ_NONNULL const char *platforms_dir);

typedef enum {
	RZ_ARCH_INFO_CODE_ALIGN = 0, ///< code/text segment alignment
	RZ_ARCH_INFO_DATA_ALIGN, ///< data segment alignment
	RZ_ARCH_INFO_INSTRUCTION_MIN_SIZE, ///< minimum instruction length
	RZ_ARCH_INFO_INSTRUCTION_MAX_SIZE, ///< maximum instruction length
	RZ_ARCH_INFO_ADDRESS_SPACE, ///< address space bit-size
	/* ignore */
	RZ_ARCH_INFO_END, ///< Used only to define the max value of RZ_ARCH_INFO_* enum
} RzArchInfo;

typedef enum {
	RZ_ARCH_EXTENSION_TYPE_GENERIC = 0, ///< Opcode extension generic
	RZ_ARCH_EXTENSION_TYPE_FLOATING_POINT, ///< Opcode extension floating point
	RZ_ARCH_EXTENSION_TYPE_VECTORIAL, ///< Opcode extension vectorial
	RZ_ARCH_EXTENSION_TYPE_VIRTUALIZATION, ///< Opcode extension virtualization
	RZ_ARCH_EXTENSION_TYPE_PRIVILEGED, ///< Opcode extension for instructions with privilieged execution
	RZ_ARCH_EXTENSION_TYPE_MMX, ///< Opcode extension for multimedia instructions
	RZ_ARCH_EXTENSION_TYPE_SSE, ///< Opcode extension for extended multimedia instructions
	RZ_ARCH_EXTENSION_TYPE_CRYPTO, ///< Opcode extension for crypto related instructions
	RZ_ARCH_EXTENSION_TYPE_THREAD, ///< Opcode extension for thread related instructions
	RZ_ARCH_EXTENSION_TYPE_PAC, ///< Opcode extension for pointer authenticated instructions
	/* ignore */
	RZ_ARCH_EXTENSION_TYPE_END, ///< Used only to define the max value of RZ_ARCH_EXTENSION_TYPE_* enum
} RzArchOpcodeExt;

typedef enum {
	RZ_ARCH_OPCODE_TYPE_UNKNOWN /*               */ = (0ull << 0), ///< Used when no other opcode can describe the instruction
	RZ_ARCH_OPCODE_TYPE_ILLEGAL /*               */ = (1ull << 0), ///< Opcode performs an illegal operation
	RZ_ARCH_OPCODE_TYPE_NOP /*                   */ = (1ull << 1), ///< Opcode performs a no-operation instruction

	/* Branch Instructions */
	RZ_ARCH_OPCODE_TYPE_JUMP /*                  */ = (1ull << 2), ///< Opcode performs a jump to a known location (sets info.reference.[absolute|relative]_jump)
	RZ_ARCH_OPCODE_TYPE_JUMP_UNKNOWN /*          */ = (1ull << 3), ///< Opcode performs a jump to an unknown location (register jump, indirect jump, etc...)
	RZ_ARCH_OPCODE_TYPE_CALL /*                  */ = (1ull << 4), ///< Opcode performs a call a subroutine to a known location (sets info.reference.[absolute|relative]_jump)
	RZ_ARCH_OPCODE_TYPE_CALL_UNKNOWN /*          */ = (1ull << 5), ///< Opcode performs a call a subroutine to an unknown location (register jump, indirect jump, etc...)
	RZ_ARCH_OPCODE_TYPE_RETURN /*                */ = (1ull << 6), ///< Opcode performs a return from a subroutine

	/* Data Transfer Instructions */
	RZ_ARCH_OPCODE_TYPE_LOAD /*                  */ = (1ull << 7), ///< Opcode performs a load operation (i.e. load a value from the memory)
	RZ_ARCH_OPCODE_TYPE_STORE /*                 */ = (1ull << 8), ///< Opcode performs a store operation (i.e. store a value to the memory)
	RZ_ARCH_OPCODE_TYPE_PUSH /*                  */ = (1ull << 9), ///< Opcode performs a push operation (i.e. push value to stack)
	RZ_ARCH_OPCODE_TYPE_POP /*                   */ = (1ull << 10), ///< Opcode performs a pop operation (i.e. pop value to stack)

	/* Compare Instructions */
	RZ_ARCH_OPCODE_TYPE_COMPARE /*               */ = (1ull << 11), ///< Opcode performs a compare operation
	RZ_ARCH_OPCODE_TYPE_TEST /*                  */ = (1ull << 12), ///< Opcode performs a tests operation (i.e. `if !(a & b)` operation)

	/* Cast Instructions */
	RZ_ARCH_OPCODE_TYPE_ZERO_EXTEND /*           */ = (1ull << 13), ///< Opcode performs a extend zero operation (cast to unsigned)
	RZ_ARCH_OPCODE_TYPE_SIGN_EXTEND /*           */ = (1ull << 14), ///< Opcode performs a extend sign operation (cast to signed)

	/* Mathematical Instructions */
	RZ_ARCH_OPCODE_TYPE_ADD /*                   */ = (1ull << 15), ///< Opcode performs a addition (a + b)
	RZ_ARCH_OPCODE_TYPE_SUBTRACT /*              */ = (1ull << 16), ///< Opcode performs a subtraction (a − b)
	RZ_ARCH_OPCODE_TYPE_MULTIPLY /*              */ = (1ull << 17), ///< Opcode performs a multiplication (a * b)
	RZ_ARCH_OPCODE_TYPE_DIVIDE /*                */ = (1ull << 18), ///< Opcode performs a division (b / a)
	RZ_ARCH_OPCODE_TYPE_MODULO /*                */ = (1ull << 19), ///< Opcode performs a modulus, i.e. remainder of a division (b % a)
	RZ_ARCH_OPCODE_TYPE_NEGATE /*                */ = (1ull << 20), ///< Opcode performs a negate operation, i.e inverts the sign of a value (a = -b)
	RZ_ARCH_OPCODE_TYPE_MATH /*                  */ = (1ull << 21), ///< Opcode performs a math operation not described above (i.e. sqrt, log2, abs, etc...)

	/* Logical/Bit-oriented Instructions */
	RZ_ARCH_OPCODE_TYPE_LOGICAL_AND /*           */ = (1ull << 22), ///< Opcode performs a and binary operation (a & b)
	RZ_ARCH_OPCODE_TYPE_LOGICAL_OR /*            */ = (1ull << 23), ///< Opcode performs a or binary operation (a | b)
	RZ_ARCH_OPCODE_TYPE_LOGICAL_XOR /*           */ = (1ull << 24), ///< Opcode performs a xor binary operation (a ^ b)
	RZ_ARCH_OPCODE_TYPE_LOGICAL_NOT /*           */ = (1ull << 25), ///< Opcode performs a one's complement binary operation (a = ~b)
	RZ_ARCH_OPCODE_TYPE_SHIFT_LEFT /*            */ = (1ull << 26), ///< Opcode performs a left shift binary operation. a << b
	RZ_ARCH_OPCODE_TYPE_SHIFT_RIGHT_UNSIGNED /*  */ = (1ull << 27), ///< Opcode performs a unsigned right shift binary operation. a >> b
	RZ_ARCH_OPCODE_TYPE_SHIFT_RIGHT_SIGNED /*    */ = (1ull << 28), ///< Opcode performs a signed right shift binary operation. a >> b
	RZ_ARCH_OPCODE_TYPE_ROTATE_LEFT /*           */ = (1ull << 30), ///< Opcode performs a left rotate binary operation. a <<< b
	RZ_ARCH_OPCODE_TYPE_ROTATE_RIGHT /*          */ = (1ull << 31), ///< Opcode performs a right rotate binary operation. a >>> b
	RZ_ARCH_OPCODE_TYPE_SWAP /*                  */ = (1ull << 32), ///< Opcode performs a swap operation of two stored values
	RZ_ARCH_OPCODE_TYPE_EXCHANGE /*              */ = (1ull << 33), ///< Opcode performs an exchange bits operation of two stored values
	RZ_ARCH_OPCODE_TYPE_COUNT_BITS /*            */ = (1ull << 34), ///< Opcode performs a count bits operation
	RZ_ARCH_OPCODE_TYPE_MOVE /*                  */ = (1ull << 35), ///< Opcode performs a count bits operation

	/* CPU Special Instructions */
	RZ_ARCH_OPCODE_TYPE_SOFT_INTERRUPT /*        */ = (1ull << 36), ///< Opcode performs a soft/software interrupt
	RZ_ARCH_OPCODE_TYPE_HARD_INTERRUPT /*        */ = (1ull << 37), ///< Opcode performs a hard/hardware interrupt
	RZ_ARCH_OPCODE_TYPE_TRAP /*                  */ = (1ull << 38), ///< Opcode performs a trap operation
	RZ_ARCH_OPCODE_TYPE_SYSCALL /*               */ = (1ull << 39), ///< Opcode performs a hard/hardware interrupt
	RZ_ARCH_OPCODE_TYPE_CRYPTOGRAPIC /*          */ = (1ull << 40), ///< Opcode performs a cryptographic operation
	RZ_ARCH_OPCODE_TYPE_SWITCH /*                */ = (1ull << 41), ///< Opcode performs a switch operation (usually followed by a case op)
	RZ_ARCH_OPCODE_TYPE_CASE /*                  */ = (1ull << 42), ///< Opcode performs a case operation (usually part of switch-case scenario)

	/* Instruction Modifiers */
	RZ_ARCH_OPCODE_TYPE_FENCE /*                 */ = (1ull << 43), ///< Opcode performs a memory fence/barrier operation, to not be confused with atomic
	RZ_ARCH_OPCODE_TYPE_ATOMIC /*                */ = (1ull << 44), ///< Opcode performs an atomic operation, to not be confused with memory fence/barrier
	RZ_ARCH_OPCODE_TYPE_CONDITIONAL /*           */ = (1ull << 45), ///< Opcode performs an conditional operation
	RZ_ARCH_OPCODE_TYPE_INDIRECT /*              */ = (1ull << 46), ///< Opcode performs an indirect jump/call/return operation
	RZ_ARCH_OPCODE_TYPE_REGISTER /*              */ = (1ull << 46), ///< Opcode performs an register jump/call/return operation
	RZ_ARCH_OPCODE_TYPE_MEMORY /*                */ = (1ull << 47), ///< Opcode performs an memory jump/call/return operation
	RZ_ARCH_OPCODE_TYPE_IO /*                    */ = (1ull << 48), ///< Opcode performs an I/O operation
	RZ_ARCH_OPCODE_TYPE_MMIO /*                  */ = (1ull << 49), ///< Opcode performs an memory I/O operation
	RZ_ARCH_OPCODE_TYPE_REPEAT /*                */ = (1ull << 50), ///< Opcode performs a repeat N-times operation

	/* Extended Jump Instructions */
	RZ_ARCH_OPCODE_TYPE_REGISTER_JUMP = (RZ_ARCH_OPCODE_TYPE_JUMP_UNKNOWN | RZ_ARCH_OPCODE_TYPE_REGISTER),
	RZ_ARCH_OPCODE_TYPE_INDIRECT_JUMP = (RZ_ARCH_OPCODE_TYPE_JUMP_UNKNOWN | RZ_ARCH_OPCODE_TYPE_INDIRECT),
	RZ_ARCH_OPCODE_TYPE_INDIRECT_REGISTER_JUMP = (RZ_ARCH_OPCODE_TYPE_INDIRECT_JUMP | RZ_ARCH_OPCODE_TYPE_REGISTER),

	/* Extended Conditional Jump Instructions */
	RZ_ARCH_OPCODE_TYPE_CONDITIONAL_JUMP = (RZ_ARCH_OPCODE_TYPE_JUMP | RZ_ARCH_OPCODE_TYPE_CONDITIONAL),
	RZ_ARCH_OPCODE_TYPE_CONDITIONAL_JUMP_UNKNOWN = (RZ_ARCH_OPCODE_TYPE_JUMP_UNKNOWN | RZ_ARCH_OPCODE_TYPE_CONDITIONAL),
	RZ_ARCH_OPCODE_TYPE_CONDITIONAL_REGISTER_JUMP = (RZ_ARCH_OPCODE_TYPE_CONDITIONAL_JUMP_UNKNOWN | RZ_ARCH_OPCODE_TYPE_REGISTER),

	/* Extended Memory Jump Instructions */
	RZ_ARCH_OPCODE_TYPE_MEMORY_JUMP = (RZ_ARCH_OPCODE_TYPE_JUMP | RZ_ARCH_OPCODE_TYPE_MEMORY),
	RZ_ARCH_OPCODE_TYPE_MEMORY_CONDITIONAL_JUMP = (RZ_ARCH_OPCODE_TYPE_CONDITIONAL_JUMP | RZ_ARCH_OPCODE_TYPE_MEMORY),

	/* Extended Call/Return Instructions */
	RZ_ARCH_OPCODE_TYPE_REGISTER_CALL = (RZ_ARCH_OPCODE_TYPE_CALL_UNKNOWN | RZ_ARCH_OPCODE_TYPE_REGISTER),
	RZ_ARCH_OPCODE_TYPE_INDIRECT_CALL = (RZ_ARCH_OPCODE_TYPE_CALL_UNKNOWN | RZ_ARCH_OPCODE_TYPE_INDIRECT),
	RZ_ARCH_OPCODE_TYPE_INDIRECT_REGISTER_CALL = (RZ_ARCH_OPCODE_TYPE_INDIRECT_CALL | RZ_ARCH_OPCODE_TYPE_REGISTER),
	RZ_ARCH_OPCODE_TYPE_CONDITIONAL_CALL = (RZ_ARCH_OPCODE_TYPE_CALL | RZ_ARCH_OPCODE_TYPE_CONDITIONAL),
	RZ_ARCH_OPCODE_TYPE_CONDITIONAL_CALL_UNKNOWN = (RZ_ARCH_OPCODE_TYPE_CALL_UNKNOWN | RZ_ARCH_OPCODE_TYPE_CONDITIONAL),
	RZ_ARCH_OPCODE_TYPE_CONDITIONAL_RETURN = (RZ_ARCH_OPCODE_TYPE_RETURN | RZ_ARCH_OPCODE_TYPE_CONDITIONAL),
} RzArchOpcodeType;

typedef struct rz_arch_opcode_asm_t {
	ut32 size; ///< opcode size in bytes
	RzStrBuf buffer; ///< inline assembly string
} RzArchOpcodeAsm;

typedef struct rz_arch_opcode_info_t {
	ut64 type; ///< Opcode type which contains a RzArchOpcodeType bitmask
	ut32 extension; ///< Opcode extension type which contains a RzArchOpcodeExt
	ut32 delayed_slot; ///< Number of delayed slots (i.e. instructions)
	union {
		ut64 absolute_jump; ///< Opcode absolute jump
		st64 relative_jump; ///< Opcode relative jump
		ut64 absolute_pointer; ///< Opcode absolute pointer to a memory location
		st64 relative_pointer; ///< Opcode relative pointer to a memory location
		ut64 io_address; ///< Opcode I/O address
		st64 mmio_address; ///< Opcode Memory I/O address
	} reference;
} RzArchOpcodeInfo;

typedef struct rz_arch_opcode_t {
	RzArchOpcodeAsm assembly;
	RzArchOpcodeInfo info;
	// TODO: add opcode tokenization for coloring & remove info structure, etc..
	RzStrBuf esil;
} RzArchOpcode;

/**
 * \brief Description of the contents of a single IL variable
 */
typedef struct rz_arch_il_init_state_var_t {
	RZ_NONNULL const char *name;
	RZ_NONNULL RzILVal *val;
} RzArchILInitStateVar;

/**
 * \brief Description of an initial state of an RzArchILVM
 *
 * This may be used by an analysis plugin to communicate how to initialize
 * variables/registers for a clean vm.
 * Everything unspecified by this may be initialized to anything (for example
 * whatever contents the RzReg currently has).
 */
typedef struct rz_arch_il_init_state_t {
	RzVector /* <RzArchILInitStateVar> */ vars; ///< Contents of global variables
} RzArchILInitState;

/**
 * \brief Description of the global context of an RzArchILVM
 *
 * This defines all information needed to initialize an IL vm in order to run
 * in a declarative way, in particular:
 *
 * * Size of the program counter: given explicitly in `pc_size`
 * * Endian: given explicitly in `big_endian`
 * * Memories: currently always one memory with index 0 bound against IO, with key size given by `mem_key_size` and value size of 8
 * * Registers: given explicitly in `reg_bindings` or derived from the register profile with `rz_il_reg_binding_derive()`
 * * Labels: given explicitly in `labels`
 * * Initial State of Variables: optionally given in `init_state`
 */
typedef struct rz_arch_il_config_t {
	ut32 pc_size; ///< size of the program counter in bits
	bool big_endian;
	/**
	 * Optional null-terminated array of registers to bind to global vars of the same name.
	 * If not specified, rz_il_reg_binding_derive will be used.
	 */
	RZ_NULLABLE const char **reg_bindings;
	ut32 mem_key_size; ///< address size for memory 0, bound against IO
	RzPVector /* <RzILEffectLabel> */ labels; ///< global labels, primarily for syscall/hook callbacks
	RZ_NULLABLE RzArchILInitState *init_state; ///< optional, initial contents for variables/registers, etc.
	// more information might go in here, for example additional memories, etc.
} RzArchILConfig;

typedef bool (*RzArchPluginInit)(RZ_NONNULL RzConfig *config, RZ_NONNULL RZ_OUT void **context);
typedef bool (*RzArchPluginUpdate)(RZ_NONNULL RzConfig *config, RZ_NULLABLE void *context);
typedef bool (*RzArchPluginFini)(RZ_NULLABLE void *context);
typedef bool (*RzArchPluginDisassemble)(RzArchOpcode *opcode, const ut8 *buffer, ut32 buffer_size, ut64 offset, void *context);
typedef bool (*RzArchPluginAssemble)(const char *assembly, RzStrBuf output, ut64 offset, void *context);
typedef bool (*RzArchPluginMaskOpcode)(const ut8 *buffer, ut32 buffer_size, RzStrBuf output, ut64 offset, void *context);
typedef ut32 (*RzArchPluginInfo)(RzArchInfo info, RZ_NULLABLE void *context);
typedef RzList /*<RzSearchKeyword*>*/ *(*RzArchPluginFunctionPreludes)(RZ_NULLABLE void *context);

typedef bool (*RzArchEsil)(void *esil);
typedef bool (*RzArchEsilLoop)(void *esil, RzArchOpcode *op);
typedef bool (*RzArchEsilTrap)(void *esil, int trap_type, int trap_code);

typedef RzArchILConfig *(*RzArchSetupIL)(ut32 endianness);

typedef struct rz_arch_plugin_t {
	const char *name; ///< plugin name.
	const char *arch; ///< architecture name.
	const char *cpus; ///< cpus types (comma separated).
	const char *desc; ///< description name.
	const char *author; ///< author name.
	const char *features; ///< architecture features list.
	const char *platforms; ///< architecture sdb platform name.
	ut32 bits; ///< architecture supported bits.
	ut32 endianness; ///< architecture supported endianness.
	RzArchPluginInit init; ///< initialize plugin.
	RzArchPluginUpdate update; ///< updates the plugin configuration.
	RzArchPluginFini fini; ///< deinitialize plugin.
	RzArchPluginDisassemble disassemble; ///< disassembles an instruction from the provided bytes.
	RzArchPluginAssemble assemble; ///< assembles an instruction from the provided assembly.
	RzArchPluginMaskOpcode mask_opcode; ///< generates a byte mask of the decoded instruction.
	RzArchPluginInfo info; ///< provides the architecture information regarding mix/max instruction size, alignment, etc..
	RzArchPluginFunctionPreludes func_preludes; ///< provides a list of expected masked patterns bytes which indicates if a function is about to start

	/* ESIL */
	RzArchEsil esil_init; ///< Initialize ESIL context.
	RzArchEsilLoop esil_post_loop; ///< Executes cycle-counting, firing interrupts, etc...
	RzArchEsilTrap esil_trap; ///< Executed on traps or exceptions.
	RzArchEsil esil_fini; ///< Deinitialize ESIL context.

	/* RZIL */
	RzArchSetupIL il_config; ///< return an IL config to execute lifted code of the given analysis' arch/cpu/bits
} RzArchPlugin;

typedef struct rz_arch_t {
	RzPVector /*<RzArchPlugin*>*/ plugins; ///< dynamic array containing
} RzArch;

#ifdef __cplusplus
}
#endif

#endif
