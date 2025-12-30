// SPDX-FileCopyrightText: 2019 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#ifndef ASM_AMD_29K_H
#define ASM_AMD_29K_H

#include <rz_types.h>
#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AMD29K_29000 29000
#define AMD29K_29050 29050

#define AMD29K_MAX_OPERANDS 6

typedef struct amd29k_instr_s {
	const char *mnemonic;
	ut64 op_type;
	ut32 operands[AMD29K_MAX_OPERANDS];
	char type[AMD29K_MAX_OPERANDS];
} amd29k_instr_t;

bool amd29k_instr_decode(const ut8 *buffer, const ut32 buffer_size, amd29k_instr_t *instruction, const ut32 cpu_id);
void amd29k_instr_print(amd29k_instr_t *instruction, ut64 address, RzStrBuf *sb);

RzStructuredData *amd29k_instr_opex(amd29k_instr_t *instruction, ut64 address);
bool amd29k_instr_is_ret(amd29k_instr_t *instruction);
ut64 amd29k_instr_jump(amd29k_instr_t *instruction, ut64 address);

#ifdef __cplusplus
}
#endif

#endif /* ASM_AMD_29K_H */
