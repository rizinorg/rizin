// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_LANG_BYTE_ARRAY_H
#define RZ_LANG_BYTE_ARRAY_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum rz_lang_byte_array_type_t {
	RZ_LANG_BYTE_ARRAY_RIZIN = 0,
	RZ_LANG_BYTE_ARRAY_ASM,
	RZ_LANG_BYTE_ARRAY_BASH,
	RZ_LANG_BYTE_ARRAY_C_CPP_BYTES,
	RZ_LANG_BYTE_ARRAY_C_CPP_HALFWORDS_BE,
	RZ_LANG_BYTE_ARRAY_C_CPP_HALFWORDS_LE,
	RZ_LANG_BYTE_ARRAY_C_CPP_WORDS_BE,
	RZ_LANG_BYTE_ARRAY_C_CPP_WORDS_LE,
	RZ_LANG_BYTE_ARRAY_C_CPP_DOUBLEWORDS_BE,
	RZ_LANG_BYTE_ARRAY_C_CPP_DOUBLEWORDS_LE,
	RZ_LANG_BYTE_ARRAY_GOLANG,
	RZ_LANG_BYTE_ARRAY_JAVA,
	RZ_LANG_BYTE_ARRAY_JSON,
	RZ_LANG_BYTE_ARRAY_KOTLIN,
	RZ_LANG_BYTE_ARRAY_NODEJS,
	RZ_LANG_BYTE_ARRAY_OBJECTIVE_C,
	RZ_LANG_BYTE_ARRAY_PYTHON,
	RZ_LANG_BYTE_ARRAY_RUST,
	RZ_LANG_BYTE_ARRAY_SWIFT,
	RZ_LANG_BYTE_ARRAY_YARA,
} RzLangByteArrayType;

typedef enum rz_lang_n_byte_array_type_t {
    RZ_LANG_N_BYTE_ARRAY_RIZIN = 0,
} RzLangNByteArrayType;

RZ_API RZ_OWN char *rz_lang_byte_array(RZ_NONNULL const ut8 *buffer, size_t size, const ut32 max_size, RzLangByteArrayType type);

#ifdef __cplusplus
}
#endif

#endif /* RZ_LANG_BYTE_ARRAY_H */
