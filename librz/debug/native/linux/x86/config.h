// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_NATIVE_DEBUGGER_CONFIG_H
#define RZ_NATIVE_DEBUGGER_CONFIG_H
#include <rz_debug.h>

#define NATIVE_ARCH_NAME "x86"

#if __i386__
#define NATIVE_ARCH_BITS (RZ_SYS_BITS_32)
#else /* __x86_64__ */
#define NATIVE_ARCH_BITS (RZ_SYS_BITS_32 | RZ_SYS_BITS_64)
#endif /* __i386__ */

#endif /* RZ_NATIVE_DEBUGGER_CONFIG_H */
