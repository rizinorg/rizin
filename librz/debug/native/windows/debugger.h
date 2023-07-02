// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_NATIVE_DEBUGGER_H
#define RZ_NATIVE_DEBUGGER_H
#include <rz_types.h>

/*
 * Windows debugger
 */
#if (__x86_64__ || __i386__)
#include "x86/config.h"
#else /* windows-arch */
#warning Unsupported debugger for this windows platform
#endif /* windows-arch */

#endif /* RZ_NATIVE_DEBUGGER_H */
