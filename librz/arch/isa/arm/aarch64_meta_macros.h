// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef AARCH64_META_MACROS_H
#define AARCH64_META_MACROS_H

/// Macro for meta programming.
/// Meant for projects using Capstone and need to support multiple
/// versions of it.
/// These macros replace several instances of the old "ARM64" with
/// the new "AArch64" name depending on the CS version.
#if CS_NEXT_VERSION < 6
#define CS_AARCH64(x) ARM64##x
#else
#define CS_AARCH64(x) AARCH64##x
#endif

#if CS_NEXT_VERSION < 6
#define CS_AARCH64pre(x) x##ARM64
#else
#define CS_AARCH64pre(x) x##AARCH64
#endif

#if CS_NEXT_VERSION < 6
#define CS_AARCH64CC(x) ARM64_CC##x
#else
#define CS_AARCH64CC(x) AArch64CC##x
#endif

#if CS_NEXT_VERSION < 6
#define CS_AARCH64_VL_(x) ARM64_VAS_##x
#else
#define CS_AARCH64_VL_(x) AARCH64LAYOUT_VL_##x
#endif

#if CS_NEXT_VERSION < 6
#define CS_aarch64_ arm64
#else
#define CS_aarch64_ aarch64
#endif

#if CS_NEXT_VERSION < 6
#define CS_aarch64(x) arm64##x
#else
#define CS_aarch64(x) aarch64##x
#endif

#if CS_NEXT_VERSION < 6
#define CS_aarch64_op()       cs_arm64_op
#define CS_aarch64_reg()      arm64_reg
#define CS_aarch64_cc()       arm64_cc
#define CS_cs_aarch64()       cs_arm64
#define CS_aarch64_extender() arm64_extender
#define CS_aarch64_shifter()  arm64_shifter
#define CS_aarch64_vas()      arm64_vas
#else
#define CS_aarch64_op()       cs_aarch64_op
#define CS_aarch64_reg()      aarch64_reg
#define CS_aarch64_cc()       AArch64CC_CondCode
#define CS_cs_aarch64()       cs_aarch64
#define CS_aarch64_extender() aarch64_extender
#define CS_aarch64_shifter()  aarch64_shifter
#define CS_aarch64_vas()      AArch64Layout_VectorLayout
#endif

#endif // AARCH64_META_MACROS_H
