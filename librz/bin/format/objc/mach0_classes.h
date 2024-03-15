// SPDX-FileCopyrightText: 2015 inisider <inisider@gmail.com>
// SPDX-FileCopyrightText: 2018-2019 Francesco Tamagni <mrmacete@protonmail.ch>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>

#include "mach0/mach0_specs.h"
#include "mach0/mach0.h"
#include "rz_bin_plugins.h"

#undef mach0_ut
#undef rz_bin_plugin_mach

#ifdef RZ_BIN_MACH064
#define mach0_ut           ut64
#define rz_bin_plugin_mach rz_bin_plugin_mach064
#else
#define mach0_ut           ut32
#define rz_bin_plugin_mach rz_bin_plugin_mach0
#endif

#ifndef MACH0_CLASSES_H
#define MACH0_CLASSES_H

RZ_API RZ_OWN RzPVector /*<RzBinClass *>*/ *MACH0_(parse_classes)(RzBinFile *bf, objc_cache_opt_info *oi);
RZ_API void MACH0_(get_class_t)(mach0_ut p, RzBinFile *bf, RzBuffer *buf, RzBinClass *klass, bool dupe, RzSkipList *relocs, objc_cache_opt_info *oi);
RZ_API void MACH0_(get_category_t)(mach0_ut p, RzBinFile *bf, RzBuffer *buf, RzBinClass *klass, RzSkipList *relocs, objc_cache_opt_info *oi);

#endif // MACH0_CLASSES_H
