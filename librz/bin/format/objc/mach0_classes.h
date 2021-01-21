#include <rz_bin.h>

#include "mach0/mach0_specs.h"
#include "mach0/mach0.h"

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

RZ_API RzList *MACH0_(parse_classes)(RzBinFile *bf);
RZ_API void MACH0_(get_class_t)(mach0_ut p, RzBinFile *bf, RzBinClass *klass, bool dupe, RzSkipList *relocs);
RZ_API void MACH0_(get_category_t)(mach0_ut p, RzBinFile *bf, RzBinClass *klass, RzSkipList *relocs);

#endif // MACH0_CLASSES_H
