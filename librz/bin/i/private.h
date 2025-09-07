// SPDX-FileCopyrightText: 2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_PRIVATE_H_
#define RZ_BIN_PRIVATE_H_

#include <rz_bin.h>
#include <rz_util.h>
#include <rz_types.h>

#define RZ_BIN_FMT_CLASS_HT_GLUE "%s#%s"

RZ_IPI RzBinFile *rz_bin_file_new(RzBin *bin, const char *file, ut64 file_sz, int fd, const char *xtrname, bool steal_ptr);
RZ_IPI RzBinObject *rz_bin_file_object_find_by_id(RzBinFile *binfile, ut32 binobj_id);
RZ_IPI RzBinFile *rz_bin_file_find_by_object_id(RzBin *bin, ut32 binobj_id);
RZ_IPI RzBinFile *rz_bin_file_xtr_load_bytes(RzBin *bin, RzBinXtrPlugin *xtr, const char *filename, const ut8 *bytes, ut64 sz, ut64 file_sz, ut64 baseaddr, ut64 loadaddr, int idx, int fd);
RZ_IPI bool rz_bin_file_set_bytes(RzBinFile *binfile, const ut8 *bytes, ut64 sz, bool steal_ptr);

RZ_IPI RzBinPlugin *rz_bin_get_binplugin_any(RzBin *bin);
RZ_IPI RzBinXtrPlugin *rz_bin_get_xtrplugin_by_name(RzBin *bin, const char *name);
RZ_IPI RzBinPlugin *rz_bin_get_binplugin_by_name(RzBin *bin, const char *name);
RZ_IPI RzBinPlugin *rz_bin_get_binplugin_by_filename(RzBin *bin);
RZ_IPI RZ_OWN char *rz_bin_file_golang_compiler(RZ_NONNULL RzBinFile *binfile);

RZ_IPI void rz_bin_object_free(RzBinObject *o);
RZ_IPI ut64 rz_bin_object_get_baddr(RzBinObject *o);
RZ_IPI RzBinObject *rz_bin_object_new(RzBinFile *binfile, RzBinPlugin *plugin, RzBinObjectLoadOptions *opts, ut64 offset, ut64 sz);
RZ_IPI RzBinObject *rz_bin_object_get_cur(RzBin *bin);
RZ_IPI RzBinObject *rz_bin_object_find_by_arch_bits(RzBinFile *bf, RZ_NONNULL const char *arch, int bits, RZ_NULLABLE const char *machine, RZ_NULLABLE const char *filename);

RZ_IPI RzBinFile *rz_bin_file_xtr_load_buffer(RzBin *bin, RzBinXtrPlugin *xtr, const char *filename, RzBuffer *buf, RzBinObjectLoadOptions *obj_opts, int idx, int fd);
RZ_IPI RzBinFile *rz_bin_file_new_from_buffer(RzBin *bin, const char *file, RzBuffer *buf, RzBinObjectLoadOptions *opts, int fd, const char *pluginname);

RZ_IPI void rz_bin_string_decode_base64(RZ_NONNULL RzBinString *bstr);

RZ_IPI bool rz_bin_demangle_symbol(RzBinSymbol *bsym, const RzDemanglerPlugin *plugin, RzDemanglerFlag flags, bool force);
RZ_IPI bool rz_bin_demangle_import(RzBinImport *import, const RzDemanglerPlugin *plugin, RzDemanglerFlag flags, bool force);

RZ_IPI int rz_bin_compare_class(RzBinClass *a, RzBinClass *b);
RZ_IPI int rz_bin_compare_method(RzBinSymbol *a, RzBinSymbol *b);
RZ_IPI int rz_bin_compare_class_field(RzBinClassField *a, RzBinClassField *b);

typedef void (*RzBinProcessLanguage)(RzBinObject *o, const void *user);
RZ_IPI void rz_bin_process_rust(RzBinObject *o, char *demangled, ut64 paddr, ut64 vaddr, bool is_method);
RZ_IPI void rz_bin_process_cxx(RzBinObject *o, char *demangled, ut64 paddr, ut64 vaddr);
RZ_IPI void rz_bin_process_swift(RzBinObject *o, RzBinSymbol *symbol);
RZ_IPI bool rz_bin_object_process_plugin_data(RZ_NONNULL RzBinFile *bf, RZ_NONNULL RzBinObject *o);

RZ_IPI const RzDemanglerPlugin *rz_bin_process_get_demangler_plugin_from_lang(RzBin *bin, RzBinLanguage language);

RZ_IPI void rz_bin_set_and_process_classes(RzBinFile *bf, RzBinObject *o);
RZ_IPI void rz_bin_set_and_process_entries(RzBinFile *bf, RzBinObject *o);
RZ_IPI void rz_bin_set_and_process_fields(RzBinFile *bf, RzBinObject *o);
RZ_IPI void rz_bin_set_and_process_file(RzBinFile *bf, RzBinObject *o);
RZ_IPI void rz_bin_set_and_process_maps(RzBinFile *bf, RzBinObject *o);
RZ_IPI void rz_bin_set_and_process_sections(RzBinFile *bf, RzBinObject *o);
RZ_IPI void rz_bin_set_and_process_strings(RzBinFile *bf, RzBinObject *o);
RZ_IPI void rz_bin_set_imports_from_plugin(RzBinFile *bf, RzBinObject *o);
RZ_IPI void rz_bin_set_symbols_from_plugin(RzBinFile *bf, RzBinObject *o);
RZ_IPI void rz_bin_set_and_process_relocs(RzBinFile *bf, RzBinObject *o, const RzDemanglerPlugin *demangler, RzDemanglerFlag flags);
RZ_IPI void rz_bin_process_imports(RzBinFile *bf, RzBinObject *o, const RzDemanglerPlugin *demangler, RzDemanglerFlag flags);
RZ_IPI void rz_bin_process_symbols(RzBinFile *bf, RzBinObject *o, const RzDemanglerPlugin *demangler, RzDemanglerFlag flags);

RZ_IPI void rz_bin_demangle_relocs_with_flags(RzBinObject *o, const RzDemanglerPlugin *demangler, RzDemanglerFlag flags);
RZ_IPI void rz_bin_demangle_imports_with_flags(RzBinObject *o, const RzDemanglerPlugin *demangler, RzDemanglerFlag flags);
RZ_IPI void rz_bin_demangle_symbols_with_flags(RzBinObject *o, const RzDemanglerPlugin *demangler, RzDemanglerFlag flags);

RZ_IPI RzBinProcessLanguage rz_bin_process_language_symbol(RzBinObject *o);
RZ_IPI RzBinProcessLanguage rz_bin_process_language_import(RzBinObject *o);

struct rz_bin_string_database_t {
	RzPVector /*<RzBinString *>*/ *pvec; ///< Contains all the strings in list form
	HtUP /*<ut64, RzBinString*>*/ *phys; ///< Contains all the strings but mapped by physical address
	HtUP /*<ut64, RzBinString*>*/ *virt; ///< Contains all the strings but mapped by virtual address
};

#endif
