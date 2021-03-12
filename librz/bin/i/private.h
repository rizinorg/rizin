// SPDX-FileCopyrightText: 2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_PRIVATE_H_
#define RZ_BIN_PRIVATE_H_

#include <rz_bin.h>
#include <rz_util.h>
#include <rz_types.h>

RZ_IPI RzBinFile *rz_bin_file_new(RzBin *bin, const char *file, ut64 file_sz, int rawstr, int fd, const char *xtrname, Sdb *sdb, bool steal_ptr);
RZ_IPI RzBinObject *rz_bin_file_object_find_by_id(RzBinFile *binfile, ut32 binobj_id);
RZ_IPI RzList *rz_bin_file_get_strings(RzBinFile *a, int min, int dump, int raw);
RZ_IPI RzBinFile *rz_bin_file_find_by_object_id(RzBin *bin, ut32 binobj_id);
RZ_IPI RzBinFile *rz_bin_file_find_by_id(RzBin *bin, ut32 binfile_id);
RZ_IPI bool rz_bin_file_set_obj(RzBin *bin, RzBinFile *bf, RzBinObject *obj);
RZ_IPI RzBinFile *rz_bin_file_xtr_load_bytes(RzBin *bin, RzBinXtrPlugin *xtr, const char *filename, const ut8 *bytes, ut64 sz, ut64 file_sz, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr);
RZ_IPI bool rz_bin_file_set_bytes(RzBinFile *binfile, const ut8 *bytes, ut64 sz, bool steal_ptr);

RZ_IPI RzBinPlugin *rz_bin_get_binplugin_any(RzBin *bin);
RZ_IPI RzBinXtrPlugin *rz_bin_get_xtrplugin_by_name(RzBin *bin, const char *name);
RZ_IPI RzBinPlugin *rz_bin_get_binplugin_by_name(RzBin *bin, const char *name);

RZ_IPI void rz_bin_section_free(RzBinSection *bs);

RZ_IPI void rz_bin_object_free(void /*RzBinObject*/ *o_);
RZ_IPI ut64 rz_bin_object_get_baddr(RzBinObject *o);
RZ_IPI void rz_bin_object_filter_strings(RzBinObject *bo);
RZ_IPI RzBinObject *rz_bin_object_new(RzBinFile *binfile, RzBinPlugin *plugin, ut64 baseaddr, ut64 loadaddr, ut64 offset, ut64 sz);
RZ_IPI RzBinObject *rz_bin_object_get_cur(RzBin *bin);
RZ_IPI RzBinObject *rz_bin_object_find_by_arch_bits(RzBinFile *binfile, const char *arch, int bits, const char *name);
RZ_IPI RBNode *rz_bin_object_patch_relocs(RzBinFile *bf, RzBinObject *o);

RZ_IPI const char *rz_bin_lang_tostring(int lang);
RZ_IPI int rz_bin_lang_type(RzBinFile *binfile, const char *def, const char *sym);
RZ_IPI bool rz_bin_lang_swift(RzBinFile *binfile);

RZ_IPI void rz_bin_class_free(RzBinClass *c);
RZ_IPI RzBinSymbol *rz_bin_class_add_method(RzBinFile *binfile, const char *classname, const char *name, int nargs);
RZ_IPI void rz_bin_class_add_field(RzBinFile *binfile, const char *classname, const char *name);

RZ_IPI RzBinFile *rz_bin_file_xtr_load_buffer(RzBin *bin, RzBinXtrPlugin *xtr, const char *filename, RzBuffer *buf, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr);
RZ_IPI RzBinFile *rz_bin_file_new_from_buffer(RzBin *bin, const char *file, RzBuffer *buf, int rawstr, ut64 baseaddr, ut64 loadaddr, int fd, const char *pluginname);
#endif
