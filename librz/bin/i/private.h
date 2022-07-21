// SPDX-FileCopyrightText: 2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_PRIVATE_H_
#define RZ_BIN_PRIVATE_H_

#include <rz_bin.h>
#include <rz_util.h>
#include <rz_types.h>

RZ_IPI RzBinFile *rz_bin_file_new(RzBin *bin, const char *file, ut64 file_sz, int fd, const char *xtrname, bool steal_ptr);
RZ_IPI RzBinObject *rz_bin_file_object_find_by_id(RzBinFile *binfile, ut32 binobj_id);
RZ_IPI RzBinFile *rz_bin_file_find_by_object_id(RzBin *bin, ut32 binobj_id);
RZ_IPI RzBinFile *rz_bin_file_find_by_id(RzBin *bin, ut32 binfile_id);
RZ_IPI bool rz_bin_file_set_obj(RzBin *bin, RzBinFile *bf, RzBinObject *obj);
RZ_IPI RzBinFile *rz_bin_file_xtr_load_bytes(RzBin *bin, RzBinXtrPlugin *xtr, const char *filename, const ut8 *bytes, ut64 sz, ut64 file_sz, ut64 baseaddr, ut64 loadaddr, int idx, int fd);
RZ_IPI bool rz_bin_file_set_bytes(RzBinFile *binfile, const ut8 *bytes, ut64 sz, bool steal_ptr);

RZ_IPI RzBinPlugin *rz_bin_get_binplugin_any(RzBin *bin);
RZ_IPI RzBinXtrPlugin *rz_bin_get_xtrplugin_by_name(RzBin *bin, const char *name);
RZ_IPI RzBinPlugin *rz_bin_get_binplugin_by_name(RzBin *bin, const char *name);
RZ_IPI RzBinPlugin *rz_bin_get_binplugin_by_filename(RzBin *bin);
RZ_IPI RZ_OWN char *rz_bin_file_golang_compiler(RZ_NONNULL RzBinFile *binfile);

RZ_IPI void rz_bin_section_free(RzBinSection *bs);

RZ_IPI void rz_bin_object_free(RzBinObject *o);
RZ_IPI ut64 rz_bin_object_get_baddr(RzBinObject *o);
RZ_IPI RzBinObject *rz_bin_object_new(RzBinFile *binfile, RzBinPlugin *plugin, RzBinObjectLoadOptions *opts, ut64 offset, ut64 sz);
RZ_IPI RzBinObject *rz_bin_object_get_cur(RzBin *bin);
RZ_IPI RzBinObject *rz_bin_object_find_by_arch_bits(RzBinFile *binfile, const char *arch, int bits, const char *name);

RZ_IPI void rz_bin_class_free(RzBinClass *c);
RZ_IPI RzBinSymbol *rz_bin_class_add_method(RzBinFile *binfile, const char *classname, const char *name, int nargs);
RZ_IPI void rz_bin_class_add_field(RzBinFile *binfile, const char *classname, const char *name);

RZ_IPI RzBinFile *rz_bin_file_xtr_load_buffer(RzBin *bin, RzBinXtrPlugin *xtr, const char *filename, RzBuffer *buf, RzBinObjectLoadOptions *obj_opts, int idx, int fd);
RZ_IPI RzBinFile *rz_bin_file_new_from_buffer(RzBin *bin, const char *file, RzBuffer *buf, RzBinObjectLoadOptions *opts, int fd, const char *pluginname);

struct rz_bin_string_database_t {
	RzList /*<RzBinString *>*/ *list; ///< Contains all the strings in list form
	HtUP /*<ut64, RzBinString*>*/ *phys; ///< Contains all the strings but mapped by physical address
	HtUP /*<ut64, RzBinString*>*/ *virt; ///< Contains all the strings but mapped by virtual address
};

#endif
