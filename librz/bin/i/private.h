#ifndef RZ_BIN_PRIVATE_H_
#define RZ_BIN_PRIVATE_H_

#include <rz_bin.h>
#include <rz_util.h>
#include <rz_types.h>

RZ_IPI RBinFile *rz_bin_file_new(RBin *bin, const char *file, ut64 file_sz, int rawstr, int fd, const char *xtrname, Sdb *sdb, bool steal_ptr);
RZ_IPI RBinObject *rz_bin_file_object_find_by_id(RBinFile *binfile, ut32 binobj_id);
RZ_IPI RzList *rz_bin_file_get_strings(RBinFile *a, int min, int dump, int raw);
RZ_IPI RBinFile *rz_bin_file_find_by_object_id(RBin *bin, ut32 binobj_id);
RZ_IPI RBinFile *rz_bin_file_find_by_id(RBin *bin, ut32 binfile_id);
RZ_IPI RBinFile *rz_bin_file_find_by_name_n(RBin *bin, const char *name, int idx);
RZ_IPI bool rz_bin_file_set_obj(RBin *bin, RBinFile *bf, RBinObject *obj);
RZ_IPI RBinFile *rz_bin_file_xtr_load_bytes(RBin *bin, RBinXtrPlugin *xtr, const char *filename, const ut8 *bytes, ut64 sz, ut64 file_sz, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr);
RZ_IPI bool rz_bin_file_set_bytes(RBinFile *binfile, const ut8 *bytes, ut64 sz, bool steal_ptr);

RZ_IPI RBinPlugin *rz_bin_get_binplugin_any(RBin *bin);
RZ_IPI RBinXtrPlugin *rz_bin_get_xtrplugin_by_name(RBin *bin, const char *name);
RZ_IPI RBinPlugin *rz_bin_get_binplugin_by_name(RBin *bin, const char *name);

RZ_IPI void rz_bin_section_free(RBinSection *bs);

RZ_IPI void rz_bin_object_free(void /*RBinObject*/ *o_);
RZ_IPI ut64 rz_bin_object_get_baddr(RBinObject *o);
RZ_IPI void rz_bin_object_filter_strings(RBinObject *bo);
RZ_IPI RBinObject *rz_bin_object_new(RBinFile *binfile, RBinPlugin *plugin, ut64 baseaddr, ut64 loadaddr, ut64 offset, ut64 sz);
RZ_IPI RBinObject *rz_bin_object_get_cur(RBin *bin);
RZ_IPI RBinObject *rz_bin_object_find_by_arch_bits(RBinFile *binfile, const char *arch, int bits, const char *name);
RZ_IPI RBNode *rz_bin_object_patch_relocs(RBin *bin, RBinObject *o);

RZ_IPI const char *rz_bin_lang_tostring(int lang);
RZ_IPI int rz_bin_lang_type(RBinFile *binfile, const char *def, const char *sym);
RZ_IPI bool rz_bin_lang_swift(RBinFile *binfile);

RZ_IPI void rz_bin_class_free(RBinClass *c);
RZ_IPI RBinSymbol *rz_bin_class_add_method(RBinFile *binfile, const char *classname, const char *name, int nargs);
RZ_IPI void rz_bin_class_add_field(RBinFile *binfile, const char *classname, const char *name);

RZ_IPI RBinFile *rz_bin_file_xtr_load_buffer(RBin *bin, RBinXtrPlugin *xtr, const char *filename, RBuffer *buf, ut64 baseaddr, ut64 loadaddr, int idx, int fd, int rawstr);
RZ_IPI RBinFile *rz_bin_file_new_from_buffer(RBin *bin, const char *file, RBuffer *buf, int rawstr, ut64 baseaddr, ut64 loadaddr, int fd, const char *pluginname);
#endif
