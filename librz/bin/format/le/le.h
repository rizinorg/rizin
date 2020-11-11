#ifndef LE_H
#define LE_H
#include <rz_bin.h>
#include "le_specs.h"

typedef struct rz_bin_le_obj_s {
	LE_image_header *header;
	bool is_le; /* Used for differences between LE and LX */
	char *filename;
	const char *type;
	const char *cpu;
	const char *os;
	const char *arch;
	ut32 headerOff; /* File offset to start of LE/LX header */
	LE_object_entry *objtbl;
	void *buf; /* Pointer to RzBuffer of file */
} rz_bin_le_obj_t;

rz_bin_le_obj_t *rz_bin_le_new_buf(RzBuffer *buf);
void rz_bin_le_free(rz_bin_le_obj_t *bin);
RzList *rz_bin_le_get_entrypoints(rz_bin_le_obj_t *bin);
RzList *rz_bin_le_get_sections(rz_bin_le_obj_t *bin);
RzList *rz_bin_le_get_symbols(rz_bin_le_obj_t *bin);
RzList *rz_bin_le_get_imports(rz_bin_le_obj_t *bin);
RzList *rz_bin_le_get_libs(rz_bin_le_obj_t *bin);
RzList *rz_bin_le_get_relocs(rz_bin_le_obj_t *bin);
#endif
