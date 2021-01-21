#ifndef RZ_PDB_H
#define RZ_PDB_H

#define _R_LIST_C
#include "rz_util.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FILE_NAME_LEN 256

struct RZ_PDB7_ROOT_STREAM;

typedef struct rz_pdb_t {
	bool (*pdb_parse)(struct rz_pdb_t *pdb);
	void (*finish_pdb_parse)(struct rz_pdb_t *pdb);
	void (*print_types)(const struct rz_pdb_t *pdb, PJ *pj, int mode);
	//	FILE *fp;
	PrintfCallback cb_printf;
	struct RZ_PDB7_ROOT_STREAM *root_stream;
	void *stream_map;
	RzList *pdb_streams;
	RzList *pdb_streams2;
	RzBuffer *buf; // mmap of file
	//	int curr;

	void (*print_gvars)(struct rz_pdb_t *pdb, ut64 img_base, PJ *pj, int format);
} RzPdb;

RZ_API bool init_pdb_parser(RzPdb *pdb, const char *filename);
RZ_API bool init_pdb_parser_with_buf(RzPdb *pdb, RzBuffer *buf);

#ifdef __cplusplus
}
#endif

#endif
