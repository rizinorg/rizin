// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2017 xarkes <antide.petit@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#ifndef RZ_AR_H
#define RZ_AR_H
#include <rz_util.h>

typedef struct RZARFP {
	char *name;
	ut64 start;
	ut64 end;
	RzBuffer *buf;
	bool shared_buf;
	ut32 st_mode;
} RzArFp;

/* Offset passed is always the real io->off of the inspected file,
 * the functions automatically translate it to relative offset within the archive */
RZ_API RzArFp *ar_open_file(const char *arname, int perm, const char *filename);
RZ_API RzList /*<RzArFp *>*/ *ar_open_all(const char *arname, int perm);
RZ_API void ar_close(RzArFp *f);
RZ_API int ar_read_at(RzArFp *f, ut64 off, void *buf, int count);
RZ_API int ar_write_at(RzArFp *f, ut64 off, void *buf, int count);
#endif // RZ_AR_H
