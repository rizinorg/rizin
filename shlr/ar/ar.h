// SPDX-FileCopyrightText: 2017 xarkes <antide.petit@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#ifndef _AR_H
#define _AR_H

typedef struct RZARFP {
	char *name;
	ut64 start;
	ut64 end;
	RzBuffer *buf;
	ut32 *refcount;
} RzArFp;

/* Offset passed is always the real io->off of the inspected file,
 * the functions automatically translate it to relative offset within the archive */
RZ_API RzArFp *ar_open_file(const char *arname, int perm, const char *filename);
RZ_API int ar_close(RzArFp *f);
RZ_API int ar_read_at(RzArFp *f, ut64 off, void *buf, int count);
RZ_API int ar_write_at(RzArFp *f, ut64 off, void *buf, int count);
#endif // _AR_H
