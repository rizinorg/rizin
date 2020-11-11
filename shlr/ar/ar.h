// SPDX-License-Identifier: LGPL-3.0-only
#ifndef _AR_H
#define _AR_H

/* Offset passed is always the real io->off of the inspected file,
 * the functions automatically translate it to relative offset within the archive */
RZ_API RzBuffer *ar_open_file(const char *arname, const char *filename);
RZ_API int ar_close(RzBuffer *b);
RZ_API int ar_read_at(RzBuffer *b, ut64 off, void *buf, int count);
RZ_API int ar_write_at(RzBuffer *b, ut64 off, void *buf, int count);

int ar_read(RzBuffer *b, void *dest, int len);
int ar_read_until_slash(RzBuffer *b, char *buffer, int limit);
int ar_read_header(RzBuffer *b, char *buffer);
int ar_read_file(RzBuffer *b, char *buffer, bool lookup, RzList *files, const char *filename);
int ar_read_filename_table(RzBuffer *b, char *buffer, RzList *files, const char *filename);
#endif	// _AR_H
