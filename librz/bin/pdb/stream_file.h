// SPDX-FileCopyrightText: 2014 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef STREAM_FILE_H
#define STREAM_FILE_H

#include <stdio.h>

int init_r_stream_file(RZ_STREAM_FILE *stream_file, RzBuffer *buf, int *pages,
	int pages_amount, int size, int page_size);

void stream_file_read(RZ_STREAM_FILE *stream_file, int size, char *res);

void stream_file_seek(RZ_STREAM_FILE *stream_file, int offset, int whence);

int stream_file_tell(RZ_STREAM_FILE *stream_file);

void stream_file_get_data(RZ_STREAM_FILE *stream_file, char *data);

void stream_file_get_size(RZ_STREAM_FILE *stream_file, int *data_size);

#endif // STREAM_FILE_H
