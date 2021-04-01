// SPDX-FileCopyrightText: 2014 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef GDATA_H
#define GDATA_H

void parse_gdata_stream(void *stream, RZ_STREAM_FILE *stream_file);
void free_gdata_stream(void *stream);

#endif // GDATA_H
