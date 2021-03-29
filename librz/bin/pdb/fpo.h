// SPDX-FileCopyrightText: 2014 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef FPO_H
#define FPO_H

void free_fpo_stream(void *stream);
void parse_fpo_stream(void *stream, RZ_STREAM_FILE *stream_file);

void free_fpo_new_stream(void *stream);
void parse_fpo_new_stream(void *stream, RZ_STREAM_FILE *stream_file);

#endif // FPO_H
