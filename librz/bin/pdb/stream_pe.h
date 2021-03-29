// SPDX-FileCopyrightText: 2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PE_H
#define PE_H

void parse_pe_stream(void *stream, RZ_STREAM_FILE *stream_file);
void free_pe_stream(void *stream);

#endif // PE_H
