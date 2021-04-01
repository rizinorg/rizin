// SPDX-FileCopyrightText: 2014 inisider <inisider@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef OMAP_H
#define OMAP_H

void parse_omap_stream(void *stream, RZ_STREAM_FILE *stream_file);
void free_omap_stream(void *stream);
int omap_remap(void *stream, int address);

#endif // OMAP_H
