#ifndef IO_MEMORY_H
#define IO_MEMORY_H

#include "rz_io.h"

typedef struct {
	ut8 *buf;
	ut32 size;
	ut64 offset;
} RzIOMalloc;

int io_memory_close(RzIODesc *fd);
int io_memory_read(RzIO *io, RzIODesc *fd, ut8 *buf, int count);
ut64 io_memory_lseek(RzIO *io, RzIODesc *fd, ut64 offset, int whence);
int io_memory_write(RzIO *io, RzIODesc *fd, const ut8 *buf, int count);
bool io_memory_resize(RzIO *io, RzIODesc *fd, ut64 count);

#endif
