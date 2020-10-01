#ifndef _IO_PRIVATE_H_
#define _IO_PRIVATE_H_

RzIOMap *io_map_new(RzIO *io, int fd, int perm, ut64 delta, ut64 addr, ut64 size);
RzIOMap *io_map_add(RzIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size, bool do_skyline);
void io_map_calculate_skyline(RzIO *io);

#endif
