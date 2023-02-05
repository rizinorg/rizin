// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#ifndef SDB_PRIVATE_H_
#define SDB_PRIVATE_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_HEADER_SYS_MMAN_H
#define HAVE_HEADER_SYS_MMAN_H HAVE_MMAN
#endif

#define SDB_V_NOT(op, fail_ret) \
	if ((op) == (fail_ret)) \
	eprintf(#op " at %s:%d failed: %s\n", __FILE__, __LINE__, strerror(errno))
#define write_(fd, buf, count) SDB_V_NOT(write(fd, buf, count), -1)
#define read_(fd, buf, count)  SDB_V_NOT(read(fd, buf, count), -1)

static inline int seek_set(int fd, off_t pos) {
	return ((fd == -1) || (lseek(fd, (off_t)pos, SEEK_SET) == -1)) ? 0 : 1;
}

static inline void ut32_pack(char s[4], ut32 u) {
	s[0] = u & 255;
	u >>= 8;
	s[1] = u & 255;
	u >>= 8;
	s[2] = u & 255;
	s[3] = u >> 8;
}

static inline void ut32_pack_big(char s[4], ut32 u) {
	s[3] = u & 255;
	u >>= 8;
	s[2] = u & 255;
	u >>= 8;
	s[1] = u & 255;
	s[0] = u >> 8;
}

static inline void ut32_unpack(char s[4], ut32 *u) {
	ut32 result = 0;
	result = (ut8)s[3];
	result <<= 8;
	result += (ut8)s[2];
	result <<= 8;
	result += (ut8)s[1];
	result <<= 8;
	result += (ut8)s[0];
	*u = result;
}

#ifdef __cplusplus
}
#endif

#endif
