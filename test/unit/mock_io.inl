// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>

/**
 * Mock RzIO as RzIOBind for a single mapped block at specified address.
 */
typedef struct io_mock_t {
	ut64 start;
	ut8 *data;
	size_t size;
} IOMock;

static bool io_mock_read_at(RzIO *io, ut64 addr, ut8 *buf, int len) {
	IOMock *mock = (void *)io;
	memset (buf, 0xff, len);
	if (addr < mock->start) {
		ut64 off = mock->start - addr;
		if (off < len) {
			memcpy (buf + off, mock->data, RZ_MIN (mock->size, len - off));
		}
	} else {
		ut64 data_off = addr - mock->start;
		if (data_off < mock->size) {
			memcpy (buf, mock->data + data_off, RZ_MIN (mock->size - data_off, len));
		}
	}
	return true;
}

static void io_mock_init(IOMock *mock, ut64 start, const ut8 *data, size_t size) {
	memset (mock, 0, sizeof (*mock));
	mock->start = start;
	mock->data = malloc (size);
	memcpy (mock->data, data, size);
	mock->size = size;
}

static void io_mock_fini(IOMock *mock) {
	free (mock->data);
}

static void io_mock_bind(IOMock *mock, RzIOBind *bind) {
	// This isn't really an RzIO so the mock should only be used when the structure itself is not accessed!
	bind->io = (void *)mock;
	bind->read_at = io_mock_read_at;
}
