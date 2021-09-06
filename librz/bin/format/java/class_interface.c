// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "class_interface.h"

Interface *java_interface_new(RzBuffer *buf, ut64 offset) {
	Interface *attr = RZ_NEW0(Interface);
	rz_return_val_if_fail(attr, NULL);
	attr->offset = offset;
	if (!rz_buf_read_be16(buf, &attr->index)) {
		free(attr);
		return NULL;
	}

	return attr;
}
