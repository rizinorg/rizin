// SPDX-FileCopyrightText: 2026
// SPDX-License-Identifier: LGPL-3.0-only

#include "jenkins.h"
#include <rz_util.h>

bool rz_jenkins_init(RzJenkins *ctx) {
	rz_return_val_if_fail(ctx, false);
	*ctx = 0;
	return true;
}

bool rz_jenkins_update(RzJenkins *ctx,const ut8 *data,size_t len) {
	rz_return_val_if_fail(ctx&&data, false);

	ut32 hash = *ctx;

	for (size_t i = 0;i<len;++i) {
		hash+= data[i];
		hash+= (hash << 10);
		hash^= (hash >> 6);
	}

	*ctx = hash;
	return true;
}

bool rz_jenkins_final(ut8 *digest, RzJenkins *ctx) {
	rz_return_val_if_fail(digest && ctx, false);

	ut32 hash= *ctx;

	hash+=(hash<<3);
	hash^=(hash>>11);
	hash += (hash<<15);


	rz_write_be32(digest,hash);

	return true;
}