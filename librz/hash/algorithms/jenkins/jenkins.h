// SPDX-FileCopyrightText: 2026
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_JENKINS_H
#define RZ_JENKINS_H

#include <rz_types.h>

#define RZ_HASH_JENKINS_DIGEST_SIZE 4
#define RZ_HASH_JENKINS_BLOCK_LENGTH 0

typedef ut32 RzJenkins;

bool rz_jenkins_init(RzJenkins *ctx);
bool rz_jenkins_update(RzJenkins *ctx,const ut8 *data, size_t len);
bool rz_jenkins_final(ut8 *digest, RzJenkins *ctx);

#endif