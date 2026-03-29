// SPDX-FileCopyrightText: 2026
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_JENKINS_H
#define RZ_JENKINS_H

#include <rz_types.h>

typedef ut32 RzJenkins;

static bool rz_jenkins_init(RzJenkins *ctx);
static bool rz_jenkins_update(RzJenkins *ctx,const ut8 *data, size_t len);
static bool rz_jenkins_final(ut8 *digest, RzJenkins *ctx);

#endif