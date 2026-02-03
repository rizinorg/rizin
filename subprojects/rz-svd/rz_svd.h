// SPDX-FileCopyrightText: 2020 Aswin C (officialcjunior) <realc@protonmail.com>, 2026 Muqeet Salam <muqeetsalam168@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_SVD_H
#define RZ_SVD_H

#include <rz_types.h>
#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_svd_interrupt_t {
	char *name;
	ut32 value;
	char *description;
} RzSvdInterrupt;

typedef struct rz_svd_device_t {
	char *name;
	char *vendor;
	char *version;
	ut32 address_width;
	ut32 data_width;
	RzList /*<RzSvdInterrupt*>*/ *interrupts;
} RzSvdDevice;

typedef struct rz_svd_context_t {
	char *file_path;
	RzList /*<RzSvdDevice*>*/ *devices;
} RzSvdContext;

RZ_API RZ_OWN RzSvdContext *rz_svd_new(RZ_NONNULL const char *svd_path);
RZ_API void rz_svd_free(RZ_NULLABLE RzSvdContext *ctx);
RZ_API RZ_NULLABLE RzSvdDevice *rz_svd_get_device(RZ_NULLABLE RzSvdContext *ctx, RZ_NULLABLE const char *device_name);
RZ_API RZ_NULLABLE RzSvdInterrupt *rz_svd_device_get_interrupt(RZ_NULLABLE RzSvdDevice *device, ut32 index);
RZ_API RZ_OWN char *rz_svd_find_file(RZ_NULLABLE const char *device_name);

#ifdef __cplusplus
}
#endif

#endif // RZ_SVD_H
