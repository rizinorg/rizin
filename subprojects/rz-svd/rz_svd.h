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

/**
 * Create a new SVD context from a file path
 * @param svd_path Path to the SVD file
 * @return RzSvdContext* or NULL on failure
 */
RZ_API RzSvdContext *rz_svd_new(const char *svd_path);

/**
 * Free an SVD context and all its data
 * @param ctx SVD context to free
 */
RZ_API void rz_svd_free(RzSvdContext *ctx);

/**
 * Get a device by name from the SVD context
 * @param ctx SVD context
 * @param device_name Device name (case-insensitive)
 * @return RzSvdDevice* or NULL if not found
 */
RZ_API RzSvdDevice *rz_svd_get_device(RzSvdContext *ctx, const char *device_name);

/**
 * Get interrupt by index
 * @param device SVD device
 * @param index Interrupt index
 * @return RzSvdInterrupt* or NULL if index out of range
 */
RZ_API RzSvdInterrupt *rz_svd_device_get_interrupt(RzSvdDevice *device, ut32 index);

/**
 * Find an SVD file for a given device name
 * Searches in standard locations:
 * - ~/.local/share/rizin/svd/
 * - /usr/share/rizin/svd/
 * - ${RZ_DATDIR}/svd/
 * 
 * @param device_name Device name
 * @return char* path to SVD file or NULL if not found (caller must free)
 */
RZ_API char *rz_svd_find_file(const char *device_name);

#ifdef __cplusplus
}
#endif

#endif // RZ_SVD_H
