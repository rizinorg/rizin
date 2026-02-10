// SPDX-FileCopyrightText: 2020 Aswin C (officialcjunior) <realc@protonmail.com>, 2026 Muqeet Salam <muqeetsalam168@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_svd.h"
#include <rz_util.h>
#include <yxml.h>
#include <string.h>
#include <ctype.h>

#define XMLBUFSIZE 4096
#define VALUESIZE  2048

typedef struct {
	uint8_t yxml_buf[XMLBUFSIZE];
	yxml_t x;
	const char *ptr;
	const char *end;
	RzSvdContext *ctx;
	RzSvdDevice *current_device;
	RzSvdInterrupt *current_interrupt;
	char value_buf[VALUESIZE];
	int depth;
	bool in_device;
	bool in_interrupt;
} SvdParser;

// Forward declarations
static void parse_svd_xml(SvdParser *parser);
static void free_interrupt(RzSvdInterrupt *interrupt);
static void free_device(RzSvdDevice *device);

static void free_interrupt(RzSvdInterrupt *interrupt) {
	if (!interrupt) {
		return;
	}
	free(interrupt->name);
	free(interrupt->description);
	free(interrupt);
}

static void free_device(RzSvdDevice *device) {
	if (!device) {
		return;
	}
	free(device->name);
	free(device->vendor);
	free(device->version);
	if (device->interrupts) {
		rz_list_free(device->interrupts);
	}
	free(device);
}

/**
 * \brief Create a new SVD context from a file path
 *
 * \param[in] svd_path Path to the SVD file
 * \return RzSvdContext* or NULL on failure
 */
RZ_API RZ_OWN RzSvdContext *rz_svd_new(RZ_NONNULL const char *svd_path) {
	if (!svd_path) {
		return NULL;
	}

	char *doc = rz_file_slurp(svd_path, NULL);
	if (!doc) {
		RZ_LOG_DEBUG("Failed to open SVD file: %s\n", svd_path);
		return NULL;
	}

	size_t doc_len = strlen(doc);
	if (!doc_len) {
		free(doc);
		return NULL;
	}

	RzSvdContext *ctx = RZ_NEW0(RzSvdContext);
	if (!ctx) {
		free(doc);
		return NULL;
	}

	ctx->file_path = strdup(svd_path);
	ctx->devices = rz_list_newf((RzListFree)free_device);
	if (!ctx->devices) {
		free(ctx->file_path);
		free(ctx);
		free(doc);
		return NULL;
	}

	SvdParser parser = { 0 };
	yxml_init(&parser.x, parser.yxml_buf, sizeof(parser.yxml_buf));
	parser.ptr = doc;
	parser.end = doc + doc_len;
	parser.ctx = ctx;

	parse_svd_xml(&parser);

	free(doc);
	return ctx;
}

/**
 * \brief Free an SVD context and all its data
 *
 * \param[in] ctx SVD context to free
 */
RZ_API void rz_svd_free(RZ_NULLABLE RzSvdContext *ctx) {
	if (!ctx) {
		return;
	}
	free(ctx->file_path);
	rz_list_free(ctx->devices);
	free(ctx);
}

/**
 * \brief Get a device by name from the SVD context
 *
 * \param[in] ctx SVD context
 * \param[in] device_name Device name (case-insensitive)
 * \return RzSvdDevice* or NULL if not found
 */
RZ_API RZ_NULLABLE RzSvdDevice *rz_svd_get_device(RZ_NULLABLE RzSvdContext *ctx, RZ_NULLABLE const char *device_name) {
	if (!ctx || !device_name) {
		return NULL;
	}

	RzListIter *iter;
	RzSvdDevice *device;
	rz_list_foreach (ctx->devices, iter, device) {
		if (device->name && strcasecmp(device->name, device_name) == 0) {
			return device;
		}
	}
	return NULL;
}

/**
 * \brief Get interrupt by index
 *
 * \param[in] device SVD device
 * \param[in] index Interrupt index
 * \return RzSvdInterrupt* or NULL if index out of range
 */
RZ_API RZ_NULLABLE RzSvdInterrupt *rz_svd_device_get_interrupt(RZ_NULLABLE RzSvdDevice *device, ut32 index) {
	if (!device || !device->interrupts) {
		return NULL;
	}

	RzListIter *iter;
	RzSvdInterrupt *interrupt;
	rz_list_foreach (device->interrupts, iter, interrupt) {
		if (interrupt->value == index) {
			return interrupt;
		}
	}
	return NULL;
}

/**
 * \brief Find an SVD file for a given device name
 *
 * Searches in standard locations in this order:
 * - $RZ_SVD_DIR/ (if environment variable is set)
 * - ~/.local/share/rizin/svd/
 * - <install_prefix>/share/rizin/svd/ (compile-time path)
 * - /usr/share/rizin/svd/
 * - /usr/local/share/rizin/svd/
 *
 * \param[in] device_name Device name
 * \return char* path to SVD file or NULL if not found (caller must free)
 */
RZ_API RZ_OWN char *rz_svd_find_file(RZ_NULLABLE const char *device_name) {
	if (!device_name) {
		return NULL;
	}

	// Create lowercase version for matching
	char *lower_name = strdup(device_name);
	if (!lower_name) {
		return NULL;
	}
	for (char *p = lower_name; *p; p++) {
		*p = tolower(*p);
	}

	// Try various locations
	char path[1024];
	
	// 1. First check RZ_SVD_DIR environment variable if set
	const char *svd_dir = getenv("RZ_SVD_DIR");
	if (svd_dir) {
		snprintf(path, sizeof(path), "%s/%s.svd", svd_dir, lower_name);
		if (rz_file_exists(path)) {
			free(lower_name);
			return strdup(path);
		}
	}
	
	// 2. Check user home directory
	const char *home = getenv("HOME");
	if (home) {
		snprintf(path, sizeof(path), "%s/.local/share/rizin/svd/%s.svd", home, lower_name);
		if (rz_file_exists(path)) {
			free(lower_name);
			return strdup(path);
		}
	}
	
	// 3. Check compile-time defined data directory (e.g., PREFIX/share/rizin/svd)
#ifdef RZ_SVD_DATADIR
	snprintf(path, sizeof(path), RZ_SVD_DATADIR "/%s.svd", lower_name);
	if (rz_file_exists(path)) {
		free(lower_name);
		return strdup(path);
	}
#endif
	
	// 4. Fallback to standard system paths
	snprintf(path, sizeof(path), "/usr/share/rizin/svd/%s.svd", lower_name);
	if (rz_file_exists(path)) {
		free(lower_name);
		return strdup(path);
	}
	
	snprintf(path, sizeof(path), "/usr/local/share/rizin/svd/%s.svd", lower_name);
	if (rz_file_exists(path)) {
		free(lower_name);
		return strdup(path);
	}

	free(lower_name);
	return NULL;
}

// XML parsing implementation
static void parse_svd_xml(SvdParser *parser) {
	enum {
		ELEM_NONE,
		ELEM_DEVICE,
		ELEM_NAME,
		ELEM_VENDOR,
		ELEM_VERSION,
		ELEM_ADDRESS_WIDTH,
		ELEM_DATA_WIDTH,
		ELEM_INTERRUPT,
		ELEM_INT_NAME,
		ELEM_INT_VALUE,
		ELEM_INT_DESC
	} current_element = ELEM_NONE;

	int depth = 0;
	int device_depth = -1;
	int interrupt_depth = -1;
	char *content_buf = NULL;
	size_t content_len = 0;

	while (parser->ptr < parser->end) {
		yxml_ret_t r = yxml_parse(&parser->x, *parser->ptr);
		parser->ptr++;

		switch (r) {
		case YXML_ELEMSTART:
			depth++;
			if (strcasecmp(parser->x.elem, "device") == 0) {
				device_depth = depth;
				parser->current_device = RZ_NEW0(RzSvdDevice);
				if (parser->current_device) {
					parser->current_device->interrupts = rz_list_newf((RzListFree)free_interrupt);
				}
			} else if (parser->current_device && depth == device_depth + 1) {
				if (strcasecmp(parser->x.elem, "name") == 0) {
					current_element = ELEM_NAME;
				} else if (strcasecmp(parser->x.elem, "vendor") == 0) {
					current_element = ELEM_VENDOR;
				} else if (strcasecmp(parser->x.elem, "version") == 0) {
					current_element = ELEM_VERSION;
				} else if (strcasecmp(parser->x.elem, "addressUnitBits") == 0) {
					current_element = ELEM_ADDRESS_WIDTH;
				} else if (strcasecmp(parser->x.elem, "width") == 0) {
					current_element = ELEM_DATA_WIDTH;
				}
			} else if (parser->current_device && strcasecmp(parser->x.elem, "interrupt") == 0) {
				interrupt_depth = depth;
				parser->current_interrupt = RZ_NEW0(RzSvdInterrupt);
			} else if (parser->current_interrupt && depth == interrupt_depth + 1) {
				if (strcasecmp(parser->x.elem, "name") == 0) {
					current_element = ELEM_INT_NAME;
				} else if (strcasecmp(parser->x.elem, "value") == 0) {
					current_element = ELEM_INT_VALUE;
				} else if (strcasecmp(parser->x.elem, "description") == 0) {
					current_element = ELEM_INT_DESC;
				}
			}
			content_len = 0;
			break;

		case YXML_CONTENT:
			if (current_element != ELEM_NONE && parser->x.data[0]) {
				size_t add_len = strlen(parser->x.data);
				if (content_len + add_len < VALUESIZE - 1) {
					if (!content_buf) {
						content_buf = parser->value_buf;
						content_buf[0] = '\0';
					}
					strcat(content_buf, parser->x.data);
					content_len += add_len;
				}
			}
			break;

		case YXML_ELEMEND:
			if (content_buf && current_element != ELEM_NONE) {
				// Trim whitespace
				char *start = content_buf;
				while (*start && isspace(*start)) start++;
				char *end = start + strlen(start) - 1;
				while (end > start && isspace(*end)) *end-- = '\0';

				switch (current_element) {
				case ELEM_NAME:
					if (parser->current_device) {
						parser->current_device->name = strdup(start);
					}
					break;
				case ELEM_VENDOR:
					if (parser->current_device) {
						parser->current_device->vendor = strdup(start);
					}
					break;
				case ELEM_VERSION:
					if (parser->current_device) {
						parser->current_device->version = strdup(start);
					}
					break;
				case ELEM_ADDRESS_WIDTH:
					if (parser->current_device) {
						parser->current_device->address_width = strtoul(start, NULL, 0);
					}
					break;
				case ELEM_DATA_WIDTH:
					if (parser->current_device) {
						parser->current_device->data_width = strtoul(start, NULL, 0);
					}
					break;
				case ELEM_INT_NAME:
					if (parser->current_interrupt) {
						parser->current_interrupt->name = strdup(start);
					}
					break;
				case ELEM_INT_VALUE:
					if (parser->current_interrupt) {
						parser->current_interrupt->value = strtoul(start, NULL, 0);
					}
					break;
				case ELEM_INT_DESC:
					if (parser->current_interrupt) {
						parser->current_interrupt->description = strdup(start);
					}
					break;
				default:
					break;
				}
			}

			if (depth == interrupt_depth && parser->current_interrupt) {
				// End of interrupt element
				if (parser->current_device && parser->current_device->interrupts) {
					rz_list_append(parser->current_device->interrupts, parser->current_interrupt);
				} else {
					free_interrupt(parser->current_interrupt);
				}
				parser->current_interrupt = NULL;
				interrupt_depth = -1;
			} else if (depth == device_depth && parser->current_device) {
				// End of device element
				rz_list_append(parser->ctx->devices, parser->current_device);
				parser->current_device = NULL;
				device_depth = -1;
			}

			depth--;
			current_element = ELEM_NONE;
			content_buf = NULL;
			content_len = 0;
			break;

		default:
			break;
		}
	}
}
