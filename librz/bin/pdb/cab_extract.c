// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_type.h>
#include <mspack.h>

#include "pdb.h"

// checks all the files and guesses if is using unix or win paths
static bool is_cab_using_unix_paths(struct mscabd_file *files) {
	bool slash = false, backslash = false;
	struct mscabd_file *fi = NULL;

	for (fi = files; fi; fi = fi->next) {
		for (char *p = fi->filename; *p; p++) {
			if (*p == '/') {
				slash = true;
			} else if (*p == '\\') {
				backslash = true;
			}
		}
		if (slash && backslash) {
			break;
		}
	}

	if (!slash) {
		/* no slashes, therefore is windows */
		return false;
	} else if (!backslash) {
		/* slashes but no backslashes, therefore is unix */
		return true;
	}

	/* check if starts with a slash */
	if (!files->next) {
		char c, *p = fi->filename;
		while ((c = *p++)) {
			if (c == '\\') {
				return false; /* is windows */
			} else if (c == '/') {
				return true; /* is unix */
			}
		}
		/* impossible scenario since at least one slash was found */
		return false;
	}

	const char *oldname = NULL;
	size_t oldlen = 0;
	for (fi = files; fi; fi = fi->next) {
		const char *name = fi->filename;
		size_t len = 0;
		while (name[len]) {
			if ((name[len] == '\\') || (name[len] == '/')) {
				break;
			}
			len++;
		}
		if (!name[len]) {
			len = 0;
		} else {
			len++;
			if (len == oldlen && !strncmp(name, oldname, len)) {
				return name[len - 1] != '\\';
			}
		}

		oldname = name;
		oldlen = len;
	}

	return false;
}

static bool is_slash(const char *str) {
	return *str == '/' || *str == '\\';
}

static bool is_previous_dir(const char *path) {
	return path[0] == '.' && path[1] == '.' && is_slash(path + 2);
}

static char *sanitize_cab_filename(struct mscabd_file *file, const char *output_dir, bool is_unix) {
	char separator = '\\';
	char os_slash = '/';
	if (is_unix) {
		separator = '/';
		os_slash = '\\';
	}

	size_t output_dir_len = strlen(output_dir) + 1; // includes the path separator
	size_t filename_len = strlen(file->filename);

	char *sanitized = RZ_NEWS0(char, output_dir_len + (filename_len * 4) + 2);
	if (!sanitized) {
		RZ_LOG_ERROR("Cannot allocate sanitized name\n");
		return NULL;
	}

	const ut8 *input = (const ut8 *)&file->filename[0];
	const ut8 *endp = (const ut8 *)&file->filename[filename_len];
	ut8 *output = (ut8 *)&sanitized[output_dir_len];

	memcpy(sanitized, output_dir, output_dir_len);
	sanitized[output_dir_len - 1] = '/';

	if (file->attribs & MSCAB_ATTRIB_UTF_NAME) {
		// sanitize utf-8 filename
		RzCodePoint code_point;
		for (; input < endp;) {
			code_point = 0;
			int len = rz_utf8_decode(input, endp - input, &code_point);
			if (!len) {
				len = 1;
				code_point = 0xFFFD;
			} else if (code_point <= 0 || code_point > 0x10FFFF || (code_point >= 0xD800 && code_point <= 0xDFFF) || code_point == 0xFFFE || code_point == 0xFFFF) {
				len = 1;
				code_point = 0xFFFD;
			}
			input += len;

			if (code_point == separator) {
				code_point = '/';
			} else if (code_point == os_slash) {
				code_point = '\\';
			}

			len = rz_utf8_encode(output, code_point);
			output += len;
		}
		*output++ = '\0';
	} else {
		// sanitize ascii filename
		ut8 c = 0;
		while (input < endp) {
			c = *input++;
			if (c == separator) {
				c = '/';
			} else if (c == os_slash) {
				c = '\\';
			}
			*output++ = c;
		}
		*output++ = '\0';
	}

	output = (ut8 *)&sanitized[output_dir_len];
	for (input = output; is_slash((const char *)input); input++) {
		// skip any leading slashes in the cab filename part
	}

	if (input != output) {
		size_t len = strlen((char *)input);
		if (len > 0) {
			memmove(output, input, len + 1);
		} else {
			/* change filename composed entirely of leading slashes to underscores */
			strcpy((char *)output, "_");
		}
	}

	// remove any "../" or "..\" in the filename
	for (; *output; output++) {
		if (is_previous_dir((const char *)output)) {
			output[0] = output[1] = '_';
			output += 2;
		}
	}

	return sanitized;
}

static const char *cab_error(struct mscab_decompressor *cd) {
	switch (cd->last_error(cd)) {
	case MSPACK_ERR_OPEN:
		return "MSPACK_ERR_OPEN";
	case MSPACK_ERR_READ:
		return "MSPACK_ERR_READ";
	case MSPACK_ERR_WRITE:
		return "MSPACK_ERR_WRITE";
	case MSPACK_ERR_SEEK:
		return "MSPACK_ERR_SEEK";
	case MSPACK_ERR_NOMEMORY:
		return "MSPACK_ERR_NOMEMORY";
	case MSPACK_ERR_SIGNATURE:
		return "MSPACK_ERR_SIGNATURE";
	case MSPACK_ERR_DATAFORMAT:
		return "MSPACK_ERR_DATAFORMAT";
	case MSPACK_ERR_CHECKSUM:
		return "MSPACK_ERR_CHECKSUM";
	case MSPACK_ERR_DECRUNCH:
		return "MSPACK_ERR_DECRUNCH";
	default:
		rz_warn_if_reached();
		return "unknown";
	}
}

/**
 * \brief  Extracts compressed PDB files into a folder.
 *
 * \param  file_cab    The file cab
 * \param  output_dir  The output dir
 *
 * \return On success returns true, otherwise false.
 */
RZ_API bool rz_bin_pdb_extract_in_folder(RZ_NONNULL const char *file_cab, RZ_NONNULL const char *output_dir) {
	rz_return_val_if_fail(file_cab && output_dir, false);

	if (!rz_file_exists(file_cab)) {
		RZ_LOG_ERROR("%s is not a file or does not exist.\n", file_cab);
		return false;
	}

	if (!rz_file_is_directory(output_dir)) {
		RZ_LOG_ERROR("%s is not a directory or does not exist.\n", output_dir);
		return false;
	}

	struct mscab_decompressor *cabd = NULL;
	struct mscabd_cabinet *cab = NULL;

	if (!(cabd = mspack_create_cab_decompressor(NULL))) {
		RZ_LOG_ERROR("Cannot allocate mscab_decompressor.\n");
		return false;
	}

	if (!(cab = cabd->open(cabd, file_cab))) {
		RZ_LOG_ERROR("Invalid compressed cab file: %s\n", file_cab);
		mspack_destroy_cab_decompressor(cabd);
		return false;
	}

	bool result = true;
	bool is_unix = is_cab_using_unix_paths(cab->files);
	for (struct mscabd_file *file = cab->files; file; file = file->next) {
		char *new_name = sanitize_cab_filename(file, output_dir, is_unix);
		if (!new_name) {
			result = false;
			break;
		}
		if (cabd->extract(cabd, file, new_name)) {
			RZ_LOG_ERROR("cab_extract: %s: %s\n", new_name, cab_error(cabd));
			free(new_name);
			result = false;
			break;
		}
		RZ_LOG_INFO("cab_extract: extracted %s\n", new_name);
		free(new_name);
	}

	cabd->close(cabd, cab);
	mspack_destroy_cab_decompressor(cabd);
	return result;
}
