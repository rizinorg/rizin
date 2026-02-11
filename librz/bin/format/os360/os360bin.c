#include "os360bin.h"

#define OS360_RECORD_PREFIX 0x02

#define OS360_RECORD_SIZE 80

static RzBinOS360EsdRecord *parse_record_esd(const ut8 *buf) {
}

static RzBinOS360TxtRecord *parse_record_txt(const ut8 *buf) {
}

static OS360_RLD_record *parse_record_rld(const ut8 *buf) {
}

static RzBinOS360SymRecord *parse_record_sym(const ut8 *buf) {
}

static RzBinOS360XsdRecord *parse_record_xsd(const ut8 *buf) {
}

static RzBinOS360EndRecord *parse_record_end(const ut8 *buf) {
}

static RzBinOS360BaseRecord *load_record_os360(OS360_record_handler *handler, const ut8 *buf) {
	if (buf[0] != OS360_RECORD_PREFIX) {
		RZ_LOG_ERROR("Invalid record prefix\n");
		return NULL;
	}

	ut32 record_type = ;
	ut64 ident = ;
	switch (record_type) {
	case OS360_RECORD_TYPE_ESD:
		/* code */
		break;

	case OS360_RECORD_TYPE_TXT:
		/* code */
		break;

	case OS360_RECORD_TYPE_RLD:
		/* code */
		break;

	case OS360_RECORD_TYPE_SYM:
		/* code */
		break;

	case OS360_RECORD_TYPE_XSD:
		/* code */
		break;

	case OS360_RECORD_TYPE_END:
		/* code */
		break;

	default:
		RZ_LOG_ERROR("Unknown record type\n");
		return NULL;
	}

	return true;
}

static bool load_all_os360_records(rz_bin_os360_obj *obj, const ut8 *buf, ut64 size) {
	if (size % OS360_RECORD_SIZE != 0) {
		RZ_LOG_ERROR("Invalid file size (not a multiple of record size)\n");
		return false;
	}

	OS360_record_handler *current = NULL;
	while (size != 0) {
		OS360_record_handler *new_rec = RZ_NEW0(OS360_record_handler);
		if (!new_rec) {
			return false;
		}

		if (!load_record_os360(new_rec, buf)) {
			RZ_FREE(new_rec);
			return false;
		}

		if (!current) {
			obj->records = new_rec;
		} else {
			current->next = new_rec;
			current = current->next;
		}

		buf += OS360_RECORD_SIZE;
		size -= OS360_RECORD_SIZE;
	}

	return true;
}

static void rz_bin_free_os360_record(OS360_record_handler *handle) {
	RZ_FREE(handle->record.content);
	RZ_FREE(handle);
}

void rz_bin_os360_destroy(rz_bin_os360_obj *obj) {
	OS360_record_handler *current = obj->records;
	while (current) {
		OS360_record_handler *next = current->next;
		rz_bin_free_os360_record(current);
		current = next;
	}
	RZ_FREE(obj);
}

rz_bin_os360_obj *rz_bin_os360_init(const ut8 *buf, ut64 size) {
	rz_bin_os360_obj *ret = NULL;

	if (!(ret = RZ_NEW0(rz_bin_os360_obj))) {
		return NULL;
	}

	if (!load_all_os360_records(ret, buf, size)) {
		rz_bin_os360_destroy(ret);
		return NULL;
	}

	return ret;
}