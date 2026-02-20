#include "os360bin.h"

#define OS360_RECORD_PREFIX 0x02

#define OS360_RECORD_SIZE 80

/**
 * \brief Read a big-endian byte chunk into a fundamental integer variable.
 *
 * Reads \p size bytes from \p src and writes them into the destination
 * fundamental variable \p fund using big-endian source order. If the chunk
 * is smaller than sizeof(fund), the bytes are written into the least
 * significant part of \p fund. The offset is computed automatically as
 * sizeof(fund) - size.
 *
 * This macro is intended for parsing truncated or variable-width integer
 * fields from binary formats (for example 3-byte addresses) and assembling
 * them into a native integer type.
 *
 * Internally it uses rz_read_array_ble(), which converts byte order to match
 * the host endianness.
 *
 * \param src  Pointer to the source byte buffer.
 * \param fund Destination fundamental integer lvalue (e.g. ut16, ut32, ut64).
 * \param size Number of bytes to read from \p src.
 *
 * \warning \p fund must be an lvalue of a fundamental integer type.
 * \warning \p size must be less than or equal to sizeof(fund).
 *
 * Example:
 * \code
 * ut32 addr = 0;
 * rz_fundamental_chunk_be(buf + 5, addr, 3); // read 3-byte BE value into ut32
 * \endcode
 */
#define rz_fundamental_chunk_be(src, fund, size) \
	size_t off = sizeof(fund) - (size); \
	ut8 *dest = ((ut8 *)&(fund)) + off; \
	rz_read_array_ble((src), dest, (size), true)

/**
 * \brief Read a little-endian byte chunk into a fundamental integer variable.
 *
 * Reads \p size bytes from \p src and writes them into the destination
 * fundamental variable \p fund assuming little-endian source order.
 * The bytes are written starting from the lowest-addressed byte of \p fund.
 *
 * This macro is suitable for variable-width little-endian integer fields.
 * Byte order is normalized to host endianness by rz_read_array_ble().
 *
 * \param src  Pointer to the source byte buffer.
 * \param fund Destination fundamental integer lvalue (e.g. ut16, ut32, ut64).
 * \param size Number of bytes to read from \p src.
 *
 * \warning \p fund must be an lvalue of a fundamental integer type.
 * \warning \p size must be less than or equal to sizeof(fund).
 *
 * Example:
 * \code
 * ut32 value = 0;
 * rz_fundamental_chunk_le(buf, value, 2); // read 2-byte LE value into ut32
 * \endcode
 */
#define rz_fundamental_chunk_le(src, fund, size) \
	rz_read_array_ble((src), &(fund), (size), false)

/**
 * \brief Read variable-length data from \p src to \p dest with specified endianess.
 *
 * \param src The source buffer from which the value is read.
 * \param dest The destination buffer to which the value is written.
 * \param size The number of bytes to be read and written.
 * \param big_endian The endianess of the data to be read;
 * if true, the data is in big-endian format, otherwise in little-endian format.
 *
 * \note The order of bytes that's be written to \p dest is same as order of
 * host machine
 */
void rz_read_array_ble(void *src, void *dest, size_t size, bool big_endian) {
	const ut8 *s = (const ut8 *)src;
	ut8 *d = (ut8 *)dest;

	/* Validate input pointers and size */
	if (!src || !dest || size == 0) {
		return;
	}

#if RZ_HOST_IS_BIG_ENDIAN
	/* Host is big-endian */
	if (big_endian) {
		/* Source is big-endian — copy as-is */
		memcpy(d, s, size);
	} else {
		/* Source is little-endian — reverse byte order */
		for (size_t i = 0; i < size; i++) {
			d[i] = s[size - 1 - i];
		}
	}
#else
	/* Host is little-endian */
	if (!big_endian) {
		/* Source is little-endian — copy as-is */
		memcpy(d, s, size);
	} else {
		/* Source is big-endian — reverse byte order */
		for (size_t i = 0; i < size; i++) {
			d[i] = s[size - 1 - i];
		}
	}
#endif
}

static RZ_OWN RzBinOS360EsdRecord *parse_record_esd(const ut8 *buf) {
	RzBinOS360EsdRecord *record = RZ_NEW0(RzBinOS360EsdRecord);
	if (!record) {
		return NULL;
	}

	record->sym_num = rz_read_be16(buf + 10);
	if (record->sym_num % 16 != 0) {
		RZ_LOG_ERROR("Invalid ESD record sym_num (not a multiple of 16)\n");
		RZ_FREE(record);
		return NULL;
	}
	record->sym_num /= 16;

	record->esid = rz_read_be16(buf + 14);

	ut8 off = 16;
	for (ut8 i = 0; i < record->sym_num - 1; i++) {
		RzBinOS360ModuleSymbol *sym = &(record->symbols[i]);

        memcpy(sym->name, buf + off, 8);
		sym->type = buf[off + 8];
		rz_fundamental_chunk_be(buf + off + 9, sym->address, 3);
		sym->addition_1 = buf[off + 12];
		rz_fundamental_chunk_be(buf + off + 13, sym->addition_2, 3);

		off += 16;
	}

	return record;
}

static RZ_OWN RzBinOS360TxtRecord *parse_record_txt(const ut8 *buf) {
	RzBinOS360TxtRecord *record = RZ_NEW0(RzBinOS360TxtRecord);
	if (!record) {
		return NULL;
	}

	rz_fundamental_chunk_be(buf + 5, record->rel_addr, 3);
	record->data_size = rz_read_be16(buf + 10);
	record->esdid = rz_read_be16(buf + 14);
	memcpy(record->data, buf + 16, record->data_size);

	return record;
}

static RZ_OWN RzBinOS360RldRecord *parse_record_rld(const ut8 *buf) {
	RzBinOS360RldRecord *record = RZ_NEW0(RzBinOS360RldRecord);
	if (!record) {
		return NULL;
	}

	ut16 data_size = rz_read_be16(buf + 10);
	if (data_size % 4 != 0) {
		RZ_LOG_ERROR("Invalid RLD record data size (not a multiple of 4)\n");
		RZ_FREE(record);
		return NULL;
	}

	ut8 entry_num = 0;
	ut8 off = 16;
	bool is_chain = false;
	while (data_size != 0) {
		RzBinOS360RelocationEntry *entry = &(record->entries[entry_num]);
		if (!is_chain) {
			entry->relocation = rz_read_be16(buf + off);
			entry->relocation_target = rz_read_be16(buf + off + 2);
			entry->flag = buf[off + 4];
			rz_fundamental_chunk_be(buf + off + 5, entry->address, 3);

			off += 8;
			data_size -= 8;
		} else {
			entry->relocation = record->entries[entry_num - 1].relocation;
			entry->relocation_target = record->entries[entry_num - 1].relocation_target;
			entry->flag = buf[off];
			rz_fundamental_chunk_be(buf + off + 1, entry->address, 3);

			off += 4;
			data_size -= 4;
		}

		is_chain = IS_CHAIN(entry->flag);
		entry_num++;
	}
	record->entry_num = entry_num;

	return record;
}

static RZ_OWN RzBinOS360SymRecord *parse_record_sym(const ut8 *buf) {
	RzBinOS360SymRecord *record = RZ_NEW0(RzBinOS360SymRecord);
	if (!record) {
		return NULL;
	}

	ut16 data_size = rz_read_be16(buf + 10); /* TODO */
	ut8 sym_num = 0;
	ut8 off = 16;
	while (data_size != 0) { /* TODO */
		RzBinOS360SymbolData *entry = &(record->data[sym_num]);

		entry->organization = buf[off];
		off++;

		entry->address = rz_read_be16(buf + off);
		off += 2;

		if (IS_HAS_NAME_PROBE(entry->organization)) {
			ut8 name_length = NAME_LENGTH_EXTRUDE(entry->organization);
            memcpy(entry->name, buf + off, name_length);

			off += name_length;
		}

		if (IS_DATA_TYPE_PROBE(entry->organization)) {
			entry->data_type = buf[off];
			off++;

			// 2 bytes for Character, Hexadecimal or Binary
			// otherwise 1 byte
			if (
				entry->data_type == OS360_SYM_D_CHAR ||
				entry->data_type == OS360_SYM_D_HEX ||
				entry->data_type == OS360_SYM_D_BIN) {
				entry->length = rz_read_be16(buf + off);
				off += 2;
			} else {
				entry->length = rz_read_be8(buf + off);
				off++;
			}

			if (IS_MULTIPLICITY_PRESENT_PROBE(entry->organization)) {
				rz_fundamental_chunk_be(buf + off, entry->multiplicity, 3);
				off += 3;
			}

			if (IS_SCALING_PRESENT_PROBE(entry->organization)) {
				entry->scale = rz_read_be16(buf + off);
				off += 2;
			}
		}

		sym_num++;
	}

	return record;
}

static RZ_OWN RzBinOS360XsdRecord *parse_record_xsd(const ut8 *buf) {
	RzBinOS360XsdRecord *record = RZ_NEW0(RzBinOS360XsdRecord);
	if (!record) {
		return NULL;
	}

	record->data_size = rz_read_be16(buf + 10);
	record->flag1 = buf[12];
	record->flag2 = buf[13];
	record->ldid_or_esdid = rz_read_be16(buf + 14);
	record->length = rz_read_be64(buf + 16);
	record->offset = rz_read_be64(buf + 20);
	record->type = buf[24];
	rz_fundamental_chunk_be(buf + 25, record->address, 3);
	record->spec = buf + 28;
	rz_fundamental_chunk_be(buf + 29, record->length_or_ident, 3);
	memcpy(record->name, buf + 32, record->length);

	return record;
}

static RZ_OWN RzBinOS360EndRecord *parse_record_end(const ut8 *buf) {
	RzBinOS360EndRecord *record = RZ_NEW0(RzBinOS360EndRecord);
	if (!record) {
		return NULL;
	}

	rz_fundamental_chunk_be(buf + 5, record->entry_address, 3);
	record->entry_esdid = rz_read_be16(buf + 14);
    memcpy(record->start_name, buf + 16, 8);
	record->module_size = rz_read_be64(buf + 28);
	record->format = buf[32];

	ut8 off = 33;
	for (ut8 i = 0; i < 2; i++) { 
        RzBinOS360IDRRecordData *idr = &record->idr[i];
		memcpy(idr->order_no, buf + off, 10);
		idr->version = rz_read_be16(buf + off + 10);
		idr->revision = rz_read_be16(buf + off + 12);
		idr->run_year = rz_read_be16(buf + off + 14);
		rz_fundamental_chunk_be(buf + off + 16, idr->run_day, 3);

		off += 18;
	}

	return record;
}

static RZ_OWN RzBinOS360BaseRecord *load_record_os360(const ut8 *buf) {
	if (buf[0] != OS360_RECORD_PREFIX) {
		RZ_LOG_ERROR("Invalid record prefix\n");
		return NULL;
	}

    RzBinOS360BaseRecord *base_record = RZ_NEW0(RzBinOS360BaseRecord);
    if (!base_record) {
        return NULL;
    }

	ut32 record_type = 0;
	rz_fundamental_chunk_be(buf + 1, record_type, 3);

	ut64 ident = rz_parse_be64(buf + 72);

	base_record->type = record_type;
	base_record->ident = ident;
	switch (record_type) {
	case OS360_RECORD_TYPE_ESD: {
		RzBinOS360EsdRecord *record = parse_record_esd(buf);
		if (!record) {
            RZ_FREE(base_record);
			return NULL;
		}
		base_record->content = record;
	} break;

	case OS360_RECORD_TYPE_TXT: {
		RzBinOS360TxtRecord *record = parse_record_txt(buf);
		if (!record) {
			RZ_FREE(base_record);
			return NULL;
		}
		base_record->content = record;
	} break;

	case OS360_RECORD_TYPE_RLD: {
		RzBinOS360TxtRecord *record = parse_record_txt(buf);
		if (!record) {
			RZ_FREE(base_record);
			return NULL;
		}
		base_record->content = record;
	} break;

	case OS360_RECORD_TYPE_SYM: {
		RzBinOS360SymRecord *record = parse_record_sym(buf);
		if (!record) {
			RZ_FREE(base_record);
			return NULL;
		}
		base_record->content = record;
	} break;

	case OS360_RECORD_TYPE_XSD: {
		RzBinOS360XsdRecord *record = parse_record_xsd(buf);
		if (!record) {
			RZ_FREE(base_record);
			return NULL;
		}
		base_record->content = record;
	} break;

	case OS360_RECORD_TYPE_END: {
		RzBinOS360EndRecord *record = parse_record_end(buf);
		if (!record) {
			RZ_FREE(base_record);
			return NULL;
		}
		base_record->content = record;
	} break;

	default:
		RZ_LOG_ERROR("Unknown record type\n");
		RZ_FREE(base_record);
		return NULL;
	}

	return base_record;
}

static bool load_all_os360_records(RzBinOS360Obj *obj, const ut8 *buf, ut64 size) {
	if (size % OS360_RECORD_SIZE != 0) {
		RZ_LOG_ERROR("Invalid file size (not a multiple of record size)\n");
		return false;
	}

	while (size != 0) {
        RzBinOS360BaseRecord *new_rec = load_record_os360(buf);
        rz_vector_push(obj->records, new_rec);

		buf += OS360_RECORD_SIZE;
		size -= OS360_RECORD_SIZE;
	}

	return true;
}

void rz_bin_os360_destroy(RzBinOS360Obj *obj) {
	rz_vector_free(obj->records);
	RZ_FREE(obj);
}

void base_record_destroy(RzBinOS360BaseRecord *record) {
    RZ_FREE(record->content)
    RZ_FREE(record);
}

RzBinOS360Obj *rz_bin_os360_init(const ut8 *buf, ut64 size) {
	RzBinOS360Obj *ret = NULL;

	if (!(ret = RZ_NEW0(RzBinOS360Obj))) {
		return NULL;
	}

    ret->records = rz_pvector_new((RzPVectorFree)base_record_destroy);

	if (!load_all_os360_records(ret, buf, size)) {
		rz_bin_os360_destroy(ret);
		return NULL;
	}

	return ret;
}

ut32 esdid_address_extract(RzBinOS360BaseRecord *record, bool* is_valid) {
	switch (record->type) {
	case OS360_RECORD_TYPE_ESD: {
		RzBinOS360EsdRecord *esd_record = record->content;
		for(ut8 i = 0; i < esd_record->sym_num; i++) {
            RzBinOS360ModuleSymbol *sym = &(esd_record->symbols[i]);
            if (sym->type != OS360_ESD_TYPE_LD) {
                return sym->address;
            }
        }
        *is_valid = false;
	}
	case OS360_RECORD_TYPE_TXT: {
		RzBinOS360TxtRecord *txt_record = record->content;
		*is_valid = true;
		return txt_record->rel_addr;
	}
	case OS360_RECORD_TYPE_XSD: {
		RzBinOS360XsdRecord *xsd_record = record->content;
        *is_valid = true;
		return xsd_record->address;
	}
	}

	*is_valid = false;
}

RZ_OWN RzBinAddr *rz_bin_os360_extract_entry_address(RZ_NONNULL RzBinOS360Obj *obj, RzBinOS360BaseRecord *record) {
        if (record->type != OS360_RECORD_TYPE_END) {
            RZ_LOG_ERROR("Record is not an END record\n");
            return NULL;
        }
        RzBinOS360EndRecord *end_record = record->content;

        if (end_record->entry_address != 0) {
			char *log = "From record with deck id %lld, found entry address: 0x%08x\n";
			RZ_LOG_DEBUG(log, record->ident, end_record->entry_address);
			RzBinAddr *entry = RZ_NEW0(RzBinAddr);
			entry->vaddr = end_record->entry_address;
			
            return entry;
		}

		if (end_record->entry_esdid != 0) {
			char *log = "From record with deck id %lld, found entry ESDID: %d\n";
			RZ_LOG_DEBUG(log, record->ident, end_record->entry_esdid);
			RzBinOS360BaseRecord *found_record = rz_bin_os360_find_record_by_esdid(obj, end_record->entry_esdid);
			if (!found_record) {
				RZ_LOG_ERROR("Failed to find record by ESDID: %d\n", end_record->entry_esdid);
				return NULL;
			}

			bool is_valid = false;
			ut32 entry_addr = esdid_address_extract(found_record, &is_valid);
			if (!is_valid) {
                char *log = "Failed to extract address for record with deck id %lld and with ESDID: %d\n";
				RZ_LOG_ERROR(log, found_record->ident, end_record->entry_esdid);
				return NULL;
			}
			RzBinAddr *entry = RZ_NEW0(RzBinAddr);
			entry->vaddr = entry_addr;
			
            return entry;
		}

		if (RZ_STR_ISNOTEMPTY(end_record->start_name)) {
			char *log = "From record with deck id %lld, found entry name: %s\n";
			RZ_LOG_DEBUG(log, record->ident, end_record->start_name);
			RzBinOS360BaseRecord *found_record = rz_bin_os360_find_record_by_ident(obj, end_record->start_name);
			if (!found_record) {
				RZ_LOG_ERROR("Failed to find record by name: %s\n", end_record->start_name);
				return NULL;
			}

            bool is_valid = false;
			ut32 entry_addr = esdid_address_extract(found_record, &is_valid);
			if (!is_valid) {
                char* log = "Failed to extract address for record with deck id %lld and with name: %s\n";
				RZ_LOG_ERROR(log, found_record->ident, end_record->start_name);
				return NULL;
			}
			RzBinAddr *entry = RZ_NEW0(RzBinAddr);
			entry->vaddr = entry_addr;
			
            return entry;
		}

    return NULL;
}

RzBinOS360BaseRecord *rz_bin_os360_find_record_by_ident(RzBinOS360Obj *obj, char *ident) {
	void **it;
	rz_pvector_foreach (obj->records, it) {
		RzBinOS360BaseRecord *record = *it;
		switch (record->type) {
            /* TODO */
		default:
			return NULL;
		}
	}

	return NULL;
}

RzBinOS360BaseRecord *rz_bin_os360_find_record_by_esdid(RzBinOS360Obj *obj, ut16 esdid) {
	void **it;
	rz_pvector_foreach (obj->records, it) {
		RzBinOS360BaseRecord *record = *it;

		switch (record->type) {
		case OS360_RECORD_TYPE_ESD: {
			RzBinOS360EsdRecord *esd_record = record->content;
			if (esd_record->esid == esdid) {
				return record;
			}
		} break;

		case OS360_RECORD_TYPE_TXT: {
			RzBinOS360TxtRecord *txt_record = record->content;
			if (txt_record->esdid == esdid) {
				return record;
			}
		} break;

		case OS360_RECORD_TYPE_XSD: {
			RzBinOS360XsdRecord *xsd_record = record->content;
			if (
				xsd_record->type != OS360_ESD_TYPE_LD &&
				xsd_record->ldid_or_esdid == esdid) {
				return record;
			}
		} break;
		}
	}

	return NULL;
}