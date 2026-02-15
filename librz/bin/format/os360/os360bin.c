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
    ut8* dest = ((ut8 *)&(fund)) + off; \
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

/**
 * \brief Convert EBCDIC string to ASCII string.
 * \param src The pointer from which the value is read.
 * \param dest The pointer to which the converted ASCII string is written.
 * \param len The length of the string to be converted.
 * \note For unconverted characters, a '?' is written to \p dest.
 */
static rz_ebcdic_to_ascii(const ut8 *src, char *dest, size_t len) {
    typedef struct {
        ut8 ebcdic;
        char ascii;
    } ebcdic_ascii_map;

    const ebcdic_ascii_map map[] = {
        {0x00, '\0'}, {0x40, ' '}, {0x4A, '¢'},
        {0x4B, '.'}, {0x4C, '<'}, 
        /* TODO*/

    };
    const size_t map_size = sizeof(map) / sizeof(map[0]);

    for (size_t i = 0; i < len; i++) {
        ut8 byte = src[i];
        char ascii_char = '?'; 
        for (size_t j = 0; j < map_size; j++) {
            if (map[j].ebcdic == byte) {
                ascii_char = map[j].ascii;
                break;
            }
        }
        dest[i] = ascii_char;
    }
}

static RzBinOS360EsdRecord *parse_record_esd(const ut8 *buf) {
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
        
        rz_ebcdic_to_ascii(buf + off, sym->name, 8);
        sym->type = buf[off + 8];
        rz_fundamental_chunk_be(buf + off + 9, sym->address, 3); 
        sym->addition_1 = buf[off + 12];
        rz_fundamental_chunk_be(buf + off + 13, sym->addition_2, 3);

        off += 16;
    }
    
    return record;
}

static RzBinOS360TxtRecord *parse_record_txt(const ut8 *buf) {
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

static RzBinOS360RldRecord *parse_record_rld(const ut8 *buf) {
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
    while(data_size != 0) {
        RzBinOS360RelocationEntry *entry = &(record->entries[entry_num]);
        if(!is_chain) {
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

static RzBinOS360SymRecord *parse_record_sym(const ut8 *buf) {
    RzBinOS360SymRecord *record = RZ_NEW0(RzBinOS360SymRecord);
    if (!record) {
        return NULL;
    }

    ut16 data_size = rz_read_be16(buf + 10); /* TODO */
    ut8 sym_num = 0;
    ut8 off = 16;
    while(data_size != 0) { /* TODO */
        RzBinOS360SymbolData *entry = &(record->data[sym_num]);

        entry->organization = buf[off];
        off++;

        entry->address = rz_read_be16(buf + off);
        off += 2;

        if (IS_HAS_NAME_PROBE(entry->organization)) {
            ut8 name_length = NAME_LENGTH_EXTRUDE(entry->organization);
            rz_ebcdic_to_ascii(buf + off, entry->name, name_length);
            
            off += name_length;
        }

        if (IS_DATA_TYPE_PROBE(entry->organization)) {
            entry->data_type = buf[off];
            off++;
            
            // 2 bytes for Character, Hexadecimal or Binary
            // otherwise 1 byte
            if(
                entry->data_type == OS360_SYM_D_CHAR ||
                entry->data_type == OS360_SYM_D_HEX ||
                entry->data_type == OS360_SYM_D_BIN
            ) {
                entry->length = rz_read_be16(buf + off);
                off += 2;
            } else {
                entry->length = rz_read_be8(buf + off);
                off++;
            }

            if(IS_MULTIPLICITY_PRESENT_PROBE(entry->organization)) {
                rz_fundamental_chunk_be(buf + off, entry->multiplicity, 3);
                off += 3;
            }

            if(IS_SCALING_PRESENT_PROBE(entry->organization)) {
                entry->scale = rz_read_be16(buff + off);
                off += 2;
            }
        }

        sym_num++;
    }

    return record;
}

static RzBinOS360XsdRecord *parse_record_xsd(const ut8 *buf) {
    RzBinOS360XsdRecord *record = RZ_NEW0(RzBinOS360XsdRecord);
    if (!record) {
        return NULL;
    }

    /* TODO */
    record->data_size;
    record->flag1;
    record->flag2;
    record->ldid_or_esdid;
    record->length;
    record->offset;
    record->type;
    record->address;
    record->spec;
    record->length_or_ident;
    record->name;

    return record;
}

static RzBinOS360EndRecord *parse_record_end(const ut8 *buf) {
    RzBinOS360EndRecord *record = RZ_NEW0(RzBinOS360EndRecord);
    if (!record) {
        return NULL;
    }

    rz_fundamental_chunk_be(buf + 5, record->entry_address, 3);
    record->entry_esdid = rz_read_be16(buf + 14);
    rz_ebcdic_to_ascii(buf + 16, record->start_name, 8);
    record->module_size = rz_read_be64(buf + 28);
    record->format_or_idr_count = buf[32];
    
    ut8 off = 33;
    for(ut8 i = 0; i < 2; i++) { /* TODO */
        memcpy(record->order_no, buf + off, 10); 
        record->version = rz_read_be16(buf + off + 10);
        record->revision = rz_read_be16(buf + off + 12);
        record->run_year = rz_read_be16(buf + off + 14);
        rz_fundamental_chunk_be(buf + off + 16, record->run_day, 3);
        
        off += 18;
    }

    return record;
}

static bool load_record_os360(OS360_record_handler *handler, const ut8 *buf) {
	if (buf[0] != OS360_RECORD_PREFIX) {
		RZ_LOG_ERROR("Invalid record prefix\n");
		return false;
	}

	ut32 record_type = 0;
    rz_fundamental_chunk_be(buf + 1, record_type, 3);

	ut64 ident = rz_parse_be64(buf + 72);

    handler->record.type = record_type;
    handler->record.ident = ident;
	switch (record_type) {
	case OS360_RECORD_TYPE_ESD:
        RzBinOS360EsdRecord* record = parse_record_esd(buf);
        if (!record) {
            return false;
        }
		handler->record.content = record;
		break;

	case OS360_RECORD_TYPE_TXT:
		RzBinOS360TxtRecord* record = parse_record_txt(buf);
        if (!record) {
            return false;
        }
		handler->record.content = record;
		break;

	case OS360_RECORD_TYPE_RLD:
		RzBinOS360TxtRecord* record = parse_record_txt(buf);
        if (!record) {
            return false;
        }
		handler->record.content = record;
		break;

	case OS360_RECORD_TYPE_SYM:
		RzBinOS360SymRecord* record = parse_record_sym(buf);
        if (!record) {
            return false;
        }
		handler->record.content = record;
		break;

	case OS360_RECORD_TYPE_XSD:
		RzBinOS360XsdRecord* record = parse_record_xsd(buf);
        if (!record) {
            return false;
        }
		handler->record.content = record;
		break;

	case OS360_RECORD_TYPE_END:
		RzBinOS360EndRecord* record = parse_record_end(buf);
        if (!record) {
            return false;
        }
		handler->record.content = record;
		break;

	default:
		RZ_LOG_ERROR("Unknown record type\n");
		return false;
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