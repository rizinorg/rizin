// SPDX-FileCopyrightText: 2015-2020 inisider <inisider@gmail.com>
// SPDX-FileCopyrightText: 2015-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "../../i/private.h"
#include "mach0_classes.h"

#define RO_META            (1 << 0)
#define MAX_CLASS_NAME_LEN 256

#ifdef RZ_BIN_MACH064
#define FAST_DATA_MASK 0x00007ffffffffff8UL
#else
#define FAST_DATA_MASK 0xfffffffcUL
#endif

#define METHOD_LIST_FLAG_IS_SMALL     0x80000000
#define METHOD_LIST_FLAG_IS_PREOPT    0x3
#define METHOD_LIST_ENTSIZE_FLAG_MASK 0xffff0003

#define RO_DATA_PTR(x) ((x)&FAST_DATA_MASK)

#if RZ_BIN_MACH064
#define rz_buf_read_mach0_ut_offset rz_buf_read_ble64_offset
#else
#define rz_buf_read_mach0_ut_offset rz_buf_read_ble32_offset
#endif

struct MACH0_(SMethodList) {
	ut32 entsize;
	ut32 count;
	/* SMethod first;  These structures follow inline */
};

struct MACH0_(SMethod) {
	mach0_ut name; /* SEL (32/64-bit pointer) */
	mach0_ut types; /* const char * (32/64-bit pointer) */
	mach0_ut imp; /* IMP (32/64-bit pointer) */
};

struct MACH0_(SClass) {
	mach0_ut isa; /* SClass* (32/64-bit pointer) */
	mach0_ut superclass; /* SClass* (32/64-bit pointer) */
	mach0_ut cache; /* Cache (32/64-bit pointer) */
	mach0_ut vtable; /* IMP * (32/64-bit pointer) */
	mach0_ut data; /* SClassRoT * (32/64-bit pointer) */
};

struct MACH0_(SClassRoT) {
	ut32 flags;
	ut32 instanceStart;
	ut32 instanceSize;
#ifdef RZ_BIN_MACH064
	ut32 reserved;
#endif
	mach0_ut ivarLayout; /* const uint8_t* (32/64-bit pointer) */
	mach0_ut name; /* const char* (32/64-bit pointer) */
	mach0_ut baseMethods; /* const SMEthodList* (32/64-bit pointer) */
	mach0_ut baseProtocols; /* const SProtocolList* (32/64-bit pointer) */
	mach0_ut ivars; /* const SIVarList* (32/64-bit pointer) */
	mach0_ut weakIvarLayout; /* const uint8_t * (32/64-bit pointer) */
	mach0_ut baseProperties; /* const SObjcPropertyList* (32/64-bit pointer) */
};

struct MACH0_(SProtocolList) {
	mach0_ut count; /* uintptr_t (a 32/64-bit value) */
	/* SProtocol* list[0];  These pointers follow inline */
};

struct MACH0_(SProtocol) {
	mach0_ut isa; /* id* (32/64-bit pointer) */
	mach0_ut name; /* const char * (32/64-bit pointer) */
	mach0_ut protocols; /* SProtocolList* (32/64-bit pointer) */
	mach0_ut instanceMethods; /* SMethodList* (32/64-bit pointer) */
	mach0_ut classMethods; /* SMethodList* (32/64-bit pointer) */
	mach0_ut optionalInstanceMethods; /* SMethodList* (32/64-bit pointer) */
	mach0_ut optionalClassMethods; /* SMethodList* (32/64-bit pointer) */
	mach0_ut instanceProperties; /* struct SObjcPropertyList* (32/64-bit pointer) */
};

struct MACH0_(SIVarList) {
	ut32 entsize;
	ut32 count;
	/* SIVar first;  These structures follow inline */
};

struct MACH0_(SIVar) {
	mach0_ut offset; /* uintptr_t * (32/64-bit pointer) */
	mach0_ut name; /* const char * (32/64-bit pointer) */
	mach0_ut type; /* const char * (32/64-bit pointer) */
	ut32 alignment;
	ut32 size;
};

struct MACH0_(SObjcProperty) {
	mach0_ut name; /* const char * (32/64-bit pointer) */
	mach0_ut attributes; /* const char * (32/64-bit pointer) */
};

struct MACH0_(SObjcPropertyList) {
	ut32 entsize;
	ut32 count;
	/* struct SObjcProperty first;  These structures follow inline */
};

struct MACH0_(SCategory) {
	mach0_ut name;
	mach0_ut targetClass;
	mach0_ut instanceMethods;
	mach0_ut classMethods;
	mach0_ut protocols;
	mach0_ut properties;
};

static mach0_ut va2pa(mach0_ut p, ut32 *offset, ut32 *left, RzBinFile *bf);
static void copy_sym_name_with_namespace(char *class_name, char *read_name, RzBinSymbol *sym);
static void get_ivar_list_t(mach0_ut p, RzBinFile *bf, RzBuffer *buf, RzBinClass *klass);
static void get_objc_property_list(mach0_ut p, RzBinFile *bf, RzBuffer *buf, RzBinClass *klass);
static void get_method_list_t(mach0_ut p, RzBinFile *bf, RzBuffer *buf, char *class_name, RzBinClass *klass, bool is_static, objc_cache_opt_info *oi);
static void get_protocol_list_t(mach0_ut p, RzBinFile *bf, RzBuffer *buf, RzBinClass *klass, objc_cache_opt_info *oi);
static void get_class_ro_t(mach0_ut p, RzBinFile *bf, RzBuffer *buf, ut32 *is_meta_class, RzBinClass *klass, objc_cache_opt_info *oi);
static RzPVector /*<RzBinClass *>*/ *MACH0_(parse_categories)(RzBinFile *bf, RzBuffer *buf, RzSkipList *relocs, objc_cache_opt_info *oi);
static bool read_ptr_pa(RzBinFile *bf, RzBuffer *buf, ut64 paddr, mach0_ut *out);
static bool read_ptr_va(RzBinFile *bf, RzBuffer *buf, ut64 vaddr, mach0_ut *out);
static char *read_str(RzBinFile *bf, RzBuffer *buf, mach0_ut p, ut32 *offset, ut32 *left);
static char *get_class_name(mach0_ut p, RzBinFile *bf, RzBuffer *buf);
static bool is_thumb(RzBinFile *bf) {
	struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *)bf->o->bin_obj;
	if (bin->hdr.cputype == 12) {
		if (bin->hdr.cpusubtype == 9) {
			return true;
		}
	}
	return false;
}

static mach0_ut va2pa(mach0_ut p, ut32 *offset, ut32 *left, RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, 0);

	mach0_ut r;
	mach0_ut addr;

	void **iter = NULL;
	RzBinSection *s = NULL;
	RzBinObject *obj = bf->o;

	struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *)obj->bin_obj;
	if (bin->va2pa) {
		return bin->va2pa(p, offset, left, bf);
	}

	const RzPVector *sctns = bin->sections_cache;
	if (!sctns) {
		sctns = rz_bin_plugin_mach.sections(bf);
		if (!sctns) {
			return 0;
		}
	}

	addr = p;
	rz_pvector_foreach (sctns, iter) {
		s = *iter;
		if (addr >= s->vaddr && addr < s->vaddr + s->vsize) {
			if (offset) {
				*offset = addr - s->vaddr;
			}
			if (left) {
				*left = s->vsize - (addr - s->vaddr);
			}
			r = (s->paddr - obj->boffset + (addr - s->vaddr));
			return r;
		}
	}

	if (offset) {
		*offset = 0;
	}
	if (left) {
		*left = 0;
	}

	return 0;
}

static void copy_sym_name_with_namespace(char *class_name, char *read_name, RzBinSymbol *sym) {
	if (!class_name) {
		class_name = "";
	}
	sym->classname = strdup(class_name);
	sym->name = strdup(read_name);
}

static int sort_by_offset(const void *_a, const void *_b, void *user) {
	RzBinClassField *a = (RzBinClassField *)_a;
	RzBinClassField *b = (RzBinClassField *)_b;
	return a->paddr - b->paddr;
}

static bool read_sivarlist(struct MACH0_(SIVarList) * il, RzBuffer *buf, ut64 base, bool bigendian) {
	ut64 offset = base;
	return rz_buf_read_ble32_offset(buf, &offset, &il->entsize, bigendian) &&
		rz_buf_read_ble32_offset(buf, &offset, &il->count, bigendian);
}

static bool read_sivar(struct MACH0_(SIVar) * i, RzBuffer *buf, ut64 base, bool bigendian) {
	ut64 offset = base;
	return rz_buf_read_mach0_ut_offset(buf, &offset, &i->offset, bigendian) &&
		rz_buf_read_mach0_ut_offset(buf, &offset, &i->name, bigendian) &&
		rz_buf_read_mach0_ut_offset(buf, &offset, &i->type, bigendian) &&
		rz_buf_read_ble32_offset(buf, &offset, &i->alignment, bigendian) &&
		rz_buf_read_ble32_offset(buf, &offset, &i->size, bigendian);
}

static void get_ivar_list_t(mach0_ut p, RzBinFile *bf, RzBuffer *buf, RzBinClass *klass) {
	struct MACH0_(SIVarList) il = { 0 };
	struct MACH0_(SIVar) i;
	mach0_ut r;
	ut32 offset, left, j;

	int len;
	bool bigendian;
	mach0_ut ivar_offset;
	RzBinClassField *field = NULL;
	ut8 offs[sizeof(mach0_ut)] = { 0 };

	if (!bf || !bf->o || !bf->o->bin_obj || !bf->o->info) {
		RZ_LOG_ERROR("Invalid RzBinFile pointer\n");
		return;
	}
	bigendian = bf->o->info->big_endian;
	if (!(r = va2pa(p, &offset, &left, bf))) {
		return;
	}
	if (r + left < r || r + sizeof(struct MACH0_(SIVarList)) < r) {
		return;
	}
	if (r > bf->size || r + left > bf->size) {
		return;
	}
	if (r + sizeof(struct MACH0_(SIVarList)) > bf->size) {
		return;
	}
	if (!read_sivarlist(&il, buf, r, bigendian)) {
		return;
	}
	p += sizeof(struct MACH0_(SIVarList));
	offset += sizeof(struct MACH0_(SIVarList));

	for (j = 0; j < il.count; j++) {
		r = va2pa(p, &offset, &left, bf);
		if (!r) {
			return;
		}
		field = rz_bin_class_field_new(UT64_MAX, UT64_MAX, NULL, klass->name, NULL, NULL);
		memset(&i, '\0', sizeof(struct MACH0_(SIVar)));
		if (r + left < r || r + sizeof(struct MACH0_(SIVar)) < r) {
			goto error;
		}
		if (r > bf->size || r + left > bf->size) {
			goto error;
		}
		if (r + sizeof(struct MACH0_(SIVar)) > bf->size) {
			goto error;
		}
		if (!read_sivar(&i, buf, r, bigendian)) {
			goto error;
		}
		field->vaddr = i.offset;
		mach0_ut offset_at = va2pa(i.offset, NULL, &left, bf);

		if (offset_at > bf->size) {
			goto error;
		}
		if (offset_at + sizeof(ivar_offset) > bf->size) {
			goto error;
		}
		if (offset_at != 0 && left >= sizeof(mach0_ut)) {
			len = rz_buf_read_at(buf, offset_at, offs, sizeof(mach0_ut));
			if (len != sizeof(mach0_ut)) {
				RZ_LOG_ERROR("Cannot read mach0_ut\n");
				goto error;
			}
			ivar_offset = rz_read_ble(offs, bigendian, 8 * sizeof(mach0_ut));
			field->paddr = ivar_offset;
		}
		r = va2pa(i.name, NULL, &left, bf);
		if (r) {
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *)bf->o->bin_obj;
			if (r + left < r) {
				goto error;
			}
			if (r > bf->size || r + left > bf->size) {
				goto error;
			}
			char *name;
			if (bin->has_crypto) {
				name = strdup("some_encrypted_data");
				left = strlen(name) + 1;
			} else {
				int name_len = RZ_MIN(MAX_CLASS_NAME_LEN, left);
				name = malloc(name_len + 1);
				len = rz_buf_read_at(buf, r, (ut8 *)name, name_len);
				if (len < 1) {
					RZ_LOG_ERROR("Cannot read class name from buffer\n");
					RZ_FREE(name);
					goto error;
				}
				name[name_len] = 0;
			}
			// XXX the field name shouldnt contain the class name
			field->name = rz_str_newf("%s::(ivar)%s", klass->name, name);
			RZ_FREE(name);
		}

		r = va2pa(i.type, NULL, &left, bf);
		if (r) {
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *)bf->o->bin_obj;
			int is_crypted = bin->has_crypto;
			if (r + left < r) {
				goto error;
			}
			if (r > bf->size || r + left > bf->size) {
				goto error;
			}
			char *type = NULL;
			if (is_crypted == 1) {
				type = strdup("some_encrypted_data");
				// 	left = strlen (name) + 1;
			} else {
				int type_len = RZ_MIN(MAX_CLASS_NAME_LEN, left);
				type = calloc(1, type_len + 1);
				if (type) {
					rz_buf_read_at(buf, r, (ut8 *)type, type_len);
					type[type_len] = 0;
				}
			}
			if (type) {
				field->type = type;
				type = NULL;
			} else {
				field->type = NULL;
			}
			rz_list_append(klass->fields, field);
		} else {
			goto error;
		}
		p += sizeof(struct MACH0_(SIVar));
		offset += sizeof(struct MACH0_(SIVar));
	}
	if (!rz_list_empty(klass->fields)) {
		rz_list_sort(klass->fields, sort_by_offset, NULL);
	}
	field = rz_bin_class_field_new(UT64_MAX, UT64_MAX, "isa", klass->name, NULL, "struct objc_class *");
	rz_list_prepend(klass->fields, field);
	return;
error:
	rz_bin_class_field_free(field);
}

///////////////////////////////////////////////////////////////////////////////
static void get_objc_property_list(mach0_ut p, RzBinFile *bf, RzBuffer *buf, RzBinClass *klass) {
	struct MACH0_(SObjcPropertyList) opl;
	struct MACH0_(SObjcProperty) op;
	mach0_ut r;
	ut32 offset, left, j;
	char *name = NULL;
	int len;
	bool bigendian;
	RzBinClassField *property = NULL;
	ut8 sopl[sizeof(struct MACH0_(SObjcPropertyList))] = { 0 };
	ut8 sop[sizeof(struct MACH0_(SObjcProperty))] = { 0 };

	if (!bf || !bf->o || !bf->o->bin_obj || !bf->o->info) {
		RZ_LOG_ERROR("Invalid RzBinFile pointer\n");
		return;
	}
	bigendian = bf->o->info->big_endian;
	r = va2pa(p, &offset, &left, bf);
	if (!r) {
		return;
	}
	memset(&opl, '\0', sizeof(struct MACH0_(SObjcPropertyList)));
	if (r + left < r || r + sizeof(struct MACH0_(SObjcPropertyList)) < r) {
		return;
	}
	if (r > bf->size || r + left > bf->size) {
		return;
	}
	if (r + sizeof(struct MACH0_(SObjcPropertyList)) > bf->size) {
		return;
	}
	if (left < sizeof(struct MACH0_(SObjcPropertyList))) {
		if (rz_buf_read_at(buf, r, sopl, left) != left) {
			return;
		}
	} else {
		len = rz_buf_read_at(buf, r, sopl, sizeof(struct MACH0_(SObjcPropertyList)));
		if (len != sizeof(struct MACH0_(SObjcPropertyList))) {
			return;
		}
	}

	opl.entsize = rz_read_ble32(&sopl[0], bigendian);
	opl.count = rz_read_ble32(&sopl[4], bigendian);

	p += sizeof(struct MACH0_(SObjcPropertyList));
	offset += sizeof(struct MACH0_(SObjcPropertyList));
	for (j = 0; j < opl.count; j++) {
		r = va2pa(p, &offset, &left, bf);
		if (!r) {
			return;
		}

		if (!(property = rz_bin_class_field_new(UT64_MAX, UT64_MAX, NULL, klass->name, NULL, NULL))) {
			return;
		}

		memset(&op, '\0', sizeof(struct MACH0_(SObjcProperty)));

		if (r + left < r || r + sizeof(struct MACH0_(SObjcProperty)) < r) {
			goto error;
		}
		if (r > bf->size || r + left > bf->size) {
			goto error;
		}
		if (r + sizeof(struct MACH0_(SObjcProperty)) > bf->size) {
			goto error;
		}

		if (left < sizeof(struct MACH0_(SObjcProperty))) {
			if (rz_buf_read_at(buf, r, sop, left) != left) {
				goto error;
			}
		} else {
			len = rz_buf_read_at(buf, r, sop, sizeof(struct MACH0_(SObjcProperty)));
			if (len != sizeof(struct MACH0_(SObjcProperty))) {
				goto error;
			}
		}
		op.name = rz_read_ble(&sop[0], bigendian, 8 * sizeof(mach0_ut));
		op.attributes = rz_read_ble(&sop[sizeof(mach0_ut)], bigendian, 8 * sizeof(mach0_ut));
		r = va2pa(op.name, NULL, &left, bf);
		if (r) {
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *)bf->o->bin_obj;
			if (r > bf->size || r + left > bf->size) {
				goto error;
			}
			if (r + left < r) {
				goto error;
			}
			if (bin->has_crypto) {
				name = strdup("some_encrypted_data");
				left = strlen(name) + 1;
			} else {
				int name_len = RZ_MIN(MAX_CLASS_NAME_LEN, left);
				name = calloc(1, name_len + 1);
				if (!name) {
					goto error;
				}
				if (rz_buf_read_at(buf, r, (ut8 *)name, name_len) != name_len) {
					goto error;
				}
			}
			property->name = rz_str_newf("%s::(property)%s", klass->name, name);
			RZ_FREE(name);
		}
#if 0
		r = va2pa (op.attributes, NULL, &left, bf);
		if (r != 0) {
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *) bf->o->bin_obj;
			int is_crypted = bin->has_crypto;

			if (r > bf->size || r + left > bf->size) goto error;
			if (r + left < r) goto error;

			if (is_crypted == 1) {
				name = strdup ("some_encrypted_data");
				left = strlen (name) + 1;
			} else {
				name = malloc (left);
				len = rz_buf_read_at (buf, r, (ut8 *)name, left);
				if (len == 0 || len == -1) goto error;
			}

			RZ_FREE (name);
		}
#endif
		rz_list_append(klass->fields, property);

		p += sizeof(struct MACH0_(SObjcProperty));
		offset += sizeof(struct MACH0_(SObjcProperty));
	}
	return;
error:
	RZ_FREE(property);
	RZ_FREE(name);
	return;
}

///////////////////////////////////////////////////////////////////////////////
static void get_method_list_t(mach0_ut p, RzBinFile *bf, RzBuffer *buf, char *class_name, RzBinClass *klass, bool is_static, objc_cache_opt_info *oi) {
	struct MACH0_(SMethodList) ml;
	mach0_ut r;
	ut32 offset, left, i;
	char *name = NULL;
	char *rtype = NULL;
	int len;
	bool bigendian;
	ut8 sml[sizeof(struct MACH0_(SMethodList))] = { 0 };
	ut8 sm[sizeof(struct MACH0_(SMethod))] = { 0 };

	RzBinSymbol *method = NULL;
	if (!bf || !bf->o || !bf->o->bin_obj || !bf->o->info) {
		RZ_LOG_ERROR("Invalid RzBinFile pointer\n");
		return;
	}
	bigendian = bf->o->info->big_endian;
	r = va2pa(p, &offset, &left, bf);
	if (!r) {
		return;
	}
	memset(&ml, '\0', sizeof(struct MACH0_(SMethodList)));

	if (r + left < r || r + sizeof(struct MACH0_(SMethodList)) < r) {
		return;
	}
	if (r > bf->size) {
		return;
	}
	if (r + sizeof(struct MACH0_(SMethodList)) > bf->size) {
		return;
	}
	if (left < sizeof(struct MACH0_(SMethodList))) {
		if (rz_buf_read_at(buf, r, sml, left) != left) {
			return;
		}
	} else {
		len = rz_buf_read_at(buf, r, sml, sizeof(struct MACH0_(SMethodList)));
		if (len != sizeof(struct MACH0_(SMethodList))) {
			return;
		}
	}
	ml.entsize = rz_read_ble(&sml[0], bigendian, 32);
	ml.count = rz_read_ble(&sml[4], bigendian, 32);
	if (ml.count < 1 || ml.count > ST32_MAX) {
		return;
	}
	if (r + (ml.count * (ml.entsize & ~METHOD_LIST_ENTSIZE_FLAG_MASK)) > bf->size) {
		return;
	}

	bool is_small = (ml.entsize & METHOD_LIST_FLAG_IS_SMALL) != 0;
	ut8 mlflags = ml.entsize & 0x3;

	p += sizeof(struct MACH0_(SMethodList));
	offset += sizeof(struct MACH0_(SMethodList));

	size_t read_size = is_small ? 3 * sizeof(ut32) : sizeof(struct MACH0_(SMethod));

	for (i = 0; i < ml.count; i++) {
		r = va2pa(p, &offset, &left, bf);
		if (!r || r == -1) {
			return;
		}

		if (!(method = RZ_NEW0(RzBinSymbol))) {
			return;
		}
		struct MACH0_(SMethod) m;
		memset(&m, '\0', sizeof(struct MACH0_(SMethod)));
		if (r + left < r || r + read_size < r) {
			goto error;
		}
		if (r > bf->size) {
			goto error;
		}
		if (r + read_size > bf->size) {
			goto error;
		}
		if (left < read_size) {
			if (rz_buf_read_at(buf, r, sm, left) != left) {
				goto error;
			}
		} else {
			len = rz_buf_read_at(buf, r, sm, read_size);
			if (len != read_size) {
				goto error;
			}
		}
		if (!is_small) {
			m.name = rz_read_ble(&sm[0], bigendian, 8 * sizeof(mach0_ut));
			m.types = rz_read_ble(&sm[sizeof(mach0_ut)], bigendian, 8 * sizeof(mach0_ut));
			m.imp = rz_read_ble(&sm[2 * sizeof(mach0_ut)], bigendian, 8 * sizeof(mach0_ut));
		} else {
			st64 name_offset = (st32)rz_read_ble(&sm[0], bigendian, 8 * sizeof(ut32));
			mach0_ut name;
			if (oi && oi->sel_string_base) {
				name = oi->sel_string_base + name_offset;
			} else {
				name = p + name_offset;
			}
			if (mlflags != METHOD_LIST_FLAG_IS_PREOPT) {
				r = va2pa(name, &offset, &left, bf);
				if (!r) {
					goto error;
				}
				ut8 tmp[8];
				if (rz_buf_read_at(buf, r, tmp, sizeof(mach0_ut)) != sizeof(mach0_ut)) {
					goto error;
				}
				m.name = rz_read_ble(tmp, bigendian, 8 * sizeof(mach0_ut));
			} else {
				m.name = name;
			}
			st64 types_offset = (st32)rz_read_ble(&sm[sizeof(ut32)], bigendian, 8 * sizeof(ut32));
			m.types = p + types_offset + 4;
			st64 imp_offset = (st32)rz_read_ble(&sm[2 * sizeof(ut32)], bigendian, 8 * sizeof(ut32));
			m.imp = p + imp_offset + 8;
		}

		r = va2pa(m.name, NULL, &left, bf);
		if (r) {
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *)bf->o->bin_obj;
			if (r + left < r) {
				goto error;
			}
			if (r > bf->size || r + MAX_CLASS_NAME_LEN > bf->size) {
				goto error;
			}
			if (bin->has_crypto) {
				name = strdup("some_encrypted_data");
				left = strlen(name) + 1;
			} else {
				int name_len = RZ_MIN(MAX_CLASS_NAME_LEN, left);
				name = malloc(name_len + 1);
				len = rz_buf_read_at(buf, r, (ut8 *)name, name_len);
				name[name_len] = 0;
				if (len < 1) {
					goto error;
				}
			}
			copy_sym_name_with_namespace(class_name, name, method);
			RZ_FREE(name);
		}

		r = va2pa(m.types, NULL, &left, bf);
		if (r != 0) {
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *)bf->o->bin_obj;
			if (r + left > bf->size) {
				left = bf->size - r;
			}
			if (r + left < r || r > bf->size || r + left > bf->size) {
				goto error;
			}
			if (bin->has_crypto) {
				rtype = strdup("some_encrypted_data");
				left = strlen(rtype) + 1;
			} else {
				left = 1;
				rtype = malloc(left + 1);
				if (!rtype) {
					goto error;
				}
				if (rz_buf_read_at(buf, r, (ut8 *)rtype, left) != left) {
					free(rtype);
					goto error;
				}
				rtype[left] = 0;
			}
			method->rtype = strdup(rtype);
			RZ_FREE(rtype);
		}

		method->vaddr = m.imp;
		if (!method->vaddr) {
			RZ_FREE(method);
			goto next;
		}
		method->type = is_static ? RZ_BIN_TYPE_FUNC_STR : RZ_BIN_TYPE_METH_STR;
		if (is_static) {
			method->method_flags |= RZ_BIN_METH_CLASS;
		}
		if (is_thumb(bf)) {
			if (method->vaddr & 1) {
				method->vaddr >>= 1;
				method->vaddr <<= 1;
			}
		}
		rz_list_append(klass->methods, method);
	next:
		p += read_size;
		offset += read_size;
	}
	return;
error:
	RZ_FREE(method);
	RZ_FREE(name);
	return;
}

///////////////////////////////////////////////////////////////////////////////
static void get_protocol_list_t(mach0_ut p, RzBinFile *bf, RzBuffer *buf, RzBinClass *klass, objc_cache_opt_info *oi) {
	struct MACH0_(SProtocolList) pl = { 0 };
	struct MACH0_(SProtocol) pc;
	char *class_name = NULL;
	ut32 offset, left, i, j;
	mach0_ut q, r;
	int len;
	bool bigendian;
	ut8 spl[sizeof(struct MACH0_(SProtocolList))] = { 0 };
	ut8 spc[sizeof(struct MACH0_(SProtocol))] = { 0 };
	ut8 sptr[sizeof(mach0_ut)] = { 0 };

	if (!bf || !bf->o || !bf->o->bin_obj || !bf->o->info) {
		RZ_LOG_ERROR("Invalid RzBinFile pointer\n");
		return;
	}
	bigendian = bf->o->info->big_endian;
	if (!(r = va2pa(p, &offset, &left, bf))) {
		return;
	}
	if (r + left < r || r + sizeof(struct MACH0_(SProtocolList)) < r) {
		return;
	}
	if (r > bf->size || r + left > bf->size) {
		return;
	}
	if (r + sizeof(struct MACH0_(SProtocolList)) > bf->size) {
		return;
	}
	if (left < sizeof(struct MACH0_(SProtocolList))) {
		if (rz_buf_read_at(buf, r, spl, left) != left) {
			return;
		}
	} else {
		len = rz_buf_read_at(buf, r, spl, sizeof(struct MACH0_(SProtocolList)));
		if (len != sizeof(struct MACH0_(SProtocolList))) {
			return;
		}
	}
	pl.count = rz_read_ble(&spl[0], bigendian, 8 * sizeof(mach0_ut));

	p += sizeof(struct MACH0_(SProtocolList));
	offset += sizeof(struct MACH0_(SProtocolList));
	for (i = 0; i < pl.count; i++) {
		if (!(r = va2pa(p, &offset, &left, bf))) {
			return;
		}
		if (r + left < r || r + sizeof(mach0_ut) < r) {
			return;
		}
		if (r > bf->size || r + left > bf->size) {
			return;
		}
		if (r + sizeof(mach0_ut) > bf->size) {
			return;
		}
		if (left < sizeof(ut32)) {
			if (rz_buf_read_at(buf, r, sptr, left) != left) {
				return;
			}
		} else {
			len = rz_buf_read_at(buf, r, sptr, sizeof(mach0_ut));
			if (len != sizeof(mach0_ut)) {
				return;
			}
		}
		q = rz_read_ble(&sptr[0], bigendian, 8 * sizeof(mach0_ut));
		if (!(r = va2pa(q, &offset, &left, bf))) {
			return;
		}
		memset(&pc, '\0', sizeof(struct MACH0_(SProtocol)));
		if (r + left < r || r + sizeof(struct MACH0_(SProtocol)) < r) {
			return;
		}
		if (r > bf->size || r + left > bf->size) {
			return;
		}
		if (r + sizeof(struct MACH0_(SProtocol)) > bf->size) {
			return;
		}
		if (left < sizeof(struct MACH0_(SProtocol))) {
			if (rz_buf_read_at(buf, r, spc, left) != left) {
				return;
			}
		} else {
			len = rz_buf_read_at(buf, r, spc, sizeof(struct MACH0_(SProtocol)));
			if (len != sizeof(struct MACH0_(SProtocol))) {
				return;
			}
		}
		j = 0;
		pc.isa = rz_read_ble(&spc[j], bigendian, 8 * sizeof(mach0_ut));

		j += sizeof(mach0_ut);
		pc.name = rz_read_ble(&spc[j], bigendian, 8 * sizeof(mach0_ut));
		j += sizeof(mach0_ut);
		pc.protocols = rz_read_ble(&spc[j], bigendian, 8 * sizeof(mach0_ut));
		j += sizeof(mach0_ut);
		pc.instanceMethods = rz_read_ble(&spc[j], bigendian, 8 * sizeof(mach0_ut));
		j += sizeof(mach0_ut);
		pc.classMethods = rz_read_ble(&spc[j], bigendian, 8 * sizeof(mach0_ut));
		j += sizeof(mach0_ut);
		pc.optionalInstanceMethods = rz_read_ble(&spc[j], bigendian, 8 * sizeof(mach0_ut));
		j += sizeof(mach0_ut);
		pc.optionalClassMethods = rz_read_ble(&spc[j], bigendian, 8 * sizeof(mach0_ut));
		j += sizeof(mach0_ut);
		pc.instanceProperties = rz_read_ble(&spc[j], bigendian, 8 * sizeof(mach0_ut));
		r = va2pa(pc.name, NULL, &left, bf);
		if (r != 0) {
			char *name = NULL;
			struct MACH0_(obj_t) *bin = (struct MACH0_(obj_t) *)bf->o->bin_obj;
			if (r + left < r) {
				return;
			}
			if (r > bf->size || r + left > bf->size) {
				return;
			}
			if (bin->has_crypto) {
				name = strdup("some_encrypted_data");
				left = strlen(name) + 1;
			} else {
				int name_len = RZ_MIN(MAX_CLASS_NAME_LEN, left);
				name = malloc(name_len + 1);
				if (!name) {
					return;
				}
				if (rz_buf_read_at(buf, r, (ut8 *)name, name_len) != name_len) {
					RZ_FREE(name);
					return;
				}
				name[name_len] = 0;
			}
			class_name = rz_str_newf("%s::(protocol)%s", klass->name, name);
			RZ_FREE(name);
		}

		if (pc.instanceMethods > 0) {
			get_method_list_t(pc.instanceMethods, bf, buf, class_name, klass, false, oi);
		}
		if (pc.classMethods > 0) {
			get_method_list_t(pc.classMethods, bf, buf, class_name, klass, true, oi);
		}
		RZ_FREE(class_name);
		p += sizeof(ut32);
		offset += sizeof(ut32);
	}
}

static const char *skipnum(const char *s) {
	while (IS_DIGIT(*s)) {
		s++;
	}
	return s;
}

// TODO: split up between module + classname
static char *demangle_classname(const char *s) {
	int modlen, len;
	const char *kstr;
	char *ret, *klass, *module;
	if (!strncmp(s, "_TtC", 4)) {
		int off = 4;
		while (s[off] && (s[off] < '0' || s[off] > '9')) {
			off++;
		}
		len = atoi(s + off);
		modlen = strlen(s + off);
		if (!len || len >= modlen) {
			return strdup(s);
		}
		module = rz_str_ndup(skipnum(s + off), len);
		int skip = (skipnum(s + off) - s) + len;
		if (s[skip] == 'P') {
			skip++;
			len = atoi(s + skip);
			skip = (skipnum(s + skip) - s) + len;
		}
		kstr = s + skip;
		len = atoi(kstr);
		modlen = strlen(kstr);
		if (!len || len >= modlen) {
			free(module);
			return strdup(s);
		}
		klass = rz_str_ndup(skipnum(kstr), len);
		ret = rz_str_newf("%s.%s", module, klass);
		free(module);
		free(klass);
	} else {
		ret = strdup(s);
	}
	return ret;
}

static char *get_class_name(mach0_ut p, RzBinFile *bf, RzBuffer *buf) {
	struct MACH0_(obj_t) * bin;
	ut32 offset, left;
	ut64 r;
	int len;
	bool bigendian;
	ut8 sc[sizeof(mach0_ut)] = { 0 };
	const ut32 ptr_size = sizeof(mach0_ut);

	if (!bf || !bf->o || !bf->o->bin_obj || !bf->o->info) {
		RZ_LOG_ERROR("Invalid RzBinFile pointer\n");
		return NULL;
	}
	if (!p) {
		return NULL;
	}
	bigendian = bf->o->info->big_endian;
	bin = (struct MACH0_(obj_t) *)bf->o->bin_obj;

	if (!(r = va2pa(p, &offset, &left, bf))) {
		return NULL;
	}
	if ((r + left) < r || (r + sizeof(sc)) < r) {
		return NULL;
	}
	if (r > bf->size) {
		return NULL;
	}
	if (r + sizeof(sc) > bf->size) {
		return NULL;
	}
	if (left < sizeof(sc)) {
		return NULL;
	}
	len = rz_buf_read_at(buf, r + 4 * ptr_size, sc, sizeof(sc));
	if (len != sizeof(sc)) {
		return NULL;
	}

	ut64 rodata = rz_read_ble(sc, bigendian, 8 * ptr_size);
	if (!(r = va2pa(rodata, &offset, &left, bf))) {
		return NULL;
	}
	if (r + left < r || r + sizeof(sc) < r) {
		return NULL;
	}
	if (r > bf->size) {
		return NULL;
	}
	if (r + sizeof(sc) > bf->size) {
		return NULL;
	}
	if (left < sizeof(sc)) {
		return NULL;
	}

#ifdef RZ_BIN_MACH064
	len = rz_buf_read_at(buf, r + 4 * sizeof(ut32) + ptr_size, sc, sizeof(sc));
#else
	len = rz_buf_read_at(buf, r + 3 * sizeof(ut32) + ptr_size, sc, sizeof(sc));
#endif
	if (len != sizeof(sc)) {
		return NULL;
	}
	ut64 name = rz_read_ble(sc, bigendian, 8 * ptr_size);

	if ((r = va2pa(name, NULL, &left, bf))) {
		if (left < 1 || r + left < r) {
			return NULL;
		}
		if (r > bf->size || r + MAX_CLASS_NAME_LEN > bf->size) {
			return NULL;
		}
		if (bin->has_crypto) {
			return strdup("some_encrypted_data");
		} else {
			int name_len = RZ_MIN(MAX_CLASS_NAME_LEN, left);
			char *name = malloc(name_len + 1);
			if (name) {
				int rc = rz_buf_read_at(buf, r, (ut8 *)name, name_len);
				if (rc != name_len) {
					rc = 0;
				}
				name[rc] = 0;
				char *result = demangle_classname(name);
				free(name);
				return result;
			}
		}
	}

	return NULL;
}

///////////////////////////////////////////////////////////////////////////////
static void get_class_ro_t(mach0_ut p, RzBinFile *bf, RzBuffer *buf, ut32 *is_meta_class, RzBinClass *klass, objc_cache_opt_info *oi) {
	struct MACH0_(obj_t) * bin;
	struct MACH0_(SClassRoT) cro = { 0 };
	ut32 offset, left, i;
	ut64 r, s;
	int len;
	bool bigendian;
	ut8 scro[sizeof(struct MACH0_(SClassRoT))] = { 0 };
	char tmpbuf[2048];

	if (!bf || !bf->o || !bf->o->bin_obj || !bf->o->info) {
		RZ_LOG_ERROR("Invalid RzBinFile pointer\n");
		return;
	}
	bigendian = bf->o->info->big_endian;
	bin = (struct MACH0_(obj_t) *)bf->o->bin_obj;
	if (!(r = va2pa(p, &offset, &left, bf))) {
		return;
	}

	if (r + left < r || r + sizeof(cro) < r) {
		return;
	}
	if (r > bf->size || r + sizeof(cro) >= bf->size) {
		return;
	}
	if (r + sizeof(cro) > bf->size) {
		return;
	}

	// TODO: use rz_buf_fread to avoid endianness issues
	if (left < sizeof(cro)) {
		RZ_LOG_ERROR("Not enough data for SClassRoT\n");
		return;
	}
	len = rz_buf_read_at(buf, r, scro, sizeof(cro));
	if (len < 1) {
		return;
	}
	i = 0;
	cro.flags = rz_read_ble(&scro[i], bigendian, 8 * sizeof(ut32));
	i += sizeof(ut32);
	cro.instanceStart = rz_read_ble(&scro[i], bigendian, 8 * sizeof(ut32));
	i += sizeof(ut32);
	cro.instanceSize = rz_read_ble(&scro[i], bigendian, 8 * sizeof(ut32));
	i += sizeof(ut32);
#ifdef RZ_BIN_MACH064
	cro.reserved = rz_read_ble(&scro[i], bigendian, 8 * sizeof(ut32));
	i += sizeof(ut32);
#endif
	cro.ivarLayout = rz_read_ble(&scro[i], bigendian, 8 * sizeof(mach0_ut));
	i += sizeof(mach0_ut);
	cro.name = rz_read_ble(&scro[i], bigendian, 8 * sizeof(mach0_ut));
	i += sizeof(mach0_ut);
	cro.baseMethods = rz_read_ble(&scro[i], bigendian, 8 * sizeof(mach0_ut));
	i += sizeof(mach0_ut);
	cro.baseProtocols = rz_read_ble(&scro[i], bigendian, 8 * sizeof(mach0_ut));
	i += sizeof(mach0_ut);
	cro.ivars = rz_read_ble(&scro[i], bigendian, 8 * sizeof(mach0_ut));
	i += sizeof(mach0_ut);
	cro.weakIvarLayout = rz_read_ble(&scro[i], bigendian, 8 * sizeof(mach0_ut));
	i += sizeof(mach0_ut);
	cro.baseProperties = rz_read_ble(&scro[i], bigendian, 8 * sizeof(mach0_ut));

	s = r;
	if ((r = va2pa(cro.name, NULL, &left, bf))) {
		if (left < 1 || r + left < r) {
			return;
		}
		if (r > bf->size || r + left > bf->size) {
			return;
		}
		if (bin->has_crypto) {
			klass->name = strdup("some_encrypted_data");
			left = strlen(klass->name) + 1;
		} else {
			int name_len = RZ_MIN(MAX_CLASS_NAME_LEN, left);
			char *name = malloc(name_len + 1);
			if (name) {
				int rc = rz_buf_read_at(buf, r, (ut8 *)name, name_len);
				if (rc != name_len) {
					rc = 0;
				}
				name[rc] = 0;
				klass->name = demangle_classname(name);
				free(name);
			}
		}
		sdb_num_set(bin->kv, rz_strf(tmpbuf, "objc_class_%s.offset", klass->name), s, 0);
	}
#ifdef RZ_BIN_MACH064
	sdb_set(bin->kv, "objc_class.format", "lllll isa super cache vtable data", 0);
#else
	sdb_set(bin->kv, "objc_class.format", "xxxxx isa super cache vtable data", 0);
#endif

	if (cro.baseMethods > 0) {
		get_method_list_t(cro.baseMethods, bf, buf, klass->name, klass, (cro.flags & RO_META) ? true : false, oi);
	}

	if (cro.baseProtocols > 0) {
		get_protocol_list_t(cro.baseProtocols, bf, buf, klass, oi);
	}

	if (cro.ivars > 0) {
		get_ivar_list_t(cro.ivars, bf, buf, klass);
	}

	if (cro.baseProperties > 0) {
		get_objc_property_list(cro.baseProperties, bf, buf, klass);
	}

	if (is_meta_class) {
		*is_meta_class = (cro.flags & RO_META) ? 1 : 0;
	}
}

static mach0_ut get_isa_value(void) {
	// TODO: according to otool sources this is taken from relocs
	return 0;
}

RZ_API void MACH0_(get_class_t)(mach0_ut p, RzBinFile *bf, RzBuffer *buf, RzBinClass *klass, bool dupe, RzSkipList *relocs, objc_cache_opt_info *oi) {
	struct MACH0_(SClass) c = { 0 };
	const int size = sizeof(struct MACH0_(SClass));
	mach0_ut r = 0;
	ut32 offset = 0, left = 0;
	ut32 is_meta_class = 0;
	int len;
	bool bigendian;
	ut8 sc[sizeof(struct MACH0_(SClass))] = { 0 };
	ut32 i;

	if (!bf || !bf->o || !bf->o->info) {
		return;
	}
	bigendian = bf->o->info->big_endian;
	if (!(r = va2pa(p, &offset, &left, bf))) {
		return;
	}
	if ((r + left) < r || (r + size) < r) {
		return;
	}
	if (r > bf->size) {
		return;
	}
	if (r + size > bf->size) {
		return;
	}
	if (left < size) {
		RZ_LOG_ERROR("Cannot parse obj class info (out of bounds)\n");
		return;
	}
	len = rz_buf_read_at(buf, r, sc, size);
	if (len != size) {
		return;
	}

	i = 0;
	c.isa = rz_read_ble(&sc[i], bigendian, 8 * sizeof(mach0_ut));
	i += sizeof(mach0_ut);
	c.superclass = rz_read_ble(&sc[i], bigendian, 8 * sizeof(mach0_ut));
	i += sizeof(mach0_ut);
	c.cache = rz_read_ble(&sc[i], bigendian, 8 * sizeof(mach0_ut));
	i += sizeof(mach0_ut);
	c.vtable = rz_read_ble(&sc[i], bigendian, 8 * sizeof(mach0_ut));
	i += sizeof(mach0_ut);
	c.data = rz_read_ble(&sc[i], bigendian, 8 * sizeof(mach0_ut));

	klass->addr = c.isa;
	if (relocs) {
		struct reloc_t reloc_at_class_addr;
		reloc_at_class_addr.addr = p + sizeof(mach0_ut);
		RzSkipListNode *found = rz_skiplist_find(relocs, &reloc_at_class_addr);
		if (found) {
			const char *_objc_class = "_OBJC_CLASS_$_";
			const int _objc_class_len = strlen(_objc_class);
			char *target_class_name = (char *)((struct reloc_t *)found->data)->name;
			if (rz_str_startswith(target_class_name, _objc_class)) {
				target_class_name += _objc_class_len;
				klass->super = strdup(target_class_name);
			}
		}
	} else if (c.superclass) {
		klass->super = get_class_name(c.superclass, bf, buf);
	}
	get_class_ro_t(RO_DATA_PTR(c.data), bf, buf, &is_meta_class, klass, oi);

#if SWIFT_SUPPORT
	if (q(c.data + n_value) & 7) {
		RZ_LOG_INFO("This is a Swift class\n");
	}
#endif
	if (!is_meta_class && !dupe) {
		mach0_ut isa_n_value = get_isa_value();
		ut64 tmp = klass->addr;
		MACH0_(get_class_t)
		(c.isa + isa_n_value, bf, buf, klass, true, relocs, oi);
		klass->addr = tmp;
	}
}

#if 0
static RzList *parse_swift_classes(RzBinFile *bf) {
	bool is_swift = false;
	RzBinString *str;
	RzListIter *iter;
	RzBinClass *cls;
	RzList *ret;
	char *lib;

	rz_list_foreach (bf->o->libs, iter, lib) {
		if (strstr (lib, "libswift")) {
			is_swift = true;
			break;
		}
	}
	if (!is_swift) {
		return NULL;
	}

	int idx = 0;
	ret = rz_list_newf (rz_bin_string_free);
	rz_list_foreach (bf->o->strings, iter, str) {
		if (!strncmp (str->string, "_TtC", 4)) {
			char *msg = strdup (str->string + 4);
			cls = RZ_NEW0 (RzBinClass);
			cls->name = strdup (msg);
			cls->super = strdup (msg);
			cls->index = idx++;
			rz_list_append (ret, cls);
			free (msg);
		}
	}
	return ret;
}
#endif

RZ_API RZ_OWN RzPVector /*<RzBinClass *>*/ *MACH0_(parse_classes)(RzBinFile *bf, objc_cache_opt_info *oi) {
	RzPVector /*<RzBinClass *>*/ *ret = NULL;
	ut64 num_of_unnamed_class = 0;
	RzBinClass *klass = NULL;
	ut32 i = 0, size = 0;
	RzList *sctns = NULL;
	bool is_found = false;
	mach0_ut p = 0;
	ut32 left = 0;
	int len;
	ut64 paddr;
	ut64 s_size;
	bool bigendian;
	ut8 pp[sizeof(mach0_ut)] = { 0 };

	rz_return_val_if_fail(bf && bf->o, NULL);

	if (!bf->o->bin_obj || !bf->o->info) {
		return NULL;
	}
	bigendian = bf->o->info->big_endian;
	struct MACH0_(obj_t) *obj = bf->o->bin_obj;

	RzBuffer *buf = obj->buf_patched ? obj->buf_patched : bf->buf;

	RzSkipList *relocs = MACH0_(get_relocs)(bf->o->bin_obj);

	ret = MACH0_(parse_categories)(bf, buf, relocs, oi);

	/* check if it's Swift */
	// ret = parse_swift_classes (bf);

	// sebfing of section with name __objc_classlist

	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections)(bf->o->bin_obj))) {
		return ret;
	}

	for (i = 0; !sections[i].last; i++) {
		if (strstr(sections[i].name, "__objc_classlist")) {
			is_found = true;
			paddr = sections[i].offset;
			s_size = sections[i].size;
			break;
		}
	}

	RZ_FREE(sections);

	if (!is_found) {
		// retain just for debug
		// RZ_LOG_ERROR("there is no section __objc_classlist\n");
		goto get_classes_error;
	}
	// end of seaching of section with name __objc_classlist

	if (!ret && !(ret = rz_pvector_new((RzPVectorFree)rz_bin_class_free))) {
		// retain just for debug
		// RZ_LOG_ERROR("RzList<RzBinClass> allocation error\n");
		goto get_classes_error;
	}
	// start of getting information about each class in file
	for (i = 0; i < s_size; i += sizeof(mach0_ut)) {
		left = s_size - i;
		if (left < sizeof(mach0_ut)) {
			RZ_LOG_ERROR("Truncated classlist data\n");
			break;
		}
		if (!(klass = RZ_NEW0(RzBinClass))) {
			// retain just for debug
			// RZ_LOG_ERROR("RzBinClass allocation error\n");
			goto get_classes_error;
		}
		if (!(klass->methods = rz_list_newf((RzListFree)rz_bin_symbol_free))) {
			// retain just for debug
			// RZ_LOG_ERROR("RzList<RzBinClassField> allocation error\n");
			goto get_classes_error;
		}
		if (!(klass->fields = rz_list_newf((RzListFree)rz_bin_class_field_free))) {
			// retain just for debug
			// RZ_LOG_ERROR("RzList<RzBinSymbol> allocation error\n");
			goto get_classes_error;
		}
		size = sizeof(mach0_ut);
		if (paddr > bf->size || paddr + size > bf->size) {
			goto get_classes_error;
		}
		if (paddr + size < paddr) {
			goto get_classes_error;
		}
		len = rz_buf_read_at(buf, paddr + i, pp, sizeof(mach0_ut));
		if (len != sizeof(mach0_ut)) {
			goto get_classes_error;
		}
		p = rz_read_ble(&pp[0], bigendian, 8 * sizeof(mach0_ut));
		MACH0_(get_class_t)
		(p, bf, buf, klass, false, relocs, oi);
		if (!klass->name) {
			klass->name = rz_str_newf("UnnamedClass%" PFMT64d, num_of_unnamed_class);
			if (!klass->name) {
				goto get_classes_error;
			}
			num_of_unnamed_class++;
		}
		rz_pvector_push(ret, klass);
	}
	return ret;

get_classes_error:
	rz_list_free(sctns);
	rz_pvector_free(ret);
	// XXX DOUBLE FREE rz_bin_class_free (klass);
	return NULL;
}

static RzPVector /*<RzBinClass *>*/ *MACH0_(parse_categories)(RzBinFile *bf, RzBuffer *buf, RzSkipList *relocs, objc_cache_opt_info *oi) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj && bf->o->info, NULL);

	RzPVector /*<RzBinClass>*/ *ret = NULL;
	RzBinObject *obj = bf->o;
	const ut32 ptr_size = sizeof(mach0_ut);
	bool is_found = false;
	ut64 paddr;
	ut64 s_size;

	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections)(obj->bin_obj))) {
		return ret;
	}

	ut32 i = 0;
	for (; !sections[i].last; i++) {
		if (strstr(sections[i].name, "__objc_catlist")) {
			is_found = true;
			paddr = sections[i].offset;
			s_size = sections[i].size;
			break;
		}
	}

	RZ_FREE(sections);

	if (!is_found) {
		goto error;
	}

	if (!ret && !(ret = rz_pvector_new((RzPVectorFree)rz_bin_class_free))) {
		goto error;
	}

	if (!relocs) {
		goto error;
	}

	for (i = 0; i < s_size; i += ptr_size) {
		RzBinClass *klass;
		mach0_ut p;

		if ((s_size - i) < ptr_size) {
			RZ_LOG_ERROR("Truncated catlist data\n");
			break;
		}
		if (!(klass = RZ_NEW0(RzBinClass))) {
			goto error;
		}
		if (!(klass->methods = rz_list_newf((RzListFree)rz_bin_symbol_free))) {
			RZ_FREE(klass);
			goto error;
		}
		if (!(klass->fields = rz_list_newf((RzListFree)rz_bin_class_field_free))) {
			RZ_FREE(klass);
			goto error;
		}
		if (!read_ptr_pa(bf, buf, paddr + i, &p)) {
			RZ_FREE(klass);
			goto error;
		}
		MACH0_(get_category_t)
		(p, bf, buf, klass, relocs, oi);
		if (!klass->name) {
			RZ_FREE(klass);
			continue;
		}
		rz_pvector_push(ret, klass);
	}
	return ret;

error:
	rz_pvector_free(ret);
	return NULL;
}

RZ_API void MACH0_(get_category_t)(mach0_ut p, RzBinFile *bf, RzBuffer *buf, RzBinClass *klass, RzSkipList *relocs, objc_cache_opt_info *oi) {
	rz_return_if_fail(bf && bf->o && bf->o->info);

	struct MACH0_(SCategory) c = { 0 };
	const int size = sizeof(struct MACH0_(SCategory));
	mach0_ut r = 0;
	ut32 offset = 0, left = 0;
	int len;
	bool bigendian = bf->o->info->big_endian;
	ut8 sc[sizeof(struct MACH0_(SCategory))] = { 0 };
	ut32 i;

	if (!(r = va2pa(p, &offset, &left, bf))) {
		return;
	}
	if ((r + left) < r || (r + size) < r) {
		return;
	}
	if (r > bf->size || r + left > bf->size) {
		return;
	}
	if (r + size > bf->size) {
		return;
	}
	if (left < size) {
		RZ_LOG_ERROR("Cannot parse obj category info out of bounds\n");
		return;
	}
	len = rz_buf_read_at(buf, r, sc, size);
	if (len != size) {
		return;
	}

	ut32 ptr_size = sizeof(mach0_ut);
	ut32 bits = 8 * ptr_size;

	i = 0;
	c.name = rz_read_ble(&sc[i], bigendian, bits);
	i += ptr_size;
	c.targetClass = rz_read_ble(&sc[i], bigendian, bits);
	i += ptr_size;
	c.instanceMethods = rz_read_ble(&sc[i], bigendian, bits);
	i += ptr_size;
	c.classMethods = rz_read_ble(&sc[i], bigendian, bits);
	i += ptr_size;
	c.protocols = rz_read_ble(&sc[i], bigendian, bits);
	i += ptr_size;
	c.properties = rz_read_ble(&sc[i], bigendian, bits);

	char *category_name = read_str(bf, buf, c.name, &offset, &left);
	if (!category_name) {
		return;
	}

	char *target_class_name = NULL;
	if (c.targetClass == 0) {
		if (!relocs) {
			RZ_FREE(category_name);
			return;
		}
		struct reloc_t reloc_at_class_addr;
		reloc_at_class_addr.addr = p + ptr_size;
		RzSkipListNode *found = rz_skiplist_find(relocs, &reloc_at_class_addr);
		if (!found) {
			RZ_FREE(category_name);
			return;
		}

		const char *_objc_class = "_OBJC_CLASS_$_";
		const int _objc_class_len = strlen(_objc_class);
		target_class_name = (char *)((struct reloc_t *)found->data)->name;
		if (!rz_str_startswith(target_class_name, _objc_class)) {
			RZ_FREE(category_name);
			return;
		}
		target_class_name += _objc_class_len;
		klass->name = rz_str_newf("%s(%s)", target_class_name, category_name);
	} else {
		mach0_ut ro_data_field = c.targetClass + 4 * ptr_size;
		mach0_ut ro_data;
		if (!read_ptr_va(bf, buf, ro_data_field, &ro_data)) {
			RZ_FREE(category_name);
			return;
		}
		mach0_ut name_field = RO_DATA_PTR(ro_data) + 3 * 4 + ptr_size;
#ifdef RZ_BIN_MACH064
		name_field += 4;
#endif
		mach0_ut name_at;
		if (!read_ptr_va(bf, buf, name_field & ~1, &name_at)) {
			RZ_FREE(category_name);
			return;
		}

		target_class_name = read_str(bf, buf, name_at, &offset, &left);
		char *demangled = NULL;
		if (target_class_name) {
			demangled = demangle_classname(target_class_name);
		}
		klass->name = rz_str_newf("%s(%s)", rz_str_get_null(demangled), category_name);
		RZ_FREE(target_class_name);
		RZ_FREE(demangled);
	}

	klass->addr = p;

	RZ_FREE(category_name);

	if (c.instanceMethods > 0) {
		get_method_list_t(c.instanceMethods, bf, buf, klass->name, klass, false, oi);
	}

	if (c.classMethods > 0) {
		get_method_list_t(c.classMethods, bf, buf, klass->name, klass, true, oi);
	}

	if (c.protocols > 0) {
		get_protocol_list_t(c.protocols, bf, buf, klass, oi);
	}

	if (c.properties > 0) {
		get_objc_property_list(c.properties, bf, buf, klass);
	}
}

static bool read_ptr_pa(RzBinFile *bf, RzBuffer *buf, ut64 paddr, mach0_ut *out) {
	rz_return_val_if_fail(out, false);
	rz_return_val_if_fail(bf && bf->o && bf->o->info, false);

	size_t ptr_size = sizeof(mach0_ut);
	ut8 pp[sizeof(mach0_ut)] = { 0 };

	int len = rz_buf_read_at(buf, paddr, pp, ptr_size);
	if (len != ptr_size) {
		return false;
	}

	mach0_ut p = rz_read_ble(&pp[0], bf->o->info->big_endian, 8 * ptr_size);
	*out = p;

	return true;
}

static bool read_ptr_va(RzBinFile *bf, RzBuffer *buf, ut64 vaddr, mach0_ut *out) {
	rz_return_val_if_fail(bf, false);
	ut32 offset = 0, left = 0;
	mach0_ut paddr = va2pa(vaddr, &offset, &left, bf);
	if (paddr == 0 || left < sizeof(mach0_ut)) {
		return false;
	}
	return read_ptr_pa(bf, buf, paddr, out);
}

static char *read_str(RzBinFile *bf, RzBuffer *buf, mach0_ut p, ut32 *offset, ut32 *left) {
	rz_return_val_if_fail(bf && offset && left, NULL);

	mach0_ut paddr = va2pa(p, offset, left, bf);
	if (paddr == 0 || *left <= 1) {
		return NULL;
	}

	int name_len = RZ_MIN(MAX_CLASS_NAME_LEN, *left);
	char *name = calloc(1, name_len + 1);
	int len = rz_buf_read_at(buf, paddr, (ut8 *)name, name_len);
	if (len < name_len) {
		RZ_LOG_ERROR("Cannot read string\n");
		RZ_FREE(name);
		return NULL;
	}

	return name;
}
