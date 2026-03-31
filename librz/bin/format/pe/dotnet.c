// SPDX-FileCopyrightText: 2022. The YARA Authors. All Rights Reserved.
// SPDX-FileCopyrightText: 2022 wingdeans <wingdeans@protonmail.com>
// SPDX-License-Identifier: Apache-2.0

#include "pe.h"
#include "dotnet.h"
#include <rz_util/rz_alloc.h>

#define MAX_METADATA_STRING_LENGTH 256

static int bin_pe_read_metadata_string(char *to, RzBuffer *frombuf, ut64 fromoff) {
	int covered = 0;
	while (covered < MAX_METADATA_STRING_LENGTH) {
		ut8 covch;
		if (!rz_buf_read8_at(frombuf, fromoff + covered, &covch)) {
			return 0;
		}

		to[covered] = covch;
		if (covch == '\0') {
			covered += 1;
			break;
		}
		covered++;
	}
	while (covered % 4 != 0) {
		covered++;
	}
	return covered;
}

static void _free_stream(Pe_image_metadata_stream *stream) {
	if (!stream) {
		return;
	}
	free(stream->Name);
	free(stream);
}

static ut32 clr_max_rows(int count, ...) {
	va_list ap;
	int i;
	ut32 biggest;
	ut32 x;

	if (count == 0) {
		return 0;
	}

	va_start(ap, count);
	biggest = va_arg(ap, uint32_t);

	for (i = 1; i < count; i++) {
		x = va_arg(ap, uint32_t);
		biggest = (x > biggest) ? x : biggest;
	}

	va_end(ap);
	return biggest;
}

static int read_image_metadata_tilde_header(RzBuffer *b, ut64 addr, Pe_image_clr *clr) {
	Pe_image_metadata_tilde_header *tilde = clr->tilde;

	st64 o_addr = rz_buf_tell(b);
	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return -1;
	}

	// Header structure
	ut8 buf[(32 + (8 * 4) + 64 + 64) / 8];
	if (!rz_buf_read(b, buf, sizeof(buf))) {
		return -1;
	}
	PE_READ_STRUCT_FIELD(tilde, Pe_image_metadata_tilde_header, Reserved1, 32);
	PE_READ_STRUCT_FIELD(tilde, Pe_image_metadata_tilde_header, MajorVersion, 8);
	PE_READ_STRUCT_FIELD(tilde, Pe_image_metadata_tilde_header, MinorVersion, 8);
	PE_READ_STRUCT_FIELD(tilde, Pe_image_metadata_tilde_header, HeapSizes, 8);
	PE_READ_STRUCT_FIELD(tilde, Pe_image_metadata_tilde_header, Reserved2, 8);
	PE_READ_STRUCT_FIELD(tilde, Pe_image_metadata_tilde_header, Valid, 64);
	PE_READ_STRUCT_FIELD(tilde, Pe_image_metadata_tilde_header, Sorted, 64);

	// Row counts
	ut8 rowcountbuf[sizeof(ut32)];
	Pe_image_metadata_tilde_rowcounts *rowcounts = RZ_NEW0(Pe_image_metadata_tilde_rowcounts);
	if (!rowcounts) {
		return -1;
	}

	Pe_image_metadata_index_sizes index_sizes;
	memset(&index_sizes, 2, sizeof(index_sizes));

	// Default index sizes are 2. Will be bumped to 4 if necessary.
	if (tilde->HeapSizes & 0x01) {
		index_sizes.string = 4;
	}
	if (tilde->HeapSizes & 0x02) {
		index_sizes.guid = 4;
	}
	if (tilde->HeapSizes & 0x04) {
		index_sizes.blob = 4;
	}

	// This is used as an offset into the rows and tables. For every bit set in
	// Valid this will be incremented. This is because the bit position doesn't
	// matter, just the number of bits that are set, when determining how many
	// rows and what the table structure is.

	for (int bit_check = 0; bit_check < 64; ++bit_check) {
		if (!((tilde->Valid >> bit_check) & 0x1)) {
			continue;
		}

		if (!rz_buf_read(b, rowcountbuf, sizeof(rowcountbuf))) { // Read row count
			goto error;
		}

#define ROW_READ(name) \
	rowcounts->name = rz_read_le32(rowcountbuf);

#define ROW_READ_WITH_INDEX(name) \
	ROW_READ(name); \
	if (rowcounts->name > 0xFFFF) { \
		index_sizes.name = 4; \
	}

		switch (bit_check) {
		case BIT_MODULE:
			ROW_READ(module)
			break;
		case BIT_TYPEREF:
			ROW_READ(typeref);
			break;
		case BIT_TYPEDEF:
			ROW_READ_WITH_INDEX(typedef_);
			break;
		case BIT_FIELDPTR:
			ROW_READ(fieldptr);
			break;
		case BIT_FIELD:
			ROW_READ_WITH_INDEX(field);
			break;
		case BIT_METHODDEFPTR:
			ROW_READ(methoddef);
			break;
		case BIT_METHODDEF:
			ROW_READ_WITH_INDEX(methoddef);
			break;
		case BIT_PARAM:
			ROW_READ_WITH_INDEX(param);
			break;
		case BIT_INTERFACEIMPL:
			ROW_READ(interfaceimpl);
			break;
		case BIT_MEMBERREF:
			ROW_READ_WITH_INDEX(memberref);
			break;
		case BIT_CONSTANT:
			ROW_READ(constant);
			break;
		case BIT_CUSTOMATTRIBUTE:
			ROW_READ(customattribute);
			break;
		case BIT_FIELDMARSHAL:
			ROW_READ(fieldmarshal);
			break;
		case BIT_DECLSECURITY:
			ROW_READ(declsecurity);
			break;
		case BIT_CLASSLAYOUT:
			ROW_READ(classlayout);
			break;
		case BIT_FIELDLAYOUT:
			ROW_READ(fieldlayout);
			break;
		case BIT_STANDALONESIG:
			ROW_READ(standalonesig);
			break;
		case BIT_EVENTMAP:
			ROW_READ(eventmap);
			break;
		case BIT_EVENTPTR:
			ROW_READ(eventptr);
			break;
		case BIT_EVENT:
			ROW_READ_WITH_INDEX(event);
			break;
		case BIT_PROPERTYMAP:
			ROW_READ(propertymap);
			break;
		case BIT_PROPERTYPTR:
			ROW_READ(propertyptr);
			break;
		case BIT_PROPERTY:
			ROW_READ_WITH_INDEX(property);
			break;
		case BIT_METHODSEMANTICS:
			ROW_READ(methodsemantics);
			break;
		case BIT_METHODIMPL:
			ROW_READ(methodimpl);
			break;
		case BIT_MODULEREF:
			ROW_READ_WITH_INDEX(moduleref);
			break;
		case BIT_TYPESPEC:
			ROW_READ(typespec);
			break;
		case BIT_IMPLMAP:
			ROW_READ(implmap);
			break;
		case BIT_FIELDRVA:
			ROW_READ(fieldrva);
			break;
		case BIT_ENCLOG:
			ROW_READ(enclog);
			break;
		case BIT_ENCMAP:
			ROW_READ(encmap);
			break;
		case BIT_ASSEMBLY:
			ROW_READ(assembly);
			break;
		case BIT_ASSEMBLYPROCESSOR:
			ROW_READ(assemblyprocessor);
			break;
		case BIT_ASSEMBLYOS:
			ROW_READ(assemblyos);
			break;
		case BIT_ASSEMBLYREF:
			ROW_READ_WITH_INDEX(assemblyref);
			break;
		case BIT_ASSEMBLYREFPROCESSOR:
			ROW_READ_WITH_INDEX(assemblyrefprocessor);
			break;
		case BIT_ASSEMBLYREFOS:
			ROW_READ(assemblyrefos);
			break;
		case BIT_FILE:
			ROW_READ(file);
			break;
		case BIT_EXPORTEDTYPE:
			ROW_READ(exportedtype);
			break;
		case BIT_MANIFESTRESOURCE:
			ROW_READ(manifestresource);
			break;
		case BIT_NESTEDCLASS:
			ROW_READ(nestedclass);
			break;
		case BIT_GENERICPARAM:
			ROW_READ_WITH_INDEX(genericparam);
			break;
		case BIT_METHODSPEC:
			ROW_READ(methodspec);
			break;
		case BIT_GENERICPARAMCONSTRAINT:
			ROW_READ(genericparamconstraint);
			break;
		default:
			break;
		}
	}

	// Now walk again this time parsing out what we care about
	for (int bit_check = 0; bit_check < 64; ++bit_check) {
		if (!((tilde->Valid >> bit_check) & 0x1)) {
			continue;
		}

#define TRY_SEEK(rowsize, rowcountname) \
	if (rz_buf_seek(b, (rowsize) * (st64)rowcounts->rowcountname, RZ_BUF_CUR) < 0) { \
		RZ_LOG_WARN("seeking #rowcountname (size %d)\n", rowsize); \
		goto error; \
	}

#define READ_BUF_INDEX_SIZE(var, index_size) \
	var = ((index_size) == 2) ? rz_read_le16(buf) : rz_read_le32(buf); \
	buf += (index_size);

#define INDEX_SIZE_FROM_TAG(name, tag_size) \
	ut32 name = (index_count > (0xFFFF >> (tag_size))) ? 4 : 2;

		// Those tables which exist, but that we don't care about must be
		// skipped.
		//
		// Sadly, given the dynamic sizes of some columns we can not have well
		// defined structures for all tables and use them accordingly. To deal
		// with this manually move the table_offset pointer by the appropriate
		// number of bytes as described in the documentation for each table.
		//
		// The table structures are documented in ECMA-335 Section II.22.

		switch (bit_check) {
		case BIT_MODULE:
			TRY_SEEK(2 + index_sizes.string +
					(index_sizes.guid * 3),
				module)

			break;

		case BIT_TYPEREF: {
			ut32 index_count = clr_max_rows(4,
				rowcounts->module,
				rowcounts->moduleref,
				rowcounts->assemblyref,
				rowcounts->typeref);
			INDEX_SIZE_FROM_TAG(index_size, 2)

			TRY_SEEK(index_size + (index_sizes.string * 2), typeref);
			break;
		}

		case BIT_TYPEDEF: {
			ut32 index_count = clr_max_rows(3,
				rowcounts->typedef_,
				rowcounts->typeref,
				rowcounts->typespec);
			INDEX_SIZE_FROM_TAG(index_size, 2)

			ut32 rowsize = 4 + (index_sizes.string * 2) +
				index_size + index_sizes.field +
				index_sizes.methoddef;
			ut32 rowcount = rowcounts->typedef_;

			ut8 *rows = calloc(rowcount, rowsize);
			if (!rz_buf_read(b, rows, (st64)rowsize * rowcount)) {
				free(rows);
				goto error;
			}

			ut8 *buf = rows;
			for (int i = 0; i < rowcount; ++i) {
				Pe_image_metadata_typedef *typedef_ = RZ_NEW0(Pe_image_metadata_typedef);

				PE_READ_STRUCT_FIELD(typedef_, Pe_image_metadata_typedef, flags, 32);
				buf += 4;

				READ_BUF_INDEX_SIZE(typedef_->name, index_sizes.string);
				READ_BUF_INDEX_SIZE(typedef_->namespace, index_sizes.string);

				READ_BUF_INDEX_SIZE(typedef_->extends, index_size)
				READ_BUF_INDEX_SIZE(typedef_->fieldlist, index_sizes.field)
				READ_BUF_INDEX_SIZE(typedef_->methodlist, index_sizes.methoddef)

				rz_list_append(clr->typedefs, typedef_);
			}
			free(rows);
			break;
		}

		case BIT_FIELDPTR:
			// This one is not documented in ECMA-335.
			TRY_SEEK(index_sizes.field, fieldptr)
			break;

		case BIT_FIELD:
			TRY_SEEK(2 + (index_sizes.string) +
					index_sizes.blob,
				field)
			break;

		case BIT_METHODDEFPTR:
			// This one is not documented in ECMA-335.
			TRY_SEEK(index_sizes.methoddef, methoddefptr)
			break;

		case BIT_METHODDEF: {
			ut32 rowsize = 4 + 2 + 2 + index_sizes.string +
				index_sizes.blob + index_sizes.param;
			ut32 rowcount = rowcounts->methoddef;

			ut8 *rows = calloc(rowcount, rowsize);
			if (!rz_buf_read(b, rows, (st64)rowsize * rowcount)) {
				free(rows);
				goto error;
			}

			ut8 *buf = rows;
			for (int i = 0; i < rowcount; ++i) {
				Pe_image_metadata_methoddef *methoddef = RZ_NEW0(Pe_image_metadata_methoddef);

				PE_READ_STRUCT_FIELD(methoddef, Pe_image_metadata_methoddef, rva, 32);
				PE_READ_STRUCT_FIELD(methoddef, Pe_image_metadata_methoddef, implflags, 16);
				PE_READ_STRUCT_FIELD(methoddef, Pe_image_metadata_methoddef, flags, 16);
				buf += 4 + 2 + 2;

				READ_BUF_INDEX_SIZE(methoddef->name, index_sizes.string)
				READ_BUF_INDEX_SIZE(methoddef->signature, index_sizes.blob)
				READ_BUF_INDEX_SIZE(methoddef->paramlist, index_sizes.param)

				rz_pvector_push(clr->methoddefs, methoddef);
			}
			free(rows);
			break;
		}

		case BIT_PARAM:
			TRY_SEEK(2 + 2 + index_sizes.string, param)
			break;

		case BIT_INTERFACEIMPL: {
			ut32 index_count = clr_max_rows(3,
				rowcounts->typedef_,
				rowcounts->typeref,
				rowcounts->typespec);
			INDEX_SIZE_FROM_TAG(index_size, 2)

			TRY_SEEK(index_sizes.typedef_ + index_size, interfaceimpl)
			break;
		}

		case BIT_MEMBERREF: {
			ut32 index_count = clr_max_rows(4,
				rowcounts->methoddef,
				rowcounts->moduleref,
				rowcounts->typeref,
				rowcounts->typespec);
			INDEX_SIZE_FROM_TAG(index_size, 3)

			TRY_SEEK(index_size + index_sizes.string +
					index_sizes.blob,
				memberref)
			break;
		}

		case BIT_CONSTANT: {
			ut32 index_count = clr_max_rows(3,
				rowcounts->param,
				rowcounts->field,
				rowcounts->property);
			INDEX_SIZE_FROM_TAG(index_size, 2)

			ut32 row_size = 1 + 1 + index_size + index_sizes.blob;

			TRY_SEEK(row_size, constant)
			break;
		}

		case BIT_CUSTOMATTRIBUTE: {
			// index_size is size of the parent column.
			ut32 index_count = clr_max_rows(21,
				rowcounts->methoddef,
				rowcounts->field,
				rowcounts->typeref,
				rowcounts->typedef_,
				rowcounts->param,
				rowcounts->interfaceimpl,
				rowcounts->memberref,
				rowcounts->module,
				rowcounts->property,
				rowcounts->event,
				rowcounts->standalonesig,
				rowcounts->moduleref,
				rowcounts->typespec,
				rowcounts->assembly,
				rowcounts->assemblyref,
				rowcounts->file,
				rowcounts->exportedtype,
				rowcounts->manifestresource,
				rowcounts->genericparam,
				rowcounts->genericparamconstraint,
				rowcounts->methodspec);
			INDEX_SIZE_FROM_TAG(index_size, 5)

			// index_size2 is size of the type column.
			index_count = clr_max_rows(2,
				rowcounts->methoddef,
				rowcounts->memberref);
			ut32 index_size2 = (index_count > (0xFFFF >> 0x03)) ? 4 : 2;

			ut32 row_size = (index_size + index_size2 + index_sizes.blob);

			TRY_SEEK(row_size, customattribute)
			break;
		}

		case BIT_FIELDMARSHAL: {
			ut32 index_count = clr_max_rows(2,
				rowcounts->field,
				rowcounts->param);
			INDEX_SIZE_FROM_TAG(index_size, 1)

			TRY_SEEK(index_size + index_sizes.blob, fieldmarshal)
			break;
		}

		case BIT_DECLSECURITY: {
			ut32 index_count = clr_max_rows(3,
				rowcounts->typedef_,
				rowcounts->methoddef,
				rowcounts->assembly);
			INDEX_SIZE_FROM_TAG(index_size, 2)

			TRY_SEEK(2 + index_size + index_sizes.blob, declsecurity)
			break;
		}

		case BIT_CLASSLAYOUT:
			TRY_SEEK(2 + 4 + index_sizes.typedef_, classlayout)
			break;

		case BIT_FIELDLAYOUT:
			TRY_SEEK(4 + index_sizes.field, fieldlayout)
			break;

		case BIT_STANDALONESIG:
			TRY_SEEK(index_sizes.blob, fieldlayout)
			break;

		case BIT_EVENTMAP:
			TRY_SEEK(index_sizes.typedef_ + index_sizes.event, eventmap)
			break;

		case BIT_EVENTPTR:
			// This one is not documented in ECMA-335.
			TRY_SEEK(index_sizes.event, eventptr)
			break;

		case BIT_EVENT: {
			ut32 index_count = clr_max_rows(3,
				rowcounts->typedef_,
				rowcounts->typeref,
				rowcounts->typespec);
			INDEX_SIZE_FROM_TAG(index_size, 2)

			TRY_SEEK(2 + index_sizes.string + index_size, event)
			break;
		}

		case BIT_PROPERTYMAP:
			TRY_SEEK(index_sizes.typedef_ + index_sizes.property, propertymap)
			break;

		case BIT_PROPERTYPTR:
			// This one is not documented in ECMA-335.
			TRY_SEEK(index_sizes.property, propertyptr)
			break;

		case BIT_PROPERTY:
			TRY_SEEK(2 + index_sizes.string + index_sizes.blob, property)
			break;

		case BIT_METHODSEMANTICS: {
			ut32 index_count = clr_max_rows(2,
				rowcounts->event,
				rowcounts->property);
			INDEX_SIZE_FROM_TAG(index_size, 1)

			TRY_SEEK(2 + index_sizes.methoddef + index_size, methodsemantics)
			break;
		}

		case BIT_METHODIMPL: {
			ut32 index_count = clr_max_rows(2,
				rowcounts->methoddef,
				rowcounts->memberref);
			INDEX_SIZE_FROM_TAG(index_size, 1)

			TRY_SEEK(index_sizes.typedef_ + (index_size * 2), methodimpl)
			break;
		}

		case BIT_MODULEREF: {
			TRY_SEEK(index_sizes.string, moduleref)
			break;
		}

		case BIT_TYPESPEC:
			TRY_SEEK(index_sizes.blob, typespec)
			break;

		case BIT_IMPLMAP: {
			ut32 index_count = clr_max_rows(2,
				rowcounts->field,
				rowcounts->methoddef);
			INDEX_SIZE_FROM_TAG(index_size, 1)

			TRY_SEEK(2 + index_size + index_sizes.string +
					index_sizes.moduleref,
				implmap)
			break;
		}

		case BIT_FIELDRVA: {
			ut32 row_size = 4 + index_sizes.field;

			TRY_SEEK(row_size, fieldrva)
			break;
		}

		case BIT_ENCLOG:
			TRY_SEEK(4 + 4, enclog)
			break;

		case BIT_ENCMAP:
			TRY_SEEK(4, encmap)
			break;

		case BIT_ASSEMBLY: {
			ut32 row_size = (4 + 2 + 2 + 2 + 2 + 4 + index_sizes.blob +
				(index_sizes.string * 2));

			TRY_SEEK(row_size, assembly)
			break;
		}

		case BIT_ASSEMBLYPROCESSOR:
			TRY_SEEK(4, assemblyprocessor)
			break;

		case BIT_ASSEMBLYOS:
			TRY_SEEK(4 + 4 + 4, assemblyos)
			break;

		case BIT_ASSEMBLYREF: {
			ut32 row_size = (2 + 2 + 2 + 2 + 4 +
				(index_sizes.blob * 2) +
				(index_sizes.string * 2));

			TRY_SEEK(row_size, assemblyref)
			break;
		}

		case BIT_ASSEMBLYREFPROCESSOR:
			TRY_SEEK(4 + index_sizes.assemblyrefprocessor, assemblyrefprocessor)
			break;

		case BIT_ASSEMBLYREFOS:
			TRY_SEEK(4 + 4 + 4 + index_sizes.assemblyref, assemblyrefos)
			break;

		case BIT_FILE:
			TRY_SEEK(4 + index_sizes.string + index_sizes.blob, file)
			break;

		case BIT_EXPORTEDTYPE: {
			ut32 index_count = clr_max_rows(3,
				rowcounts->file,
				rowcounts->assemblyref,
				rowcounts->exportedtype);
			INDEX_SIZE_FROM_TAG(index_size, 2)

			TRY_SEEK(4 + 4 + (index_sizes.string * 2) + index_size, exportedtype)
			break;
		}

		case BIT_MANIFESTRESOURCE: {
			// This is an Implementation coded index with no 3rd bit specified.
			ut32 index_count = clr_max_rows(2,
				rowcounts->file,
				rowcounts->assemblyref);
			INDEX_SIZE_FROM_TAG(index_size, 2)

			ut32 row_size = (4 + 4 + index_sizes.string + index_size);

			TRY_SEEK(row_size, manifestresource)
			break;
		}

		case BIT_NESTEDCLASS:
			TRY_SEEK(index_sizes.typedef_ * 2, nestedclass)
			break;

		case BIT_GENERICPARAM: {
			ut32 index_count = clr_max_rows(2,
				rowcounts->typedef_,
				rowcounts->methoddef);
			INDEX_SIZE_FROM_TAG(index_size, 1)

			TRY_SEEK(2 + 2 + index_size + index_sizes.string, genericparam)
			break;
		}

		case BIT_METHODSPEC: {
			ut32 index_count = clr_max_rows(2,
				rowcounts->methoddef,
				rowcounts->memberref);
			INDEX_SIZE_FROM_TAG(index_size, 1)

			TRY_SEEK(index_size + index_sizes.blob, methodspec)
			break;
		}

		case BIT_GENERICPARAMCONSTRAINT: {
			ut32 index_count = clr_max_rows(3,
				rowcounts->typedef_,
				rowcounts->typeref,
				rowcounts->typespec);
			INDEX_SIZE_FROM_TAG(index_size, 2)

			TRY_SEEK(index_sizes.genericparam + index_size, genericparamconstraint)
			break;
		}

		default:
			RZ_LOG_WARN("Unknown bit in metatable: %i\n", bit_check);
			goto error;
		}
	}

	free(rowcounts);
	rz_buf_seek(b, o_addr, RZ_BUF_SET);
	return 0;

error:
	free(rowcounts);
	rz_buf_seek(b, o_addr, RZ_BUF_SET);
	return -1;
}

static int read_image_clr_header(RzBuffer *b, ut64 addr, Pe_image_clr_header *header) {
	st64 o_addr = rz_buf_tell(b);
	if (rz_buf_seek(b, addr, RZ_BUF_SET) < 0) {
		return -1;
	}
	ut8 buf[sizeof(Pe_image_clr_header)];
	rz_buf_read(b, buf, sizeof(buf));
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, HeaderSize, 32);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, MajorRuntimeVersion, 16);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, MinorRuntimeVersion, 16);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, MetaDataDirectoryAddress, 32);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, MetaDataDirectorySize, 32);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, Flags, 32);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, EntryPointToken, 32);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, ResourcesDirectoryAddress, 32);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, ResourcesDirectorySize, 32);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, StrongNameSignatureAddress, 32);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, StrongNameSignatureSize, 32);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, CodeManagerTableAddress, 32);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, CodeManagerTableSize, 32);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, VTableFixupsAddress, 32);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, VTableFixupsSize, 32);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, ExportAddressTableJumpsAddress, 32);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, ExportAddressTableJumpsSize, 32);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, ManagedNativeHeaderAddress, 32);
	PE_READ_STRUCT_FIELD(header, Pe_image_clr_header, ManagedNativeHeaderSize, 32);
	rz_buf_seek(b, o_addr, RZ_BUF_SET);
	return sizeof(Pe_image_clr_header);
}

int bin_pe_dotnet_read_method_header(Pe_image_clr *clr, RzBuffer *b, RzBinSymbol *sym) {
	st64 o_addr = rz_buf_tell(b);
	if (rz_buf_seek(b, sym->paddr, RZ_BUF_SET) < 0) {
		return -1;
	}

	ut8 buf[sizeof(Pe_image_clr_methodheader)];
	if (!rz_buf_read8(b, buf)) {
		return -1;
	}

	if ((buf[0] & 0x03) == 0x02) { // Tiny
		sym->paddr += 1;
		sym->vaddr += 1;
		sym->size = buf[0] >> 2;
	} else if ((buf[0] & 0x03) == 0x03) { // Fat
		rz_buf_read(b, buf + 1, sizeof(Pe_image_clr_methodheader) - 1);
		Pe_image_clr_methodheader methodheader;
		PE_READ_STRUCT_FIELD((&methodheader), Pe_image_clr_methodheader, flags, 16);
		PE_READ_STRUCT_FIELD((&methodheader), Pe_image_clr_methodheader, maxstack, 16);
		PE_READ_STRUCT_FIELD((&methodheader), Pe_image_clr_methodheader, size, 32);
		PE_READ_STRUCT_FIELD((&methodheader), Pe_image_clr_methodheader, tok, 32);

		rz_warn_if_fail(methodheader.flags >> 12 == 3); // top 4 bits indicate size
		sym->paddr += 12;
		sym->vaddr += 12;
		sym->size = methodheader.size;

		// TODO: exception sections
	} else {
		rz_warn_if_reached();
	}

	rz_buf_seek(b, o_addr, RZ_BUF_SET);
	return 0;
}

// Entrypoint
int bin_pe_dotnet_init_metadata(Pe_image_clr *clr, bool big_endian, RzBuffer *b, ut64 metadata_directory) {
	Pe_image_metadata_header *metadata = RZ_NEW0(Pe_image_metadata_header);
	if (!metadata) {
		return -1;
	}
	if (!metadata_directory) {
		free(metadata);
		return -1;
	}

	int rr = rz_buf_fread_at(b, metadata_directory,
		(ut8 *)metadata, big_endian ? "1I2S" : "1i2s", 1);
	if (rr < 1) {
		goto fail;
	}

	rr = rz_buf_fread_at(b, metadata_directory + 8,
		(ut8 *)(&metadata->Reserved), big_endian ? "1I" : "1i", 1);
	if (rr < 1) {
		goto fail;
	}

	rr = rz_buf_fread_at(b, metadata_directory + 12,
		(ut8 *)(&metadata->VersionStringLength), big_endian ? "1I" : "1i", 1);
	if (rr < 1) {
		goto fail;
	}

	// read the version string
	int len = metadata->VersionStringLength; // XXX: dont trust this length
	if (len > 0) {
		metadata->VersionString = calloc(1, len + 1);
		if (!metadata->VersionString) {
			goto fail;
		}

		rr = rz_buf_read_at(b, metadata_directory + 16, (ut8 *)(metadata->VersionString), len);
		if (rr != len) {
			RZ_LOG_WARN("read (metadata header) - cannot parse version string\n");
			free(metadata->VersionString);
			free(metadata);
			return -1;
		}
	}

	// read the header after the string
	rr = rz_buf_fread_at(b, metadata_directory + 16 + metadata->VersionStringLength,
		(ut8 *)(&metadata->Flags), big_endian ? "2S" : "2s", 1);

	if (rr < 1) {
		goto fail;
	}

	clr->metadata_header = metadata;

	// read metadata streams
	int start_of_stream = metadata_directory + 20 + metadata->VersionStringLength;
	Pe_image_metadata_stream *stream;
	RzList *streams = rz_list_newf((RzListFree)_free_stream);
	if (!streams) {
		goto fail;
	}
	int count = 0;

	while (count < metadata->NumberOfStreams) {
		stream = RZ_NEW0(Pe_image_metadata_stream);
		if (!stream) {
			rz_list_free(streams);
			goto fail;
		}

		if (rz_buf_fread_at(b, start_of_stream, (ut8 *)stream, big_endian ? "2I" : "2i", 1) < 1) {
			free(stream);
			rz_list_free(streams);
			goto fail;
		}
		char *stream_name = calloc(1, MAX_METADATA_STRING_LENGTH + 1);

		if (!stream_name) {
			free(stream);
			rz_list_free(streams);
			goto fail;
		}

		if (rz_buf_size(b) < (start_of_stream + 8 + MAX_METADATA_STRING_LENGTH)) {
			free(stream_name);
			free(stream);
			rz_list_free(streams);
			goto fail;
		}
		int c = bin_pe_read_metadata_string(stream_name, b, start_of_stream + 8);
		if (c == 0) {
			free(stream_name);
			free(stream);
			rz_list_free(streams);
			goto fail;
		}

		stream->Name = stream_name;
		rz_list_append(streams, stream);
		start_of_stream += 8 + c;
		count += 1;

		// save special streams
		if (strncmp(stream_name, "#Strings", 8) == 0 && clr->strings_stream == NULL) {
			clr->strings_stream = stream;
		} else if (strncmp(stream_name, "#~", 2) == 0 && clr->tilde_stream == NULL) {
			clr->tilde_stream = stream;
		} else if (strncmp(stream_name, "#Blob", 5) == 0) {
			clr->blob_stream = stream;
		}
	}
	clr->streams = streams;

	if (clr->strings_stream) {
		RzBuffer *strings = rz_buf_new_slice(b, metadata_directory + clr->strings_stream->Offset, clr->strings_stream->Size);
		if (!strings) {
			return -1;
		}
		clr->strings = strings;
	}

	if (clr->tilde_stream && clr->blob_stream && clr->strings) {
		clr->methoddefs = rz_pvector_new(free);
		clr->typedefs = rz_list_newf(free);
		if (!clr->methoddefs || !clr->typedefs) {
			goto fail;
		}

		Pe_image_metadata_tilde_header *tilde = RZ_NEW0(Pe_image_metadata_tilde_header);
		if (!tilde) {
			goto fail;
		}

		clr->tilde = tilde;
		if (read_image_metadata_tilde_header(b, metadata_directory + clr->tilde_stream->Offset, clr)) {
			RZ_LOG_WARN("read (metadata tilde header)\n");
			goto fail;
		}
	}

	return -1;
fail:
	RZ_LOG_WARN("read (metadata header)\n");
	free(metadata);
	clr->metadata_header = NULL;
	return 0;
}

int bin_pe_dotnet_init_clr(Pe_image_clr *clr, RzBuffer *b, ut64 image_clr_hdr_paddr) {
	Pe_image_clr_header *header = RZ_NEW0(Pe_image_clr_header);
	if (!header) {
		goto error;
	}
	clr->header = header;

	int rr, len = sizeof(Pe_image_clr_header);

	rr = read_image_clr_header(b, image_clr_hdr_paddr, header);

	// probably not a .NET binary
	// 64bit?
	if (header->HeaderSize != 0x48) {
		goto error;
	}
	if (rr != len) {
		goto error;
	}
	return 0;

error:
	free(header);
	free(clr);
	return -1;
}

// Cleanup
static void free_metadata_header(Pe_image_metadata_header *metadata) {
	if (!metadata) {
		return;
	}
	free(metadata->VersionString);
	free(metadata);
}

void bin_pe_dotnet_destroy_clr(Pe_image_clr *clr) {
	if (!clr) {
		return;
	}
	free(clr->header);
	free(clr->tilde);
	free_metadata_header(clr->metadata_header);
	rz_list_free(clr->streams);
	rz_buf_free(clr->strings);

	rz_pvector_free(clr->methoddefs);
	rz_list_free(clr->typedefs);

	free(clr);
}
