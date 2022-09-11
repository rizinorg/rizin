// SPDX-FileCopyrightText: 2022. The YARA Authors. All Rights Reserved.
// SPDX-FileCopyrightText: 2022 wingdeans <wingdeans@protonmail.com>
// SPDX-License-Identifier: Apache-2.0

#include <rz_types.h>
#include <rz_vector.h>

#ifndef _INCLUDE_RZ_BIN_DOTNET_H_
#define _INCLUDE_RZ_BIN_DOTNET_H_

typedef struct {
	ut32 HeaderSize;
	ut16 MajorRuntimeVersion;
	ut16 MinorRuntimeVersion;
	ut32 MetaDataDirectoryAddress;
	ut32 MetaDataDirectorySize;
	ut32 Flags;
	ut32 EntryPointToken;
	ut32 ResourcesDirectoryAddress;
	ut32 ResourcesDirectorySize;
	ut32 StrongNameSignatureAddress;
	ut32 StrongNameSignatureSize;
	ut32 CodeManagerTableAddress;
	ut32 CodeManagerTableSize;
	ut32 VTableFixupsAddress;
	ut32 VTableFixupsSize;
	ut32 ExportAddressTableJumpsAddress;
	ut32 ExportAddressTableJumpsSize;
	ut32 ManagedNativeHeaderAddress;
	ut32 ManagedNativeHeaderSize;
} Pe_image_clr_header;

typedef struct {
	ut64 Signature;
	ut16 MajorVersion;
	ut16 MinorVersion;
	ut32 Reserved;
	ut32 VersionStringLength;
	char *VersionString;
	ut16 Flags;
	ut16 NumberOfStreams;
} Pe_image_metadata_header;

typedef struct {
	ut32 Offset;
	ut32 Size;
	char *Name;
} Pe_image_metadata_stream;

// Used to store the number of rows of each table.
typedef struct {
	ut32 module;
	ut32 typeref;
	ut32 typedef_;
	ut32 fieldptr;
	ut32 field;
	ut32 methoddefptr;
	ut32 methoddef;
	ut32 param;
	ut32 interfaceimpl;
	ut32 memberref;
	ut32 constant;
	ut32 customattribute;
	ut32 fieldmarshal;
	ut32 declsecurity;
	ut32 classlayout;
	ut32 fieldlayout;
	ut32 standalonesig;
	ut32 eventmap;
	ut32 eventptr;
	ut32 event;
	ut32 propertymap;
	ut32 propertyptr;
	ut32 property;
	ut32 methodsemantics;
	ut32 methodimpl;
	ut32 moduleref;
	ut32 typespec;
	ut32 implmap;
	ut32 fieldrva;
	ut32 enclog;
	ut32 encmap;
	ut32 assembly;
	ut32 assemblyprocessor;
	ut32 assemblyos;
	ut32 assemblyref;
	ut32 assemblyrefprocessor;
	ut32 assemblyrefos;
	ut32 file;
	ut32 exportedtype;
	ut32 manifestresource;
	ut32 nestedclass;
	ut32 genericparam;
	ut32 methodspec;
	ut32 genericparamconstraint;
} Pe_image_metadata_tilde_rowcounts;

typedef struct {
	ut32 Reserved1;
	ut8 MajorVersion;
	ut8 MinorVersion;
	ut8 HeapSizes;
	ut8 Reserved2;
	ut64 Valid;
	ut64 Sorted;
} Pe_image_metadata_tilde_header;

typedef struct {
	ut8 string;
	ut8 guid;
	ut8 blob;
	ut8 field;
	ut8 methoddef;
	ut8 memberref;
	ut8 param;
	ut8 event;
	ut8 typedef_;
	ut8 property;
	ut8 moduleref;
	ut8 assemblyrefprocessor;
	ut8 assemblyref;
	ut8 genericparam;
} Pe_image_metadata_index_sizes;

typedef struct {
	ut32 rva;
	ut16 implflags;
	ut16 flags;
	ut32 name;
	ut32 signature;
	ut32 paramlist;
} Pe_image_metadata_methoddef;

typedef struct {
	ut32 flags;
	ut32 name;
	ut32 namespace;
	ut32 extends;
	ut32 fieldlist;
	ut32 methodlist;
} Pe_image_metadata_typedef;

typedef struct {
	ut16 flags;
	ut16 maxstack;
	ut32 size;
	ut32 tok;
} Pe_image_clr_methodheader;

typedef struct {
	Pe_image_clr_header *header;
	Pe_image_metadata_header *metadata_header;
	RzList /*<Pe_image_metadata_stream *>*/ *streams;

	// special streams
	Pe_image_metadata_stream *tilde_stream;
	Pe_image_metadata_stream *strings_stream;
	Pe_image_metadata_stream *blob_stream;

	// header data
	Pe_image_metadata_tilde_header *tilde;
	RzBuffer *strings;
	RzPVector /*<Pe_image_metadata_methoddef *>*/ *methoddefs;
	RzList /*<Pe_image_metadata_typedef *>*/ *typedefs;
} Pe_image_clr;

int bin_pe_dotnet_init_metadata(Pe_image_clr *clr, bool big_endian, RzBuffer *b, ut64 metadata_directory);
int bin_pe_dotnet_init_clr(Pe_image_clr *clr, RzBuffer *b, ut64 image_clr_hdr_paddr);
void bin_pe_dotnet_destroy_clr(Pe_image_clr *clr);
int bin_pe_dotnet_read_method_header(Pe_image_clr *clr, RzBuffer *b, RzBinSymbol *sym);

// These are the bit positions in Valid which will be set if the table
// exists.
#define BIT_MODULE                 0x00
#define BIT_TYPEREF                0x01
#define BIT_TYPEDEF                0x02
#define BIT_FIELDPTR               0x03 // Not documented in ECMA-335
#define BIT_FIELD                  0x04
#define BIT_METHODDEFPTR           0x05 // Not documented in ECMA-335
#define BIT_METHODDEF              0x06
#define BIT_PARAMPTR               0x07 // Not documented in ECMA-335
#define BIT_PARAM                  0x08
#define BIT_INTERFACEIMPL          0x09
#define BIT_MEMBERREF              0x0A
#define BIT_CONSTANT               0x0B
#define BIT_CUSTOMATTRIBUTE        0x0C
#define BIT_FIELDMARSHAL           0x0D
#define BIT_DECLSECURITY           0x0E
#define BIT_CLASSLAYOUT            0x0F
#define BIT_FIELDLAYOUT            0x10
#define BIT_STANDALONESIG          0x11
#define BIT_EVENTMAP               0x12
#define BIT_EVENTPTR               0x13 // Not documented in ECMA-335
#define BIT_EVENT                  0x14
#define BIT_PROPERTYMAP            0x15
#define BIT_PROPERTYPTR            0x16 // Not documented in ECMA-335
#define BIT_PROPERTY               0x17
#define BIT_METHODSEMANTICS        0x18
#define BIT_METHODIMPL             0x19
#define BIT_MODULEREF              0x1A
#define BIT_TYPESPEC               0x1B
#define BIT_IMPLMAP                0x1C
#define BIT_FIELDRVA               0x1D
#define BIT_ENCLOG                 0x1E // Not documented in ECMA-335
#define BIT_ENCMAP                 0x1F // Not documented in ECMA-335
#define BIT_ASSEMBLY               0x20
#define BIT_ASSEMBLYPROCESSOR      0x21
#define BIT_ASSEMBLYOS             0x22
#define BIT_ASSEMBLYREF            0x23
#define BIT_ASSEMBLYREFPROCESSOR   0x24
#define BIT_ASSEMBLYREFOS          0x25
#define BIT_FILE                   0x26
#define BIT_EXPORTEDTYPE           0x27
#define BIT_MANIFESTRESOURCE       0x28
#define BIT_NESTEDCLASS            0x29
#define BIT_GENERICPARAM           0x2A
#define BIT_METHODSPEC             0x2B
#define BIT_GENERICPARAMCONSTRAINT 0x2C

#endif /* #ifndef _INCLUDE_RZ_BIN_DOTNET_H_ */
