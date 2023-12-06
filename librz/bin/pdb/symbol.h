// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RIZIN_SYMBOL_H
#define RIZIN_SYMBOL_H

#include "symbol_enum.h"
#include <rz_util/rz_buf.h>
#include <rz_pdb.h>

typedef ut16 PDBSymbolKind;
typedef ut32 PDBTypeIndex;
typedef ut32 PDBSymbolIndex;

RZ_IPI bool PDBSectionOffset_parse(RzBuffer *b, PDBSectionOffset *section_offset);

typedef struct {
	bool global : 1;
	bool managed : 1;
	PDBTypeIndex type_index;
	PDBSectionOffset offset;
	char *name;
} PDBSData;

RZ_IPI bool PDBSData_parse(RzBuffer *b, PDBSymbolKind kind, PDBSData *sdata);

typedef struct {
	bool code : 1;
	bool function : 1;
	bool managed : 1;
	bool msil : 1;
	PDBSectionOffset offset;
	char *name;
} PDBSPublic;

RZ_IPI bool PDBSPublic_parse(RzBuffer *b, PDBSymbolKind kind, PDBSPublic *s);

typedef struct {
	PDBSymbolIndex index;
	PDBSymbolKind raw_kind;
	ut16 length;
	enum {
		PDB_ScopeEnd, /// End of a scope, such as a procedure.
		PDB_ObjName, /// Name of the object file of this module.
		PDB_RegisterVariable, /// A Register variable.
		PDB_Constant, /// A constant value.
		PDB_UserDefinedType, /// A user defined type.
		PDB_MultiRegisterVariable, /// A Register variable spanning multiple registers.
		PDB_Data, /// Static data, such as a global variable.
		PDB_Public, /// A public symbol with a mangled name.
		PDB_Procedure, /// A procedure, such as a function or method.
		PDB_ThreadStorage, /// A thread local variable.
		PDB_CompileFlags, /// Flags used to compile a module.
		PDB_UsingNamespace, /// A using namespace directive.
		PDB_ProcedureReference, /// Reference to a [`ProcedureSymbol`].
		PDB_DataReference, /// Reference to an imported variable.
		PDB_AnnotationReference, /// Reference to an annotation.
		PDB_Trampoline, /// Trampoline thunk.
		PDB_Export, /// An exported symbol.
		PDB_Local, /// A local symbol in optimized code.
		PDB_BuildInfo, /// Reference to build information.
		PDB_InlineSite, /// The callsite of an inlined function.
		PDB_InlineSiteEnd, /// End of an inline callsite.
		PDB_ProcedureEnd, /// End of a procedure.
		PDB_Label, /// A label.
		PDB_Block, /// A block.
		PDB_RegisterRelative, /// Data allocated relative to a register.
		PDB_Thunk, /// A thunk.
		PDB_SeparatedCode, /// A block of separated code.
		PDB_DefRange, /// A live range of a variable.
		PDB_DefRangeSubField, /// A live range of a sub field of a variable.
		PDB_DefRangeRegister, /// A live range of a register variable.
		PDB_DefRangeFramePointerRelative, /// A live range of a frame pointer-relative variable.
		PDB_DefRangeFramePointerRelativeFullScope, /// A frame-pointer variable which is valid in the full scope of the function.
		PDB_DefRangeSubFieldRegister, /// A live range of a sub field of a register variable.
		PDB_DefRangeRegisterRelative, /// A live range of a variable related to a register.
		PDB_BasePointerRelative, /// A base pointer-relative variable.
		PDB_FrameProcedure, /// Extra frame and proc information.
		PDB_CallSiteInfo, /// Indirect call site information.
	} kind;
	void *data;
} PDBSymbol;

RZ_IPI bool PDBSymbol_parse(RzBuffer *b, PDBSymbol *symbol);

typedef struct {
	RzBuffer *b;
} PDBSymbolTable;

typedef struct {
	RzBuffer *b;
} PDBSymbolIter;

RZ_IPI bool PDBSymbolTable_iter(PDBSymbolTable *symbol_table, PDBSymbolIter *iter);
RZ_IPI PDBSymbol *PDBSymbolTable_symbol_by_index(PDBSymbolTable *symbol_table, PDBSymbolIndex index);

RZ_IPI bool PDBSymbolIter_next(PDBSymbolIter *iter, PDBSymbol *symbol);
RZ_IPI bool PDBSymbolIter_seek(PDBSymbolIter *iter, PDBSymbolIndex index);

#endif // RIZIN_SYMBOL_H
