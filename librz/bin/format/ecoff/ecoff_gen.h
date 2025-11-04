// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef ECOFF_GEN_H
#define ECOFF_GEN_H

#define ECOFF_GEN_HEADER(size) \
	typedef struct ecoff_header_##size##_t { \
		ut16 f_magic; /* magic/machine number */ \
		ut16 f_nscns; /* number of sections */ \
		st32 f_timedate; /* time & date stamp */ \
		st##size f_symptr; /* file pointer to symtab */ \
		st32 f_nsyms; /* number of symtab entries */ \
		ut16 f_opthdr; /* size of ECoff_Optional */ \
		ut16 f_flags; /* flags */ \
	} ECoff_Header_##size

#define ECOFF_GEN_SECTION(size) \
	typedef struct ecoff_section_##size##_t { \
		char s_name[8]; /* section entry name or an index to a name */ \
		ut##size s_paddr; /* physical address */ \
		ut##size s_vaddr; /* virtual address */ \
		ut##size s_size; /* section size */ \
		ut##size s_scnptr; /* file ptr to raw data for section */ \
		ut##size s_relptr; /* file ptr to relocation */ \
		ut##size s_lnnoptr; /* file ptr to line numbers */ \
		ut16 s_nreloc; /* number of relocation entries */ \
		ut16 s_nlnno; /* number of line number entries */ \
		ut32 s_flags; /* flags */ \
		/* not part of the actual section object */ \
		char *resolved_name; \
	} ECoff_Section_##size

#define ECOFF_GEN_SYMBOLIC_HEADER_1992(size) \
	typedef struct ecoff_symbolic_header_1992_##size##_t { \
		st32 iline_max; /* Number of line number entries */ \
		st32 idn_max; /* Number of dense number table (unused) */ \
		st32 ipd_max; /* Number of procedure descriptors. */ \
		st32 isym_max; /* Number of local symbols. */ \
		st32 iopt_max; /* Size of optimization symbol table. */ \
		st32 iaux_max; /* Number of auxiliary symbols. */ \
		st32 iss_max; /* Size of local string table. */ \
		st32 iss_ext_max; /* Size of external string table. */ \
		st32 ifd_max; /* Number of file descriptors. */ \
		st32 crfd; /* Number of relative file descriptors. */ \
		st32 iext_max; /* Number of external symbols. */ \
		st##size cb_line; /* Size of (packed) line number entries. */ \
		ut##size cb_line_offset; /* Offset to start of (packed) line numbers. */ \
		ut##size cb_dn_offset; /* Offset to start of dense number table (unused) */ \
		ut##size cb_pd_offset; /* Offset to start of procedure descriptors */ \
		ut##size cb_sym_offset; /* Offset to start of local symbols */ \
		ut##size cb_opt_offset; /* Offset to start of optimization entries */ \
		ut##size cb_aux_offset; /* Offset to start of auxiliary symbols */ \
		ut##size cb_ss_offset; /* Offset to start of local strings */ \
		ut##size cb_ss_ext_offset; /* Offset to start of external strings. */ \
		ut##size cb_fd_offset; /* Offset to start of file descriptors. */ \
		ut##size cb_rfd_offset; /* Offset to start of relative file descriptors. */ \
		ut##size cb_ext_offset; /* Offset to start of external symbols. */ \
	} ECoff_SymHdr1992_##size

#define ECOFF_GEN_SYMBOLIC_HEADER_7009(size) \
	typedef struct ecoff_symbolic_header_7009_##size##_t { \
		st32 iline_max; /* Number of line number entries */ \
		st##size cb_line; /* Size of (packed) line number entries. */ \
		ut##size cb_line_offset; /* Offset to start of (packed) line numbers. */ \
		st32 idn_max; /* Size of dense number table */ \
		ut##size cb_dn_offset; /* Offset to start of dense number table */ \
		st32 ipd_max; /* Number of procedure descriptors. */ \
		ut##size cb_pd_offset; /* Offset to start of procedure descriptors */ \
		st32 isym_max; /* Number of local symbols. */ \
		ut##size cb_sym_offset; /* Offset to start of local symbols */ \
		st32 iopt_max; /* Number of optimization symbol table. */ \
		ut##size cb_opt_offset; /* Offset to start of optimization entries */ \
		st32 iaux_max; /* Number of auxiliary symbols. */ \
		ut##size cb_aux_offset; /* Offset to start of auxiliary symbols */ \
		st32 iss_max; /* Size of local string table. */ \
		ut##size cb_ss_offset; /* Offset to start of local strings */ \
		st32 iss_ext_max; /* Size of external string table. */ \
		ut##size cb_ss_ext_offset; /* Offset to start of external strings. */ \
		st32 ifd_max; /* Number of file descriptors. */ \
		ut##size cb_fd_offset; /* Offset to start of file descriptors. */ \
		st32 crfd; /* Size of relative file descriptors. */ \
		ut##size cb_rfd_offset; /* Offset to start of relative file descriptors. */ \
		st32 iext_max; /* Number of external symbols. */ \
		ut##size cb_ext_offset; /* Offset to start of external symbols. */ \
	} ECoff_SymHdr7009_##size

#define ECOFF_GEN_SYMBOLIC_HEADER(size) \
	ECOFF_GEN_SYMBOLIC_HEADER_1992(size); \
	ECOFF_GEN_SYMBOLIC_HEADER_7009(size); \
	typedef struct ecoff_symbolic_header_##size##_t { \
		st16 magic; /* Symbol table magic must be 0x1992 (alpha) or 0x7009 (mips) */ \
		ut8 vstamp[2]; /* Symbol table version stamp (major.minor) */ \
		union { \
			ECoff_SymHdr1992_##size _1992; \
			ECoff_SymHdr7009_##size _7009; \
		}; \
	} ECoff_SymHdr_##size

#define ECOFF_GEN_FDE_7009(size) \
	typedef struct ecoff_file_descriptor_entry_7009_##size##_t { \
		ut##size adr; /* Address of first instruction */ \
		st32 rss; /* Offset from start of file's local string table entries to source file name (-1 if unknown). */ \
		st32 iss_base; /* Start of local strings for this file. */ \
		st##size cb_ss; /* Size of local string table entries for this file. */ \
		st32 isym_base; /* Starting index of local symbol entries for this file */ \
		st32 csym; /* Count of local symbol entries for this file. */ \
		st32 iopt_base; /* Offset from start of optimization symbol table to optimization symbol entries for this file. */ \
		st32 copt; /* Size of optimization symbol entries for this file. */ \
		st32 ipd_first; /* Starting index of procedure descriptors for this file. */ \
		st32 cpd; /* Count of procedure descriptors for this file. */ \
		st32 iaux_base; /* Starting index of auxiliary symbol entries for this file. */ \
		st32 caux; /* Count of auxiliary symbol entries for this file. */ \
		st32 iind_base; /* Starting index of indirect symbol entries for this file. */ \
		st32 cind; /* Count of indirect symbol entries for this file. */ \
		ut32 lang; /* : 5 | Source language for this file */ \
		ut32 f_merge; /* : 1 | Informs linker whether this file can be merged. */ \
		ut32 f_readin; /* : 1 | True if file was read in (as opposed to just created). */ \
		ut32 f_bigendian; /* : 1 | When true, was compiled on big endian machine. */ \
		ut32 glevel; /* : 2 | Symbolic information level with which this file was compiled. */ \
		ut32 reserved; /* : 22 | reserved bits */ \
		st##size cb_line_offset; /* Offset from start of packed line numbers to start of entries for this file */ \
		st32 cline; /* Count of line number entries (if expanded) for this file. */ \
	} ECoff_FileDescEntry7009_##size

#define ECOFF_GEN_FDE_1992(size) \
	typedef struct ecoff_file_descriptor_entry_1992_##size##_t { \
		ut##size adr; /* Address of first instruction */ \
		st##size cb_line_offset; /* Offset from start of packed line numbers to start of entries for this file */ \
		st##size cb_line; /* Size of packed line numbers for this file. */ \
		st##size cb_ss; /* Size of local string table entries for this file. */ \
		st32 rss; /* Offset from start of file's local string table entries to source file name (-1 if unknown). */ \
		st32 iss_base; /* Start of local strings for this file. */ \
		st32 isym_base; /* Starting index of local symbol entries for this file */ \
		st32 csym; /* Count of local symbol entries for this file. */ \
		st32 iline_base; /* Starting index of line number entries (if expanded) for this file. */ \
		st32 cline; /* Count of line number entries (if expanded) for this file. */ \
		st32 iopt_base; /* Offset from start of optimization symbol table to optimization symbol entries for this file. */ \
		st32 copt; /* Size of optimization symbol entries for this file. */ \
		st32 ipd_first; /* Starting index of procedure descriptors for this file. */ \
		st32 cpd; /* Count of procedure descriptors for this file. */ \
		st32 iaux_base; /* Starting index of auxiliary symbol entries for this file. */ \
		st32 caux; /* Count of auxiliary symbol entries for this file. */ \
		st32 rfd_base; /* Starting index of relative file descriptors for this file. */ \
		st32 crfd; /* Count of relative file descriptors for this file. */ \
		ut16 lang; /* : 5 | Source language for this file */ \
		ut16 f_merge; /* : 1 | Informs linker whether this file can be merged. */ \
		ut16 f_readin; /* : 1 | True if file was read in (as opposed to just created). */ \
		ut16 f_bigendian; /* : 1 | When true, was compiled on big endian machine. */ \
		ut16 glevel; /* : 2 | Symbolic information level with which this file was compiled. */ \
		ut16 f_trim; /* : 1 | Unused. */ \
		ut16 reserved; /* : 5 | reserved bits */ \
		ut8 vstamp[2]; /* Symbol table version stamp from the .o files. */ \
		ut32 reserved2; /* reserved bytes */ \
	} ECoff_FileDescEntry1992_##size

#define ECOFF_GEN_FDE(size) \
	ECOFF_GEN_FDE_7009(size); \
	ECOFF_GEN_FDE_1992(size); \
	typedef struct ecoff_file_descriptor_entry_##size##_t { \
		union { \
			ECoff_FileDescEntry7009_##size _7009; \
			ECoff_FileDescEntry1992_##size _1992; \
		}; \
	} ECoff_FileDescEntry_##size

#define ECOFF_GEN_PDE_7009(size) \
	typedef struct ecoff_procedure_descriptor_entry_7009_##size##_t { \
		ut##size adr; /* The start address of this procedure. (-1 if no .text) */ \
		st32 isym; /* Start of local symbols for this procedure. */ \
		st##size cb_line_offset; /* Offset to the start of this procedure's line numbers from the start of the file descriptor entry */ \
		ut32 regmask; /* Saved general register mask */ \
		st32 regoffset; /* Offset from the virtual frame pointer to the general register save area in the stack frame. */ \
		st32 iopt; /* Start of procedure's optimization symbol entries. */ \
		ut32 fregmask; /* Saved floating-point register mask. */ \
		st32 fregoffset; /* Offset from the virtual frame pointer to the floating-point register save area in the stack frame. */ \
		st32 frameoffset; /* Size of the fixed part of the stack frame. */ \
		st16 framereg; /* Frame pointer register number. */ \
		st16 pcreg; /* PC (Program Counter) register number. */ \
		st32 sline; /* Start of line number entries (if expanded) for this procedure (-1 if unknown). */ \
		st32 eline; /* End of line number entries (if expanded) for this procedure (-1 if unknown). */ \
		st32 oline; /* Offset of line number entries (if expanded) for this procedure (-1 if unknown). */ \
	} ECoff_ProcDescEntry7009_##size

#define ECOFF_GEN_PDE_1992(size) \
	typedef struct ecoff_procedure_descriptor_entry_1992_##size##_t { \
		ut##size adr; /* The start address of this procedure. (-1 if no .text) */ \
		st##size cb_line_offset; /* Offset to the start of this procedure's line numbers from the start of the file descriptor entry */ \
		st32 isym; /* Start of local symbols for this procedure. */ \
		st32 iline; /* Start of line number entries (if expanded) for this procedure (-1 if unknown). */ \
		ut32 regmask; /* Saved general register mask */ \
		st32 regoffset; /* Offset from the virtual frame pointer to the general register save area in the stack frame. */ \
		st32 iopt; /* Start of procedure's optimization symbol entries. */ \
		ut32 fregmask; /* Saved floating-point register mask. */ \
		st32 fregoffset; /* Offset from the virtual frame pointer to the floating-point register save area in the stack frame. */ \
		st32 frameoffset; /* Size of the fixed part of the stack frame. */ \
		st32 ln_low; /* Lowest source line number within this file for the procedure */ \
		st32 ln_high; /* Highest source line number within this file for the procedure */ \
		ut32 gp_prologue; /* : 8 | Size of gp prologue. */ \
		ut32 gp_used; /* : 1 | Flag set if the procedure uses gp. */ \
		ut32 reg_frame; /* : 1 | True if the procedure is a light-weight or null-weight procedure. */ \
		ut32 prof; /* : 1 | True if the procedure has been compiled with –pg for gprof profiling. */ \
		ut32 reserved; /* : 13 | Must be zero. */ \
		ut32 localoff; /* : 8 | Bias value for accessing local symbols on the stack at run time. */ \
		st16 framereg; /* Frame pointer register number. */ \
		st16 pcreg; /* PC (Program Counter) register number. */ \
	} ECoff_ProcDescEntry1992_##size

#define ECOFF_GEN_PDE(size) \
	ECOFF_GEN_PDE_7009(size); \
	ECOFF_GEN_PDE_1992(size); \
	typedef struct ecoff_procedure_descriptor_entry_##size##_t { \
		union { \
			ECoff_ProcDescEntry7009_##size _7009; \
			ECoff_ProcDescEntry1992_##size _1992; \
		}; \
	} ECoff_ProcDescEntry_##size

#define ECOFF_GEN_LOC_SYM(size) \
	typedef struct ecoff_local_symbol_##size##_t { \
		st##size value; /* A field that can contain an address, size, offset, or index. */ \
		st32 iss; /* Offset from the iss_base field of a file descriptor table entry to the name of the symbol (-1 if no name). */ \
		ut32 st; /* : 6 | Symbol type */ \
		ut32 sc; /* : 5 | Storage class */ \
		ut32 reserved; /* : 1 | Must be zero. */ \
		ut32 index; /* : 20 | An index into either the local symbol table or auxiliary symbol table. */ \
		/* not part of the actual section object */ \
		char *resolved_name; \
	} ECoff_LocalSymbol_##size

#define ECOFF_GEN_EXT_SYM(size) \
	typedef struct ecoff_external_symbol_##size##_t { \
		ECoff_LocalSymbol_##size asym; /* External symbol table entry */ \
		ut32 jmptbl; /* : 1 | Unused. */ \
		ut32 cobol_main; /* : 1 | Flag set to indicate that the symbol is a COBOL main procedure. */ \
		ut32 weakext; /* : 1 | Flag set to identify the symbol as a weak external. */ \
		ut32 alignment; /* : 4 | Power of two byte alignment for common storage class symbols biased by 2^3 (8) */ \
		ut32 xport; /* : 1 | Flag set to indicate the symbol is to be exported from a shared library. */ \
		ut32 multiext; /* : 1 | Flag set to indicate that multiple definitions of the symbol are allowed. */ \
		ut32 reserved; /* : 23 | Must be zero. */ \
		st32 ifd; /* Index of the file descriptor where the symbol is defined. (-1 for undefined) */ \
	} ECoff_ExternSymbol_##size

#define ECOFF_GEN_TYPES(size) \
	ECOFF_GEN_HEADER(size); \
	ECOFF_GEN_SECTION(size); \
	ECOFF_GEN_SYMBOLIC_HEADER(size); \
	ECOFF_GEN_FDE(size); \
	ECOFF_GEN_PDE(size); \
	ECOFF_GEN_LOC_SYM(size); \
	ECOFF_GEN_EXT_SYM(size)

#endif /* ECOFF_GEN_H */
