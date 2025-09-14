// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#define ROUND_UP_4(x) ((x) + (4 - 1)) / 4 * 4

#define FP_LAYOUT 0x10

#define X86          0
#define X86_64       1
#define ARM          2
#define AARCH64      3
#define SPARC        4
#define SPARC_V8PLUS 5
#define SPARC_V9     6
#define SPARC32_FP   (FP_LAYOUT | SPARC)
#define SPARC64_FP   (FP_LAYOUT | SPARC_V9)
// OpenBSD regs have their own note types in coredumps.
// They are only for registers and store no other information.
#define OPENBSD_SPARC_V9    7
#define OPENBSD_SPARC_V9_FP (FP_LAYOUT | OPENBSD_SPARC_V9)
// MIPS related constants.
// The size of the pr status depends on the ABI
#define MIPS_32   8
#define MIPS_64   9
#define MIPS_FP32 (FP_LAYOUT | MIPS_32)
#define MIPS_FP64 (FP_LAYOUT | MIPS_64)
// Floating point register layout.
#define ARCH_LEN (FP_LAYOUT | 0xf)

// See elf.c::elfcore_grok_solaris_note_impl() of binutil's bfd
// https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=bfd/elf.c;h=6ef603010918f14eda69f0d0dc1637b4d51e8157;hb=HEAD#l11777
// OR
// linux/arch/sparc/include/asm/elf_64.h or elf_32.h
// Shared by OpenBSD and Linux
// Layout is:
// G0 --> G7
// O0 --> O7
// L0 --> L7
// I0 --> I7
// PSR, PC, nPC, Y, WIM, TBR
#define SPARC32_REGS_SIZE (4 * 38)
// Layout is:
// G0 --> G7
// O0 --> O7
// L0 --> L7
// I0 --> I7
// TSTATE, TPC, TNPC, Y
#define SPARC64_REGS_SIZE            (8 * 36)
#define SPARC32_PR_STATUS_REG_OFFSET 0x48
#define SPARC64_PR_STATUS_REG_OFFSET 0x70
// OpenBSD has an extra note type for the registers and
// hence an extra buffer (not shared with PRSTATUS)
#define SPARC64_OPENBSD_REG_OFFSET 0x0

// The ones for Linux coredumps.
// linux/arch/sparc/include/asm/elf_64.h or elf_32.h
//
// ```
// typedef struct {
// 	union {
// 		unsigned int	pr_regs[32]; // unsigned long in elf_32.h
// 		unsigned long	pr_dregs[16];
// 	} pr_fr;
// 	unsigned int __unused;
// 	unsigned int	pr_fsr; // unsigned long in elf_32.h
// 	unsigned char	pr_qcnt;
// 	unsigned char	pr_q_entrysize;
// 	unsigned char	pr_en;
// 	unsigned int	pr_q[64];
// } compat_elf_fpregset_t;
// ```
#define SPARC32_FPREGS_SIZE ((4 * 32) + 4 + 4 + 1 + 1 + 1) /* Ignore q regs. They are invalid for Sparc32. */
#define SPARC64_FPREGS_SIZE ((4 * 32) + 4 + 4 + 1 + 1 + 1 + (8 * 32))
// See:
// https://github.com/torvalds/linux/blob/b320789d6883cc00ac78ce83bccbfe7ed58afcf0/fs/binfmt_elf_fdpic.c#L1378
#define SPARC32_FPREG_OFFSET 0x0
#define SPARC64_FPREG_OFFSET 0x0

// From openbsd/sys/arch/sparc64/include/reg.h
//
// These are 64 + 2 + 1 = 67 4byte words.
//
// ```
// struct fpreg {
// 	u_int	fr_regs[64];		/* our view is 64 32-bit registers */
// 	int64_t	fr_fsr;			/* %fsr */
// 	int	fr_gsr;			/* graphics state reg */
// };
// ```
#define SPARC64_OPENBSD_FPREGS_SIZE  ((4 * 64) + 8 + 4)
#define SPARC64_OPENBSD_FPREG_OFFSET 0x0

// o6 is the stack pointer. So g0-g7,o0-5 come before it.
// Same for OpenBSD and Linux.
#define SPARC32_PR_STATUS_REG_OFFSET_SP (4 * 14)
#define SPARC64_PR_STATUS_REG_OFFSET_SP (8 * 14)

// MIPS number of registers.
#define MIPS_N_GPR_REGS          45
#define MIPS_N_FP_REGS           33
#define MIPS32_REGS_SIZE         (4 * MIPS_N_GPR_REGS) // int32
#define MIPS64_REGS_SIZE         (8 * MIPS_N_GPR_REGS) // int64
#define MIPS_FP32_REGS_SIZE      (4 * MIPS_N_FP_REGS) // float32
#define MIPS_FP64_REGS_SIZE      (8 * MIPS_N_FP_REGS) // float64
#define MIPS_GPR32_STATUS_OFFSET (96)
#define MIPS_GPR64_STATUS_OFFSET (112)

static RzBinElfPrStatusLayout prstatus_layouts[ARCH_LEN] = {
	[X86] = { 160, 0x48, 32, 0x3c },
	[X86_64] = { 216, 0x70, 64, 0x98 },
	[ARM] = { 72, 0x48, 32, 0x34 },
	[AARCH64] = { 272, 0x70, 64, 0xf8 },

	[SPARC] = { SPARC32_REGS_SIZE, SPARC32_PR_STATUS_REG_OFFSET, 32, SPARC32_PR_STATUS_REG_OFFSET_SP },
	[SPARC_V8PLUS] = { SPARC32_REGS_SIZE, SPARC32_PR_STATUS_REG_OFFSET, 32, SPARC32_PR_STATUS_REG_OFFSET_SP },
	[SPARC_V9] = { SPARC64_REGS_SIZE, SPARC64_PR_STATUS_REG_OFFSET, 64, SPARC64_PR_STATUS_REG_OFFSET_SP },
	[OPENBSD_SPARC_V9] = { SPARC64_REGS_SIZE, SPARC64_OPENBSD_REG_OFFSET, 64, SPARC64_PR_STATUS_REG_OFFSET_SP },

	[MIPS_32] = { MIPS32_REGS_SIZE, MIPS_GPR32_STATUS_OFFSET, 0, 0 },
	[MIPS_64] = { MIPS64_REGS_SIZE, MIPS_GPR64_STATUS_OFFSET, 0, 0 },

	[SPARC32_FP] = { SPARC32_FPREGS_SIZE, SPARC32_FPREG_OFFSET, 0, 0 },
	[SPARC64_FP] = { SPARC64_FPREGS_SIZE, SPARC32_FPREG_OFFSET, 0, 0 },
	[OPENBSD_SPARC_V9_FP] = { SPARC64_OPENBSD_FPREGS_SIZE, SPARC64_OPENBSD_FPREG_OFFSET, 0, 0 },

	[MIPS_FP32] = { MIPS_FP32_REGS_SIZE, 4, 0, 0 },
	[MIPS_FP64] = { MIPS_FP64_REGS_SIZE, 8, 0, 0 },
};

static bool parse_register_note(ELFOBJ *bin, RzVector /*<RzBinElfNote>*/ *notes, Elf_(Nhdr) * note_segment_header, ut64 offset, size_t n_type) {
	RzBinElfPrStatusLayout *layout = NULL;
	if (n_type == NT_PRSTATUS) {
		layout = Elf_(rz_bin_elf_get_prstatus_layout)(bin);
		if (!layout) {
			RZ_LOG_WARN("Fetching registers from core file not supported for this architecture.\n");
			return false;
		}
	} else {
		layout = Elf_(rz_bin_elf_get_regset_layout)(bin, n_type);
		if (!layout) {
			RZ_LOG_WARN("Fetching FP registers from core file not supported for this architecture.\n");
			return false;
		}
	}

	RzBinElfNote *note = rz_vector_push(notes, NULL);
	if (!note) {
		return false;
	}

	note->type = n_type;

	note->prstatus.regstate_size = layout->regsize;
	note->prstatus.regstate = RZ_NEWS(ut8, layout->regsize);
	if (!note->prstatus.regstate) {
		return false;
	}

	if (rz_buf_read_at(bin->b, offset + layout->regdelta, note->prstatus.regstate, note->prstatus.regstate_size) != layout->regsize) {
		RZ_LOG_WARN("Failed to read register state from CORE file\n");
		return false;
	}

	return true;
}

static bool get_note_file_aux(ELFOBJ *bin, RzBinElfNoteFile *file, ut64 *offset) {
	return Elf_(rz_bin_elf_read_addr)(bin, offset, &file->start_vaddr) &&
		Elf_(rz_bin_elf_read_addr)(bin, offset, &file->end_vaddr) &&
		Elf_(rz_bin_elf_read_off)(bin, offset, &file->file_off);
}

static bool get_note_file(ELFOBJ *bin, RzBinElfNoteFile *file, ut64 *offset) {
	ut64 tmp = *offset;
	if (!get_note_file_aux(bin, file, offset)) {
		RZ_LOG_WARN("Failed to read NT_FILE at 0x%" PFMT64x ".\n", tmp);
	}

	return true;
}

static bool set_note_file(ELFOBJ *bin, RzBinElfNoteFile *file, ut64 *offset, char *name) {
	if (!get_note_file(bin, file, offset)) {
		return false;
	}

	file->file = name;
	return true;
}

static bool parse_note_file(ELFOBJ *bin, RzVector /*<RzBinElfNote>*/ *notes, Elf_(Nhdr) * note_segment_header, ut64 offset) {
	Elf_(Addr) n_maps;
	if (!Elf_(rz_bin_elf_read_addr)(bin, &offset, &n_maps)) {
		return false;
	}

	offset += sizeof(Elf_(Addr)); // skip page size always 1

	Elf_(Addr) strings_offset; // offset after the addr-array
	if (!Elf_(rz_bin_elf_mul_addr)(&strings_offset, n_maps, sizeof(Elf_(Addr)) * 3)) {
		return false;
	}

	ut64 entry_offset = offset;
	for (Elf_(Addr) i = 0; i < n_maps; i++) {
		if (strings_offset >= note_segment_header->n_descsz) {
			return false;
		}

		char *name = rz_buf_get_nstring(bin->b, offset + strings_offset, note_segment_header->n_descsz);
		if (!name) {
			return false;
		}

		RzBinElfNote *note = rz_vector_push(notes, NULL);
		if (!note) {
			free(name);
			return false;
		}

		note->type = NT_FILE;

		if (!set_note_file(bin, &note->file, &entry_offset, name)) {
			return false;
		}

		strings_offset += strlen(name) + 1;
	}

	return true;
}

/**
 * \brief Psrse note and return true if the parsing should continue. False if there was an error.
 */
static bool set_note(ELFOBJ *bin, RzVector /*<RzBinElfNote>*/ *notes, Elf_(Nhdr) * note_segment_header, ut64 offset) {
	switch (note_segment_header->n_type) {
	default:
		RZ_LOG_INFO("n_type %u not handled.\n", note_segment_header->n_type);
		break;
	case NT_PRSTATUS:
	case NT_FPREGSET:
	case NT_OPENBSD_REGS:
	case NT_OPENBSD_FPREGS:
	case NT_OPENBSD_XFPREGS:
		if (!parse_register_note(bin, notes, note_segment_header, offset, note_segment_header->n_type)) {
			RZ_LOG_INFO("Failed to parse n_type %u.\n", note_segment_header->n_type);
			// The parsing should continue if FP registers are not parsed for the current architecture.
			return Elf_(rz_bin_elf_get_regset_layout)(bin, note_segment_header->n_type) == NULL;
		}
		break;
	case NT_FILE:
		if (!parse_note_file(bin, notes, note_segment_header, offset)) {
			RZ_LOG_WARN("Failed to parse NT_FILE.\n");
			return false;
		}
		break;
	}

	return true;
}

static bool read_note_segment_header(ELFOBJ *bin, ut64 *offset, Elf_(Nhdr) * note_segment_header) {
	if (!Elf_(rz_bin_elf_read_word)(bin, offset, &note_segment_header->n_namesz)) {
		return false;
	}

	if (!Elf_(rz_bin_elf_read_word)(bin, offset, &note_segment_header->n_descsz)) {
		return false;
	}

	if (!Elf_(rz_bin_elf_read_word)(bin, offset, &note_segment_header->n_type)) {
		return false;
	}

	return true;
}

static bool set_note_segment(ELFOBJ *bin, RzVector /*<RzBinElfNote>*/ *notes, RzBinElfSegment *segment) {
	ut64 offset = segment->data.p_offset;

	while (offset < segment->data.p_offset + segment->data.p_filesz) {
		Elf_(Nhdr) note_segment_header;

		if (!read_note_segment_header(bin, &offset, &note_segment_header)) {
			return false;
		}

		offset += ROUND_UP_4(note_segment_header.n_namesz); // skip name

		if (!set_note(bin, notes, &note_segment_header, offset)) {
			return false;
		}

		offset += ROUND_UP_4(note_segment_header.n_descsz); // skip note description
	}

	return true;
}

static void note_prstatus_free(RzBinElfNotePrStatus *ptr) {
	free(ptr->regstate);
}

static void note_file_free(RzBinElfNoteFile *ptr) {
	free(ptr->file);
}

static void note_free(void *e, RZ_UNUSED void *user) {
	RzBinElfNote *ptr = e;

	switch (ptr->type) {
	case NT_FILE:
		note_file_free(&ptr->file);
		break;
	case NT_PRSTATUS:
	case NT_FPREGSET:
	case NT_OPENBSD_REGS:
	case NT_OPENBSD_FPREGS:
	case NT_OPENBSD_XFPREGS:
		note_prstatus_free(&ptr->prstatus);
		break;
	}
}

static void note_segment_free(void *e, RZ_UNUSED void *user) {
	RzVector *ptr = e;
	rz_vector_fini(ptr);
}

static const size_t elf_get_prstatus_layout_mips(const ELFOBJ *bin, bool is_fp) {
	size_t fp = is_fp ? FP_LAYOUT : 0;
	if (bin->ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
		return fp | MIPS_64;
	}
	return fp | MIPS_32;
}

RZ_BORROW RzBinElfPrStatusLayout *Elf_(rz_bin_elf_get_prstatus_layout)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	switch (bin->ehdr.e_machine) {
	case EM_AARCH64:
		return prstatus_layouts + AARCH64;
	case EM_ARM:
		return prstatus_layouts + ARM;
	case EM_386:
		return prstatus_layouts + X86;
	case EM_X86_64:
		return prstatus_layouts + X86_64;
	case EM_SPARC:
		return prstatus_layouts + SPARC;
	case EM_SPARC32PLUS:
		return prstatus_layouts + SPARC_V8PLUS;
	case EM_SPARCV9:
		return prstatus_layouts + SPARC_V9;
	case EM_MIPS:
		/* fall-thru */
	case EM_MIPS_RS3_LE:
		/* fall-thru */
	case EM_MIPS_X:
		return prstatus_layouts + elf_get_prstatus_layout_mips(bin, false);
	}

	return NULL;
}

/**
 * \brief Returns the register layout for an ELF note type storing register values.
 * Commonly this is PR_STATUS. But on some OS (OpenBSD) there is a specific
 * note type just for register values.
 * For these ones the layout is returned.
 * For PRSTATUS use Elf_(rz_bin_elf_get_prstatus_layout)().
 *
 * \param bin The ELF object.
 * \param The note type.
 *
 * \return The register layout or NULL in case of failure.
 */
RZ_BORROW RzBinElfPrStatusLayout *Elf_(rz_bin_elf_get_regset_layout)(RZ_NONNULL ELFOBJ *bin, Elf_(Word) n_type) {
	rz_return_val_if_fail(bin, NULL);

	size_t off = 0;
	switch (bin->ehdr.e_machine) {
	default:
		return NULL;
	case EM_MIPS:
		/* fall-thru */
	case EM_MIPS_RS3_LE:
		/* fall-thru */
	case EM_MIPS_X:
		if (n_type == NT_FPREGSET) {
			off = elf_get_prstatus_layout_mips(bin, true);
		} else {
			rz_warn_if_reached();
			return NULL;
		}
		break;
	case EM_SPARC:
		if (n_type == NT_FPREGSET) {
			off = FP_LAYOUT | SPARC;
		} else {
			rz_warn_if_reached();
			return NULL;
		}
		break;
	case EM_SPARC32PLUS:
		if (n_type == NT_FPREGSET) {
			off = FP_LAYOUT | SPARC_V8PLUS;
		} else {
			rz_warn_if_reached();
			return NULL;
		}
		break;
	case EM_SPARCV9:
		if (n_type == NT_FPREGSET) {
			off = FP_LAYOUT | SPARC_V9;
		} else if (n_type == NT_OPENBSD_REGS) {
			off = OPENBSD_SPARC_V9;
		} else {
			off = FP_LAYOUT | OPENBSD_SPARC_V9;
		}
		break;
	}

	return prstatus_layouts + off;
}

RZ_OWN RzVector /*<RzVector<RzBinElfNote>>*/ *Elf_(rz_bin_elf_notes_new)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	RzVector *result = rz_vector_new(sizeof(RzVector), note_segment_free, NULL);
	if (!result) {
		return NULL;
	}

	RzBinElfSegment *segment;
	rz_bin_elf_foreach_segments(bin, segment) {
		if (!segment->is_valid || segment->data.p_type != PT_NOTE) {
			continue;
		}

		RzVector *notes = rz_vector_push(result, NULL);
		if (!notes) {
			rz_vector_free(result);
			return NULL;
		}

		rz_vector_init(notes, sizeof(RzBinElfNote), note_free, NULL);

		if (!set_note_segment(bin, notes, segment)) {
			rz_vector_fini(notes);
			rz_vector_free(result);
			return NULL;
		}
	}

	if (!rz_vector_len(result)) {
		rz_vector_free(result);
		return NULL;
	}

	return result;
}

bool Elf_(rz_bin_elf_has_notes)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);
	return bin->notes;
}
