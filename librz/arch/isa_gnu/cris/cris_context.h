// SPDX-FileCopyrightText: 2025 ahmed-kamal2004 <ahmedkamal200427@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CRIS_CONTEXT_H
#define CRIS_CONTEXT_H

#include <rz_util.h>
#include <common_gnu/disas-asm.h>

/**
 * \brief Holds disassembly context and state for CRIS asm.
 */
typedef struct {
	struct disassemble_info disasm_obj;
	unsigned long Offset;
	RzStrBuf *buf_global;
	unsigned char bytes[8];
	long case_offset; ///< Value of first element in switch.
	long case_offset_counter; ///< How many more case-offsets to print.
	long no_of_case_offsets; ///< Number of case offsets.
	long last_immediate; ///< Candidate for next case_offset.
} CrisContext;

#endif