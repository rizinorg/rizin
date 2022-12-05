// SPDX-FileCopyrightText: 2022 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#include <mdmp_windefs.h>
#include <librz/bin/format/pe/pe64.h>

// the original PE64_UNWIND_CODE is a union
typedef struct windows_x64_unwind_code_t {
	ut8 CodeOffset;
	ut8 UnwindOp; // : 4;
	ut8 OpInfo; // : 4;
	ut16 FrameOffset;
	ut64 offset;
} Win64UnwindCode;

typedef struct windows_x64_unwind_info_t {
	ut8 Version; // : 3;
	ut8 Flags; // : 5;
	ut8 SizeOfProlog;
	ut8 CountOfCodes;
	ut8 FrameRegister; // : 4;
	ut8 FrameOffset; // : 4;
	Win64UnwindCode *code;
} Win64UnwindInfo;

enum {
	AMD64_INDEX_RAX = 0,
	AMD64_INDEX_RCX,
	AMD64_INDEX_RDX,
	AMD64_INDEX_RBX,
	AMD64_INDEX_RSP,
	AMD64_INDEX_RBP,
	AMD64_INDEX_RSI,
	AMD64_INDEX_RDI,
	AMD64_INDEX_R8,
	AMD64_INDEX_R9,
	AMD64_INDEX_R10,
	AMD64_INDEX_R11,
	AMD64_INDEX_R12,
	AMD64_INDEX_R13,
	AMD64_INDEX_R14,
	AMD64_INDEX_R15,
	AMD64_INDEX_RIP,
};

static Win64UnwindCode *windows_x64_unwind_code_new(RzDebug *dbg, ut64 at, ut32 count) {
	ut8 code[sizeof(ut16)] = { 0 };

	Win64UnwindCode *uc = RZ_NEWS0(Win64UnwindCode, count);
	if (!uc) {
		return NULL;
	}

	for (ut32 i = 0; i < count; ++i, at += sizeof(ut16)) {
		if (!dbg->iob.read_at(dbg->iob.io, at, code, sizeof(code))) {
			free(uc);
			return NULL;
		}
		uc[i].CodeOffset = code[0];
		uc[i].UnwindOp = code[1] & 0x0F;
		uc[i].OpInfo = code[1] >> 4;
		uc[i].FrameOffset = rz_read_le16(code);
		uc[i].offset = at;
	}

	return uc;
}

static Win64UnwindInfo *windows_x64_unwind_info_new(RzDebug *dbg, ut64 at) {
	ut8 tmp[sizeof(PE64_UNWIND_INFO)] = { 0 };
	if (!dbg->iob.read_at(dbg->iob.io, at, tmp, sizeof(tmp))) {
		return NULL;
	}

	Win64UnwindInfo *info = RZ_NEW0(Win64UnwindInfo);
	if (!info) {
		return NULL;
	}

	// The ordering of bits in C bitfields is implementation defined.
	// this ensures the endianness (here is little endian) is kept
	info->Version = tmp[0] & 0x07;
	info->Flags = tmp[0] >> 3;
	info->SizeOfProlog = tmp[1];
	info->CountOfCodes = tmp[2];
	info->FrameRegister = tmp[3] & 0x0F;
	info->FrameOffset = tmp[3] >> 4;

	info->code = windows_x64_unwind_code_new(dbg, at + 4, info->CountOfCodes);
	if (!info->code) {
		free(info);
		return NULL;
	}
	return info;
}

#define windows_x64_unwind_code_free free

static void windows_x64_unwind_info_free(Win64UnwindInfo *info) {
	if (!info) {
		return;
	}
	windows_x64_unwind_code_free(info->code);
	free(info);
}

static void set_amd64_register(struct context_type_amd64 *context, ut8 reg_idx, ut64 value) {
	switch (reg_idx) {
	case AMD64_INDEX_RAX:
		context->rax = value;
		return;
	case AMD64_INDEX_RCX:
		context->rcx = value;
		return;
	case AMD64_INDEX_RDX:
		context->rdx = value;
		return;
	case AMD64_INDEX_RBX:
		context->rbx = value;
		return;
	case AMD64_INDEX_RSP:
		context->rsp = value;
		return;
	case AMD64_INDEX_RBP:
		context->rbp = value;
		return;
	case AMD64_INDEX_RSI:
		context->rsi = value;
		return;
	case AMD64_INDEX_RDI:
		context->rdi = value;
		return;
	case AMD64_INDEX_R8:
		context->r8 = value;
		return;
	case AMD64_INDEX_R9:
		context->r9 = value;
		return;
	case AMD64_INDEX_R10:
		context->r10 = value;
		return;
	case AMD64_INDEX_R11:
		context->r11 = value;
		return;
	case AMD64_INDEX_R12:
		context->r12 = value;
		return;
	case AMD64_INDEX_R13:
		context->r13 = value;
		return;
	case AMD64_INDEX_R14:
		context->r14 = value;
		return;
	case AMD64_INDEX_R15:
		context->r15 = value;
		return;
	case AMD64_INDEX_RIP:
		context->rip = value;
		return;
	default:
		RZ_LOG_ERROR("debug: cannot set amd64 register due unknown index %u\n", reg_idx);
		return;
	}
}

static ut64 get_amd64_register(const struct context_type_amd64 *context, ut8 reg_idx) {
	switch (reg_idx) {
	case AMD64_INDEX_RAX:
		return context->rax;
	case AMD64_INDEX_RCX:
		return context->rcx;
	case AMD64_INDEX_RDX:
		return context->rdx;
	case AMD64_INDEX_RBX:
		return context->rbx;
	case AMD64_INDEX_RSP:
		return context->rsp;
	case AMD64_INDEX_RBP:
		return context->rbp;
	case AMD64_INDEX_RSI:
		return context->rsi;
	case AMD64_INDEX_RDI:
		return context->rdi;
	case AMD64_INDEX_R8:
		return context->r8;
	case AMD64_INDEX_R9:
		return context->r9;
	case AMD64_INDEX_R10:
		return context->r10;
	case AMD64_INDEX_R11:
		return context->r11;
	case AMD64_INDEX_R12:
		return context->r12;
	case AMD64_INDEX_R13:
		return context->r13;
	case AMD64_INDEX_R14:
		return context->r14;
	case AMD64_INDEX_R15:
		return context->r15;
	case AMD64_INDEX_RIP:
		return context->rip;
	default:
		RZ_LOG_ERROR("debug: cannot get amd64 register due unknown index %u\n", reg_idx);
		return 0;
	}
}

static int is_pc_inside_module(const void *value, const void *list_data) {
	const ut64 pc = *(const ut64 *)value;
	const RzDebugMap *module = list_data;
	return !(pc >= module->addr && pc < module->addr_end);
}

#define CMP(x, y)                   (st64)((st64)x - ((PE64_RUNTIME_FUNCTION *)y)->EndAddress)
#define READ_AT(address, buf, size) dbg->iob.read_at(dbg->iob.io, address, buf, size)

static bool init_module_runtime_functions(RzDebug *dbg, RzVector /*<PE64_RUNTIME_FUNCTION>*/ *functions, ut64 module_base) {
	ut8 buf[sizeof(ut32)] = { 0 };

	const ut64 lfanew_offset = module_base + rz_offsetof(Pe64_image_dos_header, e_lfanew);
	READ_AT(lfanew_offset, buf, sizeof(buf));
	const ut64 pe_offset = module_base + rz_read_le32(buf);

	const ut64 exception_entry_offset = pe_offset + rz_offsetof(Pe64_image_nt_headers, optional_header.DataDirectory[PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION]);
	READ_AT(exception_entry_offset, buf, sizeof(buf));
	const ut64 exception_table_va = module_base + rz_read_le32(buf);

	READ_AT(exception_entry_offset + 4, buf, sizeof(buf));
	const ut32 exception_table_size = rz_read_le32(buf);
	if (!exception_table_size || exception_table_size == UT32_MAX) {
		return false;
	}

	ut8 *section = malloc(exception_table_size);
	if (!section) {
		return false;
	}

	rz_vector_fini(functions);
	rz_vector_init(functions, sizeof(PE64_RUNTIME_FUNCTION), NULL, NULL);
	if (!rz_vector_reserve(functions, exception_table_size / sizeof(PE64_RUNTIME_FUNCTION))) {
		rz_vector_fini(functions);
		free(section);
		return false;
	}

	if (!READ_AT(exception_table_va, section, exception_table_size)) {
		rz_vector_fini(functions);
		free(section);
		return false;
	}

	for (ut64 offset = 0; offset < exception_table_size; offset += sizeof(PE64_RUNTIME_FUNCTION)) {
		PE64_RUNTIME_FUNCTION rfcn;
		rfcn.BeginAddress = rz_read_le32(section + offset + rz_offsetof(PE64_RUNTIME_FUNCTION, BeginAddress));
		rfcn.EndAddress = rz_read_le32(section + offset + rz_offsetof(PE64_RUNTIME_FUNCTION, EndAddress));
		rfcn.UnwindData = rz_read_le32(section + offset + rz_offsetof(PE64_RUNTIME_FUNCTION, UnwindData));
		if (!rfcn.BeginAddress) {
			break;
		}
		rz_vector_push(functions, &rfcn);
	}
	free(section);
	return true;
}

static ut64 read_register_from_memory(RzDebug *dbg, ut64 at) {
	ut8 buf[8] = { 0 };
	if (!dbg->iob.read_at(dbg->iob.io, at, buf, sizeof(buf))) {
		return 0;
	}
	return rz_read_le64(buf);
}

static ut32 read_unwind_code_slot_32(RzDebug *dbg, const Win64UnwindInfo *info, int *index) {
	ut8 tmp[sizeof(ut32)] = { 0 };
	ut64 offset = info->code[*index].offset;
	if (!dbg->iob.read_at(dbg->iob.io, offset, tmp, sizeof(tmp))) {
		return 0;
	}
	ut32 ret = rz_read_le32(tmp);
	*index += 2;
	return ret;
}

static ut16 read_unwind_code_slot_16(RzDebug *dbg, const Win64UnwindInfo *info, int *index) {
	ut8 tmp[sizeof(ut16)] = { 0 };
	ut64 offset = info->code[*index].offset;
	if (!dbg->iob.read_at(dbg->iob.io, offset, tmp, sizeof(tmp))) {
		return 0;
	}
	ut16 ret = rz_read_le16(tmp);
	*index += 1;
	return ret;
}

// Decides if current rsp or another register is used as the frame base (eg. rbp, etc)
static ut64 get_frame_base(const Win64UnwindInfo *info, const struct context_type_amd64 *context, const ut64 function_address) {
	const ut64 rip_offset_to_function = context->rip - function_address;
	if (!info->FrameRegister) {
		// There is no register being used as the frame base, use rsp
		return context->rsp;
	} else if ((rip_offset_to_function >= info->SizeOfProlog) || ((info->Flags & PE64_UNW_FLAG_CHAININFO) != 0)) {
		// There is a register being used as a frame base, and we definetly already set it
		ut64 value = get_amd64_register(context, info->FrameRegister);
		return value - info->FrameOffset * 16;
	}

	// There is a register being used as a frame base, unknown if we set it yet
	int i;
	Win64UnwindCode *code = NULL;
	// Find unwind of where frame register is being set
	for (i = 0; i < info->CountOfCodes; i++) {
		if (code[i].UnwindOp == UWOP_SET_FPREG) {
			break;
		}
	}

	// Check if we already set the frame register
	if (rip_offset_to_function >= code[i].CodeOffset) {
		ut64 value = get_amd64_register(context, info->FrameRegister);
		return value - info->FrameOffset * 16;
	}
	return context->rsp;
}

static inline bool
unwind_function(
	RzDebug *dbg,
	RzDebugFrame *frame,
	PE64_RUNTIME_FUNCTION *rfcn,
	struct context_type_amd64 *context,
	const ut64 module_address,
	const ut64 function_address) {

	bool is_chained = false;
	ut64 machine_frame_start = 0;
	bool is_machine_frame = false;

	ut64 unwind_info_address = module_address + rfcn->UnwindInfoAddress;
	Win64UnwindInfo *info = NULL;

	do {
		// Read initial unwind info structure
		info = windows_x64_unwind_info_new(dbg, unwind_info_address);
		if (!info) {
			return false;
		}

		// Get address that is used as the base for stack accesses
		ut64 frame_base = get_frame_base(info, context, function_address);

		if (info->Version != 1 && info->Version != 2) {
			// Version 1 found in user-space, version 2 in kernel
			RZ_LOG_ERROR("Unwind info version (%" PFMT32d ") for function 0x%" PFMT64x " is not recognized\n",
				(ut32)info->Version, function_address);
			free(info);
			return false;
		}

		int i = 0;
		while (i < info->CountOfCodes) {
			Win64UnwindCode *code = &info->code[i];
			i++;
			// Check if we are already past the prolog instruction
			// If we are processing a chained scope, always process all of them
			if (!is_chained && context->rip < function_address + code->CodeOffset) {
				// Skip, as it wasn't executed yet
				switch (code->UnwindOp) {
				case UWOP_ALLOC_LARGE:
					i++;
					if (code->OpInfo) {
						i++;
					}
					break;
				case UWOP_SAVE_XMM128:
				case UWOP_SAVE_NONVOL:
				case UWOP_UNKNOWN1:
					i++;
					break;
				case UWOP_SAVE_XMM128_FAR:
				case UWOP_SAVE_NONVOL_FAR:
				case UWOP_UNKNOWN2:
					i += 2;
					break;
				default:
					break;
				}
				continue;
			}
			ut16 offset;
			switch (code->UnwindOp) {
			case UWOP_PUSH_NONVOL: /* info == register number */
				set_amd64_register(context, code->OpInfo, read_register_from_memory(dbg, context->rsp));
				context->rsp += 8;
				break;
			case UWOP_ALLOC_LARGE: /* info == unscaled or scaled, alloc size in next 1 or 2 slots */
				if (code->OpInfo) {
					context->rsp += read_unwind_code_slot_32(dbg, info, &i);
				} else {
					context->rsp += read_unwind_code_slot_16(dbg, info, &i) * 8;
				}
				break;
			case UWOP_ALLOC_SMALL: /* info == size of allocation / 8 - 1 */
				context->rsp += (code->OpInfo * 8) + 8;
				break;
			case UWOP_SET_FPREG: /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
				frame->bp = get_amd64_register(context, info->FrameRegister);
				context->rsp = frame->bp - info->FrameOffset * 16;
				break;
			case UWOP_SAVE_NONVOL: /* info == register number, offset in next slot */
				offset = read_unwind_code_slot_16(dbg, info, &i) * 8;
				set_amd64_register(context, code->OpInfo, read_register_from_memory(dbg, frame_base + offset));
				break;
			case UWOP_SAVE_XMM128: /* info == XMM reg number, offset in next slot */
			case UWOP_UNKNOWN1: /* 1 extra slot */
				i++;
				break;
			case UWOP_SAVE_NONVOL_FAR: /* info == register number, offset in next 2 slots */
				offset = read_unwind_code_slot_32(dbg, info, &i);
				set_amd64_register(context, code->OpInfo, read_register_from_memory(dbg, frame_base + offset));
				break;
			case UWOP_SAVE_XMM128_FAR: /* info == XMM reg number, offset in next 2 slots */
			case UWOP_UNKNOWN2: /* 2 extra slots */
				i += 2;
				break;
			case UWOP_PUSH_MACHFRAME: /* info == 0: no error-code, 1: error-code */
				if (code->OpInfo) {
					context->rsp += 8;
				}
				is_machine_frame = true;
				machine_frame_start = context->rsp + 40;
				context->rip = read_register_from_memory(dbg, context->rsp);
				context->rsp = read_register_from_memory(dbg, context->rsp + 24);
				break;
			}
		}
		if (!(info->Flags & PE64_UNW_FLAG_CHAININFO)) {
			break;
		}
		if (i % 2) {
			i++;
		}

		// Read chained RUNTIME_FUNCTION
		const ut64 chained_fcn_address = unwind_info_address + rz_offsetof(PE64_UNWIND_INFO, UnwindCode[i]);
		ut8 buf[sizeof(PE64_RUNTIME_FUNCTION)];
		READ_AT(chained_fcn_address, buf, sizeof(buf));

		// Get unwind info from the chained RUNTIME_FUNCTION
		unwind_info_address = module_address + rz_read_at_le32(buf, rz_offsetof(PE64_RUNTIME_FUNCTION, UnwindInfoAddress));

		RZ_FREE_CUSTOM(info, windows_x64_unwind_info_free);
		// Make sure we process all the chained unwind ops
		is_chained = true;
	} while (1);

	if (is_machine_frame) {
		frame->size = machine_frame_start - frame->sp;
	} else {
		frame->size = context->rsp - frame->sp;
		context->rip = read_register_from_memory(dbg, context->rsp);
		context->rsp += 8;
	}
	windows_x64_unwind_info_free(info);
	return true;
}

static ut64 get_register_value(RzDebug *dbg, const char *reg_name) {
	RzRegItem *reg = rz_reg_get(dbg->reg, reg_name, -1);
	if (!reg) {
		rz_warn_if_reached();
		return 0;
	}
	return rz_reg_get_value(dbg->reg, reg);
}

static bool backtrace_windows_x64(RZ_IN RzDebug *dbg, RZ_INOUT RzList /*<RzDebugFrame *>*/ **out_frames, RZ_INOUT struct context_type_amd64 *context) {
	RzList *frames = *out_frames ? *out_frames : rz_list_newf(free);
	*out_frames = frames;
	if (!frames) {
		return true;
	}
	RzList *modules = rz_debug_modules_list(dbg);
	if (!modules) {
		return true;
	}
	if (!context->rsp) {
		context->mx_csr = get_register_value(dbg, "mxcsr");
		context->seg_cs = get_register_value(dbg, "cs");
		context->seg_ds = get_register_value(dbg, "ds");
		context->seg_es = get_register_value(dbg, "es");
		context->seg_fs = get_register_value(dbg, "fs");
		context->seg_gs = get_register_value(dbg, "gs");
		context->seg_ss = get_register_value(dbg, "ss");

		context->e_flags = get_register_value(dbg, "eflags");

		context->dr0 = get_register_value(dbg, "dr0");
		context->dr1 = get_register_value(dbg, "dr1");
		context->dr2 = get_register_value(dbg, "dr2");
		context->dr3 = get_register_value(dbg, "dr3");
		context->dr6 = get_register_value(dbg, "dr6");
		context->dr7 = get_register_value(dbg, "dr7");

		context->rax = get_register_value(dbg, "rax");
		context->rcx = get_register_value(dbg, "rcx");
		context->rdx = get_register_value(dbg, "rdx");
		context->rbx = get_register_value(dbg, "rbx");
		context->rsp = get_register_value(dbg, "rsp");
		context->rbp = get_register_value(dbg, "rbp");
		context->rsi = get_register_value(dbg, "rsi");
		context->rdi = get_register_value(dbg, "rdi");
		context->r8 = get_register_value(dbg, "r8");
		context->r9 = get_register_value(dbg, "r9");
		context->r10 = get_register_value(dbg, "r10");
		context->r11 = get_register_value(dbg, "r11");
		context->r12 = get_register_value(dbg, "r12");
		context->r13 = get_register_value(dbg, "r13");
		context->r14 = get_register_value(dbg, "r14");
		context->r15 = get_register_value(dbg, "r15");

		context->rip = get_register_value(dbg, "rip");
	}
	RzDebugMap *last_module = NULL;
	RzVector functions;
	rz_vector_init(&functions, 0, NULL, NULL);
	bool ret = true;
	while (true) {
		RzDebugFrame *frame = RZ_NEW0(RzDebugFrame);
		if (!frame) {
			break;
		}
		frame->addr = context->rip;
		frame->sp = context->rsp;
		rz_list_append(frames, frame);

		// Find in which module current rip is
		RzListIter *it = rz_list_find(modules, &context->rip, is_pc_inside_module);
		if (!it) {
			// Either broken stack or module info not avalable (PEB paged out, etc)
			break;
		}
		RzDebugMap *module = rz_list_iter_get_data(it);
		if (!module) {
			// Should never happen
			break;
		}
		if (module != last_module) {
			// Read runtime function entries for module
			if (!init_module_runtime_functions(dbg, &functions, module->addr)) {
				ret = false;
				break;
			}
			last_module = module;
		}
		int index;
		const ut64 offset_from_base = context->rip - module->addr;
		rz_vector_upper_bound(&functions, offset_from_base, index, CMP);
		if (index == rz_vector_len(&functions)) {
			// Leaf function
			frame->size = 0;
			context->rip = read_register_from_memory(dbg, context->rsp);
			context->rsp += 8;
		} else {
			// Not a leaf function
			PE64_RUNTIME_FUNCTION *rfcn = rz_vector_index_ptr(&functions, index);
			ut64 function_address = module->addr + rfcn->BeginAddress;
			for (index--; function_address > context->rip && index >= 0; index--) {
				rfcn = rz_vector_index_ptr(&functions, index);
				function_address = module->addr + rfcn->BeginAddress;
			}
			if (index < 0 && function_address > context->rip) {
				ret = false;
				break;
			}
			if (!unwind_function(dbg, frame, rfcn, context, module->addr, function_address)) {
				break;
			}
		}
	}
	if (!ret) {
		free(rz_list_pop(frames));
	}
	rz_list_free(modules);
	rz_vector_fini(&functions);
	return ret;
}
