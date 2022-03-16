// SPDX-FileCopyrightText: 2022 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#include <mdmp_windefs.h>
#include <librz/bin/format/pe/pe64.h>

static int is_pc_inside_module(const void *value, const void *list_data) {
	const ut64 pc = *(const ut64 *)value;
	const RzDebugMap *module = list_data;
	return !(pc >= module->addr && pc < module->addr_end);
}

#define CMP(x, y)                   (st64)((st64)x - ((PE64_RUNTIME_FUNCTION *)y)->EndAddress)
#define READ_AT(address, buf, size) dbg->iob.read_at(dbg->iob.io, address, buf, size)

static inline bool init_module_runtime_functions(RzDebug *dbg, RzVector *functions, ut64 module_base) {
	ut8 buf[4];

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

	ut64 offset;
	for (offset = 0; offset < exception_table_size; offset += sizeof(PE64_RUNTIME_FUNCTION)) {
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

static inline ut64 read_register(RzDebug *dbg, ut64 at) {
	ut8 buf[8];
	dbg->iob.read_at(dbg->iob.io, at, buf, sizeof(buf));
	return rz_read_le64(buf);
}

static inline ut32 read_slot32(RzDebug *dbg, PE64_UNWIND_INFO *info, int *index) {
	ut32 ret = rz_read_le32(&info->UnwindCode[*index]);
	*index += 2;
	return ret;
}

static inline ut16 read_slot16(RzDebug *dbg, PE64_UNWIND_INFO *info, int *index) {
	ut16 ret = rz_read_le16(&info->UnwindCode[*index]);
	*index += 1;
	return ret;
}

// Decides if current rsp or another register is used as the frame base (eg. rbp, etc)
static inline ut64 get_frame_base(const PE64_UNWIND_INFO *info, const struct context_type_amd64 *context, const ut64 function_address) {
	const ut64 rip_offset_to_function = context->rip - function_address;
	const ut64 *integer_registers = &context->rax;
	if (!info->FrameRegister) {
		// There is no register being used as the frame base, use rsp
		return context->rsp;
	} else if ((rip_offset_to_function >= info->SizeOfProlog) || ((info->Flags & PE64_UNW_FLAG_CHAININFO) != 0)) {
		// There is a register being used as a frame base, and we definetly already set it
		return integer_registers[info->FrameRegister] - info->FrameOffset * 16;
	} else {
		// There is a register being used as a frame base, unknown if we set it yet
		int i;
		// Find unwind of where frame register is being set
		for (i = 0; i < info->CountOfCodes; i++) {
			if (info->UnwindCode[i].UnwindOp == UWOP_SET_FPREG) {
				break;
			}
		}
		// Check if we already set the frame register
		if (rip_offset_to_function >= info->UnwindCode[i].CodeOffset) {
			return integer_registers[info->FrameRegister] - info->FrameOffset * 16;
		} else {
			return context->rsp;
		}
	}
}

static inline PE64_UNWIND_INFO *read_unwind_info(RzDebug *dbg, ut64 at) {
	PE64_UNWIND_INFO *info = RZ_NEW0(PE64_UNWIND_INFO);
	if (!info) {
		return NULL;
	}
	READ_AT(at, (ut8 *)info, sizeof(*info));
	const size_t unwind_code_array_sz = info->CountOfCodes * sizeof(PE64_UNWIND_CODE);
	void *tmp = realloc(info, sizeof(PE64_UNWIND_INFO) + unwind_code_array_sz);
	if (!tmp) {
		free(info);
		return NULL;
	}
	info = tmp;
	READ_AT(at + rz_offsetof(PE64_UNWIND_INFO, UnwindCode), (ut8 *)info->UnwindCode, unwind_code_array_sz);
	return info;
}

static inline bool unwind_function(
	RzDebug *dbg,
	RzDebugFrame *frame,
	PE64_RUNTIME_FUNCTION *rfcn,
	struct context_type_amd64 *context,
	const ut64 module_address,
	const ut64 function_address) {

	bool is_chained = false;
	ut64 *integer_registers = &context->rax;
	ut64 machine_frame_start;
	bool is_machine_frame = false;

	ut64 unwind_info_address = module_address + rfcn->UnwindInfoAddress;

	// Read initial unwind info structure
	PE64_UNWIND_INFO *info = read_unwind_info(dbg, unwind_info_address);
	if (!info) {
		return false;
	}

	// Get address that is used as the base for stack accesses
	ut64 frame_base = get_frame_base(info, context, function_address);

process_chained_info:
	if (info->Version != 1 && info->Version != 2) {
		// Version 1 found in user-space, version 2 in kernel
		RZ_LOG_ERROR("Unwind info version (%" PFMT32d ") for function 0x%" PFMT64x " is not recognized\n",
			(ut32)info->Version, function_address);
		free(info);
		return false;
	}
	int i = 0;
	while (i < info->CountOfCodes) {
		const PE64_UNWIND_CODE code = info->UnwindCode[i];
		i++;
		// Check if we are already past the prolog instruction
		// If we are processing a chained scope, always process all of them
		if (!is_chained && context->rip < function_address + code.CodeOffset) {
			// Skip, as it wasn't executed yet
			switch (code.UnwindOp) {
			case UWOP_ALLOC_LARGE:
				i++;
				if (code.OpInfo) {
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
		switch (code.UnwindOp) {
		case UWOP_PUSH_NONVOL: /* info == register number */
			integer_registers[code.OpInfo] = read_register(dbg, context->rsp);
			context->rsp += 8;
			break;
		case UWOP_ALLOC_LARGE: /* info == unscaled or scaled, alloc size in next 1 or 2 slots */
			if (code.OpInfo) {
				context->rsp += read_slot32(dbg, info, &i);
			} else {
				context->rsp += read_slot16(dbg, info, &i) * 8;
			}
			break;
		case UWOP_ALLOC_SMALL: /* info == size of allocation / 8 - 1 */
			context->rsp += code.OpInfo * 8 + 8;
			break;
		case UWOP_SET_FPREG: /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
			frame->bp = integer_registers[info->FrameRegister];
			context->rsp = integer_registers[info->FrameRegister] - info->FrameOffset * 16;
			break;
		case UWOP_SAVE_NONVOL: /* info == register number, offset in next slot */
			offset = read_slot16(dbg, info, &i) * 8;
			integer_registers[code.OpInfo] = read_register(dbg, frame_base + offset);
			break;
		case UWOP_SAVE_XMM128: /* info == XMM reg number, offset in next slot */
		case UWOP_UNKNOWN1: /* 1 extra slot */
			i++;
			break;
		case UWOP_SAVE_NONVOL_FAR: /* info == register number, offset in next 2 slots */
			offset = read_slot32(dbg, info, &i);
			integer_registers[code.OpInfo] = read_register(dbg, frame_base + offset);
			break;
		case UWOP_SAVE_XMM128_FAR: /* info == XMM reg number, offset in next 2 slots */
		case UWOP_UNKNOWN2: /* 2 extra slots */
			i += 2;
			break;
		case UWOP_PUSH_MACHFRAME: /* info == 0: no error-code, 1: error-code */
			if (code.OpInfo) {
				context->rsp += 8;
			}
			is_machine_frame = true;
			machine_frame_start = context->rsp + 40;
			context->rip = read_register(dbg, context->rsp);
			context->rsp = read_register(dbg, context->rsp + 24);
			break;
		}
	}
	if (info->Flags & PE64_UNW_FLAG_CHAININFO) {
		if (i % 2) {
			i++;
		}

		// Read chained RUNTIME_FUNCTION
		const ut64 chained_fcn_address = unwind_info_address + rz_offsetof(PE64_UNWIND_INFO, UnwindCode[i]);
		ut8 buf[sizeof(PE64_RUNTIME_FUNCTION)];
		READ_AT(chained_fcn_address, buf, sizeof(buf));

		// Get unwind info from the chained RUNTIME_FUNCTION
		unwind_info_address = module_address + rz_read_le32(buf + rz_offsetof(PE64_RUNTIME_FUNCTION, UnwindInfoAddress));
		free(info);
		info = read_unwind_info(dbg, unwind_info_address);
		if (!info) {
			return false;
		}

		// Make sure we process all the chained unwind ops
		is_chained = true;
		goto process_chained_info;
	}
	if (is_machine_frame) {
		frame->size = machine_frame_start - frame->sp;
	} else {
		frame->size = context->rsp - frame->sp;
		context->rip = read_register(dbg, context->rsp);
		context->rsp += 8;
	}
	free(info);
	return true;
}

static bool backtrace_windows_x64(RZ_IN RzDebug *dbg, RZ_INOUT RzList **out_frames, RZ_INOUT struct context_type_amd64 *context) {
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
		int arena_size;
		ut8 *arena = rz_reg_get_bytes(dbg->reg, RZ_REG_TYPE_GPR, &arena_size);
		if (!arena || arena_size < sizeof(*context)) {
			rz_list_free(modules);
			return true;
		}
		memcpy(context, arena, sizeof(*context));
		free(arena);
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
			context->rip = read_register(dbg, context->rsp);
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
