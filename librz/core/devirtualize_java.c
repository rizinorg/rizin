// SPDX-FileCopyrightText: 2026 historicattle <sirigere.naren@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_core.h>
#include "core_private.h"
#include "../bin/format/java/class_bin.h"

typedef struct java_value_t {
	const char *type;
	ut64 allocation;
	ut8 width;
	bool initialized;
} JavaValue;

typedef struct java_frame_t {
	JavaValue *locals;
	JavaValue *stack;
	ut16 local_count;
	ut16 capacity;
	ut16 count;
	ut16 depth;
} JavaFrame;

typedef struct java_descriptor_t {
	ut16 arguments;
	ut16 slots;
	ut8 return_width;
} JavaDescriptor;

typedef struct java_target_t {
	RzBinFile *file;
	const char *owner;
	RzBinJavaMethodInfo method;
} JavaTarget;

typedef struct java_call_t {
	ut64 addr;
	RzPVector *targets;
} JavaCall;

typedef struct java_context_t {
	RzCore *core;
	RzBinJavaClass *bin;
	RzStrConstPool strings;
	RzVector calls;
	bool emit;
} JavaContext;

typedef struct java_block_t {
	RzAnalysisBlock *block;
	JavaFrame input;
	bool reached;
	bool queued;
} JavaBlock;

static const char *intern(JavaContext *ctx, RZ_OWN char *text) {
	const char *result = NULL;
	if (text) {
		result = rz_str_constpool_get(&ctx->strings, text);
	}
	free(text);
	return result;
}

static bool type_width(const char **cursor, ut8 *width) {
	const char *p = *cursor;
	while (*p == '[') {
		p++;
	}
	*width = 1;
	switch (*p++) {
	case 'J':
	case 'D':
		*width = 2;
		break;
	case 'B':
	case 'C':
	case 'F':
	case 'I':
	case 'S':
	case 'Z':
		break;
	case 'L':
		if (!*p || *p == ';') {
			return false;
		}
		while (*p && *p != ';') {
			p++;
		}
		if (*p++ != ';') {
			return false;
		}
		break;
	default:
		return false;
	}
	*width = **cursor == '[' ? 1 : *width;
	*cursor = p;
	return true;
}

static bool descriptor(const char *text, JavaDescriptor *descriptor) {
	memset(descriptor, 0, sizeof(*descriptor));
	if (!text || *text++ != '(') {
		return false;
	}
	while (*text && *text != ')') {
		ut8 width;
		if (!type_width(&text, &width) || descriptor->slots + width > 255) {
			return false;
		}
		descriptor->arguments++;
		descriptor->slots += width;
	}
	if (*text++ != ')') {
		return false;
	}
	if (*text == 'V') {
		text++;
	} else if (!type_width(&text, &descriptor->return_width)) {
		return false;
	}
	return !*text;
}

static const char *class_name(JavaContext *ctx, RzBinJavaClass *bin) {
	return intern(ctx, rz_bin_java_class_name(bin));
}

static const char *class_type(JavaContext *ctx, RzBinJavaClass *bin, ut16 index) {
	return intern(ctx, rz_bin_java_class_const_pool_resolve_index(bin, index));
}

static RzBinFile *loaded_class(JavaContext *ctx, const char *type) {
	RzBinFile *file;
	RzBinFile *result = NULL;
	RzListIter *it;
	rz_list_foreach (ctx->core->bin->binfiles, it, file) {
		RzBinObject *object = file->o;
		if (!object || object->lang != RZ_BIN_LANGUAGE_JAVA || !object->bin_obj ||
			!RZ_STR_EQ(class_name(ctx, object->bin_obj), type)) {
			continue;
		}
		if (result) {
			return NULL;
		}
		result = file;
	}
	return result;
}

static bool subtype(JavaContext *ctx, const char *type, const char *base, unsigned depth) {
	if (!type || !base || depth > 64) {
		return false;
	}
	if (!strcmp(type, base)) {
		return true;
	}
	RzBinFile *file = loaded_class(ctx, type);
	if (!file) {
		return false;
	}
	RzBinJavaClass *bin = file->o->bin_obj;
	const char *super = NULL;
	if (strcmp(type, "Ljava/lang/Object;")) {
		super = intern(ctx, rz_bin_java_class_super(bin));
	}
	if (super && subtype(ctx, super, base, depth + 1)) {
		return true;
	}
	for (ut32 i = 0; i < rz_bin_java_class_interface_count(bin); i++) {
		const char *interface = intern(ctx, rz_bin_java_class_interface_name(bin, i));
		if (interface && subtype(ctx, interface, base, depth + 1)) {
			return true;
		}
	}
	return false;
}

static bool lookup(JavaContext *ctx, const char *type, const char *name, const char *descriptor, bool virtual_only, JavaTarget *target) {
	for (unsigned depth = 0; type && depth < 64; depth++) {
		RzBinFile *file = loaded_class(ctx, type);
		if (!file) {
			return false;
		}
		RzBinJavaClass *bin = file->o->bin_obj;
		for (ut32 i = 0; i < rz_bin_java_class_method_count(bin); i++) {
			RzBinJavaMethodInfo method;
			if (!rz_bin_java_class_method(bin, i, &method)) {
				continue;
			}
			bool eligible = !virtual_only || !(method.access_flags & (METHOD_ACCESS_FLAG_STATIC | METHOD_ACCESS_FLAG_PRIVATE));
			if (eligible && !strcmp(method.name, name) && !strcmp(method.descriptor, descriptor)) {
				*target = (JavaTarget){ .file = file, .owner = type, .method = method };
				return true;
			}
			rz_bin_java_method_info_fini(&method);
		}
		if (!strcmp(type, "Ljava/lang/Object;")) {
			type = NULL;
		} else {
			type = intern(ctx, rz_bin_java_class_super(bin));
		}
	}
	return false;
}

static void virtual_xref(RzCore *core, const char *name, ut64 addr) {
	HtSP *xrefs = rz_analysis_get_virtual_xrefs(core->analysis);
	if (!xrefs) {
		return;
	}
	RzSetU *set = ht_sp_find(xrefs, name, NULL);
	if (!set) {
		set = rz_set_u_new();
		if (!set || !ht_sp_insert(xrefs, name, set)) {
			rz_set_u_free(set);
			return;
		}
	}
	rz_set_u_add(set, addr);
}

static void call_fini(void *element, RZ_UNUSED void *user) {
	JavaCall *call = element;
	rz_pvector_free(call->targets);
}

static int target_cmp(const char *a, const char *b, RZ_UNUSED void *user) {
	return strcmp(a, b);
}

static void call_add(JavaContext *ctx, ut64 addr, RZ_OWN char *target) {
	JavaCall *call = NULL;
	JavaCall *candidate;
	rz_vector_foreach (&ctx->calls, candidate) {
		if (candidate->addr == addr) {
			call = candidate;
			break;
		}
	}
	if (!call) {
		JavaCall fresh = { .addr = addr, .targets = rz_pvector_new(free) };
		if (!fresh.targets || !rz_vector_push(&ctx->calls, &fresh)) {
			rz_pvector_free(fresh.targets);
			free(target);
			return;
		}
		call = rz_vector_tail(&ctx->calls);
	}
	void **it;
	rz_pvector_foreach (call->targets, it) {
		if (!strcmp(*it, target)) {
			free(target);
			return;
		}
	}
	rz_pvector_push(call->targets, target);
}

static void calls_emit(JavaContext *ctx) {
	JavaCall *call;
	rz_vector_foreach (&ctx->calls, call) {
		rz_pvector_sort(call->targets, (RzPVectorComparator)target_cmp, NULL);
		RzStrBuf text;
		rz_strbuf_init(&text);
		void **it;
		rz_pvector_foreach (call->targets, it) {
			if (rz_strbuf_length(&text)) {
				rz_strbuf_append(&text, " / ");
			} else {
				rz_strbuf_append(&text, "Java Virtual Call: ");
			}
			rz_strbuf_append(&text, *it);
		}
		const char *comment = rz_strbuf_get(&text);
		const char *old = rz_meta_get_string(ctx->core->analysis, RZ_META_TYPE_COMMENT, call->addr);
		if (*comment && (!old || !strstr(old, comment))) {
			char *combined;
			if (old && *old) {
				combined = rz_str_newf("%s\n%s", old, comment);
			} else {
				combined = rz_str_dup(comment);
			}
			if (combined) {
				rz_meta_set_string(ctx->core->analysis, RZ_META_TYPE_COMMENT, call->addr, combined);
				free(combined);
			}
		}
		rz_strbuf_fini(&text);
	}
}

static void emit_call(JavaContext *ctx, JavaValue receiver, const RzBinJavaMemberInfo *member, ut64 addr) {
	if (!receiver.type || !receiver.initialized || !strcmp(member->owner, "Ljava/lang/invoke/MethodHandle;") ||
		!strcmp(member->owner, "Ljava/lang/invoke/VarHandle;") || !subtype(ctx, receiver.type, member->owner, 0)) {
		return;
	}
	JavaTarget resolved;
	if (!lookup(ctx, member->owner, member->name, member->descriptor, false, &resolved)) {
		return;
	}
	bool eligible = (resolved.method.access_flags & METHOD_ACCESS_FLAG_PUBLIC) && !(resolved.method.access_flags & METHOD_ACCESS_FLAG_STATIC);
	rz_bin_java_method_info_fini(&resolved.method);
	JavaTarget target;
	if (!eligible || !lookup(ctx, receiver.type, member->name, member->descriptor, true, &target)) {
		return;
	}
	if (!(target.method.access_flags & METHOD_ACCESS_FLAG_PUBLIC) || (target.method.access_flags & METHOD_ACCESS_FLAG_ABSTRACT)) {
		rz_bin_java_method_info_fini(&target.method);
		return;
	}
	char *class_name = rz_str_ndup(target.owner + 1, strlen(target.owner) - 2);
	if (class_name) {
		rz_str_replace_char(class_name, '/', '.');
	}
	char *identity = NULL;
	if (class_name) {
		identity = rz_str_newf("%s.%s%s", class_name, member->name, member->descriptor);
	}
	if (identity) {
		virtual_xref(ctx->core, identity, addr);
		call_add(ctx, addr, identity);
	}
	free(class_name);
	ut64 destination = target.method.code_addr;
	if (destination != UT64_MAX && target.method.code_size) {
		destination = rz_bin_object_addr_with_base(target.file->o, destination);
		RzIOMap *map = rz_io_map_get(ctx->core->io, destination);
		bool mapped;
		if (ctx->core->io->va) {
			mapped = map && map->fd == target.file->fd;
		} else {
			mapped = rz_core_file_cur_fd(ctx->core) == target.file->fd;
		}
		if (mapped && rz_io_is_valid_offset(ctx->core->io, destination, RZ_PERM_R)) {
			rz_analysis_xrefs_set(ctx->core->analysis, addr, destination, RZ_ANALYSIS_XREF_TYPE_CALL);
		}
	}
	rz_bin_java_method_info_fini(&target.method);
}

static bool frame_init(JavaFrame *frame, ut16 locals, ut16 stack) {
	*frame = (JavaFrame){ .local_count = locals, .capacity = stack };
	frame->locals = RZ_NEWS0(JavaValue, locals);
	frame->stack = RZ_NEWS0(JavaValue, stack);
	if ((!locals || frame->locals) && (!stack || frame->stack)) {
		return true;
	}
	free(frame->locals);
	free(frame->stack);
	*frame = (JavaFrame){ 0 };
	return false;
}

static void frame_fini(JavaFrame *frame) {
	free(frame->locals);
	free(frame->stack);
}

static bool frame_copy(JavaFrame *dst, const JavaFrame *src) {
	if (!frame_init(dst, src->local_count, src->capacity)) {
		return false;
	}
	dst->count = src->count;
	dst->depth = src->depth;
	if (src->local_count) {
		memcpy(dst->locals, src->locals, sizeof(JavaValue) * src->local_count);
	}
	if (src->count) {
		memcpy(dst->stack, src->stack, sizeof(JavaValue) * src->count);
	}
	return true;
}

static bool push(JavaFrame *frame, JavaValue value) {
	if (!value.width || frame->count >= frame->capacity || frame->depth + value.width > frame->capacity) {
		return false;
	}
	frame->stack[frame->count++] = value;
	frame->depth += value.width;
	return true;
}

static bool pop(JavaFrame *frame, JavaValue *value) {
	if (!frame->count) {
		return false;
	}
	*value = frame->stack[--frame->count];
	frame->depth -= value->width;
	return true;
}

static bool drop(JavaFrame *frame, unsigned count, unsigned slots) {
	unsigned depth = frame->depth;
	JavaValue value;
	for (unsigned i = 0; i < count; i++) {
		if (!pop(frame, &value)) {
			return false;
		}
	}
	return depth - frame->depth == slots;
}

static bool frame_merge(JavaFrame *dst, const JavaFrame *src) {
	if (dst->count != src->count || dst->depth != src->depth) {
		return false;
	}
	for (ut16 i = 0; i < dst->count; i++) {
		if (dst->stack[i].width != src->stack[i].width) {
			return false;
		}
	}
	bool changed = false;
	for (ut32 i = 0; i < (ut32)dst->local_count + dst->count; i++) {
		JavaValue *a;
		const JavaValue *b;
		if (i < dst->local_count) {
			a = &dst->locals[i];
			b = &src->locals[i];
		} else {
			a = &dst->stack[i - dst->local_count];
			b = &src->stack[i - src->local_count];
		}
		if (a->width != b->width || a->type != b->type || a->allocation != b->allocation || a->initialized != b->initialized) {
			JavaValue merged = { .width = a->width == b->width ? a->width : 0 };
			if (memcmp(a, &merged, sizeof(*a))) {
				*a = merged;
				changed = true;
			}
		}
	}
	return changed;
}

static bool load(JavaFrame *frame, ut8 opcode, ut16 index) {
	JavaValue value = { .width = opcode == rz_analysis_java_opcode_byname("lload") || opcode == rz_analysis_java_opcode_byname("dload") ? 2 : 1 };
	if ((ut32)index + value.width > frame->local_count) {
		return false;
	}
	if (opcode == rz_analysis_java_opcode_byname("aload") && frame->locals[index].width == 1) {
		value = frame->locals[index];
	}
	return push(frame, value);
}

static bool store(JavaFrame *frame, ut8 opcode, ut16 index) {
	ut8 width = opcode == rz_analysis_java_opcode_byname("lstore") || opcode == rz_analysis_java_opcode_byname("dstore") ? 2 : 1;
	JavaValue value;
	if ((ut32)index + width > frame->local_count || !pop(frame, &value) || value.width != width) {
		return false;
	}
	if (index && frame->locals[index - 1].width == 2) {
		frame->locals[index - 1] = (JavaValue){ 0 };
	}
	if (width == 2 || frame->locals[index].width == 2) {
		frame->locals[index + 1] = (JavaValue){ 0 };
	}
	if (opcode == rz_analysis_java_opcode_byname("astore")) {
		frame->locals[index] = value;
	} else {
		frame->locals[index] = (JavaValue){ .width = width };
	}
	return true;
}

/**
 * \brief Apply the stack and receiver effects of a Java field access or invocation.
 *
 * Uses the member descriptor to consume operands and produce unknown results.
 * Matching constructor calls initialize tracked aliases of the receiver;
 * virtual and interface calls are resolved when ctx->emit is enabled.
 */
static bool track_member(JavaContext *ctx, JavaFrame *frame, ut8 opcode, ut16 index, ut64 addr) {
	RzBinJavaMemberInfo member;
	if (!rz_bin_java_class_member(ctx->bin, index, &member)) {
		return false;
	}
	bool field = opcode >= rz_analysis_java_opcode_byname("getstatic") && opcode <= rz_analysis_java_opcode_byname("putfield");
	bool valid_kind;
	if (field) {
		valid_kind = member.kind == RZ_BIN_JAVA_MEMBER_FIELD;
	} else {
		valid_kind = member.kind == RZ_BIN_JAVA_MEMBER_METHOD || member.kind == RZ_BIN_JAVA_MEMBER_INTERFACE_METHOD;
	}
	JavaValue value = { .width = 1 };
	bool ok = valid_kind;
	if (ok && field) {
		const char *cursor = member.descriptor;
		bool put = opcode == rz_analysis_java_opcode_byname("putstatic") || opcode == rz_analysis_java_opcode_byname("putfield");
		ok = type_width(&cursor, &value.width) && !*cursor && (!put || drop(frame, 1, value.width));
		if (ok && (opcode == rz_analysis_java_opcode_byname("getfield") || opcode == rz_analysis_java_opcode_byname("putfield"))) {
			ok = drop(frame, 1, 1);
		}
		if (ok && !put) {
			ok = push(frame, value);
		}
	} else if (ok) {
		JavaDescriptor shape;
		bool instance = opcode != rz_analysis_java_opcode_byname("invokestatic");
		ok = descriptor(member.descriptor, &shape) && drop(frame, shape.arguments, shape.slots);
		if (ok && instance) {
			ok = pop(frame, &value) && value.width == 1;
			if (ok && opcode == rz_analysis_java_opcode_byname("invokespecial") && !strcmp(member.name, "<init>") && value.type && !value.initialized) {
				ok = !strcmp(value.type, member.owner) && !shape.return_width;
				for (ut32 i = 0; ok && i < (ut32)frame->local_count + frame->count; i++) {
					JavaValue *alias;
					if (i < frame->local_count) {
						alias = &frame->locals[i];
					} else {
						alias = &frame->stack[i - frame->local_count];
					}
					if (alias->type == value.type && alias->allocation == value.allocation) {
						alias->initialized = true;
					}
				}
			} else if (ok && ctx->emit && (opcode == rz_analysis_java_opcode_byname("invokevirtual") || opcode == rz_analysis_java_opcode_byname("invokeinterface"))) {
				emit_call(ctx, value, &member, addr);
			}
		}
		if (ok && shape.return_width) {
			ok = push(frame, (JavaValue){ .width = shape.return_width });
		}
	}
	rz_bin_java_member_info_fini(&member);
	return ok;
}

static bool stack_op(JavaFrame *frame, ut8 opcode) {
	JavaValue value;
	if (opcode == rz_analysis_java_opcode_byname("pop") || opcode == rz_analysis_java_opcode_byname("pop2")) {
		if (!pop(frame, &value)) {
			return false;
		}
		if (opcode == rz_analysis_java_opcode_byname("pop")) {
			return value.width == 1;
		}
		return value.width == 2 || drop(frame, 1, 1);
	}
	if (opcode == rz_analysis_java_opcode_byname("dup")) {
		return frame->count && frame->stack[frame->count - 1].width == 1 && push(frame, frame->stack[frame->count - 1]);
	}
	if (opcode == rz_analysis_java_opcode_byname("swap") && frame->count >= 2 && frame->stack[frame->count - 1].width == 1 && frame->stack[frame->count - 2].width == 1) {
		value = frame->stack[frame->count - 1];
		frame->stack[frame->count - 1] = frame->stack[frame->count - 2];
		frame->stack[frame->count - 2] = value;
		return true;
	}
	return false;
}

/**
 * \brief Interpret one supported Java bytecode in the abstract receiver frame.
 *
 * Normalizes implicit local indices and updates locals and the operand stack.
 * Member operations may emit call annotations through track_member(). Control
 * flow propagation is handled separately by the caller.
 */
static bool step(JavaContext *ctx, JavaFrame *frame, const RzAnalysisOp *op, const ut8 *opcode) {
	ut8 bytecode = opcode[0];
	JavaValue value = { .width = 1 };

	if (bytecode == rz_analysis_java_opcode_byname("nop")) {
		return true;
	}

	if (bytecode >= rz_analysis_java_opcode_byname("aconst_null") && bytecode <= rz_analysis_java_opcode_byname("ldc2_w")) {
		bool wide = bytecode == rz_analysis_java_opcode_byname("lconst_0") || bytecode == rz_analysis_java_opcode_byname("lconst_1") ||
			bytecode == rz_analysis_java_opcode_byname("dconst_0") || bytecode == rz_analysis_java_opcode_byname("dconst_1") ||
			bytecode == rz_analysis_java_opcode_byname("ldc2_w");
		value.width = wide ? 2 : 1;
		return push(frame, value);
	}

	ut16 index = UT16_MAX;
	if ((bytecode >= rz_analysis_java_opcode_byname("iload") && bytecode <= rz_analysis_java_opcode_byname("aload")) ||
		(bytecode >= rz_analysis_java_opcode_byname("istore") && bytecode <= rz_analysis_java_opcode_byname("astore")) ||
		bytecode == rz_analysis_java_opcode_byname("iinc")) {
		index = opcode[1];
	} else if ((bytecode >= rz_analysis_java_opcode_byname("getstatic") && bytecode <= rz_analysis_java_opcode_byname("invokeinterface")) ||
		bytecode == rz_analysis_java_opcode_byname("new") || bytecode == rz_analysis_java_opcode_byname("checkcast")) {
		index = rz_read_be16(opcode + 1);
	}

	if (bytecode >= rz_analysis_java_opcode_byname("iload_0") && bytecode <= rz_analysis_java_opcode_byname("aload_3")) {
		index = (bytecode - rz_analysis_java_opcode_byname("iload_0")) % 4;
		bytecode = rz_analysis_java_opcode_byname("iload") + (bytecode - rz_analysis_java_opcode_byname("iload_0")) / 4;
	}

	if (bytecode >= rz_analysis_java_opcode_byname("istore_0") && bytecode <= rz_analysis_java_opcode_byname("astore_3")) {
		index = (bytecode - rz_analysis_java_opcode_byname("istore_0")) % 4;
		bytecode = rz_analysis_java_opcode_byname("istore") + (bytecode - rz_analysis_java_opcode_byname("istore_0")) / 4;
	}

	if (bytecode >= rz_analysis_java_opcode_byname("iload") && bytecode <= rz_analysis_java_opcode_byname("aload")) {
		return load(frame, bytecode, index);
	}

	if (bytecode >= rz_analysis_java_opcode_byname("istore") && bytecode <= rz_analysis_java_opcode_byname("astore")) {
		return store(frame, bytecode, index);
	}

	if (bytecode >= rz_analysis_java_opcode_byname("pop") && bytecode <= rz_analysis_java_opcode_byname("swap")) {
		return stack_op(frame, bytecode);
	}

	if (bytecode >= rz_analysis_java_opcode_byname("iadd") && bytecode <= rz_analysis_java_opcode_byname("drem")) {
		value.width = (bytecode - rz_analysis_java_opcode_byname("iadd")) % 2 ? 2 : 1;
		return drop(frame, 2, 2 * value.width) && push(frame, value);
	}

	if (bytecode == rz_analysis_java_opcode_byname("iinc")) {
		if (index >= frame->local_count) {
			return false;
		}
		frame->locals[index] = value;
		return true;
	}

	if (bytecode >= rz_analysis_java_opcode_byname("getstatic") && bytecode <= rz_analysis_java_opcode_byname("invokeinterface")) {
		return track_member(ctx, frame, bytecode, index, op->addr);
	}

	if (bytecode == rz_analysis_java_opcode_byname("new")) {
		value.type = class_type(ctx, ctx->bin, index);
		value.allocation = op->addr;
		return value.type && *value.type == 'L' && push(frame, value);
	}

	if (bytecode == rz_analysis_java_opcode_byname("checkcast")) {
		return class_type(ctx, ctx->bin, index) && frame->count && frame->stack[frame->count - 1].width == 1;
	}

	if ((bytecode >= rz_analysis_java_opcode_byname("ifeq") && bytecode <= rz_analysis_java_opcode_byname("ifle")) ||
		bytecode == rz_analysis_java_opcode_byname("ifnull") || bytecode == rz_analysis_java_opcode_byname("ifnonnull")) {
		return drop(frame, 1, 1);
	}

	if (bytecode >= rz_analysis_java_opcode_byname("if_icmpeq") && bytecode <= rz_analysis_java_opcode_byname("if_acmpne")) {
		return drop(frame, 2, 2);
	}

	return bytecode == rz_analysis_java_opcode_byname("goto") || bytecode == rz_analysis_java_opcode_byname("return");
}

static JavaBlock *block_at(JavaBlock *blocks, size_t count, ut64 addr) {
	for (size_t i = 0; i < count; i++) {
		if (blocks[i].block->addr == addr) {
			return &blocks[i];
		}
	}
	return NULL;
}

static void propagate(JavaBlock *blocks, size_t count, ut64 addr, const JavaFrame *frame) {
	JavaBlock *next = block_at(blocks, count, addr);
	if (!next) {
		return;
	}
	if (!next->reached) {
		next->reached = frame_copy(&next->input, frame);
		next->queued = next->reached;
	} else if (frame_merge(&next->input, frame)) {
		next->queued = true;
	}
}

static bool replay_block(JavaContext *ctx, const RzBinJavaMethodInfo *method, const ut8 *bytes, JavaBlock *entry, JavaFrame *output) {
	if (!frame_copy(output, &entry->input)) {
		return false;
	}
	ut32 start = entry->block->addr - method->code_addr;
	ut32 size = RZ_MIN(entry->block->size, method->code_size - start);
	RzAnalysisOp *op = rz_analysis_op_new();
	if (!size || !op) {
		rz_analysis_op_free(op);
		return false;
	}
	for (ut32 pc = 0; pc < size;) {
		if (rz_analysis_op(ctx->core->analysis, op, entry->block->addr + pc, bytes + start + pc,
			    size - pc, RZ_ANALYSIS_OP_MASK_BASIC) <= 0 ||
			op->size < 1 || !step(ctx, output, op, bytes + start + pc)) {
			rz_analysis_op_free(op);
			return false;
		}
		pc += op->size;
		rz_analysis_op_fini(op);
	}
	rz_analysis_op_free(op);
	return true;
}

static void analyze(JavaContext *ctx, RzAnalysisFunction *function, const RzBinJavaMethodInfo *method, const ut8 *bytes) {
	size_t count = rz_pvector_len(function->bbs);
	JavaBlock *blocks = RZ_NEWS0(JavaBlock, count);
	if (!blocks) {
		return;
	}
	for (size_t i = 0; i < count; i++) {
		blocks[i].block = rz_pvector_at(function->bbs, i);
	}
	JavaBlock *entry = block_at(blocks, count, method->code_addr);
	if (!entry || !frame_init(&entry->input, method->max_locals, method->max_stack)) {
		free(blocks);
		return;
	}
	entry->reached = entry->queued = true;
	for (;;) {
		JavaBlock *current = NULL;
		for (size_t i = 0; i < count; i++) {
			if (blocks[i].queued) {
				current = &blocks[i];
				break;
			}
		}
		if (!current || rz_cons_is_breaked()) {
			break;
		}
		current->queued = false;
		JavaFrame output = { 0 };
		if (!replay_block(ctx, method, bytes, current, &output)) {
			frame_fini(&output);
			continue;
		}
		if (current->block->jump != UT64_MAX) {
			propagate(blocks, count, current->block->jump, &output);
		}
		if (current->block->fail != UT64_MAX) {
			propagate(blocks, count, current->block->fail, &output);
		}
		frame_fini(&output);
	}
	ctx->emit = true;
	for (size_t i = 0; i < count; i++) {
		if (!blocks[i].reached) {
			continue;
		}
		JavaFrame output = { 0 };
		replay_block(ctx, method, bytes, &blocks[i], &output);
		frame_fini(&output);
		frame_fini(&blocks[i].input);
	}
	free(blocks);
}

static bool method_at(RzBinObject *object, RzBinJavaClass *bin, ut64 addr, RzBinJavaMethodInfo *result) {
	for (ut32 i = 0; i < rz_bin_java_class_method_count(bin); i++) {
		RzBinJavaMethodInfo method;
		if (!rz_bin_java_class_method(bin, i, &method)) {
			continue;
		}
		if (method.code_addr != UT64_MAX) {
			method.code_addr = rz_bin_object_addr_with_base(object, method.code_addr);
			if (addr >= method.code_addr && addr - method.code_addr < method.code_size) {
				*result = method;
				return true;
			}
		}
		rz_bin_java_method_info_fini(&method);
	}
	return false;
}

/**
 * \brief Devirtualize Java calls with exact receiver types in the current method.
 *
 * Frames flow through the existing CFG. Unsupported bytecodes stop only their
 * path; differing values merge to unknown. This intentionally leaves interface
 * defaults, package-private dispatch, invokedynamic, and caller inference alone.
 */
RZ_IPI void rz_core_analysis_devirtualize_java_methods(RZ_NULLABLE RzCore *core) {
	if (!core) {
		return;
	}
	RzBinObject *object = rz_bin_cur_object(core->bin);
	RzAnalysisFunction *function = rz_analysis_get_fcn_in(core->analysis, core->offset, RZ_ANALYSIS_FCN_TYPE_NULL);
	if (!object || object->lang != RZ_BIN_LANGUAGE_JAVA || !object->bin_obj) {
		return;
	}
	if (!function) {
		RZ_LOG_ERROR("Analyze the Java function first (af/aa)\n");
		return;
	}
	const RzAnalysisPlugin *plugin = rz_analysis_plugin_current(core->analysis);
	if (!plugin || !RZ_STR_EQ(plugin->arch, "java")) {
		RZ_LOG_ERROR("Java analysis plugin must be selected\n");
		return;
	}
	JavaContext ctx = { .core = core, .bin = object->bin_obj };
	RzBinJavaMethodInfo method;
	if (!method_at(object, ctx.bin, core->offset, &method)) {
		RZ_LOG_ERROR("Cannot find Java method at 0x%08" PFMT64x "\n", core->offset);
		return;
	}
	ut8 *bytes = NULL;
	if (method.code_size && method.code_size <= 65535) {
		bytes = malloc(method.code_size);
	}
	bool ready = bytes && rz_str_constpool_init(&ctx.strings);
	rz_vector_init(&ctx.calls, sizeof(JavaCall), call_fini, NULL);
	if (ready && method.code_addr <= UT64_MAX - method.code_size &&
		rz_io_nread_at(core->io, method.code_addr, bytes, method.code_size) == method.code_size) {
		rz_cons_break_push(NULL, NULL);
		analyze(&ctx, function, &method, bytes);
		rz_cons_break_pop();
		calls_emit(&ctx);
	}
	rz_vector_fini(&ctx.calls);
	if (ready) {
		rz_str_constpool_fini(&ctx.strings);
	}
	free(bytes);
	rz_bin_java_method_info_fini(&method);
}
