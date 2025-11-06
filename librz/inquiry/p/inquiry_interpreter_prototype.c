// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_inquiry.h>

bool interpret(
	ut64 entry_point,
	RZ_NONNULL RZ_BORROW RzThreadQueue /*<ut64>*/ *request_il,
	RZ_NONNULL RZ_BORROW RzThreadQueue /*<RzInquiryILQueueElement *>*/ *receive_il,
	RZ_NONNULL RZ_BORROW RzPVector /*<RzInquiryYieldQueue*>*/ *yield_queues) {
  return true;
}

static RzInquiryInterpreterPlugin interpreter_prototype = {
	.name = "abstr_int_prototype",
	.author = "Rot127",
	.version = "0.1p",
	.desc = "A prototype interpreter for constant/bottom abstractions.",
	.license = "LGPL-3.0-only",
	.supported_abstractions = RZ_INQUIRY_ABSTRACTION_CONST,
	.init = NULL,
	.fini = NULL,
	.interpret = interpret
};

RZ_API RzInquiryPlugin rz_inquiry_plugin_interpreter_prototype = {
	.p_interpreter = &interpreter_prototype,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_INTERPRETER,
	.data = &interpreter_prototype
};
#endif
