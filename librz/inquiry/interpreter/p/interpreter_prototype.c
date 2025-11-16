// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_inquiry.h>

bool eval(RZ_NONNULL RZ_BORROW RzInterpreterAbstrState *state,
	RZ_NONNULL const RzILOpEffect *effect,
	RZ_NONNULL RZ_BORROW HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	void *plugin_data) {
	RZ_LOG_WARN("Hello from Protoype eval.\n");
	return true;
}

static RzInterpreterPlugin rz_interpreter_plugin_prototype = {
	.name = "abstr_int_prototype",
	.author = "Rot127",
	.version = "0.1p",
	.desc = "A prototype interpreter for constant/bottom abstractions.",
	.license = "LGPL-3.0-only",
	.supported_abstractions = RZ_INTERPRETER_ABSTRACTION_CONST,
	.supported_yields = RZ_INTERPRETER_YIELD_KIND_XREF,
	.init = NULL,
	.fini = NULL,
	.eval = eval,
};

RZ_API RzInquiryPlugin rz_inquiry_plugin_interpreter_prototype = {
	.p_interpreter = &rz_interpreter_plugin_prototype,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_INTERPRETER,
	.data = &interpreter_prototype
};
#endif
