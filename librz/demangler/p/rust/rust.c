#include <rz_demangler.h>
#include <rz_libdemangle.h>

RZ_API RzDemanglerPlugin rz_demangler_plugin_rust = {
	.language = "rust",
	.license = "LGPL3",
	.author = "pancake",
	.demangle = &libdemangle_handler_rust,
};
