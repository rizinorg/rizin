#include <rz_demangler.h>
#include <rz_libdemangle.h>

RZ_API RzDemanglerPlugin rz_demangler_plugin_msvc = {
	.language = "msvc",
	.license = "LGPL3",
	.author = "inisider",
	.demangle = &libdemangle_handler_msvc,
};
