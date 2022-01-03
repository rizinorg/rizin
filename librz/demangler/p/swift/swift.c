#include <rz_demangler.h>
#include <rz_libdemangle.h>

RZ_API RzDemanglerPlugin rz_demangler_plugin_swift = {
	.language = "swift",
	.license = "MIT",
	.author = "pancake",
	.demangle = &libdemangle_handler_swift,
};
