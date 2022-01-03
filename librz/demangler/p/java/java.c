#include <rz_demangler.h>
#include <rz_libdemangle.h>

RZ_API RzDemanglerPlugin rz_demangler_plugin_java = {
	.language = "java",
	.license = "LGPL3",
	.author = "deroad",
	.demangle = &libdemangle_handler_java,
};
