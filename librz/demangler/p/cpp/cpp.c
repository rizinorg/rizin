#include <rz_demangler.h>
#include <rz_libdemangle.h>

RZ_API RzDemanglerPlugin rz_demangler_plugin_cpp = {
	.language = "c++",
	.license = "GPL-2",
	.author = "Free Software Foundation",
	.demangle = &libdemangle_handler_cxx,
};
