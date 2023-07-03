#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_IPI Option *Option_new(void *data, size_t size, OptionFree free_func) {
	Option *opt = RZ_NEW0(Option);
	if (!opt) {
		return NULL;
	}
	opt->valid = 1;
	opt->data = malloc(size);
	if (!opt->data) {
		free(opt);
		return NULL;
	}
	opt->size = size;
	opt->free = free_func;
	if (opt->data) {
		memcpy(opt->data, data, size);
	}
	return opt;
}

RZ_IPI Option *none() {
	Option *opt = RZ_NEW0(Option);
	if (!opt) {
		return NULL;
	}
	return opt;
}

RZ_IPI void Option_free(Option *opt) {
	if (opt->valid && opt->free) {
		opt->free(opt->data);
	}
	free(opt);
}

RZ_IPI Option *Option_map(Option *option, OptionAction action) {
	if (option->valid) {
		return action(option->data);
	}
	return option;
}
