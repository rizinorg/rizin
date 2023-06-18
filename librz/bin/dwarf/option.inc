typedef void (*OptionFree)(void *);

typedef struct {
	int valid; // A flag to indicate if the value is present (1) or not (0)
	void *data; // The actual value (as a void pointer)
	size_t size; // Size of the data pointed to by value
	OptionFree free;
} Option;

typedef Option *(*OptionAction)(void *);

Option *Option_new(void *data, size_t size, OptionFree free_func) {
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

#define some(x) Option_new(x, sizeof(*x), (OptionFree)free)

Option *none() {
	Option *opt = RZ_NEW0(Option);
	if (!opt) {
		return NULL;
	}
	return opt;
}

void Option_free(Option *opt) {
	if (opt->valid && opt->free) {
		opt->free(opt->data);
	}
	free(opt);
}

Option *Option_map(Option *option, OptionAction action) {
	if (option->valid) {
		return action(option->data);
	}
	return option;
}
