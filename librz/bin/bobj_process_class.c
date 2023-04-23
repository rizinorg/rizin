// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

typedef struct process_class_ctx_s {
	RzBinObject *object;
	bool filter_name;
	RzThreadLock *lock;
	RzThreadHtPP *classes; ///< name to class
	RzThreadHtPP *methods; ///< glue(class#name#vaddr) to class method
	RzThreadHtPP *fields; ///< glue(class#name#vaddr) to class field
	RzThreadHtUP *vaddr; ///< vaddr to class method
} process_class_ctx_t;

static void process_class_method(process_class_ctx_t *ctx, RzBinSymbol *method) {
	// rebase physical address
	method->paddr += ctx->object->opts.loadaddr;

	char *key = rz_str_newf(RZ_BIN_FMT_CLASS_HT_GLUE, method->classname, method->name, method->vaddr);
	if (!key) {
		RZ_LOG_ERROR("bin: failed to allocate class-method string\n");
		return;
	}

	if (!rz_th_ht_pp_find(ctx->methods, key, NULL)) {
		rz_th_ht_pp_insert(ctx->methods, key, method);
	}
	free(key);
}

static void process_class_field(process_class_ctx_t *ctx, RzBinClassField *field) {
	// rebase physical address
	field->paddr += ctx->object->opts.loadaddr;

	char *key = rz_str_newf(RZ_BIN_FMT_CLASS_HT_GLUE, field->classname, field->name, field->vaddr);
	if (!key) {
		RZ_LOG_ERROR("bin: failed to allocate class-field string\n");
		return;
	}

	if (!rz_th_ht_pp_find(ctx->fields, key, NULL)) {
		rz_th_ht_pp_insert(ctx->fields, key, field);
	}
	free(key);
}

static void process_handle_class(RzBinClass *klass, process_class_ctx_t *ctx) {
	if (!rz_th_ht_pp_find(ctx->classes, klass->name, NULL)) {
		rz_th_ht_pp_insert(ctx->classes, klass->name, klass);
	} else if (ctx->filter_name) {
		char *name = rz_str_newf("%s_%08" PFMT64x, klass->name, klass->addr);
		free(klass->name);
		klass->name = name;
		rz_th_ht_pp_insert(ctx->classes, klass->name, klass);
	}

	RzListIter *iter;
	RzBinSymbol *method;
	RzBinClassField *field;
	rz_list_foreach (klass->methods, iter, method) {
		process_class_method(ctx, method);
	}

	rz_list_foreach (klass->fields, iter, field) {
		process_class_field(ctx, field);
	}

	rz_list_sort(klass->methods, (RzListComparator)rz_bin_compare_method);
	rz_list_sort(klass->fields, (RzListComparator)rz_bin_compare_class_field);
}

static void set_and_process_classes(RzBinFile *bf, RzBinObject *o) {
	RzBin *bin = bf->rbin;
	RzBinPlugin *plugin = o->plugin;

	rz_list_free(o->classes);
	if (!(bin->filter_rules & (RZ_BIN_REQ_CLASSES | RZ_BIN_REQ_CLASSES_SOURCES)) ||
		!plugin->classes || !(o->classes = plugin->classes(bf))) {
		o->classes = rz_list_newf((RzListFree)rz_bin_class_free);
	}
	rz_warn_if_fail(o->classes->free);

	ht_pp_free(o->name_to_class_object);
	ht_pp_free(o->glue_to_class_method);
	ht_pp_free(o->glue_to_class_field);
	ht_up_free(o->vaddr_to_class_method);

	process_class_ctx_t ctx = {
		.object = o,
		.filter_name = bin->filter,
		.classes = rz_th_ht_pp_new0(),
		.methods = rz_th_ht_pp_new0(),
		.fields = rz_th_ht_pp_new0(),
		.vaddr = rz_th_ht_up_new0(),
	};

	if (!ctx.classes || !ctx.methods || !ctx.fields || !ctx.vaddr) {
		RZ_LOG_ERROR("bin: failed to allocate RzThread data for class & field process\n");
		goto fail;
	}

	rz_th_iterate_list(o->classes, (RzThreadIterator)process_handle_class, RZ_THREAD_POOL_ALL_CORES, &ctx);

	o->name_to_class_object = rz_th_ht_pp_move(ctx.classes);
	o->glue_to_class_method = rz_th_ht_pp_move(ctx.methods);
	o->glue_to_class_field = rz_th_ht_pp_move(ctx.fields);
	o->vaddr_to_class_method = rz_th_ht_up_move(ctx.vaddr);

fail:
	rz_th_ht_pp_free(ctx.classes);
	rz_th_ht_pp_free(ctx.methods);
	rz_th_ht_pp_free(ctx.fields);
	rz_th_ht_up_free(ctx.vaddr);
}
