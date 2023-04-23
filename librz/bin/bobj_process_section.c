// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

typedef struct process_section_s {
	ut64 loadaddr;
	RzThreadHtPP *db;
} process_section_t;

static void process_handle_section(RzBinSection *section, process_section_t *process) {
	// rebase physical address
	section->paddr += process->loadaddr;
}

static void process_handle_section_and_filter(RzBinSection *section, process_section_t *process) {
	// rebase physical address
	section->paddr += process->loadaddr;

	// check if section name was already found, then rename it.
	if (!rz_th_ht_pp_find(process->db, section->name, NULL)) {
		rz_th_ht_pp_insert(process->db, section->name, section);
		return;
	}

	char *name = rz_str_newf("%s_%08" PFMT64x, section->name, section->vaddr);
	free(section->name);
	section->name = name;
}

static void set_and_process_sections(RzBinFile *bf, RzBinObject *o) {
	RzBin *bin = bf->rbin;
	RzBinPlugin *plugin = o->plugin;

	rz_list_free(o->sections);
	if (!plugin->sections || !(o->sections = plugin->sections(bf))) {
		o->sections = rz_list_newf((RzListFree)rz_bin_section_free);
	}

	RzThreadIterator iterator = (RzThreadIterator)process_handle_section;
	process_section_t process = {
		.loadaddr = o->opts.loadaddr,
		.db = NULL,
	};

	if (bin->filter) {
		iterator = (RzThreadIterator)process_handle_section_and_filter;
		process.db = rz_th_ht_pp_new0();
	}

	rz_th_iterate_list(o->sections, iterator, RZ_THREAD_POOL_ALL_CORES, &process);
	rz_th_ht_pp_free(process.db);
}
