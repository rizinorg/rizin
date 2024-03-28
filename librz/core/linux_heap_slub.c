// SPDX-FileCopyrightText: 2024 rockrid3r <rockrid3r@outlook.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_types.h>
#include <rz_config.h>
#include <rz_endian.h>

#ifdef KHEAP64
#include "linux_heap_slub64.h"
#else
#include "linux_heap_slub.h"
#endif

// #define SLUB_DEBUG

typedef enum {
	LINKED_LIST_OK = 0,
	LINKED_LIST_CORRUPTED,
	LINKED_LIST_CYCLE,
} GH_(LinkedListState);

typedef struct {
	GH_(LinkedListState)
	state;
	RzVector /*<GHT>*/ *freelist_vector;
} GH_(Freelist);

typedef struct {
	GHT slab_addr; ///< base of current struct slab
	GHT next; ///< pointer to the next slab in slab list (`.next` or `.slab_list` in `struct slab`)
	GHT freelist; ///< slab.freelist
	bool is_corrupted; ///< true if current struct slab is in an unmapped memory (i.e. \p slab_addr is corrupted) */
} GH_(Slab);

typedef struct {
	GH_(LinkedListState)
	state;
	RzVector /*<Slab>*/ *slablist_vector;
} GH_(Slablist);

static GH_(Freelist) * GH_(freelist_new)() {
	GH_(Freelist) *freelist = rz_mem_alloc(sizeof(GH_(Freelist)));
	if (!freelist) {
		return NULL;
	}
	freelist->freelist_vector = rz_vector_new(sizeof(GHT), NULL, NULL);
	if (!freelist->freelist_vector) {
		return NULL;
	}
	return freelist;
}

static void GH_(freelist_free)(GH_(Freelist) * fl) {
	rz_vector_free(fl->freelist_vector);
	free(fl);
}

static GH_(Slablist) * GH_(slab_list_new)() {
	GH_(Slablist) *slablist = rz_mem_alloc(sizeof(GH_(Slablist)));
	if (!slablist) {
		return NULL;
	}
	slablist->slablist_vector = rz_vector_new(sizeof(GH_(Slab)), NULL, NULL);
	if (!slablist->slablist_vector) {
		return NULL;
	}
	return slablist;
}

static void GH_(slab_list_free)(GH_(Slablist) * slablist) {
	rz_vector_free(slablist->slablist_vector);
	free(slablist);
}

/**
 * \brief Searches for the element which duplicates the last one.
 * \param slablist Slablist with at least 1 element.
 */
static size_t GH_(slab_list_find_duplicate)(GH_(Slablist) * slablist) {
	GH_(Slab) * slab_it;
	GH_(Slab) *last = rz_vector_tail(slablist->slablist_vector);

	size_t dup_idx = -1;
	size_t i = 0;
	size_t slablist_len = slablist->slablist_vector->len;

	rz_vector_foreach(slablist->slablist_vector, slab_it) {
		if (i + 1 < slablist_len && slab_it->slab_addr == last->slab_addr) {
			dup_idx = i;
			break;
		}
		++i;
	}
	return dup_idx;
}

/**
 * \brief Searches for the element which duplicates the last one.
 * \param freelist Freelist with at least 1 element.
 */
static size_t GH_(freelist_find_duplicate)(GH_(Freelist) * freelist) {
	GHT *it;
	GHT *last = rz_vector_tail(freelist->freelist_vector);

	size_t dup_idx = -1;
	size_t i = 0;
	size_t freelist_len = freelist->freelist_vector->len;

	rz_vector_foreach(freelist->freelist_vector, it) {
		if (i + 1 < freelist_len && *it == *last) {
			dup_idx = i;
			break;
		}
		++i;
	}
	return dup_idx;
}

static ut8 GH_(size_index)[24] = {
	3, /* 8 */
	4, /* 16 */
	5, /* 24 */
	5, /* 32 */
	6, /* 40 */
	6, /* 48 */
	6, /* 56 */
	6, /* 64 */
	1, /* 72 */
	1, /* 80 */
	1, /* 88 */
	1, /* 96 */
	7, /* 104 */
	7, /* 112 */
	7, /* 120 */
	7, /* 128 */
	2, /* 136 */
	2, /* 144 */
	2, /* 152 */
	2, /* 160 */
	2, /* 168 */
	2, /* 176 */
	2, /* 184 */
	2 /* 192 */
};

static inline unsigned int GH_(size_index_elem)(unsigned int bytes) {
	return (bytes - 1) / 8;
}

static int GH_(fls)(unsigned int x) {
	int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xffff0000u)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000u)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000u)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000u)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000u)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}

static RzBinSymbol *GH_(get_symbol_by_name)(RzCore *core, const char *sym_name) {
	RzBin *bin = core->bin;
	RzBinObject *o = rz_bin_cur_object(bin);
	RzPVector *syms = o ? (RzPVector *)rz_bin_object_get_symbols(o) : NULL;
	void **iter;
	RzBinSymbol *s;

	rz_pvector_foreach (syms, iter) {
		s = *iter;
		if (!strcmp(s->name, sym_name)) {
			return s;
		}
	}

	return NULL;
}

static RzTypeStructMember *GH_(find_member_in_btype)(RzCore *core, RzBaseType *btype, const char *membname, size_t base_offset, size_t *p_memb_offset) {
	RzTypeStructMember *memb_iter;
	RzTypeStructMember *memb = NULL;

	RzTypeDB *typedb = core->analysis->typedb;
	rz_vector_foreach(&btype->struct_data.members, memb_iter) {
		if (!strcmp(memb_iter->name, membname)) {
			memb = memb_iter;
			*p_memb_offset = base_offset + memb->offset;
			break;
		}

		if (!memb_iter->type) {
			continue;
		}

		// unwrap if anonymous
		char *memb_iter_typename = memb_iter->type->identifier.name;
		if (!memb_iter_typename) {
			continue;
		}
		bool is_anon = !strncmp(memb_iter_typename, "anonymous", strlen("anonymous")); // TODO: fix false positives
		if (!is_anon) { // don't unwrap non-anon structs/unions
			continue;
		}

		RzBaseType *memb_iter_btype = rz_type_db_get_base_type(typedb, memb_iter_typename);
		if (!memb_iter_btype) {
			continue;
		}

		memb = GH_(find_member_in_btype)(core, memb_iter_btype, membname, base_offset + memb_iter->offset, p_memb_offset);
		if (memb) {
			break;
		}
	}

	return memb;
}

/**
 * \brief Returns offset to member from struct base. Unwraps anonymous members.
 * \param typename
 * \param membname
 *
 * For this:
 * struct S {
 *     int32_t a;
 *     struct {
 *         uint32_t b;
 *         uint32_t c;
 *     };
 * };
 * function called with \p typename="S" and \p membname="b" returns 4.
 */
static size_t GH_(offset_in_struct)(RzCore *core, const char *typename, const char *membname) {
	RzTypeDB *typedb = core->analysis->typedb;
	RzBaseType *btype = rz_type_db_get_base_type(typedb, typename);

	size_t memb_offset = -1;
	GH_(find_member_in_btype)
	(core, btype, membname, 0, &memb_offset);

	return memb_offset;
}

static size_t GH_(offset_in_2d_arr)(size_t size2, size_t elem_size, size_t idx1, size_t idx2) {
	return idx1 * size2 * elem_size + idx2 * elem_size;
}

static size_t GH_(offset_in_arr)(size_t elem_size, size_t idx) {
	return elem_size * idx;
}

/**
 * \brief Returns the kmem_cache pointer of a general cache given it's size.
 * \param core RzCore pointer
 * \param size The size of a general cache (8 for kmalloc-8, 32 for kmalloc-32, etc.)
 * \return Pointer to kmem_cache structure corresponding to the given size.
 *
 * Reimplementation of `kmalloc_slab` from https://elixir.bootlin.com/linux/v6.1.58/source/mm/slab_common.c#L719.
 */
static GHT GH_(get_kmem_cache)(RzCore *core, size_t cache_size) {
	int cache_type = 0; // KMALLOC_NORMAL
	ut8 index;

	if (cache_size <= 192) {
		index = GH_(size_index)[GH_(size_index_elem)(cache_size)];
	} else {
		index = GH_(fls)(cache_size - 1);
	}

	RzBinSymbol *kmalloc_caches = GH_(get_symbol_by_name)(core, "kmalloc_caches");
	if (kmalloc_caches == NULL) {
		return GHT_MAX;
	}

	GHT kmem_cache;

	// deref 2d array: kmalloc_caches[cache_type][index]
	size_t size2 = 12 + 1 + 1; // PAGE_SHIFT + 1 + 1
	bool read_ok;
	read_ok = rz_io_read_at_mapped(
		core->io,
		kmalloc_caches->vaddr + GH_(offset_in_2d_arr)(size2, sizeof(GHT), cache_type, index),
		(void *)&kmem_cache,
		sizeof(GHT));
	return read_ok ? kmem_cache : GHT_MAX;
}

static bool read_struct_member(
	RzCore *core, void *dest, GHT struct_base, const char *struct_name,
	const char *member_name, size_t size) {

	GHT member_offset = GH_(offset_in_struct)(core, struct_name, member_name);
	if (member_offset == GHT_MAX) {
		eprintf("Could not find member '%s' of struct '%s'", member_name, struct_name);
		return false;
	}

	bool read_ok;

	read_ok = rz_io_read_at_mapped(
		core->io,
		struct_base + member_offset,
		dest,
		size);

	return read_ok;
}

static GHT GH_(get_kmem_cache_cpu)(RzCore *core, GHT kmem_cache, size_t n_cpu) {
	bool read_ok;
	RzBinSymbol *per_cpu_offset = GH_(get_symbol_by_name)(core, "__per_cpu_offset");
	if (!per_cpu_offset) {
		return GHT_MAX;
	}

	GHT percpu_n;
	read_ok = rz_io_read_at_mapped(
		core->io,
		per_cpu_offset->vaddr + GH_(offset_in_arr)(sizeof(GHT), n_cpu),
		(void *)&percpu_n,
		sizeof(GHT));
	if (!read_ok) {
		return GHT_MAX;
	}

	GHT cpu_slab;
	GHT cpu_slab_member_offset = GH_(offset_in_struct)(core, "kmem_cache", "cpu_slab");
	if (cpu_slab_member_offset == GHT_MAX) {
		eprintf("Could not find member 'cpu_slab' of struct 'kmem_cache'\n");
		return GHT_MAX;
	}
	read_ok = rz_io_read_at_mapped(
		core->io,
		kmem_cache + cpu_slab_member_offset,
		(void *)&cpu_slab,
		sizeof(GHT));
	if (!read_ok) {
		return GHT_MAX;
	}

	GHT kmem_cache_cpu = percpu_n + cpu_slab;

	return kmem_cache_cpu;
}

// TODO: add NODES_SHIFT config parameter
static GHT GH_(get_kmem_cache_node)(RzCore *core, GHT kmem_cache, size_t node_n) {
	GHT kmem_cache_node;
	bool read_ok;
	GHT node_member_offset = GH_(offset_in_struct)(core, "kmem_cache", "node");
	if (node_member_offset == GHT_MAX) {
		eprintf("Could not find member 'node' of struct 'kmem_cache'\n");
		return GHT_MAX;
	}
	read_ok = rz_io_read_at_mapped(
		core->io,
		kmem_cache + node_member_offset + GH_(offset_in_arr)(sizeof(GHT), node_n),
		(void *)&kmem_cache_node,
		sizeof(GHT));
	if (!read_ok) {
		return GHT_MAX;
	}

	return kmem_cache_node;
}

static inline GHT GH_(decode_freelist)(GHT freelist, GHT p_freelist, GHT cache_rand) {
	return GH(rz_swap_ut)(p_freelist) ^ cache_rand ^ freelist;
}

static GH_(Freelist) * GH_(collect_freelist)(RzCore *core, GHT freelist, size_t freelist_offset, GHT cache_rand) {
	bool read_ok;
	GH_(Freelist) *result = GH_(freelist_new)();
	if (!result) {
		return NULL;
	}
	RzVector *freelist_vector = result->freelist_vector;

	if (!freelist) {
		return result;
	}

	SetU *prev = set_u_new();

	set_u_add(prev, freelist);
	rz_vector_push(freelist_vector, &freelist);

	while (true) {
		GHT chunk_base = freelist;

		read_ok = rz_io_read_at_mapped(
			core->io,
			chunk_base + freelist_offset,
			(void *)&freelist,
			sizeof(GHT));

		if (core->analysis->vmlinux_config->config_tbl->config_slab_freelist_hardened) {
			freelist = GH_(decode_freelist)(freelist, chunk_base + freelist_offset, cache_rand);
		}

		// check if freelist was corrupted
		if (!read_ok) {
			result->state = LINKED_LIST_CORRUPTED;
			goto out;
		}

		// check if end
		if (!freelist) {
			result->state = LINKED_LIST_OK;
			goto out;
		}

		// check if cycle
		if (set_u_contains(prev, freelist)) {
			result->state = LINKED_LIST_CYCLE;
			rz_vector_push(freelist_vector, &freelist);
			goto out;
		}

		set_u_add(prev, freelist);
		rz_vector_push(freelist_vector, &freelist);
	}

out:
	set_u_free(prev);
	return result;
}

static void GH_(dump_freelist)(GH_(Freelist) * freelist) {
	RzVector *freelist_vector = freelist->freelist_vector;
	GHT *it;
	size_t i = 0;

	size_t dup_idx = -1;
	size_t freelist_len = freelist->freelist_vector->len;

	if (freelist->state == LINKED_LIST_CYCLE) {
		printf("NOTE: freelist is cycled\n");
		dup_idx = GH_(freelist_find_duplicate)(freelist);
	} else if (freelist->state == LINKED_LIST_CORRUPTED) {
		printf("NOTE: freelist is corrupted\n");
	}

	printf("Freelist len: %lu\n", freelist_len);
	rz_vector_foreach(freelist_vector, it) {
		printf("\t0x%" GHFMTx "%s", *it, dup_idx == i ? " *" : "");
		if (i + 1 == freelist_vector->len) {
			switch (freelist->state) {
			case LINKED_LIST_OK:
				break;
			case LINKED_LIST_CORRUPTED:
				printf(" (corrupted)");
				break;
			case LINKED_LIST_CYCLE:
				printf(" *(cycle)");
				break;
			}
		}
		printf("\n");
		++i;
	}
}

/**
 * \brief collects slablist until it encounters \p slablist_head_addr .
 * \param core
 * \param first_slab_addr
 * \param slablist_head_addr stop if slab with this address encountered.
 * \param next_membname Member of `struct slab` which points to the next slab in a list. Either "next" (for partial freelist) or "slab_list".
 */
static GH_(Slablist) * GH_(collect_slablist)(RzCore *core, GHT first_slab_addr, GHT slablist_head_addr, const char *next_membname) {
	GH_(Slablist) *slablist = GH_(slab_list_new)();
	if (!slablist) {
		return NULL;
	}
	RzVector *slablist_vector = slablist->slablist_vector;

	if (!first_slab_addr) {
		return slablist;
	}

	char *slab_typename;
	if (rz_vmlinux_vercmp_with_str(core->analysis->vmlinux_config->version, "5.17") > 0) {
		slab_typename = "slab";
	} else {
		slab_typename = "page";
	}

	SetU *prev = set_u_new();

	GHT slab_addr = first_slab_addr;
	GHT slab_next, slab_freelist;
	GH_(Slab)
	slab;
	while (slab_addr != slablist_head_addr) {
		/* begins with processing 'first_slab_addr' and goes on like this. Differs from how collect_freelist orders things. */

		// get "next" from "slab"
		bool read_ok;
		read_ok = read_struct_member(
			core,
			(void *)&slab_next,
			slab_addr,
			slab_typename,
			next_membname,
			sizeof(GHT));

		if (!read_ok) { // slab was corrupted
			slablist->state = LINKED_LIST_CORRUPTED;

			slab.is_corrupted = true;
			rz_vector_push(slablist_vector, &slab);

			goto out;
		}

		read_ok = read_struct_member(
			core,
			(void *)&slab_freelist,
			slab_addr,
			slab_typename,
			"freelist",
			sizeof(GHT));

		if (!read_ok) { // slab was corrupted
			slablist->state = LINKED_LIST_CORRUPTED;

			slab.is_corrupted = true;
			rz_vector_push(slablist_vector, &slab);

			goto out;
		}

		slab.freelist = slab_freelist;
		slab.next = slab_next;
		slab.slab_addr = slab_addr;
		slab.is_corrupted = false;

		if (set_u_contains(prev, slab_addr)) {
			slablist->state = LINKED_LIST_CYCLE;

			rz_vector_push(slablist_vector, &slab);

			goto out;
		}

		rz_vector_push(slablist_vector, &slab);
		set_u_add(prev, slab_addr);

		slab_addr = slab_next;
		memset(&slab, 0, sizeof(slab));
	}

out:
	set_u_free(prev);
	return slablist;
}

static bool GH_(dump_cpu_lockless_freelist)(RzCore *core, GHT kmem_cache, GHT kmem_cache_cpu) {
	GHT freelist;
	unsigned long freelist_offset;
	GHT cache_rand = 0;

	bool read_ok;

	// get "freelist" from "kmem_cache_cpu".
	read_ok = read_struct_member(
		core,
		(void *)&freelist,
		kmem_cache_cpu,
		"kmem_cache_cpu",
		"freelist",
		sizeof(GHT));
	if (!read_ok) {
		return false;
	}

	// get "offset" from "kmem_cache"
	read_ok = read_struct_member(
		core,
		(void *)&freelist_offset,
		kmem_cache,
		"kmem_cache",
		"offset",
		sizeof(unsigned int));

	if (!read_ok) {
		return false;
	}

	if (core->analysis->vmlinux_config->config_tbl->config_slab_freelist_hardened) {
		// get "random" from "kmem_cache"
		read_ok = read_struct_member(
			core,
			(void *)&cache_rand,
			kmem_cache,
			"kmem_cache",
			"random",
			sizeof(GHT));
		if (!read_ok) {
			return false;
		}
	}

	GH_(Freelist) *fl = GH_(collect_freelist)(core, freelist, freelist_offset, cache_rand);
	if (!fl) {
		return false;
	}
	GH_(dump_freelist)
	(fl);
	GH_(freelist_free)
	(fl);
	return true;
}

static bool GH_(dump_cpu_regular_freelist)(RzCore *core, GHT kmem_cache, GHT kmem_cache_cpu) {
	GHT freelist, slab;
	GHT cache_rand = 0;
	unsigned int freelist_offset;
	char *slab_member, *slab_member_type;
	bool read_ok;

	if (rz_vmlinux_vercmp_with_str(core->analysis->vmlinux_config->version, "5.17") > 0) {
		slab_member = "slab";
		slab_member_type = "slab";
	} else {
		slab_member = "page";
		slab_member_type = "page";
	}

	// get "slab" from "kmem_cache_cpu"
	read_ok = read_struct_member(
		core,
		(void *)&slab,
		kmem_cache_cpu,
		"kmem_cache_cpu",
		slab_member,
		sizeof(GHT));
	if (!read_ok) {
		return false;
	}

	// get "freelist" from "slab"
	read_ok = read_struct_member(
		core,
		(void *)&freelist,
		slab,
		slab_member_type,
		"freelist",
		sizeof(GHT));
	if (!read_ok) {
		return false;
	}

	// get "freelist_offset" from "kmem_cache"
	read_ok = read_struct_member(
		core,
		(void *)&freelist_offset,
		kmem_cache,
		"kmem_cache",
		"offset",
		sizeof(unsigned int));
	if (!read_ok) {
		return false;
	}

	if (core->analysis->vmlinux_config->config_tbl->config_slab_freelist_hardened) {
		// get "random" from "kmem_cache"
		read_ok = read_struct_member(
			core,
			(void *)&cache_rand,
			kmem_cache,
			"kmem_cache",
			"random",
			sizeof(GHT));
		if (!read_ok) {
			return false;
		}
	}

	GH_(Freelist) *fl = GH_(collect_freelist)(core, freelist, freelist_offset, cache_rand);
	if (!fl) {
		return false;
	}
	GH_(dump_freelist)
	(fl);
	GH_(freelist_free)
	(fl);
	return true;
}

static void GH_(dump_partial)(RzCore *core, GH_(Slablist) * partials, unsigned int freelist_offset, GHT cache_rand) {
	GHT freelist;
	GH_(Slab) * slab_it;

	if (!partials) {
		return;
	}

	size_t slablist_len = rz_vector_len(partials->slablist_vector);
	size_t i = 0;
	rz_vector_foreach(partials->slablist_vector, slab_it) {
		printf("=============== Partial list #%ld/%ld ===============\n", i + 1, slablist_len);
		if (slab_it->is_corrupted) {
			printf("ERROR: corresponding slab is corrupted\n");
			continue;
		}

		if (i + 1 == rz_vector_len(partials->slablist_vector) && partials->state == LINKED_LIST_CYCLE) {
			// slab list is cycled.
			// last element is duplicate of some previous.
			size_t dup_idx = GH_(slab_list_find_duplicate)(partials);
			printf("NOTE: corresponding slab duplicates #%ld (slab list is cycled)\n", dup_idx + 1);
		}

		freelist = slab_it->freelist;
		GH_(Freelist) *fl = GH_(collect_freelist)(core, freelist, freelist_offset, cache_rand);
		if (!fl) {
			continue;
		}
		GH_(dump_freelist)
		(fl);
		GH_(freelist_free)
		(fl);

		++i;
	}
}

static bool GH_(dump_cpu_partial_freelist)(RzCore *core, GHT kmem_cache, GHT kmem_cache_cpu) {
	GHT partial;
	GHT cache_rand = 0;
	unsigned int freelist_offset;
	bool read_ok;

	// get "partial" from "kmem_cache_cpu"
	read_ok = read_struct_member(
		core,
		(void *)&partial,
		kmem_cache_cpu,
		"kmem_cache_cpu",
		"partial",
		sizeof(GHT));
	if (!read_ok) {
		return false;
	}

	// get "freelist_offset" from "kmem_cache"
	read_ok = read_struct_member(
		core,
		(void *)&freelist_offset,
		kmem_cache,
		"kmem_cache",
		"offset",
		sizeof(unsigned int));
	if (!read_ok) {
		return false;
	}

	if (core->analysis->vmlinux_config->config_tbl->config_slab_freelist_hardened) {
		// get "random" from "kmem_cache"
		read_ok = read_struct_member(
			core,
			(void *)&cache_rand,
			kmem_cache,
			"kmem_cache",
			"random",
			sizeof(GHT));
		if (!read_ok) {
			return false;
		}
	}

	GH_(Slablist) *partials = GH_(collect_slablist)(core, partial, 0, "next");
	if (!partials) {
		return false;
	}
	GH_(dump_partial)
	(core, partials, freelist_offset, cache_rand);
	GH_(slab_list_free)
	(partials);
	return true;
}

static bool GH_(dump_node_freelist)(RzCore *core, GHT kmem_cache, GHT kmem_cache_node) {
	GHT partial;
	GHT cache_rand = 0;
	unsigned int freelist_offset;
	bool read_ok;

	// get "partial" from "kmem_cache_node"
	read_ok = read_struct_member(
		core,
		(void *)&partial,
		kmem_cache_node,
		"kmem_cache_node",
		"partial",
		sizeof(GHT));
	if (!read_ok) {
		return false;
	}

	// get "freelist_offset" from "kmem_cache"
	read_ok = read_struct_member(
		core,
		(void *)&freelist_offset,
		kmem_cache,
		"kmem_cache",
		"offset",
		sizeof(unsigned int));
	if (!read_ok) {
		return false;
	}

	if (core->analysis->vmlinux_config->config_tbl->config_slab_freelist_hardened) {
		// get "random" from "kmem_cache"
		read_ok = read_struct_member(
			core,
			(void *)&cache_rand,
			kmem_cache,
			"kmem_cache",
			"random",
			sizeof(GHT));
		if (!read_ok) {
			return false;
		}
	}

	GHT partial_member_offset;
	if ((partial_member_offset = GH_(offset_in_struct)(core, "kmem_cache_node", "partial")) == GHT_MAX) {
		eprintf("Could not find member 'partial' of struct 'kmem_cache_node'");
		return false;
	}
	GHT slablist_head_addr = kmem_cache_node + partial_member_offset;
	GH_(Slablist) *partials = GH_(collect_slablist)(core, partial, slablist_head_addr, "slab_list");
	if (!partials) {
		return false;
	}
	GH_(dump_partial)
	(core, partials, freelist_offset, cache_rand);
	GH_(slab_list_free)
	(partials);
	return true;
}

/**
 * \brief Dump lockless freelist command
 */
RZ_IPI RzCmdStatus GH_(rz_cmd_debug_slub_dump_lockless_freelist_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput *output_state) {
	if (rz_debug_is_dead(core->dbg)) {
		RZ_LOG_ERROR("Debugging session is dead.\n");
		return RZ_CMD_STATUS_INVALID;
	}

	if (!core->analysis->vmlinux_config) {
		RZ_LOG_ERROR("Vmlinux flag was not set. Restart rizin with `bin.elf.vmlinux=true`\n");
		return RZ_CMD_STATUS_INVALID;
	}

	(void)output_state;
	size_t n_cpu;
	size_t cache_size;

	RzNum *num = rz_num_new(NULL, NULL, NULL);
	cache_size = rz_num_get(num, argv[1]);
	if (num->nc.errors) {
		RZ_LOG_ERROR("Incorrect cache_size passed\n");
		return RZ_CMD_STATUS_INVALID;
	}
	n_cpu = 0; // default

	if (argc >= 2) {
		n_cpu = rz_num_get(num, argv[2]);
		if (num->nc.errors) {
			RZ_LOG_ERROR("Incorrect n_cpu passed\n");
			return RZ_CMD_STATUS_INVALID;
		}
	}

	GHT kmem_cache = GH_(get_kmem_cache)(core, cache_size);
	if (kmem_cache == GHT_MAX) {
		RZ_LOG_ERROR("Could not find kmem_cache\n");
		return RZ_CMD_STATUS_ERROR;
	}
	GHT kmem_cache_cpu = GH_(get_kmem_cache_cpu)(core, kmem_cache, n_cpu);
	if (kmem_cache_cpu == GHT_MAX) {
		RZ_LOG_ERROR("Could not find kmem_cache_cpu\n");
		return RZ_CMD_STATUS_ERROR;
	}
	GH_(dump_cpu_lockless_freelist)
	(core, kmem_cache, kmem_cache_cpu);
	return RZ_CMD_STATUS_OK;
}

/**
 * \brief Dump regular (locking) freelist command
 */
RZ_IPI RzCmdStatus GH_(rz_cmd_debug_slub_dump_regular_freelist_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput *output_state) {
	if (rz_debug_is_dead(core->dbg)) {
		RZ_LOG_ERROR("Debugging session is dead.\n");
		return RZ_CMD_STATUS_INVALID;
	}

	if (!core->analysis->vmlinux_config) {
		RZ_LOG_ERROR("Vmlinux flag was not set. Restart rizin with `bin.elf.vmlinux=true`\n");
		return RZ_CMD_STATUS_INVALID;
	}

	(void)output_state;
	size_t n_cpu;
	size_t cache_size;

	RzNum *num = rz_num_new(NULL, NULL, NULL);
	cache_size = rz_num_get(num, argv[1]);
	if (num->nc.errors) {
		RZ_LOG_ERROR("Incorrect cache_size passed\n");
		return RZ_CMD_STATUS_INVALID;
	}
	n_cpu = 0; // default

	if (argc >= 2) {
		n_cpu = rz_num_get(num, argv[2]);
		if (num->nc.errors) {
			RZ_LOG_ERROR("Incorrect n_cpu passed\n");
			return RZ_CMD_STATUS_INVALID;
		}
	}

	GHT kmem_cache = GH_(get_kmem_cache)(core, cache_size);
	if (kmem_cache == GHT_MAX) {
		RZ_LOG_ERROR("Could not find kmem_cache\n");
		return RZ_CMD_STATUS_ERROR;
	}
	GHT kmem_cache_cpu = GH_(get_kmem_cache_cpu)(core, kmem_cache, n_cpu);
	if (kmem_cache_cpu == GHT_MAX) {
		RZ_LOG_ERROR("Could not find kmem_cache_cpu\n");
		return RZ_CMD_STATUS_ERROR;
	}
	GH_(dump_cpu_regular_freelist)
	(core, kmem_cache, kmem_cache_cpu);
	return RZ_CMD_STATUS_OK;
}

/**
 * \brief Dump partial freelists command
 */
RZ_IPI RzCmdStatus GH_(rz_cmd_debug_slub_dump_partial_freelist_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput *output_state) {
	if (rz_debug_is_dead(core->dbg)) {
		RZ_LOG_ERROR("Debugging session is dead.\n");
		return RZ_CMD_STATUS_INVALID;
	}

	if (!core->analysis->vmlinux_config) {
		RZ_LOG_ERROR("Vmlinux flag was not set. Restart rizin with `bin.elf.vmlinux=true`\n");
		return RZ_CMD_STATUS_INVALID;
	}

	(void)output_state;
	size_t n_cpu;
	size_t cache_size;

	RzNum *num = rz_num_new(NULL, NULL, NULL);
	cache_size = rz_num_get(num, argv[1]);
	if (num->nc.errors) {
		RZ_LOG_ERROR("Incorrect cache_size passed\n");
		return RZ_CMD_STATUS_INVALID;
	}
	n_cpu = 0; // default

	if (argc >= 2) {
		n_cpu = rz_num_get(num, argv[2]);
		if (num->nc.errors) {
			RZ_LOG_ERROR("Incorrect n_cpu passed\n");
			return RZ_CMD_STATUS_INVALID;
		}
	}

	GHT kmem_cache = GH_(get_kmem_cache)(core, cache_size);
	if (kmem_cache == GHT_MAX) {
		RZ_LOG_ERROR("Could not find kmem_cache\n");
		return RZ_CMD_STATUS_ERROR;
	}
	GHT kmem_cache_cpu = GH_(get_kmem_cache_cpu)(core, kmem_cache, n_cpu);
	if (kmem_cache_cpu == GHT_MAX) {
		RZ_LOG_ERROR("Could not find kmem_cache_cpu\n");
		return RZ_CMD_STATUS_ERROR;
	}

	GH_(dump_cpu_partial_freelist)
	(core, kmem_cache, kmem_cache_cpu);

	return RZ_CMD_STATUS_OK;
}

/**
 * \brief Dump node freelists command
 */
RZ_IPI RzCmdStatus GH_(rz_cmd_debug_slub_dump_node_freelist_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput *output_state) {
	if (rz_debug_is_dead(core->dbg)) {
		RZ_LOG_ERROR("Debugging session is dead.\n");
		return RZ_CMD_STATUS_INVALID;
	}

	if (!core->analysis->vmlinux_config) {
		RZ_LOG_ERROR("Vmlinux flag was not set. Restart rizin with `bin.elf.vmlinux=true`\n");
		return RZ_CMD_STATUS_INVALID;
	}

	(void)output_state;

	size_t n_node;
	size_t cache_size;

	RzNum *num = rz_num_new(NULL, NULL, NULL);
	cache_size = rz_num_get(num, argv[1]);
	if (num->nc.errors) {
		RZ_LOG_ERROR("Incorrect cache_size passed\n");
		return RZ_CMD_STATUS_INVALID;
	}
	n_node = 0; // default

	if (argc >= 2) {
		n_node = rz_num_get(num, argv[2]);
		if (num->nc.errors) {
			RZ_LOG_ERROR("Incorrect n_node passed\n");
			return RZ_CMD_STATUS_INVALID;
		}
	}

	GHT kmem_cache = GH_(get_kmem_cache)(core, cache_size);
	if (kmem_cache == GHT_MAX) {
		RZ_LOG_ERROR("Could not find kmem_cache\n");
		return RZ_CMD_STATUS_ERROR;
	}
	GHT kmem_cache_node = GH_(get_kmem_cache_node)(core, kmem_cache, n_node);
	if (kmem_cache_node == GHT_MAX) {
		RZ_LOG_ERROR("Could not find kmem_cache_node\n");
		return RZ_CMD_STATUS_ERROR;
	}

	GH_(dump_node_freelist)
	(core, kmem_cache, kmem_cache_node);

	return RZ_CMD_STATUS_OK;
}
