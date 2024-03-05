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
	GH_(LinkedListState) state;
	RzVector* freelist_vector;
} GH_(Freelist);

typedef struct {
	GHT slab_addr; /* base of current struct slab */
	GHT next; /* slab->next */
	GHT freelist; /* slab->freelist */
	bool is_corrupted; /* true if current struct slab is in an unmapped memory */
} GH_(Slab);

typedef struct {
	GH_(LinkedListState) state;
	RzVector* /* <Slab> */ slablist_vector;
} GH_(Slablist);

static void GH_(freelist_new)() {
	return rz_mem_alloc(sizeof(GH_(Freelist)));
}

static void GH_(freelist_free) (GH_(Freelist)* fl) {
	rz_vector_free(fl->freelist_vector);
	free(fl);
}

static ut8 GH_(size_index)[24] = {
	3,	/* 8 */
	4,	/* 16 */
	5,	/* 24 */
	5,	/* 32 */
	6,	/* 40 */
	6,	/* 48 */
	6,	/* 56 */
	6,	/* 64 */
	1,	/* 72 */
	1,	/* 80 */
	1,	/* 88 */
	1,	/* 96 */
	7,	/* 104 */
	7,	/* 112 */
	7,	/* 120 */
	7,	/* 128 */
	2,	/* 136 */
	2,	/* 144 */
	2,	/* 152 */
	2,	/* 160 */
	2,	/* 168 */
	2,	/* 176 */
	2,	/* 184 */
	2	/* 192 */
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

static RzBinSymbol* GH_(get_symbol_by_name)(RzCore *core, const char *sym_name) {
    RzBin *bin = core->bin;
    RzBinObject *o = rz_bin_cur_object(bin);
	RzPVector *syms = o ? (RzPVector *)rz_bin_object_get_symbols(o) : NULL;
    void** iter;
    RzBinSymbol *s;

	rz_pvector_foreach (syms, iter) {
		s = *iter;
		if (!strcmp(s->name, sym_name)) {
			return s;
		}
	}

    return NULL;
}



/**
 * \brief Returns offset to member from struct base
 * \param typename
 * \param membname
 * 
 * TODO: unwrap anonymous members. For example extract 'freelist' from here:
 * struct kmem_cache_cpu {
 * 		union { 
 * 			struct { void** freelist; unsigned long tid; };
 * 			freelist_aba_t freelist_tid; 
 * 		}
 * 		struct slab* slab;
 * 		// the rest
 * }
*/

static RzTypeStructMember* GH_(find_member_in_btype)(RzCore* core, RzBaseType* btype, const char* membname, size_t base_offset, size_t *p_memb_offset) {
	RzTypeStructMember* memb_iter;
	RzTypeStructMember* memb = NULL;

#ifdef SLUB_DEBUG
	printf("find_member_in_btype(btype='%s', membname='%s', base_offset=%lu)\n", btype->name, membname, base_offset);
#endif
	RzTypeDB* typedb = core->analysis->typedb;
	rz_vector_foreach(&btype->struct_data.members, memb_iter) {
#ifdef SLUB_DEBUG
		printf("processing member '%s' at offset %lu\n", memb_iter->name, memb_iter->offset);
#endif
		if (!strcmp(memb_iter->name, membname)) {
			memb = memb_iter;
			*p_memb_offset = base_offset + memb->offset;
			break;
		}

		if (!memb_iter->type) {
#ifdef SLUB_DEBUG
			printf("typename for '%s' is NULL\n", memb_iter->name);
#endif
			continue;
		}

		// unwrap if anonymous
		char* memb_iter_typename = memb_iter->type->identifier.name;
		if (!memb_iter_typename) {
			continue;
		}
		bool is_anon = !strncmp(memb_iter_typename, "anonymous", strlen("anonymous")); // TODO: fix false positives
		if (!is_anon) { // don't unwrap not-anon structs/unions
#ifdef SLUB_DEBUG
			printf("[-] typename '%s' for member '%s' is not anonymous\n", memb_iter_typename, memb_iter->name);
#endif
			continue;
		} else {
#ifdef SLUB_DEBUG
			printf("[+] typename '%s' for member '%s' is anonymous\n", memb_iter_typename, memb_iter->name);
#endif
		}
		
		RzBaseType* memb_iter_btype = rz_type_db_get_base_type(typedb, memb_iter_typename);
		if (!memb_iter_btype) {
#ifdef SLUB_DEBUG
			printf("Could not find corresponding btype for '%s'\n", memb_iter_typename);
#endif
			continue;
		}

		memb = GH_(find_member_in_btype)(core, memb_iter_btype, membname, base_offset + memb_iter->offset, p_memb_offset);
		if (memb) {
#ifdef SLUB_DEBUG
			printf("found member '%s' at offset %lu\n", membname, base_offset + memb->offset);
#endif
			break;
		}
	}

	return memb;
}

static size_t GH_(offset_in_struct)(RzCore* core, const char* typename, const char* membname) {
	RzTypeDB* typedb = core->analysis->typedb;
	RzBaseType* btype = rz_type_db_get_base_type(typedb, typename);
	
	size_t memb_offset = -1;
	GH_(find_member_in_btype)(core, btype, membname, 0, &memb_offset);

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
#ifdef SLUB_DEBUG
	printf("index in kmalloc_caches: %u\n", index);
#endif
    RzBinSymbol *kmalloc_caches = GH_(get_symbol_by_name)(core, "kmalloc_caches");
    if (kmalloc_caches == NULL) {
        return GHT_MAX;
    }
#ifdef SLUB_DEBUG
	printf("kmalloc_caches: 0x%llx\n", kmalloc_caches->vaddr + rz_bin_get_baddr(core->bin));
#endif
    
    GHT kmem_cache;
	
    // deref 2d array: kmalloc_caches[cache_type][index]
	size_t size2 = 12 + 1 + 1; // PAGE_SHIFT + 1 + 1
    rz_io_read_at_mapped(
        core->io, 
        kmalloc_caches->vaddr + GH_(offset_in_2d_arr)(size2, sizeof(GHT), cache_type, index),
        (void*)&kmem_cache,
        sizeof(GHT)
    );
    return kmem_cache;
}

static GHT GH_(get_kmem_cache_cpu)(RzCore *core, GHT kmem_cache, size_t n_cpu) {
    RzBinSymbol *per_cpu_offset = GH_(get_symbol_by_name)(core, "__per_cpu_offset");
#ifdef SLUB_DEBUG
	printf("__per_cpu_offset: 0x%llx\n", per_cpu_offset->vaddr);
#endif
	
	GHT percpu_n;
	rz_io_read_at_mapped(
		core->io,
		per_cpu_offset->vaddr + GH_(offset_in_arr)(sizeof(GHT), n_cpu),
		(void*)&percpu_n,
		sizeof(GHT)
	);

	GHT cpu_slab;
	rz_io_read_at_mapped(
		core->io,
		kmem_cache + GH_(offset_in_struct)(core, "kmem_cache", "cpu_slab"),
		(void*)&cpu_slab,
		sizeof(GHT)
	);

	GHT kmem_cache_cpu = percpu_n + cpu_slab;

	return kmem_cache_cpu;
}

// TODO: add NODES_SHIFT config parameter
static GHT GH_(get_kmem_cache_node)(RzCore* core, GHT kmem_cache, size_t node_n) {
	GHT kmem_cache_node;
	rz_io_read_at_mapped(
		core->io,
		kmem_cache + GH_(offset_in_struct)(core, "kmem_cache", "node") + GH_(offset_in_arr)(sizeof(GHT), node_n),
		(void*)&kmem_cache_node,
		sizeof(GHT)
	);
	return kmem_cache_node;
}

static inline GHT GH_(decode_freelist)(GHT freelist, GHT p_freelist, GHT cache_rand) {
	return GH(rz_swap_ut)(p_freelist) ^ cache_rand ^ freelist;
}

static GH_(Freelist)* GH_(collect_freelist)(RzCore* core, GHT freelist, size_t freelist_offset, GHT cache_rand) {
	bool read_ok;
	GH_(Freelist)* result = freelist_new();
	result->freelist_vector = rz_vector_new(sizeof(GHT), NULL, NULL);
	RzVector* freelist_vector = result->freelist_vector;

	if (!freelist) {
		return result;
	}

	SetU* prev = set_u_new();

	set_u_add(prev, freelist);
	rz_vector_push(freelist_vector, &freelist);

#ifdef SLUB_DEBUG
	printf("================ COLLECT FREELIST(freelist=0x%" GHFMTx ", freelist_offset=%lu, cache_rand=0x%" GHFMTx ") ==============\n",
			freelist, freelist_offset, cache_rand);
#endif

	while (true) {
		GHT chunk_base = freelist;
#ifdef SLUB_DEBUG
		printf("chunk_base: 0x%" GHFMTx "\n", chunk_base);
		printf("reading freelist @ p_freelist: 0x%" GHFMTx "\n", chunk_base + (GHT)freelist_offset);
#endif
		read_ok = rz_io_read_at_mapped(
			core->io,
			chunk_base + freelist_offset,
			(void*)&freelist,
			sizeof(GHT)
		);

#ifdef SLUB_DEBUG
		printf("obfuscated freelist: 0x%" GHFMTx "\n", freelist);
#endif
		if (core->analysis->vmlinux_config->config_tbl->config_slab_freelist_hardened) {
			freelist = GH_(decode_freelist)(freelist, chunk_base + freelist_offset, cache_rand);
		}
#ifdef SLUB_DEBUG
		printf("deobfuscated freelist: 0x%" GHFMTx "\n", freelist);
#endif

		// check if freelist was corrupted
		if (!read_ok) {
			// TODO
#ifdef SLUB_DEBUG
			printf("[!] freelist corrupted\n");
#endif
			result->state = LINKED_LIST_CORRUPTED;
			goto out;
		}

		// check if end
		if (!freelist) {
#ifdef SLUB_DEBUG
			printf("[*] freelist ok\n");
#endif
			result->state = LINKED_LIST_OK;
			goto out;
		}

		// check if cycle
		if (set_u_contains(prev, freelist)) {
#ifdef SLUB_DEBUG
			printf("[!] freelist cycle\n");
#endif
			result->state = LINKED_LIST_CYCLE;
			rz_vector_push(freelist_vector, &freelist);
			goto out;
		}

		set_u_add(prev, freelist);
		rz_vector_push(freelist_vector, &freelist);
	}

out:
#ifdef SLUB_DEBUG
	printf("[*] returning from freelist collect\n");
#endif
	set_u_free(prev);
	return result;
}

static void GH_(dump_freelist)(GH_(Freelist)* freelist) {
	RzVector* freelist_vector = freelist->freelist_vector;
	GHT* it;
	size_t i = 0;
#ifdef SLUB_DEBUG
	printf("[*] dumping freelist\n");
#endif
	rz_vector_foreach(freelist_vector, it) {
		printf("0x%" GHFMTx, *it);
		if (i + 1 == freelist_vector->len) {
			switch(freelist->state) {
					case LINKED_LIST_OK:
						break;
					case LINKED_LIST_CORRUPTED:
						printf(" (corrupted)");
						break;
					case LINKED_LIST_CYCLE:
						printf(" (cycle)");
						break;
			}
		}
		printf("\n");
		++i;
	}
#ifdef SLUB_DEBUG
	printf("[*] exit from freelist dump\n");
#endif
}

/**
 * \brief collects slablist until it encounters \p slablist_head_addr
 * \param core
 * \param first_slab_addr
 * \param slablist_head_addr
 * \param next_membname either "next" (for partial freelist) or "slab_list"
*/
static GH_(Slablist)* GH_(collect_slablist)(RzCore* core, GHT first_slab_addr, GHT slablist_head_addr, const char* next_membname) {
	GH_(Slablist)* slablist = rz_mem_alloc(sizeof(GH_(Slablist)));
	slablist->slablist_vector = rz_vector_new(sizeof(GH_(Slab)), NULL, NULL);
	RzVector* slablist_vector = slablist->slablist_vector;

	if (!first_slab_addr) {
		return slablist;
	}

	char* slab_typename;
	if (vmlinux_vercmp_with_str(core->analysis->vmlinux_config->version, "5.17") > 0) {
		slab_typename = "slab";
	} else {
		slab_typename = "page";
	}

	SetU* prev = set_u_new();

	GHT slab_addr = first_slab_addr;
	GHT slab_next, slab_freelist;
	GH_(Slab) slab;
	while (slab_addr != slablist_head_addr) {
		/* begins with processing 'first_slab_addr' and goes on like this. Differs from how collect_freelist orders things. */

		// get "next" from "slab"
		bool read_ok = rz_io_read_at_mapped(
			core->io,
			slab_addr + GH_(offset_in_struct)(core, slab_typename, next_membname),
			(void*)&slab_next,
			sizeof(GHT)
		);

		if (!read_ok) { // slab was corrupted
			slablist->state = LINKED_LIST_CORRUPTED;
			
			slab.is_corrupted = true;
			rz_vector_push(slablist_vector, &slab);

			goto out;
		}

		read_ok = rz_io_read_at_mapped(
			core->io,
			slab_addr + GH_(offset_in_struct)(core, slab_typename, "freelist"),
			(void*)&slab_freelist,
			sizeof(GHT)
		);

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



// TODO: replace struct member type with their actual type (using typedb)
static void GH_(dump_cpu_lockless_freelist)(RzCore* core, GHT kmem_cache, GHT kmem_cache_cpu) {
	GHT freelist;
	unsigned long freelist_offset;
	GHT cache_rand;
	
	// get "freelist" from "kmem_cache_cpu".
	// Dirty hardcode: offsetof(kmem_cache_cpu, freelist)=0.
	// Can't use offset_in_struct since it does not yet support anonymous member unwrapping.
	rz_io_read_at_mapped(
		core->io,
		kmem_cache_cpu + GH_(offset_in_struct)(core, "kmem_cache_cpu", "freelist"),
		(void*)&freelist,
		sizeof(GHT)
	);
#ifdef SLUB_DEBUG
	printf("freelist: 0x%" GHFMTx "\n", freelist);
#endif

	// get "offset" from "kmem_cache"
	rz_io_read_at_mapped(
		core->io,
		kmem_cache + GH_(offset_in_struct)(core, "kmem_cache", "offset"),
		(void*)&freelist_offset,
		sizeof(unsigned int)
	);
#ifdef SLUB_DEBUG
	printf("freelist_offset: %lu\n", freelist_offset);
#endif

	if (core->analysis->vmlinux_config->config_tbl->config_slab_freelist_hardened) {
		// get "random" from "kmem_cache"	
		rz_io_read_at_mapped(
			core->io,
			kmem_cache + GH_(offset_in_struct)(core, "kmem_cache", "random"),
			(void*)&cache_rand,
			sizeof(GHT)
		);
		#ifdef SLUB_DEBUG
			printf("cache random: 0x%" GHFMTx "\n", cache_rand);
		#endif
	}

	GH_(Freelist)* fl = GH_(collect_freelist)(core, freelist, freelist_offset, cache_rand);
	GH_(dump_freelist)(fl);
	freelist_free(fl);
}

// TODO: replace struct member type with their actual type (using typedb)
static void GH_(dump_cpu_regular_freelist)(RzCore* core, GHT kmem_cache, GHT kmem_cache_cpu) {
	GHT freelist, slab;
	GHT cache_rand;
	unsigned int freelist_offset;
	char *slab_member, *slab_member_type;

	if (vmlinux_vercmp_with_str(core->analysis->vmlinux_config->version, "5.17") > 0) {
		slab_member = "slab";
		slab_member_type = "slab";
	} else {
		slab_member = "page";
		slab_member_type = "page";
	}
#ifdef SLUB_DEBUG
	printf("[*] Selected slab member: '%s'\n", slab_member);
#endif

	// get "slab" from "kmem_cache_cpu"
	rz_io_read_at_mapped(
		core->io,
		kmem_cache_cpu + GH_(offset_in_struct)(core, "kmem_cache_cpu", slab_member),
		(void*)&slab,
		sizeof(GHT)
	);

	// get "freelist" from "slab"
	rz_io_read_at_mapped(
		core->io,
		slab + GH_(offset_in_struct)(core, slab_member_type, "freelist"),
		(void*)&freelist,
		sizeof(GHT)
	);

	// get "freelist_offset" from "kmem_cache"
	rz_io_read_at_mapped(
		core->io,
		kmem_cache + GH_(offset_in_struct)(core, "kmem_cache", "offset"),
		(void*)&freelist_offset,
		sizeof(unsigned int)
	);

	if (core->analysis->vmlinux_config->config_tbl->config_slab_freelist_hardened) {
		// get "random" from "kmem_cache"
		rz_io_read_at_mapped(
			core->io,
			kmem_cache + GH_(offset_in_struct)(core, "kmem_cache", "random"),
			(void*)&cache_rand,
			sizeof(GHT)
		);
	}

	GH_(Freelist)* fl = GH_(collect_freelist)(core, freelist, freelist_offset, cache_rand);
	GH_(dump_freelist)(fl);
	freelist_free(fl);
}

static void GH_(dump_partial)(RzCore* core, GH_(Slablist) *partials, unsigned int freelist_offset, GHT cache_rand) {
	GHT freelist;
	GH_(Slab)* slab_it;

	// TODO: what if partials->state->LINKED_LIST_CORRUPTED/LINKED_LIST_CYCLE ?

	size_t slablist_len = rz_vector_len(partials->slablist_vector);
	size_t i = 0;
	rz_vector_foreach(partials->slablist_vector, slab_it) {
#ifdef SLUB_DEBUG
		printf(
			"[*] processing freelist {.slab_addr=%" GHFMTx 
			", .next=%" GHFMTx
			", .freelist=%" GHFMTx
			", .is_corrupted=%s}\n",
			slab_it->slab_addr,
			slab_it->next,
			slab_it->freelist,
			slab_it->is_corrupted ? "true" : "false"
		);
#endif

		printf("=============== Partial list %ld/%ld ===============\n", i, slablist_len);
		freelist = slab_it->freelist;
		GH_(Freelist)* fl = GH_(collect_freelist)(core, freelist, freelist_offset, cache_rand);
		GH_(dump_freelist)(fl);
		freelist_free(fl);
		
		++i;
	}
}

// TODO: replace struct member type with their actual type (using typedb)
static void GH_(dump_cpu_partial_freelist)(RzCore* core, GHT kmem_cache, GHT kmem_cache_cpu) {
	GHT partial;
	GHT cache_rand;
	unsigned int freelist_offset;

	// get "partial" from "kmem_cache_cpu"
	rz_io_read_at_mapped(
		core->io,
		kmem_cache_cpu + GH_(offset_in_struct)(core, "kmem_cache_cpu", "partial"),
		(void*)&partial,
		sizeof(GHT)
	);

#ifdef SLUB_DEBUG
	printf("partial: %" GHFMTx "\n", partial);
#endif

	// get "freelist_offset" from "kmem_cache"
	rz_io_read_at_mapped(
		core->io,
		kmem_cache + GH_(offset_in_struct)(core, "kmem_cache", "offset"),
		(void*)&freelist_offset,
		sizeof(unsigned int)
	);

	if (core->analysis->vmlinux_config->config_tbl->config_slab_freelist_hardened) {
		// get "random" from "kmem_cache"
		rz_io_read_at_mapped(
			core->io,
			kmem_cache + GH_(offset_in_struct)(core, "kmem_cache", "random"),
			(void*)&cache_rand,
			sizeof(GHT)
		);
	}

	GH_(Slablist)* partials = GH_(collect_slablist)(core, partial, 0, "next");
	GH_(dump_partial)(core, partials, freelist_offset, cache_rand);
}

static void GH_(dump_node_freelist)(RzCore* core, GHT kmem_cache, GHT kmem_cache_node) {
	GHT partial;
	GHT cache_rand;
	unsigned int freelist_offset;

	// get "partial" from "kmem_cache_node"
	rz_io_read_at_mapped(
		core->io,
		kmem_cache_node + GH_(offset_in_struct)(core, "kmem_cache_node", "partial"),
		(void*)&partial,
		sizeof(GHT)
	);

#ifdef SLUB_DEBUG
	printf("partial: %" GHFMTx "\n", partial);
#endif

	// get "freelist_offset" from "kmem_cache"
	rz_io_read_at_mapped(
		core->io,
		kmem_cache + GH_(offset_in_struct)(core, "kmem_cache", "offset"),
		(void*)&freelist_offset,
		sizeof(unsigned int)
	);

	if (core->analysis->vmlinux_config->config_tbl->config_slab_freelist_hardened) {
		// get "random" from "kmem_cache"
		rz_io_read_at_mapped(
			core->io,
			kmem_cache + GH_(offset_in_struct)(core, "kmem_cache", "random"),
			(void*)&cache_rand,
			sizeof(GHT)
		);
	}

	GHT slablist_head_addr = kmem_cache_node + GH_(offset_in_struct)(core, "kmem_cache_node", "partial");
	GH_(Slablist)* partials = GH_(collect_slablist)(core, partial, slablist_head_addr, "slab_list");
	GH_(dump_partial)(core, partials, freelist_offset, cache_rand);
}

/**
 * \brief dump lockless freelist command
*/
RZ_IPI RzCmdStatus GH_(rz_cmd_debug_slub_dump_lockless_freelist_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput* output_state) {
	rz_return_val_if_fail(core->analysis->vmlinux_config, RZ_CMD_STATUS_INVALID);

	(void)output_state;
	size_t n_cpu;
	size_t cache_size;

#ifdef SLUB_DEBUG
	for (size_t i  = 0; i < argc; ++i) {
		printf("argv[%lu] == '%s'\n", i, argv[i]);
	}
#endif

#ifdef SLUB_DEBUG
	printf("target bits: %d\n", core->rasm->bits);
#endif
	
	cache_size = rz_num_get(NULL, argv[1]);
	n_cpu = 0; // default

	if (argc >= 2) {
		n_cpu = rz_num_get(NULL, argv[2]);
	}
#ifdef SLUB_DEBUG
	printf("cache_size=%lu, n_cpu=%lu\n", cache_size, n_cpu);
	printf("vmlinux baddr: 0x%llx\n", rz_bin_get_baddr(core->bin));
#endif
	
	GHT kmem_cache = GH_(get_kmem_cache)(core, cache_size);
#ifdef SLUB_DEBUG
	printf("kmem_cache: 0x%" GHFMTx "\n", kmem_cache);
#endif
	GHT kmem_cache_cpu = GH_(get_kmem_cache_cpu)(core, kmem_cache, n_cpu);
#ifdef SLUB_DEBUG
	printf("kmem_cache_cpu: 0x%" GHFMTx "\n", kmem_cache_cpu);
#endif
	GH_(dump_cpu_lockless_freelist)(core, kmem_cache, kmem_cache_cpu);
	return RZ_CMD_STATUS_OK;
}

/**
 * \brief dump regular (locking) freelist command
*/
RZ_IPI RzCmdStatus GH_(rz_cmd_debug_slub_dump_regular_freelist_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput* output_state) {
	rz_return_val_if_fail(core->analysis->vmlinux_config, RZ_CMD_STATUS_INVALID);

	(void)output_state;
	size_t n_cpu;
	size_t cache_size;

#ifdef SLUB_DEBUG
	for (size_t i  = 0; i < argc; ++i) {
		printf("argv[%lu] == '%s'\n", i, argv[i]);
	}
#endif

#ifdef SLUB_DEBUG
	printf("target bits: %d\n", core->rasm->bits);
#endif
	
	cache_size = rz_num_get(NULL, argv[1]);
	n_cpu = 0; // default

	if (argc >= 2) {
		n_cpu = rz_num_get(NULL, argv[2]);
	}
#ifdef SLUB_DEBUG
	printf("cache_size=%lu, n_cpu=%lu\n", cache_size, n_cpu);
	printf("vmlinux baddr: 0x%llx\n", rz_bin_get_baddr(core->bin));
#endif
	
	GHT kmem_cache = GH_(get_kmem_cache)(core, cache_size);
#ifdef SLUB_DEBUG
	printf("kmem_cache: 0x%" GHFMTx "\n", kmem_cache);
#endif
	GHT kmem_cache_cpu = GH_(get_kmem_cache_cpu)(core, kmem_cache, n_cpu);
#ifdef SLUB_DEBUG
	printf("kmem_cache_cpu: 0x%" GHFMTx "\n", kmem_cache_cpu);
#endif
	GH_(dump_cpu_regular_freelist)(core, kmem_cache, kmem_cache_cpu);
	return RZ_CMD_STATUS_OK;
}

// TODO: fail if bin.elf.vmlinux=false
/**
 * \brief Dump partial freelists command
*/
RZ_IPI RzCmdStatus GH_(rz_cmd_debug_slub_dump_partial_freelist_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput* output_state) {
	rz_return_val_if_fail(core->analysis->vmlinux_config, RZ_CMD_STATUS_INVALID);

	(void)output_state;
	size_t n_cpu;
	size_t cache_size;

#ifdef SLUB_DEBUG
	for (size_t i  = 0; i < argc; ++i) {
		printf("argv[%lu] == '%s'\n", i, argv[i]);
	}
#endif

#ifdef SLUB_DEBUG
	printf("target bits: %d\n", core->rasm->bits);
#endif
	
	cache_size = rz_num_get(NULL, argv[1]);
	n_cpu = 0; // default

	if (argc >= 2) {
		n_cpu = rz_num_get(NULL, argv[2]);
	}
#ifdef SLUB_DEBUG
	printf("cache_size=%lu, n_cpu=%lu\n", cache_size, n_cpu);
	printf("vmlinux baddr: 0x%llx\n", rz_bin_get_baddr(core->bin));
#endif
	
	GHT kmem_cache = GH_(get_kmem_cache)(core, cache_size);
#ifdef SLUB_DEBUG
	printf("kmem_cache: 0x%" GHFMTx "\n", kmem_cache);
#endif
	GHT kmem_cache_cpu = GH_(get_kmem_cache_cpu)(core, kmem_cache, n_cpu);
#ifdef SLUB_DEBUG
	printf("kmem_cache_cpu: 0x%" GHFMTx "\n", kmem_cache_cpu);
#endif

	GH_(dump_cpu_partial_freelist)(core, kmem_cache, kmem_cache_cpu);
	
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus GH_(rz_cmd_debug_slub_dump_node_freelist_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput* output_state) {
	rz_return_val_if_fail(core->analysis->vmlinux_config, RZ_CMD_STATUS_INVALID);

	(void)output_state;

	size_t n_node;
	size_t cache_size;

#ifdef SLUB_DEBUG
	for (size_t i  = 0; i < argc; ++i) {
		printf("argv[%lu] == '%s'\n", i, argv[i]);
	}
#endif

#ifdef SLUB_DEBUG
	printf("target bits: %d\n", core->rasm->bits);
#endif
	
	cache_size = rz_num_get(NULL, argv[1]);
	n_node = 0; // default

	if (argc >= 2) {
		n_node = rz_num_get(NULL, argv[2]);
	}
#ifdef SLUB_DEBUG
	printf("cache_size=%lu, n_node=%lu\n", cache_size, n_node);
	printf("vmlinux baddr: 0x%llx\n", rz_bin_get_baddr(core->bin));
#endif
	
	GHT kmem_cache = GH_(get_kmem_cache)(core, cache_size);
#ifdef SLUB_DEBUG
	printf("kmem_cache: 0x%" GHFMTx "\n", kmem_cache);
#endif
	GHT kmem_cache_node = GH_(get_kmem_cache_node)(core, kmem_cache, n_node);
#ifdef SLUB_DEBUG
	printf("kmem_cache_node: 0x%" GHFMTx "\n", kmem_cache_node);
#endif

	GH_(dump_node_freelist)(core, kmem_cache, kmem_cache_node);

	return RZ_CMD_STATUS_OK;
}