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
	FREELIST_OK = 0,
	FREELIST_CORRUPTED,
	FREELIST_CYCLE,
} GH_(FreelistState);

typedef struct {
	GH_(FreelistState) state;
	RzVector* freelist_vector;
} GH_(Freelist);

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
static size_t GH_(offset_in_struct)(RzCore* core, const char* typename, const char* membname) {
	RzTypeDB* typedb = core->analysis->typedb;
	RzBaseType* btype = rz_type_db_get_base_type(typedb, typename);
	RzTypeStructMember* memb_iter;
	RzTypeStructMember* memb = NULL;
	rz_vector_foreach(&btype->struct_data.members, memb_iter) {
		if (!strcmp(memb_iter->name, membname)) {
			memb = memb_iter;
		}
	}
	if (memb == NULL) {
		return (size_t)-1;
	}
	return memb->offset;
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
	printf("index in kmalloc_caches: %lu\n", index);
#endif
    RzBinSymbol *kmalloc_caches = GH_(get_symbol_by_name)(core, "kmalloc_caches");
    if (kmalloc_caches == NULL) {
        return GHT_MAX;
    }
#ifdef SLUB_DEBUG
	printf("kmalloc_caches: 0x%lx\n", kmalloc_caches->vaddr + rz_bin_get_baddr(core->bin));
#endif
    
    GHT kmem_cache;
	
    // deref 2d array: kmalloc_caches[cache_type][index]
	size_t size2 = 12 + 1 + 1; // PAGE_SHIFT + 1 + 1
#ifdef SLUB_DEBUG
	printf("offset in 2d addr: %lu\n", GH_(offset_in_2d_arr)(size2, sizeof(GHT), cache_type, index));
#endif
    rz_io_read_at_mapped(
        core->io, 
        kmalloc_caches->vaddr + GH_(offset_in_2d_arr)(size2, sizeof(GHT), cache_type, index),
        &kmem_cache,
        sizeof(GHT)
    );
    return kmem_cache;
}

static GHT GH_(get_kmem_cache_cpu)(RzCore *core, GHT kmem_cache, size_t n_cpu) {
    RzBinSymbol *per_cpu_offset = GH_(get_symbol_by_name)(core, "__per_cpu_offset");
#ifdef SLUB_DEBUG
	printf("__per_cpu_offset: 0x%lx\n", per_cpu_offset->vaddr);
#endif
	
	GHT percpu_n;
	rz_io_read_at_mapped(
		core->io,
		per_cpu_offset->vaddr + GH_(offset_in_arr)(sizeof(GHT), n_cpu),
		&percpu_n,
		sizeof(GHT)
	);

	GHT cpu_slab;
	rz_io_read_at_mapped(
		core->io,
		kmem_cache + GH_(offset_in_struct)(core, "kmem_cache", "cpu_slab"),
		&cpu_slab,
		sizeof(GHT)
	);

	GHT kmem_cache_cpu = percpu_n + cpu_slab;

	return kmem_cache_cpu;
}

static GHT GH_(get_kmem_cache_node)(RzCore* core, GHT kmem_cache, size_t node_n) {
	RzBaseType *kmem_cache_node_btype = rz_type_db_get_base_type(core->analysis->typedb, "kmem_cache_node");
	GHT kmem_cache_node_n;
	rz_io_read_at_mapped(
		core->io,
		kmem_cache + GH_(offset_in_struct)(core, "kmem_cache", "node") + offset_in_arr(kmem_cache_node_btype->size, node_n),
		&kmem_cache_node_n,
		sizeof(GHT)
	);
	return kmem_cache_node_n;
}

static inline GHT GH_(decode_freelist)(GHT freelist, GHT p_freelist, GHT cache_rand) {
	return GH(rz_swap_ut)(p_freelist) ^ cache_rand ^ freelist;
}

static GH_(Freelist)* GH_(collect_freelist)(RzCore* core, GHT freelist, size_t freelist_offset, GHT cache_rand) {
	bool read_ok;
	GH_(Freelist)* result = rz_mem_alloc(sizeof(GH_(Freelist)));

	SetU* prev = set_u_new();
	result->freelist_vector = rz_vector_new(sizeof(GHT), NULL, NULL);
#ifdef SLUB_DEBUG
	printf("================ COLLECT FREELIST(freelist=0x%lx, freelist_offset=%lu, cache_rand=0x%lx) ==============\n",
			freelist, freelist_offset, cache_rand);
#endif

	RzVector* freelist_vector = result->freelist_vector;
	while (true) {
		GHT chunk_base = freelist;
#ifdef SLUB_DEBUG
		printf("chunk_base: 0x%lx\n", chunk_base);
		printf("reading freelist @ p_freelist: %lx\n", chunk_base + freelist_offset);
#endif
		read_ok = rz_io_read_at_mapped(
			core->io,
			chunk_base + freelist_offset,
			&freelist,
			sizeof(GHT)
		);

#ifdef SLUB_DEBUG
		printf("obfuscated freelist: %lx\n", freelist);
#endif
		freelist = GH_(decode_freelist)(freelist, chunk_base + freelist_offset, cache_rand);
#ifdef SLUB_DEBUG
		printf("deobfuscated freelist: %lx\n", freelist);
#endif

		// check if freelist was corrupted
		if (!read_ok) {
			// TODO
#ifdef SLUB_DEBUG
			printf("[!] freelist corrupted\n");
#endif
			result->state = FREELIST_CORRUPTED;
			goto out;
		}

		// check if end
		if (!freelist) {
#ifdef SLUB_DEBUG
			printf("[*] freelist ok\n");
#endif
			result->state = FREELIST_OK;
			goto out;
		}

		// check if cycle
		if (set_u_contains(prev, freelist)) {
#ifdef SLUB_DEBUG
			printf("[!] freelist cycle\n");
#endif
			result->state = FREELIST_CYCLE;
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
					case FREELIST_OK:
						break;
					case FREELIST_CORRUPTED:
						printf(" (corrupted)");
						break;
					case FREELIST_CYCLE:
						printf(" (cycle)");
						break;
			}
		}
		printf("\n");
		++i;
	}
#ifdef SLUB_DEBUG
	printf("[*] exit from freelist dump");
#endif
}


// TODO: replace struct member type with their actual type (using typedb)
static void GH_(dump_cpu_lockless_freelist)(RzCore* core, GHT kmem_cache, GHT kmem_cache_cpu) {
	GHT freelist;
	// Dirty hardcode: offsetof(kmem_cache_cpu, freelist)=0.
	// Can't use offset_in_struct since it does not yet support anonymous member unwrapping.
	GHT p_freelist = kmem_cache_cpu + 0;
	rz_io_read_at_mapped(
		core->io,
		p_freelist,
		&freelist,
		sizeof(GHT)
	);
#ifdef SLUB_DEBUG
	printf("freelist: 0x%lx\n", freelist);
#endif

	unsigned int freelist_offset;
	rz_io_read_at_mapped(
		core->io,
		kmem_cache + GH_(offset_in_struct)(core, "kmem_cache", "offset"),
		&freelist_offset,
		sizeof(unsigned int)
	);
#ifdef SLUB_DEBUG
	printf("freelist_offset: %lu\n", freelist_offset);
#endif

	GHT cache_rand;
	rz_io_read_at_mapped(
		core->io,
		kmem_cache + GH_(offset_in_struct)(core, "kmem_cache", "random"),
		&cache_rand,
		sizeof(GHT)
	);
#ifdef SLUB_DEBUG
	printf("cache random: 0x%lx\n", cache_rand);
#endif

	GH_(Freelist)* fl = GH_(collect_freelist)(core, freelist, freelist_offset, cache_rand);
	GH_(dump_freelist)(fl);
}

RZ_IPI RzCmdStatus GH_(rz_cmd_debug_slub_dump_freelist_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput* output_state) {
	(void)output_state;
	size_t n_cpu;
	size_t cache_size;

#ifdef SLUB_DEBUG
	for (size_t i  = 0; i < argc; ++i) {
		printf("argv[%lu] == '%s'\n", i, argv[i]);
	}
#endif

#ifdef SLUB_DEBUG
	printf("target bits: %lu\n", core->rasm->bits);
#endif
	
	cache_size = rz_num_get(NULL, argv[1]);
	n_cpu = 0; // default

	if (argc >= 2) {
		n_cpu = rz_num_get(NULL, argv[2]);
	}
#ifdef SLUB_DEBUG
	printf("cache_size=%lu, n_cpu=%lu\n", cache_size, n_cpu);
	printf("vmlinux baddr: 0x%lx\n", rz_bin_get_baddr(core->bin));
#endif
	
	GHT kmem_cache = GH_(get_kmem_cache)(core, cache_size);
#ifdef SLUB_DEBUG
	printf("kmem_cache: 0x%lx\n", kmem_cache);
#endif
	GHT kmem_cache_cpu = GH_(get_kmem_cache_cpu)(core, kmem_cache, n_cpu);
#ifdef SLUB_DEBUG
	printf("kmem_cache_cpu: 0x%lx\n", kmem_cache_cpu);
#endif
	GH_(dump_cpu_lockless_freelist)(core, kmem_cache, kmem_cache_cpu);
	return RZ_CMD_STATUS_OK;
}