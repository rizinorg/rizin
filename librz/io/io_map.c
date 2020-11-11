/* rizin - LGPL - Copyright 2017-2019 - condret, MaskRay */

#include <rz_io.h>
#include <stdlib.h>
#include <sdb.h>
#include "rz_binheap.h"
#include "rz_util.h"
#include "rz_vector.h"

#define END_OF_MAP_IDS UT32_MAX

#define CMP_END_GTE(addr, itv) \
	(((addr) < rz_itv_end (*(RzInterval *)(itv))) ? -1 : 1)

#define CMP_END_GTE_PART(addr, part) \
	(((addr) < (rz_itv_end (((RzIOMapSkyline *)(part))->itv)) || !rz_itv_end (((RzIOMapSkyline *)(part))->itv)) ? -1 : 1)

#define CMP_BEGIN_GTE_PART(addr, part) \
	(((addr) > (rz_itv_begin (((RzIOMapSkyline *)(part))->itv))) - ((addr) < (rz_itv_begin (((RzIOMapSkyline *)(part))->itv))))

static bool add_map_to_skyline(RzIO *io, RzIOMap *map) {
	size_t slot;
	RzPVector *skyline = &io->map_skyline;

	RzIOMapSkyline *new_part = RZ_NEW (RzIOMapSkyline);
	new_part->map = map;
	new_part->itv = map->itv;
	const ut64 new_part_end = rz_itv_end (new_part->itv);

	// `part` is the first RzIOMapSkyline with part->itv.addr >= new_part->itv.addr
	rz_pvector_lower_bound (skyline, new_part->itv.addr, slot, CMP_BEGIN_GTE_PART);
	RzIOMapSkyline *part = slot < rz_pvector_len (skyline) ? rz_pvector_at (skyline, slot) : NULL;
	if (slot) {
		RzIOMapSkyline *prev_part = rz_pvector_at (skyline, slot - 1);
		const ut64 prev_part_end = rz_itv_end (prev_part->itv);
		if (prev_part_end > rz_itv_begin (new_part->itv)) {
			if (prev_part_end > new_part_end) {
				RzIOMapSkyline *tail = RZ_NEW (RzIOMapSkyline);
				tail->map = prev_part->map;
				tail->itv.addr = new_part_end;
				tail->itv.size = prev_part_end - rz_itv_begin (tail->itv);
				if (slot < rz_pvector_len (skyline)) {
					rz_pvector_insert (skyline, slot, tail);
				} else {
					rz_pvector_push (skyline, tail);
				}
			}
			prev_part->itv.size = rz_itv_begin (new_part->itv) - rz_itv_begin (prev_part->itv);
		}
	}
	if (part) {
		while (part && rz_itv_include (new_part->itv, part->itv)) {
			// Remove `part` that fits in `new_part`
			rz_pvector_remove_at (skyline, slot);
			part = slot < rz_pvector_len (skyline) ? rz_pvector_at (skyline, slot) : NULL;
		}
		if (part && rz_itv_overlap (new_part->itv, part->itv)) {
			// Chop start of last `part` that intersects `new_part`
			const ut64 oaddr = rz_itv_begin (part->itv);
			part->itv.addr = new_part_end;
			part->itv.size -= rz_itv_begin (part->itv) - oaddr;
		}
	}
	if (slot < rz_pvector_len (skyline)) {
		rz_pvector_insert (skyline, slot, new_part);
	} else {
		rz_pvector_push (skyline, new_part);
	}
	return true;
}

// Store map parts that are not covered by others into io->map_skyline
void io_map_calculate_skyline(RzIO *io) {
	rz_pvector_clear (&io->map_skyline);
	// Last map has highest priority (it shadows previous maps)
	void **it;
	rz_pvector_foreach (&io->maps, it) {
		add_map_to_skyline (io, (RzIOMap *)*it);
	}
}

RzIOMap* io_map_new(RzIO* io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	if (!size || !io || !io->map_ids) {
		return NULL;
	}
	RzIOMap* map = RZ_NEW0 (RzIOMap);
	if (!map || !io->map_ids || !rz_id_pool_grab_id (io->map_ids, &map->id)) {
		free (map);
		return NULL;
	}
	map->fd = fd;
	map->delta = delta;
	if ((UT64_MAX - size + 1) < addr) {
		/// XXX: this is leaking a map!!!
		io_map_new (io, fd, perm, delta - addr, 0LL, size + addr);
		size = -(st64)addr;
	}
	// RzIOMap describes an interval of addresses (map->from; map->to)
	map->itv = (RzInterval){ addr, size };
	map->perm = perm;
	map->delta = delta;
	// new map lives on the top, being top the list's tail
	rz_pvector_push (&io->maps, map);
	add_map_to_skyline (io, map);
	return map;
}

RZ_API RzIOMap *rz_io_map_new(RzIO *io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	return io_map_new (io, fd, perm, delta, addr, size);
}

RZ_API bool rz_io_map_remap(RzIO *io, ut32 id, ut64 addr) {
	RzIOMap *map = rz_io_map_resolve (io, id);
	if (map) {
		ut64 size = map->itv.size;
		map->itv.addr = addr;
		if (UT64_MAX - size + 1 < addr) {
			map->itv.size = -addr;
			rz_io_map_new (io, map->fd, map->perm, map->delta - addr, 0, size + addr);
		}
		io_map_calculate_skyline (io);
		return true;
	}
	return false;
}

RZ_API bool rz_io_map_remap_fd(RzIO *io, int fd, ut64 addr) {
	RzIOMap *map;
	bool retval = false;
	RzList *maps = rz_io_map_get_for_fd (io, fd);
	if (maps) {
		map = rz_list_get_n (maps, 0);
		if (map) {
			retval = rz_io_map_remap (io, map->id, addr);
		}
		rz_list_free (maps);
	}
	return retval;
}

static void _map_free(void* p) {
	RzIOMap* map = (RzIOMap*) p;
	if (map) {
		free (map->name);
		free (map);
	}
}

RZ_API void rz_io_map_init(RzIO* io) {
	rz_return_if_fail (io);
	rz_pvector_init (&io->maps, _map_free);
	if (io->map_ids) {
		rz_id_pool_free (io->map_ids);
	}
	io->map_ids = rz_id_pool_new (1, END_OF_MAP_IDS);
}

// check if a map with exact the same properties exists
RZ_API bool rz_io_map_exists(RzIO *io, RzIOMap *map) {
	rz_return_val_if_fail (io && map, false);
	void **it;
	rz_pvector_foreach (&io->maps, it) {
		RzIOMap *m = *it;
		if (!memcmp (m, map, sizeof (RzIOMap))) {
			return true;
		}
	}
	return false;
}

// check if a map with specified id exists
RZ_API bool rz_io_map_exists_for_id(RzIO* io, ut32 id) {
	return rz_io_map_resolve (io, id) != NULL;
}

RZ_API RzIOMap* rz_io_map_resolve(RzIO *io, ut32 id) {
	rz_return_val_if_fail (io && id, false);
	void **it;
	rz_pvector_foreach (&io->maps, it) {
		RzIOMap *map = *it;
		if (map->id == id) {
			return map;
		}
	}
	return NULL;
}

RzIOMap* io_map_add(RzIO* io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	//check if desc exists
	RzIODesc* desc = rz_io_desc_get (io, fd);
	if (desc) {
		//a map cannot have higher permissions than the desc belonging to it
		return io_map_new (io, fd, (perm & desc->perm) | (perm & RZ_PERM_X),
				delta, addr, size);
	}
	return NULL;
}

RZ_API RzIOMap *rz_io_map_add(RzIO *io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	return io_map_add (io, fd, perm, delta, addr, size);
}

RZ_API RzIOMap *rz_io_map_add_batch(RzIO *io, int fd, int perm, ut64 delta, ut64 addr, ut64 size) {
	return io_map_add (io, fd, perm, delta, addr, size);
}

RZ_API void rz_io_update(RzIO *io) {
	io_map_calculate_skyline (io);
}

RZ_API RzIOMap* rz_io_map_get_paddr(RzIO* io, ut64 paddr) {
	rz_return_val_if_fail (io, NULL);
	void **it;
	rz_pvector_foreach_prev (&io->maps, it) {
		RzIOMap *map = *it;
		if (map->delta <= paddr && paddr <= map->delta + map->itv.size - 1) {
			return map;
		}
	}
	return NULL;
}

// gets first map where addr fits in
RZ_API RzIOMap *rz_io_map_get(RzIO* io, ut64 addr) {
	rz_return_val_if_fail (io, NULL);
	const RzPVector *skyline = &io->map_skyline;
	size_t i, len = rz_pvector_len (skyline);
	rz_pvector_lower_bound (skyline, addr, i, CMP_END_GTE_PART);
	if (i == len) {
		return NULL;
	}
	const RzIOMapSkyline *sky = rz_pvector_at (skyline, i);
	return sky->itv.addr <= addr ? sky->map : NULL;
}

RZ_API bool rz_io_map_is_mapped(RzIO* io, ut64 addr) {
	rz_return_val_if_fail (io, false);
	return (bool)rz_io_map_get (io, addr);
}

RZ_API void rz_io_map_reset(RzIO* io) {
	rz_io_map_fini (io);
	rz_io_map_init (io);
	io_map_calculate_skyline (io);
}

RZ_API bool rz_io_map_del(RzIO *io, ut32 id) {
	rz_return_val_if_fail (io, false);
	size_t i;
	for (i = 0; i < rz_pvector_len (&io->maps); i++) {
		RzIOMap *map = rz_pvector_at (&io->maps, i);
		if (map->id == id) {
			rz_pvector_remove_at (&io->maps, i);
			_map_free (map);
			rz_id_pool_kick_id (io->map_ids, id);
			io_map_calculate_skyline (io);
			return true;
		}
	}
	return false;
}

//delete all maps with specified fd
RZ_API bool rz_io_map_del_for_fd(RzIO* io, int fd) {
	rz_return_val_if_fail (io, false);
	bool ret = false;
	size_t i;
	for (i = 0; i < rz_pvector_len (&io->maps);) {
		RzIOMap *map = rz_pvector_at (&io->maps, i);
		if (!map) {
			rz_pvector_remove_at (&io->maps, i);
		} else if (map->fd == fd) {
			rz_id_pool_kick_id (io->map_ids, map->id);
			//delete iter and map
			rz_pvector_remove_at (&io->maps, i);
			_map_free (map);
			ret = true;
		} else {
			i++;
		}
	}
	if (ret) {
		io_map_calculate_skyline (io);
	}
	return ret;
}

//brings map with specified id to the tail of of the list
//return a boolean denoting whether is was possible to priorized
RZ_API bool rz_io_map_priorize(RzIO* io, ut32 id) {
	rz_return_val_if_fail (io, false);
	size_t i;
	for (i = 0; i < rz_pvector_len (&io->maps); i++) {
		RzIOMap *map = rz_pvector_at (&io->maps, i);
		// search for iter with the correct map
		if (map->id == id) {
			rz_pvector_remove_at (&io->maps, i);
			rz_pvector_push (&io->maps, map);
			io_map_calculate_skyline (io);
			return true;
		}
	}
	return false;
}

RZ_API bool rz_io_map_depriorize(RzIO* io, ut32 id) {
	rz_return_val_if_fail (io, false);
	size_t i;
	for (i = 0; i < rz_pvector_len (&io->maps); i++) {
		RzIOMap *map = rz_pvector_at (&io->maps, i);
		// search for iter with the correct map
		if (map->id == id) {
			rz_pvector_remove_at (&io->maps, i);
			rz_pvector_push_front (&io->maps, map);
			io_map_calculate_skyline (io);
			return true;
		}
	}
	return false;
}

RZ_API bool rz_io_map_priorize_for_fd(RzIO *io, int fd) {
	rz_return_val_if_fail (io, false);
	//we need a clean list for this, or this becomes a segfault-field
	rz_io_map_cleanup (io);
	RzPVector temp;
	rz_pvector_init (&temp, NULL);
	size_t i;
	for (i = 0; i < rz_pvector_len (&io->maps);) {
		RzIOMap *map = rz_pvector_at (&io->maps, i);
		if (map->fd == fd) {
			rz_pvector_push (&temp, map);
			rz_pvector_remove_at (&io->maps, i);
			continue;
		}
		i++;
	}
	rz_pvector_insert_range (&io->maps, rz_pvector_len (&io->maps), temp.v.a, rz_pvector_len (&temp));
	rz_pvector_clear (&temp);
	io_map_calculate_skyline (io);
	return true;
}

//may fix some inconsistencies in io->maps
RZ_API void rz_io_map_cleanup(RzIO* io) {
	rz_return_if_fail (io);
	//remove all maps if no descs exist
	if (!io->files) {
		rz_io_map_fini (io);
		rz_io_map_init (io);
		return;
	}
	bool del = false;
	size_t i;
	for (i = 0; i < rz_pvector_len (&io->maps);) {
		RzIOMap *map = rz_pvector_at (&io->maps, i);
		if (!map) {
			// remove iter if the map is a null-ptr, this may fix some segfaults. This should never happen.
			rz_warn_if_reached ();
			rz_pvector_remove_at (&io->maps, i);
			del = true;
		} else if (!rz_io_desc_get (io, map->fd)) {
			//delete map and iter if no desc exists for map->fd in io->files
			rz_id_pool_kick_id (io->map_ids, map->id);
			map = rz_pvector_remove_at (&io->maps, i);
			_map_free (map);
			del = true;
		} else {
			i++;
		}
	}
	if (del) {
		io_map_calculate_skyline (io);
	}
}

RZ_API void rz_io_map_fini(RzIO* io) {
	rz_return_if_fail (io);
	rz_pvector_clear (&io->maps);
	rz_id_pool_free (io->map_ids);
	io->map_ids = NULL;
	rz_pvector_clear (&io->map_skyline);
}

RZ_API void rz_io_map_set_name(RzIOMap* map, const char* name) {
	if (!map || !name) {
		return;
	}
	free (map->name);
	map->name = strdup (name);
}

RZ_API void rz_io_map_del_name(RzIOMap* map) {
	if (map) {
		RZ_FREE (map->name);
	}
}

// TODO: very similar to rz_io_map_next_address, decide which one to use
RZ_API ut64 rz_io_map_next_available(RzIO* io, ut64 addr, ut64 size, ut64 load_align) {
	if (load_align == 0) {
		load_align = 1;
	}
	ut64 next_addr = addr,
	end_addr = next_addr + size;
	void **it;
	rz_pvector_foreach (&io->maps, it) {
		RzIOMap *map = *it;
		ut64 to = rz_itv_end (map->itv);
		next_addr = RZ_MAX (next_addr, to + (load_align - (to % load_align)) % load_align);
		// XXX - This does not handle when file overflow 0xFFFFFFFF000 -> 0x00000FFF
		// adding the check for the map's fd to see if this removes contention for
		// memory mapping with multiple files. infinite loop ahead?
		if ((map->itv.addr <= next_addr && next_addr < to) || rz_itv_contain (map->itv, end_addr)) {
			next_addr = to + (load_align - (to % load_align)) % load_align;
			return rz_io_map_next_available (io, next_addr, size, load_align);
		}
		break;
	}
	return next_addr;
}

// TODO: very similar to rz_io_map_next_available. decide which one to use
RZ_API ut64 rz_io_map_next_address(RzIO* io, ut64 addr) {
	ut64 lowest = UT64_MAX;
	void **it;
	rz_pvector_foreach (&io->maps, it) {
		RzIOMap *map = *it;
		ut64 from = rz_itv_begin (map->itv);
		if (from > addr && addr < lowest) {
			lowest = from;
		}
		ut64 to = rz_itv_end (map->itv);
		if (to > addr && to < lowest) {
			lowest = to;
		}
	}
	return lowest;
}

RZ_API RzList* rz_io_map_get_for_fd(RzIO* io, int fd) {
	RzList* map_list = rz_list_newf (NULL);
	if (!map_list) {
		return NULL;
	}
	void **it;
	rz_pvector_foreach (&io->maps, it) {
		RzIOMap *map = *it;
		if (map && map->fd == fd) {
			rz_list_append (map_list, map);
		}
	}
	return map_list;
}

RZ_API bool rz_io_map_resize(RzIO *io, ut32 id, ut64 newsize) {
	RzIOMap *map;
	if (!newsize || !(map = rz_io_map_resolve (io, id))) {
		return false;
	}
	ut64 addr = map->itv.addr;
	if (UT64_MAX - newsize + 1 < addr) {
		map->itv.size = -addr;
		rz_io_map_new (io, map->fd, map->perm, map->delta - addr, 0, newsize + addr);
		return true;
	}
	map->itv.size = newsize;
	io_map_calculate_skyline (io);
	return true;
}

// find a location that can hold enough bytes without overlapping
// XXX this function is buggy and doesnt works as expected, but i need it for a PoC for now
RZ_API ut64 rz_io_map_location(RzIO *io, ut64 size) {
	ut64 base = (io->bits == 64)? 0x60000000000LL: 0x60000000;
	while (rz_io_map_get (io, base)) {
		base += 0x200000;
	}
	return base;
}
