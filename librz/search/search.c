// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include "search_internal.h"

RZ_LIB_VERSION(rz_search);

typedef struct search_ctx {
	RzIO *io; ///< the RzIO struct to use
	RzSearchCollection *col; ///< collection to use
	RzSearchOpt *opt; ///< User options
	RzThreadQueue *hits; ///< Hits list
	RzAtomicBool *loop; ///< used to stop or not the execution
} search_ctx_t;

static void *search_cancel_th(void *user) {
	search_ctx_t *ctx = (search_ctx_t *)user;
	RzSearchOpt *opt = ctx->opt;

	do {
		size_t n_hits = rz_th_queue_size(ctx->hits);
		if (!opt->cancel_cb(opt->cancel_usr, n_hits)) {
			rz_atomic_bool_set(ctx->loop, false);
			break;
		}
		rz_sys_usleep(100000);
	} while (rz_atomic_bool_get(ctx->loop));

	return NULL;
}

static bool search_iterator_cb(void *element, void *user) {
	search_ctx_t *ctx = (search_ctx_t *)user;
	RzIOMap *map = (RzIOMap *)element;
	if (!map) {
		return rz_atomic_bool_get(ctx->loop);
	}

	RzSearchOpt *opt = ctx->opt;
	RzSearchCollection *col = ctx->col;

	ut8 *buffer = malloc(opt->buffer_size);
	if (!buffer) {
		rz_atomic_bool_set(ctx->loop, false);
		return false;
	}

	const ut64 from = rz_itv_begin(map->itv);
	const ut64 to = rz_itv_end(map->itv);

	for (ut64 at = from; at < to; at += opt->buffer_size) {
		if (!rz_atomic_bool_get(ctx->loop)) {
			break;
		}
		// calculate the buffer size
		size_t size = opt->buffer_size;
		if ((at + opt->buffer_size) > to) {
			size = to - at;
		}
		// read the buffer
		if (!rz_io_read_at(ctx->io, at, buffer, size)) {
			RZ_LOG_ERROR("search: failed to read at 0x%08" PFMT64x " (%" PFMTSZu " bytes)\n", at, size);
			break;
		} else if (!col->search_over(col->collection, at, buffer, size, ctx->hits)) {
			RZ_LOG_ERROR("search: failed search at 0x%08" PFMT64x "\n", at);
			break;
		}
	}

	free(buffer);
	return rz_atomic_bool_get(ctx->loop);
}

/**
 * \brief      Perform a search within the given search maps of a collection
 *
 * \param      opt        The RzSearchOpt to use
 * \param      col        The RzSearchCollection to use
 * \param      io         The RzIO layer to use
 * \param      search_in  The search maps for the boundaries
 *
 * \return     On success returns all the hits.
 */
RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_search_run(RZ_NONNULL RzSearchOpt *opt, RZ_NONNULL RzSearchCollection *col, RZ_NONNULL RzIO *io, RZ_NONNULL RzList /*<RzIOMap *>*/ *search_in) {
	rz_return_val_if_fail(opt && col && io && search_in, NULL);
	search_ctx_t ctx = { 0 };
	RzList *results = NULL;
	RzThreadQueue *hits = NULL;
	RzThread *cancel_th = NULL;

	if (opt->buffer_size < 1) {
		RZ_LOG_ERROR("search: cannot search when buffer size is less than %u bytes.\n", RZ_SEARCH_MIN_BUFFER_SIZE);
		return NULL;
	}

	if (rz_list_empty(search_in)) {
		RZ_LOG_ERROR("search: cannot search in an empty RzIOMap list.\n");
		return NULL;
	}

	if (rz_search_collection_is_empty(col)) {
		RZ_LOG_ERROR("search: cannot perform the search when the search collection is empty.\n");
		return NULL;
	}

	hits = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, (RzListFree)rz_search_hit_free);
	if (!hits) {
		RZ_LOG_ERROR("search: cannot allocate RzSearchHit queue.\n");
		return NULL;
	}

	ctx.col = col;
	ctx.opt = opt;
	ctx.io = io;
	ctx.loop = rz_atomic_bool_new(true);

	if (opt->cancel_cb) {
		// create cancel thread
		cancel_th = rz_th_new(search_cancel_th, &ctx);
		if (!cancel_th) {
			RZ_LOG_ERROR("search: cannot allocate cancel thread.\n");
			rz_th_queue_free(hits);
			return NULL;
		}
	}

	if (!rz_th_iterate_list(search_in, search_iterator_cb, opt->max_threads, &ctx)) {
		RZ_LOG_ERROR("search: cannot iterate over list.\n");
	} else {
		results = rz_th_queue_pop_all(hits);
	}

	if (cancel_th) {
		// stop & free cancel thread.
		rz_atomic_bool_set(ctx.loop, false);
		rz_th_wait(cancel_th);
		rz_th_free(cancel_th);
	}

	rz_th_queue_free(hits);
	return results;
}

/**
 * \brief      Allocate and initialize a new RzSearchHit
 *
 * \param[in]  metadata  The metadata linked to the hit (can be NULL)
 * \param[in]  address   The address where the hit happened
 * \param[in]  size      The size of the hit data (can be 0)
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_IPI RZ_OWN RzSearchHit *rz_search_hit_new(const char *metadata, ut64 address, size_t size) {
	RzSearchHit *hit = RZ_NEW0(RzSearchHit);
	if (!hit) {
		return NULL;
	}
	hit->metadata = rz_str_dup(metadata);
	hit->address = address;
	hit->size = size;
	return hit;
}

/**
 * \brief      Frees a RzSearchHit structure
 *
 * \param      hit  The RzSearchHit pointer to free
 */
RZ_API void rz_search_hit_free(RZ_NULLABLE RzSearchHit *hit) {
	if (!hit) {
		return;
	}
	free(hit->metadata);
	free(hit);
}