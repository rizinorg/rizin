// SPDX-FileCopyrightText: 2026 Shivam Chaudhary <sc31122004@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_HEATMAP_H
#define RZ_HEATMAP_H

#include <rz_types.h>
#include <rz_util/rz_iterator.h>
#include <rz_util/rz_strbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_heatmap_t RzHeatmap;

/**
 * \brief Cell coordinate within the heatmap grid.
 */
typedef struct rz_heatmap_coord_t {
	size_t row; ///< Row index (0-based)
	size_t col; ///< Column index (0-based)
	size_t index; ///< Linear cell index (0-based)
} RzHeatmapCoord;

/**
 * \brief Callback to query the progress of a cell (0.0 to 1.0).
 *
 * \param cell Pointer to cell identifier (e.g. RzHeatmapCoord* or user data)
 * \param user_data Caller-provided context
 * \return Progress value in range [0.0, 1.0]
 */
typedef float (*RzHeatmapProgressCb)(void *cell, void *user_data);

/**
 * \brief Optional callback to get a row label (e.g. memory address).
 *
 * \param row Row index
 * \param user_data Caller-provided context
 * \return String label for the row (must not be NULL, or return empty string)
 */
typedef const char *(*RzHeatmapRowLabelCb)(size_t row, void *user_data);

/**
 * \brief Callback returning an iterator over cells that need to be updated.
 *
 * \param user_data Caller-provided context
 * \return Initialized RzIterator yielding cell pointers (e.g. RzHeatmapCoord*)
 */
typedef RzIterator (*RzHeatmapUpdateCb)(void *user_data);

/**
 * \brief Color palette configuration for heatmap.
 */
typedef enum {
	RZ_HEATMAP_PALETTE_BLUE_GREEN = 0, ///< Shades of blue for <100%, green for 100%
	RZ_HEATMAP_PALETTE_GRAYSCALE, ///< Grayscale / intensity-based
} RzHeatmapPalette;

/**
 * \brief Configuration options for RzHeatmap.
 */
typedef struct rz_heatmap_options_t {
	const char *title; ///< Optional title string printed at the top
	const char *legend; ///< Optional legend string printed at the bottom
	size_t total_cells; ///< Total number of cells to plot
	size_t cols; ///< Fixed columns count (0 to auto-fit to term_width)
	size_t term_width; ///< Width of terminal (defaults to 80 if 0)
	size_t term_height; ///< Height of terminal (defaults to 24 if 0)
	bool use_color; ///< Emit ANSI color escape sequences
	bool use_utf8; ///< Use UTF-8 block characters (█) instead of ASCII (#)
	RzHeatmapPalette palette; ///< Color palette choice
} RzHeatmapOptions;

/**
 * \brief Initialize default options for RzHeatmapOptions.
 *
 * \param opts Options struct to initialize
 * \param total_cells Total number of cells to plot
 */
RZ_API void rz_heatmap_options_init(RZ_NONNULL RzHeatmapOptions *opts, size_t total_cells);

/**
 * \brief Create a new RzHeatmap instance.
 *
 * \param opts Configuration options
 * \param progress_cb Callback to fetch cell progress (mandatory)
 * \param user_data Caller context passed to callbacks
 * \return Newly allocated RzHeatmap instance, or NULL on failure
 */
RZ_API RZ_OWN RzHeatmap *rz_heatmap_new(
	RZ_NONNULL const RzHeatmapOptions *opts,
	RZ_NONNULL RzHeatmapProgressCb progress_cb,
	RZ_NULLABLE void *user_data);

/**
 * \brief Free an RzHeatmap instance.
 *
 * \param hm Heatmap instance to free
 */
RZ_API void rz_heatmap_free(RZ_NULLABLE RzHeatmap *hm);

/**
 * \brief Set an optional row label callback.
 *
 * \param hm Heatmap instance
 * \param cb Callback returning label string for each row
 */
RZ_API void rz_heatmap_set_row_label_cb(RZ_NONNULL RzHeatmap *hm, RZ_NULLABLE RzHeatmapRowLabelCb cb);

/**
 * \brief Set an optional update callback to support dynamic partial updates.
 *
 * \param hm Heatmap instance
 * \param cb Callback returning an RzIterator for changed cells
 */
RZ_API void rz_heatmap_set_update_cb(RZ_NONNULL RzHeatmap *hm, RZ_NULLABLE RzHeatmapUpdateCb cb);

/**
 * \brief Update the user_data context pointer associated with the heatmap.
 *
 * \param hm Heatmap instance
 * \param user_data New context pointer
 */
RZ_API void rz_heatmap_set_user_data(RZ_NONNULL RzHeatmap *hm, RZ_NULLABLE void *user_data);

/**
 * \brief Render the entire heatmap to a newly allocated string.
 *
 * \param hm Heatmap instance
 * \return Formatted string (must be freed by caller), or NULL on failure
 */
RZ_API RZ_OWN char *rz_heatmap_render(RZ_NONNULL RzHeatmap *hm);

/**
 * \brief Render dynamic update ANSI sequences for cells changed since last render.
 *
 * If an update callback is configured, it iterates over updated cells and produces
 * ANSI cursor movement and color sequences to redraw only the modified cells in place.
 * If no update callback is configured, it re-renders the full heatmap in-place.
 *
 * \param hm Heatmap instance
 * \return ANSI update string (must be freed by caller), or NULL on failure
 */
RZ_API RZ_OWN char *rz_heatmap_render_dynamic_update(RZ_NONNULL RzHeatmap *hm);

/**
 * \brief Get computed layout information (rows and columns).
 *
 * \param hm Heatmap instance
 * \param rows Output pointer for total rows
 * \param cols Output pointer for columns per row
 */
RZ_API void rz_heatmap_get_dimensions(RZ_NONNULL const RzHeatmap *hm, RZ_OUT size_t *rows, RZ_OUT size_t *cols);

#ifdef __cplusplus
}
#endif

#endif // RZ_HEATMAP_H

