// SPDX-FileCopyrightText: 2022 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include <rz_util/rz_assert.h>

#define DEFAULT_SPEED 1
#define ZOOM_DEFAULT  1

/**
 * \brief Create the string buffer with the horisontal histogram
 *
 *		 █    ██      █             █                                        █
 *		 █    ██      █             █                                       ██
 *	 █   █    ██      █             █ █                                     ██
 *	 ██  █    ██  █ ███             █ █              █                      ██   █
 *	 ██  ██   ███ █ ███             █ █              █ █     █    █   █ █   ██   █
 *	 ██  ██   ███ █ ███          █  █ █         █    █ █    ██    █   ███   ██   █
 *	 ██  ██   ███ █ ███          █  █ █  █      █    █ █    ██    █   ███  ███ █ █
 *	███  ██   ███ █ ███          █  █ █  █      █    █ █    ██    █   ███  █████ █
 *	███████   ███ █ ███          █  █ █  █      █    ███    ██    █   ███  █████ █
 *	███████   ███ █ ███   ██    ██  █ █  █  █   █    ███   ███   ██   ███  █████ █
 *	███████  ████ █ ███   ██    ██  █ █  █  █   █    ███   ███   ██   ████ █████ █
 * 	███████  ████ █ ███   ██    ██  █ █  ██ █   ██   ███   ███   ██   ████ █████ █
 *	███████__████_█_███__███__█_██_████__████___██__████___███___██__█████_█████_█
 *
 * \param opts Histogram options: color, style, legend and cursor position
 * \param data A buffer with the numerical data in the format of one byte per value
 * \param width Width of the histogram
 * \param height Height of the histogram
 */
RZ_API RZ_OWN RzStrBuf *rz_histogram_horizontal(RZ_NONNULL RzHistogramOptions *opts, RZ_NONNULL const ut8 *data, ut32 width, ut32 height) {
	rz_return_val_if_fail(opts && data, NULL);
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		return NULL;
	}

	size_t i, j;
	ut32 cols = 78;
	ut32 rows = height > 0 ? height : 10;
	const char *vline = opts->unicode ? RUNE_LINE_VERT : "|";
	const char *block = opts->unicode ? UTF_BLOCK : "#";
	const char *kol[5];
	kol[0] = opts->pal->call;
	kol[1] = opts->pal->jmp;
	kol[2] = opts->pal->cjmp;
	kol[3] = opts->pal->mov;
	kol[4] = opts->pal->nop;
	if (opts->color) {
		for (i = 0; i < rows; i++) {
			size_t threshold = i * (0xff / rows);
			size_t koli = i * 5 / rows;
			for (j = 0; j < cols; j++) {
				int realJ = j * width / cols;
				if (255 - data[realJ] < threshold || (i + 1 == rows)) {
					if (opts->thinline) {
						rz_strbuf_appendf(buf, "%s%s%s", kol[koli], vline, Color_RESET);
					} else {
						rz_strbuf_appendf(buf, "%s%s%s", kol[koli], block, Color_RESET);
					}
				} else {
					rz_strbuf_append(buf, " ");
				}
			}
			rz_strbuf_append(buf, "\n");
		}
		return buf;
	}

	for (i = 0; i < rows; i++) {
		size_t threshold = i * (0xff / rows);
		for (j = 0; j < cols; j++) {
			size_t realJ = j * width / cols;
			if (255 - data[realJ] < threshold) {
				if (opts->thinline) {
					rz_strbuf_append(buf, vline);
				} else {
					rz_strbuf_appendf(buf, "%s%s%s", Color_BGGRAY, block, Color_RESET);
				}
			} else if (i + 1 == rows) {
				rz_strbuf_append(buf, "_");
			} else {
				rz_strbuf_append(buf, " ");
			}
		}
		rz_strbuf_append(buf, "\n");
	}
	return buf;
}

static void histogram_block(RZ_NONNULL RzHistogramOptions *opts, RZ_NONNULL RzStrBuf *buf, int k, int cols) {
	rz_return_if_fail(opts && buf);
	const char *h_line = opts->unicode ? RUNE_LONG_LINE_HORIZ : "-";
	const char *block = opts->unicode ? UTF_BLOCK : "#";
	if (cols < 1) {
		cols = 1;
	}
	if (opts->color) {
		const char *kol[5];
		kol[0] = opts->pal->nop;
		kol[1] = opts->pal->mov;
		kol[2] = opts->pal->cjmp;
		kol[3] = opts->pal->jmp;
		kol[4] = opts->pal->call;
		int idx = (int)((k * 4) / cols);
		if (idx < 5) {
			const char *str = kol[idx];
			if (opts->thinline) {
				rz_strbuf_appendf(buf, "%s%s%s", str, h_line, Color_RESET);
			} else {
				rz_strbuf_appendf(buf, "%s%s%s", str, block, Color_RESET);
			}
		}
	} else {
		if (opts->thinline) {
			rz_strbuf_append(buf, h_line);
		} else {
			rz_strbuf_append(buf, block);
		}
	}
}

/**
 * \brief Create the string buffer with the vertical histogram
 *
 * │████████████████████████████████████████████████
 * │███
 * │████████████████████████████████████████████
 * │█████████████████████
 * │███████████████████████████████████████████████
 * │█████████████
 * │██████████████
 *
 * \param opts Histogram options: color, style, legend and cursor position
 * \param data A buffer with the numerical data in the format of one byte per value
 * \param width Width of the histogram
 * \param step Step for the new line
 */
RZ_API RZ_OWN RzStrBuf *rz_histogram_vertical(RZ_NONNULL RzHistogramOptions *opts, RZ_NONNULL const ut8 *data, int width, int step) {
	rz_return_val_if_fail(opts && data, NULL);
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		return NULL;
	}

	const int increment = 5;
	const char *v_line = opts->unicode ? RUNE_LINE_VERT : "|";
	int i = 0, j;

	// get the max of columns
	int cols = 0;
	for (i = 0; i < width; i++) {
		cols = data[i] > cols ? data[i] : cols;
	}
	cols /= 5;
	for (i = 0; i < width; i++) {
		ut8 next = (i + 1 < width) ? data[i + 1] : 0;
		int base = 0, k = 0;
		if (step > 0) {
			if (opts->offset) {
				ut64 at = opts->offpos + (i * step);
				if (opts->cursor) {
					if (i == opts->curpos) {
						rz_strbuf_appendf(buf, Color_INVERT "> 0x%08" PFMT64x " " Color_RESET, at);
					} else {
						rz_strbuf_appendf(buf, "  0x%08" PFMT64x " ", at);
					}
				} else {
					rz_strbuf_appendf(buf, "0x%08" PFMT64x " ", at);
				}
			}
			rz_strbuf_appendf(buf, "%03x %04x %s", i, data[i], v_line);
		} else {
			rz_strbuf_appendf(buf, "%s", v_line);
		}
		if (next < increment) {
			base = 1;
		}
		if (next < data[i]) {
			if (data[i] > increment) {
				for (j = 0; j < next + base; j += increment) {
					histogram_block(opts, buf, k, cols);
					k++;
				}
			}
			for (j = next + increment; j + base < data[i]; j += increment) {
				histogram_block(opts, buf, k, cols);
				k++;
			}
		} else {
			histogram_block(opts, buf, k, cols);
			k++;
		}
		if (i + 1 == width) {
			for (j = data[i] + increment + base; j + base < next; j += increment) {
				histogram_block(opts, buf, k, cols);
				k++;
			}
		} else if (data[i + 1] > data[i]) {
			for (j = data[i] + increment + base; j + base < next; j += increment) {
				histogram_block(opts, buf, k, cols);
				k++;
			}
		}
		if (opts->color) {
			rz_strbuf_append(buf, Color_RESET);
		}
		rz_strbuf_append(buf, "\n");
	}
	return buf;
}

RZ_API RzHistogramOptions *rz_histogram_options_new() {
	RzHistogramOptions *histops = RZ_NEW0(RzHistogramOptions);
	if (!histops) {
		return NULL;
	}
	return histops;
}

RZ_API void rz_histogram_options_free(RzHistogramOptions *histops) {
	free(histops);
}

RZ_API RzHistogramInteractive *rz_histogram_interactive_new(RzConsCanvas *can, RzHistogramOptions *opts) {
	RzHistogramInteractive *hist = RZ_NEW0(RzHistogramInteractive);
	if (!hist) {
		return NULL;
	}
	hist->opts = opts;
	hist->can = can;
	hist->zoom = ZOOM_DEFAULT;
	hist->movspeed = DEFAULT_SPEED;
	hist->barnumber = 0;
	return hist;
}

RZ_API void rz_histogram_interactive_free(RzHistogramInteractive *hist) {
	if (!hist) {
		return;
	}
	rz_cons_canvas_free(hist->can);
	rz_histogram_options_free(hist->opts);
	free(hist);
}

RZ_API void rz_histogram_interactive_zoom_in(RzHistogramInteractive *hist) {
	hist->zoom += ZOOM_DEFAULT;
	if(hist->zoom > ((hist->w < hist->h) ? hist->w : hist->h))hist->zoom -= ZOOM_DEFAULT;
}

RZ_API void rz_histogram_interactive_zoom_out(RzHistogramInteractive *hist) {
	hist->zoom -= ZOOM_DEFAULT;
	if (hist->zoom == 0) {
		hist->zoom = ZOOM_DEFAULT;
	}
}

/**
 * \brief Create the string buffer with the horisontal histogram
 *
 *		 █    ██      █             █                                        █
 *		 █    ██      █             █                                       ██
 *	 █   █    ██      █             █ █                                     ██
 *	 ██  █    ██  █ ███             █ █              █                      ██   █
 *	 ██  ██   ███ █ ███             █ █              █ █     █    █   █ █   ██   █
 *	 ██  ██   ███ █ ███          █  █ █         █    █ █    ██    █   ███   ██   █
 *	 ██  ██   ███ █ ███          █  █ █  █      █    █ █    ██    █   ███  ███ █ █
 *	███  ██   ███ █ ███          █  █ █  █      █    █ █    ██    █   ███  █████ █
 *	███████   ███ █ ███          █  █ █  █      █    ███    ██    █   ███  █████ █
 *	███████   ███ █ ███   ██    ██  █ █  █  █   █    ███   ███   ██   ███  █████ █
 *	███████  ████ █ ███   ██    ██  █ █  █  █   █    ███   ███   ██   ████ █████ █
 * 	███████  ████ █ ███   ██    ██  █ █  ██ █   ██   ███   ███   ██   ████ █████ █
 *	███████__████_█_███__███__█_██_████__████___██__████___███___██__█████_█████_█
 *
 * \param hist Information about the interactive histogram
 * \param data A buffer with the numerical data in the format of one byte per value
 * \param width Width of the histogram
 * \param height Height of the histogram
 */
RZ_API RZ_OWN RzStrBuf *rz_histogram_interactive_horizontal(RZ_NONNULL RzHistogramInteractive *hist, const unsigned char *data, unsigned int width, unsigned int height, int histogramwidth) {
	rz_return_val_if_fail(data, NULL);
	RzStrBuf *buf = rz_strbuf_new("");
	if (!buf) {
		return NULL;
	}

	RzHistogramOptions *opts = hist->opts;
	size_t i, j;
	ut32 cols = width;
	ut32 rows = height > 0 ? height : 10;
	rows--;
	const char *vline = opts->unicode ? RUNE_LINE_VERT : "|";
	const char *block = opts->unicode ? UTF_BLOCK : "#";
	const char *kol[5];
	kol[0] = opts->pal->call;
	kol[1] = opts->pal->jmp;
	kol[2] = opts->pal->cjmp;
	kol[3] = opts->pal->mov;
	kol[4] = opts->pal->nop;
	int zoom;
	if(width > hist->zoom){

	}
	width /= zoom;
	if (opts->color) {
		int adder = 0;
		adder = ((hist->barnumber + 1) / width) * width;
		if (hist->barnumber - adder > width / 2) {
			adder += (hist->barnumber - adder - width / 2);
		} else {
			adder -= (width / 2 - (hist->barnumber - adder));
		}
		for (i = 0; i < rows; i++) {
			size_t threshold = i * (0xff / rows);
			size_t koli = i * 5 / rows;
			int k;
			for (j = 0; j < width; j++) {
				int realj = adder + j;
				if(i!= 0 && i%((int)(rows/zoom)) == 0 && realj < hist->size && realj >= 0 && (255 - data[realj] < threshold || (i + 1 == rows))){
					for (k = 0; k < zoom; k++) {
						if(realj == hist->barnumber){
							rz_strbuf_appendf(buf,"%s%s%s", Color_RED, "\u2580", Color_RESET);
						}else{
							rz_strbuf_appendf(buf, "%s%s%s", kol[koli], "\u2580", Color_RESET);
						}
					}
				}
				else if (realj < hist->size && realj >= 0 && (255 - data[realj] < threshold || (i + 1 == rows))) {
					if (realj == hist->barnumber) {
						for (k = 0; k < zoom; k++) {
							rz_strbuf_appendf(buf, "%s%s%s", Color_RED, block, Color_RESET);
						}
					} else if (opts->thinline) {
						for (k = 0; k < zoom; k++) {
							rz_strbuf_appendf(buf, "%s%s%s", kol[koli], vline, Color_RESET);
						}
					} else {
						for (k = 0; k < zoom; k++) {
							rz_strbuf_appendf(buf, "%s%s%s", kol[koli], block, Color_RESET);
						}
					}
				} else {
					for (k = 0; k < zoom; k++) {
						rz_strbuf_append(buf, " ");
					}
				}
			}
			rz_strbuf_append(buf, "\n");
		}
		rz_strbuf_appendf(buf, "Current Index %d data %d", hist->barnumber, data[hist->barnumber]);
		return buf;
	}
	int k = 0;
	int adder = 0;
	adder = ((hist->barnumber + 1) / width) * width;
	if (hist->barnumber - adder > width / 2) {
		adder += (hist->barnumber - adder - width / 2);
	} else {
		adder -= (width / 2 - (hist->barnumber - adder));
	}
	for (i = 0; i < rows; i++) {
		size_t threshold = i * (0xff / rows);
		for (j = 0; j < cols; j++) {
			int realJ = adder + j;
			if (realJ < 0 && realJ >= hist->size) {
				for (k = 0; k < zoom; k++) {
					rz_strbuf_append(buf, " ");
				}
			} else if (255 - data[realJ] < threshold) {
				if (opts->thinline) {
					for (k = 0; k < zoom; k++) {
						rz_strbuf_append(buf, block);
					}
				} else {
					for (k = 0; k < zoom; k++) {
						rz_strbuf_appendf(buf, "%s%s%s", Color_BGGRAY, block, Color_RESET);
					}
				}
			} else if (i + 1 == rows) {
				for (k = 0; k < zoom; k++) {
					rz_strbuf_append(buf, "_");
				}
			} else {
				for (k = 0; k < zoom; k++) {
					rz_strbuf_append(buf, " ");
				}
			}
		}
		rz_strbuf_append(buf, "\n");
	}
	rz_strbuf_appendf(buf, "Current Index %d data %d\n", hist->barnumber, data[hist->barnumber]);
	return buf;
}
