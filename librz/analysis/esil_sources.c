// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_lib.h>

RZ_API void rz_analysis_esil_sources_init(RzAnalysisEsil *esil) {
	if (esil && !esil->sources) {
		esil->sources = rz_id_storage_new(1, 0xffffffff); //0 is reserved for stuff from plugins
	}
}

RZ_API ut32 rz_analysis_esil_load_source(RzAnalysisEsil *esil, const char *path) {
	RzAnalysisEsilSource *src;

	if (!esil) {
		eprintf("no esil?\n");
		return 0;
	}

	src = RZ_NEW0(RzAnalysisEsilSource);
	src->content = rz_lib_dl_open(path);
	if (!src->content) {
		eprintf("no content\n");
		free(src);
		return 0;
	}

	rz_analysis_esil_sources_init(esil);
	if (!rz_id_storage_add(esil->sources, src, &src->id)) {
		eprintf("cannot add to storage\n");
		rz_lib_dl_close(src->content);
		free(src);
		return 0;
	}

	return src->id;
}

static RzAnalysisEsilSource *_get_source(RzAnalysisEsil *esil, ut32 src_id) {
	if (!esil || !esil->sources) {
		return NULL;
	}
	return (RzAnalysisEsilSource *)rz_id_storage_get(esil->sources, src_id);
}

RZ_API void *rz_analysis_esil_get_source(RzAnalysisEsil *esil, ut32 src_id) {
	RzAnalysisEsilSource *src = _get_source(esil, src_id);

	return src ? src->content : NULL;
}

RZ_API bool rz_analysis_esil_claim_source(RzAnalysisEsil *esil, ut32 src_id) {
	RzAnalysisEsilSource *src = _get_source(esil, src_id);

	if (src) {
		src->claimed++;
		return true;
	}
	return false;
}

RZ_API void rz_analysis_esil_release_source(RzAnalysisEsil *esil, ut32 src_id) {
	RzAnalysisEsilSource *src = _get_source(esil, src_id);

	if (!src) {
		return;
	}
	if (src->claimed <= 1) {
		rz_id_storage_delete(esil->sources, src_id);
		rz_lib_dl_close(src->content);
		free(src);
	} else {
		src->claimed--;
	}
}

static bool _free_source_cb(void *user, void *data, ut32 id) {
	RzAnalysisEsilSource *src = (RzAnalysisEsilSource *)data;

	if (src) {
		rz_lib_dl_close(src->content);
	}
	free(src);
	return true;
}

RZ_API void rz_analysis_esil_sources_fini(RzAnalysisEsil *esil) {
	if (esil) {
		rz_id_storage_foreach(esil->sources, _free_source_cb, NULL);
		rz_id_storage_free(esil->sources);
	}
}
