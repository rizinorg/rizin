// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_lib.h>
#include <rz_inquiry.h>

#include "rz_analysis.h"
#include "rz_bin.h"
#include "rz_inquiry/rz_bcfg.h"
#include "rz_types.h"
#include "rz_util/ht_pp.h"
#include "rz_util/ht_sp.h"
#include "rz_util/ht_up.h"
#include "rz_util/rz_graph.h"
#include "rz_util/rz_iterator.h"
#include "rz_util/rz_log.h"
#include "rz_util/rz_set.h"
#include "rz_util/rz_str.h"
#include "rz_vector.h"
#include <rz_il.h>
#include <rz_list.h>
#include <rz_types_base.h>
#include <rz_util/rz_assert.h>

#if 0
RZ_LIB_VERSION(rz_inquiry);

static RzInquiryPlugin *inquiry_static_plugins[] = { RZ_INQUIRY_STATIC_PLUGINS };

RZ_API const size_t rz_inquiry_get_n_plugins() {
	return RZ_ARRAY_SIZE(inquiry_static_plugins);
}

RZ_API RZ_BORROW RzInquiryPlugin *rz_inquiry_get_plugin(size_t index) {
	if (index >= RZ_ARRAY_SIZE(inquiry_static_plugins)) {
		return NULL;
	}
	return inquiry_static_plugins[index];
}
#endif

RZ_API bool rz_inquiry_plugin_add(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_OWN RZ_NONNULL RzInquiryPlugin *plugin) {
	rz_return_val_if_fail(inquiry && plugin, false);
	if (!plugin->value_domain) {
		rz_warn_if_reached();
		return false;
	}

	if (!ht_sp_insert(inquiry->plugins, plugin->name, plugin)) {
		RZ_LOG_WARN("Plugin '%s' was already added.\n", plugin->name);
		return true;
	}

	void **p_data = RZ_NEW0(void *);
	if (!ht_sp_insert(inquiry->plugins_data, plugin->name, p_data)) {
		rz_warn_if_reached();
		return false;
	}
	return true;
}

RZ_API bool rz_inquiry_plugin_del(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_OWN RZ_NONNULL RzInquiryPlugin *plugin) {
	rz_return_val_if_fail(inquiry && plugin, false);

	void **p_data = ht_sp_find(inquiry->plugins_data, plugin->name, NULL);
#if 0
	if (plugin->p_interpreter->fini) {
		plugin->p_interpreter->fini(p_data ? *p_data : NULL);
	}
#endif
	free(p_data);
	if (plugin->value_domain) {
		return ht_sp_delete(inquiry->plugins, plugin->name);
	}
	rz_warn_if_reached();
	return false;
}

RZ_API void rz_inquiry_function_free(RZ_NULLABLE RZ_OWN RzInquiryFunction *fcn) {
	if (!fcn) {
		return;
	}
	rz_inquiry_bcfg_free(fcn->bcfg);
	rz_vector_free(fcn->entry_points);
	free(fcn);
}

RZ_IPI RZ_OWN RzInquiryFunction *rz_inquiry_function_new() {
	RzInquiryFunction *fcn = RZ_NEW0(RzInquiryFunction);
	if (!fcn) {
		return NULL;
	}
	fcn->bcfg = rz_inquiry_bcfg_new(RZ_GRAPH_IMPL_LIST);
	fcn->entry_points = rz_vector_new(sizeof(ut64), NULL, NULL);
	if (!fcn->bcfg || !fcn->entry_points) {
		rz_inquiry_function_free(fcn);
		return NULL;
	}
	return fcn;
}

RZ_API RZ_OWN char *rz_inquiry_function_str(const RzInquiryFunction *fcn) {
	RzStrBuf *buf = rz_strbuf_new("");
	rz_strbuf_append(buf, "ifcn: [");
	ut64 *it;
	size_t i = 0;
	rz_vector_foreach (fcn->entry_points, it) {
		rz_strbuf_appendf(buf, "%s0x%" PFMT64x, (i++ > 0 ? ", " : " "), *it);
	}
	rz_strbuf_append(buf, " ]\n");
	RzIterator *iter = rz_graph_get_nodes(fcn->bcfg->graph);
	RzGraphNode *n;
	rz_iterator_foreach(iter, n) {
		const RzInquiryBlock *bb = rz_graph_node_get_data(n);
		rz_strbuf_appendf(buf, "\t0x%" PFMT64x ":0x%" PFMT64x "\n", bb->addr, bb->size);
	}
	rz_iterator_free(iter);
	return rz_strbuf_drain(buf);
}

RZ_API RZ_OWN RzInquiry *rz_inquiry_new(void) {
	RzInquiry *iq = RZ_NEW0(RzInquiry);
	if (!iq) {
		return NULL;
	}
	iq->plugins = ht_sp_new(HT_STR_CONST, NULL, NULL);
	iq->plugins_data = ht_sp_new(HT_STR_CONST, NULL, NULL);
	iq->call_candidates = ht_up_new(NULL, free);
	iq->dynamic_xrefs = rz_vector_new(sizeof(RzAnalysisXRef), NULL, NULL);
	iq->bcfg = rz_inquiry_bcfg_new(RZ_GRAPH_IMPL_LIST);
	if (!iq->plugins || !iq->plugins_data || !iq->bcfg) {
		ht_sp_free(iq->plugins);
		ht_sp_free(iq->plugins_data);
		rz_inquiry_bcfg_free(iq->bcfg);
		free(iq);
		return NULL;
	}

#if 0
	for (size_t i = 0; i < RZ_ARRAY_SIZE(inquiry_static_plugins); ++i) {
		rz_inquiry_plugin_add(iq, inquiry_static_plugins[i]);
	}
#endif
	return iq;
}

RZ_API void rz_inquiry_free(RZ_OWN RZ_NULLABLE RzInquiry *iq) {
	if (!iq) {
		return;
	}
#if 0
	for (size_t i = 0; i < RZ_ARRAY_SIZE(inquiry_static_plugins); ++i) {
		rz_inquiry_plugin_del(iq, inquiry_static_plugins[i]);
	}
#endif
	ht_sp_free(iq->plugins);
	ht_sp_free(iq->plugins_data);
	ht_up_free(iq->call_candidates);
	rz_inquiry_bcfg_free(iq->bcfg);
	rz_vector_free(iq->dynamic_xrefs);
	free(iq);
}

RZ_IPI void rz_inquiry_add_xref(RzInquiry *iq, const RzAnalysisXRef *xref) {
	rz_vector_push(iq->dynamic_xrefs, (void *)xref);
}

RZ_API bool rz_inquiry_xref_interpreter_filter(RZ_NONNULL const RzAnalysisXRef *xref, RZ_NONNULL const RzPVector /*<RzBinSection *>*/ *allowed_segments) {
	rz_return_val_if_fail(xref && allowed_segments, false);
	void **it;
	rz_pvector_foreach (allowed_segments, it) {
		const RzBinSection *sec = *it;

		ut64 start = sec->vaddr;
		ut64 end = start + sec->vsize;
		if (RZ_BETWEEN_EXCL(start, xref->to, end)) {
			switch (xref->type) {
			case RZ_ANALYSIS_XREF_TYPE_CALL_RET:
			case RZ_ANALYSIS_XREF_TYPE_CALL:
			case RZ_ANALYSIS_XREF_TYPE_CODE:
			case RZ_ANALYSIS_XREF_TYPE_RETURN:
				return sec->perm & RZ_PERM_X;
			case RZ_ANALYSIS_XREF_TYPE_MEM_WRITE:
				return sec->perm & RZ_PERM_W;
			case RZ_ANALYSIS_XREF_TYPE_MEM_READ:
			case RZ_ANALYSIS_XREF_TYPE_STRING:
				return sec->perm & RZ_PERM_R;
			case RZ_ANALYSIS_XREF_TYPE_NULL:
				rz_warn_if_reached();
				return false;
			}
		}
	}
	return false;
}

RZ_API bool rz_inquiry_get_fcn_symbol_addr(RzCore *core, RZ_OUT RzSetU *symbol_targets) {
	rz_return_val_if_fail(core && symbol_targets, false);
	RzPVector /*<RzBinSection *>*/ *sections = rz_bin_object_get_sections(core->bin->cur->o);
	if (!sections) {
		rz_warn_if_reached();
		return false;
	}
	// Add function addresses of function symbols in the executable region.
	void **it;
	const RzPVector *symbols = rz_bin_object_get_symbols(core->bin->cur->o);
	if (!symbols) {
		rz_pvector_free(sections);
		rz_warn_if_reached();
		return false;
	}
	rz_pvector_foreach (symbols, it) {
		RzBinSymbol *sym = *it;
		if (!RZ_STR_EQ(sym->type, RZ_BIN_TYPE_FUNC_STR)) {
			continue;
		}
		void **it2;
		rz_pvector_foreach (sections, it2) {
			RzBinSection *sec = *it2;
			if (sec->perm & RZ_PERM_X &&
				RZ_BETWEEN_EXCL(sec->vaddr, sym->vaddr, sec->vaddr + sec->vsize)) {
				rz_set_u_add(symbol_targets, sym->vaddr);
				break;
			}
		}
	}
	rz_pvector_free(sections);
	return true;
}

RZ_API bool rz_inquiry_convert_and_add_to_analysis(
	RzAnalysis *analysis,
	RzInquiry *inquiry,
	const RzPVector /*<RzInquiryFunction *>*/ *fcns,
	const RzPVector /*<RzBinSymbol *>*/ *symbols) {
	rz_return_val_if_fail(analysis && inquiry && fcns && symbols, false);
	// Add all discovered binary blocks to analysis

	RzIterator *iter = rz_graph_get_nodes(inquiry->bcfg->graph);
	RzGraphNode *n;
	rz_iterator_foreach(iter, n) {
		const RzInquiryBlock *bb = rz_graph_node_get_data(n);
		rz_analysis_add_bb(analysis, bb->addr, bb->size);
		RzAnalysisBlock *abb = rz_analysis_get_block_at(analysis, bb->addr);
		RzIterator *out_edges = rz_inquiry_bcfg_get_outgoing_edges(inquiry->bcfg, bb->addr);
		if (!out_edges) {
			continue;
		}
		RzGraphEdge *e;
		rz_iterator_foreach(out_edges, e) {
			ut64 target = rz_graph_node_get_id(rz_graph_edge_get_to(e));
			RzInquiryBCFGEdgeType type = (RzInquiryBCFGEdgeType)(utptr)rz_graph_edge_get_data(e);
			switch (type) {
			default:
				continue;
			case RZ_INQUIRY_BCFG_EDGE_TYPE_CALL_RET:
			case RZ_INQUIRY_BCFG_EDGE_TYPE_CF:
			case RZ_INQUIRY_BCFG_EDGE_TYPE_JMP: {
				if (abb->jump == UT64_MAX && abb->fail != target) {
					abb->jump = target;
				} else if (abb->fail == UT64_MAX && abb->jump != target) {
					abb->fail = target;
				} else if (abb->fail != target && abb->jump != target) {
					RZ_LOG_WARN("The basic block at 0x%" PFMT64x " has more than two outgoing edges.\n"
						    "\t\tHas jump = 0x%" PFMT64x " fail = 0x%" PFMT64x ". Will miss = 0x%" PFMT64x " (%d)\n",
						bb->addr, abb->jump, abb->fail,
						target, type);
				}
				break;
			}
			}
		}
		rz_iterator_free(out_edges);
	}
	rz_iterator_free(iter);

	RzAnalysisXRef *xref;
	rz_vector_foreach (inquiry->dynamic_xrefs, xref) {
		rz_analysis_xrefs_set(analysis, xref->from, xref->to, xref->type);
	}

	// Convert the Inquiry functions to analysis function.
	void **it;
	rz_pvector_foreach (fcns, it) {
		RzInquiryFunction *fcn = *it;

		ut64 fcn_addr = *(ut64 *)rz_vector_head(fcn->entry_points);
		char new_fcn_name[64] = { 0 };
		void **it;
		rz_pvector_foreach (symbols, it) {
			RzBinSymbol *s = *it;
			if (s->vaddr == fcn_addr && RZ_STR_EQ(s->type, RZ_BIN_TYPE_FUNC_STR)) {
				rz_strf(new_fcn_name, "sym.%s", s->name);
				break;
			}
		}
		if (new_fcn_name[0] == '\0') {
			rz_strf(new_fcn_name, "fcn_0x%" PFMT64x, fcn_addr);
		}
		RzAnalysisFunction *afcn = rz_analysis_create_function(analysis, new_fcn_name, fcn_addr, RZ_ANALYSIS_FCN_TYPE_FCN);
		if (!afcn) {
			rz_warn_if_reached();
			continue;
		}

		RzIterator *iter = rz_graph_get_nodes(fcn->bcfg->graph);
		RzGraphNode *n;
		rz_iterator_foreach(iter, n) {
			const RzInquiryBlock *bb = rz_graph_node_get_data(n);
			RzAnalysisBlock *abb = rz_analysis_get_block_at(analysis, bb->addr);
			if (!abb && !(abb = rz_analysis_create_block(analysis, bb->addr, bb->size))) {
				rz_warn_if_reached();
				continue;
			}
			rz_analysis_function_add_block(afcn, abb);
		}
		rz_iterator_free(iter);
	}
	return true;
}

RZ_API bool rz_inquiry_function_deduction(
	RZ_NONNULL RZ_BORROW RzAnalysis *analysis,
	RZ_NONNULL RZ_BORROW RzInquiry *inquiry,
	RZ_NONNULL RZ_BORROW RzSetU *symbol_addresses,
	RZ_NONNULL const RzPVector /*<RzBinSymbol *>*/ *symbols,
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code,
	RZ_NONNULL RZ_OUT RzPVector /*<RzInquiryFunction *>*/ *inquiry_fcns) {
	rz_return_val_if_fail(analysis && inquiry && symbol_addresses && symbols && ignored_code && inquiry_fcns, false);
	if (!rz_inquiry_algo_revng_fcn_detection(
		    symbol_addresses,
		    inquiry->call_candidates,
		    inquiry->bcfg,
		    inquiry_fcns,
		    ignored_code)) {
		rz_warn_if_reached();
		return false;
	}
	return true;
}
