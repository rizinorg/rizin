// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_inquiry.h>

#include "rz_inquiry_plugins.h"

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

RZ_API bool rz_inquiry_plugin_add(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_OWN RZ_NONNULL RzInquiryPlugin *plugin) {
	rz_return_val_if_fail(inquiry && plugin, false);
	if (plugin->p_interpreter) {
		if (!ht_sp_insert(inquiry->plugins, plugin->p_interpreter->name, plugin)) {
			RZ_LOG_WARN("Plugin '%s' was already added.\n", plugin->p_interpreter->name);
		}
		return true;
	}

	rz_warn_if_reached();
	return false;
}

RZ_API bool rz_inquiry_plugin_del(RZ_BORROW RZ_NONNULL RzInquiry *inquiry, RZ_OWN RZ_NONNULL RzInquiryPlugin *plugin) {
	rz_return_val_if_fail(inquiry && plugin, false);

	if (plugin->p_interpreter) {
		return ht_sp_delete(inquiry->plugins, plugin->p_interpreter->name);
	}
	rz_warn_if_reached();
	return false;
}
