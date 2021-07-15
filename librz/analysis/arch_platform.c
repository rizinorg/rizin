// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_arch.h>
#include <string.h>

/**
 * \brief Creates a new RzArchPlatformItem type
 */
RZ_API RZ_OWN RzArchPlatformItem *rz_arch_platform_item_new(RZ_NULLABLE const char *name) {
	RzArchPlatformItem *item = RZ_NEW0(RzArchPlatformItem);
	if (!item) {
		return NULL;
	}
	item->name = name ? strdup(name) : NULL;
	item->comment = NULL;
	return item;
}

/**
 * \brief Creates a new RzArchPlatformTarget type
 */
RZ_API RZ_OWN RzArchPlatformTarget *rz_arch_platform_target_new() {
	RzArchPlatformTarget *target = RZ_NEW0(RzArchPlatformTarget);
	if (!target) {
		return NULL;
	}
	target->platforms = ht_up_new0();
	if (!target->platforms) {
		free(target);
		return NULL;
	}
	return target;
}

/**
 * \brief Frees an RzArchPlatformTarget type
 */
RZ_API void rz_arch_platform_target_free(RzArchPlatformTarget *target) {
	if (!target) {
		return;
	}
	ht_up_free(target->platforms);
	free(target);
}

/**
 * \brief Frees an RzArchPlatformItem type
 */
RZ_API void rz_arch_platform_item_free(RzArchPlatformItem *item) {
	if (!item) {
		return;
	}
	free(item->name);
	free(item->comment);
	free(item);
}

static bool sdb_load_platform_profile(RZ_NONNULL RzArchPlatformTarget *t, RZ_NONNULL Sdb *sdb) {
	rz_return_val_if_fail(t && sdb, false);
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(sdb, false);
	char *argument_key, *comment, *name;
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "name")) {
			name = sdbkv_key(kv);

			RzArchPlatformItem *item = rz_arch_platform_item_new(name);

			argument_key = rz_str_newf("%s.address", item->name);
			if (!argument_key) {
				rz_arch_platform_item_free(item);
				return false;
			}
			ut64 address = sdb_num_get(sdb, argument_key, NULL);
			if (!address) {
				rz_arch_platform_item_free(item);
				return false;
			}

			argument_key = rz_str_newf("%s.comment", item->name);
			comment = sdb_get(sdb, argument_key, NULL);
			if (comment) {
				item->comment = comment;
			}
			ht_up_insert(t->platforms, address, item);
		}
	}
	return true;
}

static bool sdb_load_arch_platform_by_path(RZ_NONNULL RzArchPlatformTarget *t, RZ_NONNULL const char *path) {
	rz_return_val_if_fail(t && path, false);
	if (!path) {
		return false;
	}
	Sdb *db = sdb_new(0, path, 0);
	if (!db) {
		return false;
	}
	bool result = sdb_load_platform_profile(t, db);
	sdb_close(db);
	sdb_free(db);
	return result;
}

/**
 * \brief Loads the contents of the Platform Profile to the RzArchPlatformTarget
 *
 * \param t reference to RzArchPlatformTarget
 * \param path reference to path of the SDB file
 */
RZ_API bool rz_arch_load_platform_sdb(RZ_NONNULL RzArchPlatformTarget *t, RZ_NONNULL const char *path) {
	rz_return_val_if_fail(t && path, false);
	if (!path) {
		return false;
	}
	if (!rz_file_exists(path)) {
		return false;
	}
	return sdb_load_arch_platform_by_path(t, path);
}

/**
 * \brief Initialize Platform Profiles by setting the path to the corresponding SDB file
 * 
 * \param t reference to RzArchPlatformTarget
 * \param arch reference to the selected architecture (value of `asm.arch`
 * \param platform reference to the selected platform (value of `asm.platform`)
 * \param dir_prefix reference to the directory prefix or the value of dir.prefix
 */
RZ_API bool rz_arch_platform_init(RzArchPlatformTarget *t, RZ_NONNULL const char *arch, RZ_NONNULL const char *cpu,
	const char *platform, RZ_NONNULL const char *dir_prefix) {

	if (!platform) {
		return false;
	}
	rz_return_val_if_fail(arch && cpu && dir_prefix, false);
	char *path = rz_str_newf(RZ_JOIN_4_PATHS("%s", RZ_SDB, "asm/platforms", "%s-%s-%s.sdb"),
		dir_prefix, arch, cpu, platform);
	if (!path) {
		return false;
	}
	rz_arch_load_platform_sdb(t, path);
	free(path);
	return true;
}
