// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_platform.h>
#include <string.h>

/**
 * \brief Creates a new RzPlatformItem type
 */
RZ_API RZ_OWN RzPlatformItem *rz_platform_item_new(RZ_NULLABLE const char *name) {
	RzPlatformItem *item = RZ_NEW0(RzPlatformItem);
	if (!item) {
		return NULL;
	}
	item->name = name ? strdup(name) : NULL;
	item->comment = NULL;
	return item;
}

/**
 * \brief Creates a new RzPlatformTargetIndex type
 */
RZ_API RZ_OWN RzPlatformTargetIndex *rz_platform_target_index_new() {
	RzPlatformTargetIndex *target = RZ_NEW0(RzPlatformTargetIndex);
	if (!target) {
		return NULL;
	}
	target->platforms = ht_up_new(NULL, NULL);
	if (!target->platforms) {
		free(target);
		return NULL;
	}
	return target;
}

/**
 * \brief Frees an RzPlatformTargetIndex type
 */
RZ_API void rz_platform_target_index_free(RzPlatformTargetIndex *target) {
	if (!target) {
		return;
	}
	ht_up_free(target->platforms);
	free(target->path);
	free(target);
}

/**
 * \brief Frees an RzPlatformItem type
 */
RZ_API void rz_platform_item_free(RzPlatformItem *item) {
	if (!item) {
		return;
	}
	free(item->name);
	free(item->comment);
	free(item);
}

static bool sdb_load_platform_profile(RZ_NONNULL RzPlatformTargetIndex *t, RZ_NONNULL Sdb *sdb) {
	rz_return_val_if_fail(t && sdb, false);

	SdbKv *kv;
	RzListIter *iter;
	RzList *l = sdb_get_kv_list(sdb, false);
	rz_list_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "name")) {
			char *name = sdbkv_key(kv);

			RzPlatformItem *item = rz_platform_item_new(name);

			char *argument_key = rz_str_newf("%s.address", item->name);
			if (!argument_key) {
				rz_platform_item_free(item);
				return false;
			}
			ut64 address = sdb_num_get(sdb, argument_key, NULL);
			if (!address) {
				rz_platform_item_free(item);
				return false;
			}

			argument_key = rz_str_newf("%s.comment", item->name);
			char *comment = sdb_get(sdb, argument_key, NULL);
			if (comment) {
				item->comment = comment;
			}
			ht_up_insert(t->platforms, address, item);
		}
	}
	return true;
}

static bool sdb_load_arch_platform_by_path(RZ_NONNULL RzPlatformTargetIndex *t, RZ_NONNULL const char *path) {
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
 * \brief Loads the contents of the Platform Profile to the RzPlatformTargetIndex
 *
 * \param t reference to RzPlatformTargetIndex
 * \param path reference to path of the SDB file
 */
RZ_API bool rz_platform_target_index_load_sdb(RZ_NONNULL RzPlatformTargetIndex *t, RZ_NONNULL const char *path) {
	rz_return_val_if_fail(t && path, false);
	if (!rz_file_exists(path)) {
		return false;
	}
	return sdb_load_arch_platform_by_path(t, path);
}

/**
 * \brief Initialize Platform Profiles by setting the path to the corresponding SDB file
 *
 * \param t reference to RzPlatformTargetIndex
 * \param arch reference to the selected architecture (value of `asm.arch`
 * \param platform reference to the selected platform (value of `asm.platform`)
 * \param platforms_dir reference to the directory containing platform files
 */
RZ_API bool rz_platform_target_index_init(RzPlatformTargetIndex *t, RZ_NONNULL const char *arch, RZ_NONNULL const char *cpu,
	const char *platform, RZ_NONNULL const char *platforms_dir) {
	if (RZ_STR_ISEMPTY(platform)) {
		return true;
	}
	rz_return_val_if_fail(arch && cpu && platforms_dir, false);

	char buf[50];
	char *path = rz_file_path_join(platforms_dir, rz_strf(buf, "%s-%s-%s.sdb", arch, cpu, platform));
	if (!path) {
		return false;
	}
	if (t->path && !strcmp(t->path, path)) {
		free(path);
		return true;
	}
	free(t->path);
	t->path = path;
	return rz_platform_target_index_load_sdb(t, path);
}
