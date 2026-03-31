// SPDX-FileCopyrightText: 2025 ahmed-kamal2004 <ahmedkamal200427@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_magic.h>

RZ_OWN RzMagicLine *rz_magic_line_new(void);

void rz_magic_line_free(RZ_OWN RZ_NULLABLE RzMagicLine *);

int magic_compare(const void *incoming, const RBNode *in_tree, void *user);

int magic_named_compare(const void *incoming, const RBNode *in_tree, void *user);

RZ_BORROW char *magic_strtoull(RZ_NONNULL const char *, RZ_NONNULL ut64 *);

RZ_BORROW char *magic_strtoll(RZ_NONNULL const char *, RZ_NONNULL int64_t *);

bool magic_load(RZ_NONNULL RZ_BORROW RzMagic *, RZ_NONNULL FILE *f);

RZ_OWN char *magic_test(RZ_NONNULL const RzMagic *, RZ_NONNULL const void *, size_t, int);