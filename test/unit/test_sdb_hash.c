// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#include "minunit.h"
#include <sdb.h>
#include <rz_util/ht_uu.h>
#include <rz_util/ht_up.h>
#include <rz_util/ht_pp.h>
#include <rz_util/ht_pu.h>
#include <rz_util/ht_sp.h>
#include <rz_util/ht_su.h>
#include <rz_util/ht_ss.h>
#include <rz_util/rz_str.h>

typedef struct _test_struct {
	char *name;
	int age;
} Person;

bool test_ht_insert_lookup(void) {
	HtSS *ht = sdb_ht_new();
	sdb_ht_insert(ht, "AAAA", "vAAAA");
	sdb_ht_insert(ht, "BBBB", "vBBBB");
	sdb_ht_insert(ht, "CCCC", "vCCCC");

	mu_assert_streq(sdb_ht_find(ht, "BBBB", NULL), "vBBBB", "BBBB value wrong");
	mu_assert_streq(sdb_ht_find(ht, "AAAA", NULL), "vAAAA", "AAAA value wrong");
	mu_assert_streq(sdb_ht_find(ht, "CCCC", NULL), "vCCCC", "CCCC value wrong");

	sdb_ht_free(ht);
	mu_end;
}

bool test_ht_update_lookup(void) {
	HtSS *ht = sdb_ht_new();
	sdb_ht_insert(ht, "AAAA", "vAAAA");
	sdb_ht_insert(ht, "BBBB", "vBBBB");

	// test update to add a new element
	sdb_ht_update(ht, "CCCC", "vCCCC");
	mu_assert_streq(sdb_ht_find(ht, "CCCC", NULL), "vCCCC", "CCCC value wrong");

	// test update to replace an existing element
	sdb_ht_update(ht, "AAAA", "vDDDD");
	mu_assert_streq(sdb_ht_find(ht, "AAAA", NULL), "vDDDD", "DDDD value wrong");

	sdb_ht_free(ht);
	mu_end;
}

bool test_ht_delete(void) {
	HtSS *ht = sdb_ht_new();
	mu_assert("nothing should be deleted", !sdb_ht_delete(ht, "non existing"));

	sdb_ht_insert(ht, "AAAA", "vAAAA");
	mu_assert("AAAA should be deleted", sdb_ht_delete(ht, "AAAA"));
	mu_assert("AAAA still there", !sdb_ht_find(ht, "AAAA", NULL));

	sdb_ht_free(ht);
	mu_end;
}

bool test_ht_insert_kvp(void) {
	HtSS *ht = sdb_ht_new();
	SdbKv *kv = sdbkv_new("AAAA", "vAAAA");
	mu_assert("AAAA shouldn't exist", !sdb_ht_find_kvp(ht, "AAAA", NULL));
	sdb_ht_insert_kvp(ht, kv, false);
	free(kv);

	mu_assert("AAAA should exist", sdb_ht_find_kvp(ht, "AAAA", NULL));
	SdbKv *kv2 = sdbkv_new("AAAA", "vNEWAAAA");
	mu_assert("AAAA shouldn't be replaced", !sdb_ht_insert_kvp(ht, kv2, false));
	mu_assert("AAAA should be replaced", sdb_ht_insert_kvp(ht, kv2, true));
	free(kv2);

	SdbKv *foundkv = sdb_ht_find_kvp(ht, "AAAA", NULL);
	mu_assert_streq(foundkv->base.value, "vNEWAAAA", "vNEWAAAA should be there");

	sdb_ht_free(ht);
	mu_end;
}

ut32 create_collision(RZ_UNUSED const char *key) {
	return 10;
}

bool test_ht_insert_collision(void) {
	HtSS *ht = sdb_ht_new();
	ht->opt.hashfn = create_collision;
	ht_ss_insert(ht, "AAAA", "vAAAA");
	mu_assert_streq(sdb_ht_find(ht, "AAAA", NULL), "vAAAA", "AAAA should be there");
	ht_ss_insert(ht, "BBBB", "vBBBB");
	mu_assert_streq(sdb_ht_find(ht, "AAAA", NULL), "vAAAA", "AAAA should still be there");
	mu_assert_streq(sdb_ht_find(ht, "BBBB", NULL), "vBBBB", "BBBB should be there");
	ht_ss_insert(ht, "CCCC", "vBBBB");
	mu_assert_streq(sdb_ht_find(ht, "CCCC", NULL), "vBBBB", "CCCC should be there");

	sdb_ht_free(ht);
	mu_end;
}

ut32 key2hash(const char *key) {
	return atoi(key);
}

bool test_ht_grow(void) {
	HtSS *ht = sdb_ht_new();
	char str[15], vstr[15];
	char buf[100];
	int i;

	ht->opt.hashfn = key2hash;
	for (i = 0; i < 20000; ++i) {
		snprintf(str, 15, "%d", i);
		snprintf(vstr, 15, "v%d", i);
		sdb_ht_insert(ht, str, vstr);
	}

	for (i = 0; i < 20000; ++i) {
		snprintf(str, 15, "%d", i);
		snprintf(vstr, 15, "v%d", i);
		char *v = sdb_ht_find(ht, str, NULL);
		snprintf(buf, 100, "%s/%s should be there", str, vstr);
		mu_assert(buf, v);
		snprintf(buf, 100, "%s/%s should be right", str, vstr);
		mu_assert_streq(v, vstr, buf);
	}

	sdb_ht_free(ht);
	mu_end;
}

bool test_ht_kvp(void) {
	HtSS *ht = sdb_ht_new();
	SdbKv *kvp = sdbkv_new("AAAA", "vAAAA");

	mu_assert_eq(kvp->base.key_len, 4, "key_len should be 4");
	mu_assert_eq(kvp->base.value_len, 5, "value_len should be 5");
	mu_assert("kvp should be inserted", sdb_ht_insert_kvp(ht, kvp, false));
	free(kvp);

	kvp = sdb_ht_find_kvp(ht, "AAAA", NULL);
	mu_assert_eq(kvp->base.key_len, 4, "key_len should be 4 after kvp_insert");
	mu_assert_eq(kvp->base.value_len, 5, "value_len should be 5 after kvp_insert");

	sdb_ht_insert(ht, "BBBB", "vBBBB");
	kvp = sdb_ht_find_kvp(ht, "BBBB", NULL);
	mu_assert_eq(kvp->base.key_len, 4, "key_len should be 4 after insert");
	mu_assert_eq(kvp->base.value_len, 5, "value_len should be 5 after insert");

	sdb_ht_free(ht);
	mu_end;
}

Person *duplicate_person(Person *p) {
	Person *c = malloc(sizeof(Person));
	c->name = strdup(p->name);
	c->age = p->age;
	return c;
}

void free_person(Person *p) {
	if (!p) {
		return;
	}
	free(p->name);
	free(p);
}

size_t calcSizePerson(void *c) {
	Person *p = c;
	return sizeof(*p);
}
bool test_ht_general(void) {
	int retval = MU_PASSED;
	bool found = false;
	Person *p, *person1 = malloc(sizeof(Person));
	if (!person1) {
		mu_cleanup_fail(err_malloc, "person1 malloc");
	}
	person1->name = strdup("radare");
	person1->age = 10;

	Person *person2 = malloc(sizeof(Person));
	if (!person2) {
		mu_cleanup_fail(err_free_person1, "person2 malloc");
	}
	person2->name = strdup("pancake");
	person2->age = 9000;

	HtSP *ht = ht_sp_new(HT_STR_DUP, (HtSPDupValue)duplicate_person, (HtSPFreeValue)free_person);
	if (!ht) {
		mu_cleanup_fail(err_free_persons, "ht alloc");
	}
	ht_sp_insert(ht, "radare", (void *)person1);
	ht_sp_insert(ht, "pancake", (void *)person2);
	p = ht_sp_find(ht, "radare", &found);
	mu_assert("radare not found", found);
	mu_assert_streq(p->name, "radare", "wrong person");
	mu_assert_eq(p->age, 10, "wrong radare age");

	p = ht_sp_find(ht, "pancake", &found);
	mu_assert("radare not found", found);
	mu_assert_streq(p->name, "pancake", "wrong person");
	mu_assert_eq(p->age, 9000, "wrong pancake age");

	(void)ht_sp_find(ht, "not", &found);
	mu_assert("found but it should not exists", !found);

	ht_sp_delete(ht, "pancake");
	p = ht_sp_find(ht, "pancake", &found);
	mu_assert("pancake was deleted", !found);

	ht_sp_insert(ht, "pancake", (void *)person2);
	ht_sp_delete(ht, "radare");
	ht_sp_update(ht, "pancake", (void *)person1);
	p = ht_sp_find(ht, "pancake", &found);

	mu_assert("pancake was updated", found);
	mu_assert_streq(p->name, "radare", "wrong person");
	mu_assert_eq(p->age, 10, "wrong age");

	ht_sp_free(ht);
err_free_persons:
	free_person(person2);
err_free_person1:
	free_person(person1);
err_malloc:
	mu_cleanup_end;
}

bool should_not_be_caled(void *user, const char *k, const void *v) {
	mu_fail("this function should not be called");
	return false;
}

bool test_empty_ht(void) {
	HtSP *ht = ht_sp_new(HT_STR_DUP, NULL, NULL);
	ht_sp_foreach_cb(ht, should_not_be_caled, NULL);
	void *r = ht_sp_find(ht, "key1", NULL);
	mu_assert_null(r, "key1 should not be present");
	ht_sp_free(ht);
	mu_end;
}

bool test_insert(void) {
	HtSS *ht = ht_ss_new(HT_STR_CONST, HT_STR_CONST);
	void *r;
	bool res;
	bool found;

	res = ht_ss_insert(ht, "key1", "value1");
	mu_assert("key1 should be a new element", res);
	r = ht_ss_find(ht, "key1", &found);
	mu_assert("found should be true", found);
	mu_assert_streq(r, "value1", "value1 should be retrieved");

	res = ht_ss_insert(ht, "key1", "value2");
	mu_assert("key1 should be an already existing element", !res);
	r = ht_ss_find(ht, "key1", &found);
	mu_assert_streq(r, "value1", "value1 should be retrieved");
	mu_assert("found should be true", found);

	r = ht_ss_find(ht, "key2", &found);
	mu_assert_null(r, "key2 should not be present");
	mu_assert("found for key2 should be false", !found);

	ht_ss_free(ht);
	mu_end;
}

bool test_update(void) {
	HtSS *ht = ht_ss_new(HT_STR_DUP, HT_STR_DUP);
	bool found;

	ht_ss_insert(ht, "key1", "value1");
	ht_ss_update(ht, "key1", "value2");
	void *r = ht_ss_find(ht, "key1", &found);
	mu_assert_streq(r, "value2", "value2 should be retrieved");
	mu_assert("found should be true", found);
	ht_ss_free(ht);
	mu_end;
}

bool test_delete(void) {
	HtSS *ht = ht_ss_new(HT_STR_DUP, HT_STR_DUP);
	bool found;

	ht_ss_insert(ht, "key1", "value1");
	ht_ss_delete(ht, "key1");
	void *r = ht_ss_find(ht, "key1", &found);
	mu_assert_null(r, "key1 should not be found");
	mu_assert("found should be false", !found);
	ht_ss_free(ht);
	mu_end;
}

static bool grow_1_found[3];
static bool grow_1_foreach(void *user, const char *k, int v) {
	grow_1_found[v] = true;
	return true;
}

bool test_grow_1(void) {
	HtSP *ht = ht_sp_new(HT_STR_DUP, NULL, NULL);
	int i;

	for (i = 0; i < 3; ++i) {
		grow_1_found[i] = false;
	}

	ht_sp_insert(ht, "key0", (void *)0);
	ht_sp_insert(ht, "key1", (void *)1);
	ht_sp_insert(ht, "key2", (void *)2);

	ht_sp_foreach_cb(ht, (HtSPForeachCallback)grow_1_foreach, NULL);
	for (i = 0; i < 3; ++i) {
		if (!grow_1_found[i]) {
			fprintf(stderr, "i = %d\n", i);
			mu_fail("An element has not been traversed");
		}
	}

	ht_sp_free(ht);
	mu_end;
}

bool test_grow_2(void) {
	HtSS *ht = ht_ss_new(HT_STR_DUP, HT_STR_DUP);
	char *r;
	bool found;
	int i;

	for (i = 0; i < 3000; ++i) {
		char buf[20], buf2[20];
		snprintf(buf, 20, "key%d", i);
		snprintf(buf2, 20, "value%d", i);
		ht_ss_insert(ht, buf, buf2);
	}

	r = ht_ss_find(ht, "key1", &found);
	mu_assert_streq(r, "value1", "value1 should be retrieved");
	mu_assert("found should be true", found);

	r = ht_ss_find(ht, "key2000", &found);
	mu_assert_streq(r, "value2000", "value2000 should be retrieved");
	mu_assert("found should be true", found);

	r = ht_ss_find(ht, "key4000", &found);
	mu_assert_null(r, "key4000 should not be there");
	mu_assert("found should be false", !found);

	ht_ss_free(ht);
	mu_end;
}

bool test_grow_3(void) {
	HtSS *ht = ht_ss_new(HT_STR_DUP, HT_STR_DUP);
	char *r;
	bool found;
	int i;

	for (i = 0; i < 3000; ++i) {
		char buf[20], buf2[20];
		snprintf(buf, 20, "key%d", i);
		snprintf(buf2, 20, "value%d", i);
		ht_ss_insert(ht, buf, buf2);
	}

	for (i = 0; i < 3000; i += 3) {
		char buf[20];
		snprintf(buf, 20, "key%d", i);
		ht_ss_delete(ht, buf);
	}

	r = ht_ss_find(ht, "key1", &found);
	mu_assert_streq(r, "value1", "value1 should be retrieved");
	mu_assert("found should be true", found);

	r = ht_ss_find(ht, "key2000", &found);
	mu_assert_streq(r, "value2000", "value2000 should be retrieved");
	mu_assert("found should be true", found);

	r = ht_ss_find(ht, "key4000", &found);
	mu_assert_null(r, "key4000 should not be there");
	mu_assert("found should be false", !found);

	r = ht_ss_find(ht, "key0", &found);
	mu_assert_null(r, "key0 should not be there");
	mu_assert("found should be false", !found);

	for (i = 1; i < 3000; i += 3) {
		char buf[20];
		snprintf(buf, 20, "key%d", i);
		ht_ss_delete(ht, buf);
	}

	r = ht_ss_find(ht, "key1", &found);
	mu_assert_null(r, "key1 should not be there");
	mu_assert("found should be false", !found);

	ht_ss_free(ht);
	mu_end;
}

bool test_grow_4(void) {
	HtSS *ht = ht_ss_new(HT_STR_DUP, HT_STR_OWN);
	char *r;
	bool found;
	int i;

	for (i = 0; i < 3000; ++i) {
		char buf[20], *buf2;
		snprintf(buf, 20, "key%d", i);
		buf2 = malloc(20);
		snprintf(buf2, 20, "value%d", i);
		ht_ss_insert(ht, buf, buf2);
	}

	r = ht_ss_find(ht, "key1", &found);
	mu_assert_streq(r, "value1", "value1 should be retrieved");
	mu_assert("found should be true", found);

	r = ht_ss_find(ht, "key2000", &found);
	mu_assert_streq(r, "value2000", "value2000 should be retrieved");
	mu_assert("found should be true", found);

	for (i = 0; i < 3000; i += 3) {
		char buf[20];
		snprintf(buf, 20, "key%d", i);
		ht_ss_delete(ht, buf);
	}

	r = ht_ss_find(ht, "key2000", &found);
	mu_assert_streq(r, "value2000", "value2000 should be retrieved");
	mu_assert("found should be true", found);

	r = ht_ss_find(ht, "key0", &found);
	mu_assert_null(r, "key0 should not be there");
	mu_assert("found should be false", !found);

	for (i = 1; i < 3000; i += 3) {
		char buf[20];
		snprintf(buf, 20, "key%d", i);
		ht_ss_delete(ht, buf);
	}

	r = ht_ss_find(ht, "key1", &found);
	mu_assert_null(r, "key1 should not be there");
	mu_assert("found should be false", !found);

	ht_ss_free(ht);
	mu_end;
}

bool foreach_delete_cb(void *user, const ut64 key, const void *v) {
	HtUP *ht = (HtUP *)user;

	ht_up_delete(ht, key);
	return true;
}

bool test_foreach_delete(void) {
	HtUP *ht = ht_up_new((HtUPDupValue)strdup, free);

	// create a collision
	ht_up_insert(ht, 0, "value1");
	ht_up_insert(ht, ht->size, "value2");
	ht_up_insert(ht, ht->size * 2, "value3");
	ht_up_insert(ht, ht->size * 3, "value4");

	ht_up_foreach_cb(ht, foreach_delete_cb, ht);
	ht_up_foreach_cb(ht, (HtUPForeachCallback)should_not_be_caled, NULL);

	ht_up_free(ht);
	mu_end;
}

bool test_update_key(void) {
	bool res;
	HtUP *ht = ht_up_new((HtUPDupValue)strdup, free);

	// create a collision
	ht_up_insert(ht, 0, "value1");
	ht_up_insert(ht, 0xdeadbeef, "value2");
	ht_up_insert(ht, 0xcafebabe, "value3");

	res = ht_up_update_key(ht, 0xcafebabe, 0x10000);
	mu_assert("cafebabe should be updated", res);
	res = ht_up_update_key(ht, 0xdeadbeef, 0x10000);
	mu_assert("deadbeef should NOT be updated, because there's already an element at 0x10000", !res);

	const char *v = ht_up_find(ht, 0x10000, NULL);
	mu_assert_streq(v, "value3", "value3 should be at 0x10000");
	v = ht_up_find(ht, 0xdeadbeef, NULL);
	mu_assert_streq(v, "value2", "value2 should remain at 0xdeadbeef");

	ht_up_free(ht);
	mu_end;
}

bool test_ht_pu_ops(void) {
	bool res;
	ut64 val;
	HtSU *ht = ht_su_new(HT_STR_DUP);

	ht_su_insert(ht, "key1", 0xcafebabe);
	val = ht_su_find(ht, "key1", &res);
	mu_assert_eq(val, 0xcafebabe, "0xcafebabe should be retrieved");
	mu_assert("found should be true", res);

	res = ht_su_insert(ht, "key1", 0xdeadbeefdeadbeef);
	mu_assert("key1 should be an already existing element", !res);
	val = ht_su_find(ht, "key1", &res);
	mu_assert_eq(val, 0xcafebabe, "0xcafebabe should still be retrieved");

	res = ht_su_update(ht, "key1", 0xdeadbeefdeadbeef);
	mu_assert("key1 should be updated", res);
	val = ht_su_find(ht, "key1", &res);
	mu_assert_eq(val, 0xdeadbeefdeadbeef, "0xdeadbeefdeadbeef should be retrieved");
	mu_assert("found should be true", res);

	res = ht_su_delete(ht, "key1");
	mu_assert("key1 should be deleted", res);
	val = ht_su_find(ht, "key1", &res);
	mu_assert_eq(val, 0, "0 should be retrieved");
	mu_assert("found should be false", !res);

	ht_su_free(ht);
	mu_end;
}

bool test_insert_update_ex(void) {
	HtSU *ht = ht_su_new(HT_STR_CONST);

	HtSUKv *inserted_kv = NULL;
	mu_assert_eq(ht_su_insert_ex(ht, "foobar", 1337, &inserted_kv), HT_RC_INSERTED, "HT_RC_INSERTED");
	mu_assert_notnull(inserted_kv, "inserted_kv");
	mu_assert_streq(inserted_kv->key, "foobar", "key");
	mu_assert_eq(inserted_kv->value, 1337, "value");

	HtSUKv *existing_kv = NULL;
	mu_assert_eq(ht_su_insert_ex(ht, "foobar", 101, &existing_kv), HT_RC_EXISTING, "HT_RC_EXISTING");
	mu_assert_notnull(existing_kv, "existing_kv");
	mu_assert_streq(existing_kv->key, "foobar", "key");
	mu_assert_eq(existing_kv->value, 1337, "value");

	HtSUKv *inserted_kv2 = NULL;
	mu_assert_eq(ht_su_update_ex(ht, "deadbeef", 404, &inserted_kv2), HT_RC_INSERTED, "HT_RC_INSERTED");
	mu_assert_notnull(inserted_kv2, "inserted_kv2");
	mu_assert_streq(inserted_kv2->key, "deadbeef", "key");
	mu_assert_eq(inserted_kv2->value, 404, "value");

	HtSUKv *updated_kv = NULL;
	mu_assert_eq(ht_su_update_ex(ht, "deadbeef", 123456, &updated_kv), HT_RC_UPDATED, "HT_RC_UPDATED");
	mu_assert_notnull(updated_kv, "updated_kv");
	mu_assert_streq(updated_kv->key, "deadbeef", "key");
	mu_assert_eq(updated_kv->value, 123456, "value");

	HtUU *ht2 = ht_uu_new();

	for (size_t i = 0; i < 100; ++i) {
		HtUUKv *tmp = NULL;
		ht_uu_insert_ex(ht2, 4 * i, i + 200, &tmp);
		mu_assert_notnull(tmp, "KV is set after rehashing");
		mu_assert_eq(tmp->value, i + 200, "KV is valid after rehashing");
	}

	ht_su_free(ht);
	ht_uu_free(ht2);
	mu_end;
}

bool test_ht_size(void) {
	HtUU *ht = ht_uu_new();
	mu_assert_eq(ht_uu_size(ht), 0, "Length wrong.");
	ht_uu_insert(ht, 0x5050505, 0x5050505);
	ht_uu_insert(ht, 0x5050505, 0x5050505);
	ht_uu_insert(ht, 0x6060606, 0x6060606);
	ht_uu_insert(ht, 0x7070707, 0x7070707);
	ht_uu_insert(ht, 0x7070707, 0x7070707);
	mu_assert_eq(ht_uu_size(ht), 3, "Length wrong.");
	bool found = false;
	ht_uu_find(ht, 0x5050505, &found);
	mu_assert_true(found, "Value was not added.");
	ht_uu_find(ht, 0x6060606, &found);
	mu_assert_true(found, "Value was not added.");
	ht_uu_find(ht, 0x7070707, &found);
	mu_assert_true(found, "Value was not added.");

	ht_uu_delete(ht, 0x7070707);
	ht_uu_find(ht, 0x7070707, &found);
	mu_assert_false(found, "Value was not deleted.");
	mu_assert_eq(ht_uu_size(ht), 2, "Length wrong.");

	// Double delete
	ht_uu_delete(ht, 0x7070707);
	ht_uu_find(ht, 0x7070707, &found);
	mu_assert_false(found, "Value was not deleted.");
	mu_assert_eq(ht_uu_size(ht), 2, "Length wrong.");
	ht_uu_free(ht);
	mu_end;
}

bool test_ht_uu_foreach(void) {
	HtUU *ht = ht_uu_new();
	ut32 icnt = 0;
	HtUUIter it;
	ht_foreach(uu, ht, it) {
		icnt++;
	}
	mu_assert_eq(icnt, 0, "Wrong number of iterations");
	ht_uu_insert(ht, 0x1010101, 0x1010101);
	ht_uu_insert(ht, 0x2020202, 0x2020202);
	ht_uu_insert(ht, 0x3030303, 0x3030303);
	ht_uu_insert(ht, 0x4040404, 0x4040404);
	ht_uu_insert(ht, 0x5050505, 0x5050505);
	icnt = 0;
	ht_foreach(uu, ht, it) {
		icnt++;
		mu_assert_true(
		          it.kv->value == 0x1010101 ||
		          it.kv->value == 0x2020202 ||
		          it.kv->value == 0x3030303 ||
		          it.kv->value == 0x4040404 ||
		          it.kv->value == 0x5050505,
		          "Value mismtach"
		          );
	}
	mu_assert_eq(icnt, 5, "Wrong number of iterations");
	icnt = 0;
	// Test write of value
	ht_foreach(uu, ht, it) {
		icnt++;
		if(it.kv->value == 0x1010101) {
			it.kv->value = 0x0;
		}
	}
	mu_assert_eq(icnt, 5, "Wrong number of iterations");
	bool found = false;
	ut64 v = ht_uu_find(ht, 0x1010101, &found);
	mu_assert_true(found, "Key not in hash map");
	mu_assert_eq(v, 0x0, "Value didn't change.");
	ht_uu_free(ht);
	mu_end;
}

bool test_ht_ss_foreach(void) {
	HtSS *ht = ht_ss_new(HT_STR_CONST, HT_STR_CONST);
	ut32 icnt = 0;
	HtSSIter it;
	ht_foreach(ss, ht, it) {
		icnt++;
	}
	mu_assert_eq(icnt, 0, "Wrong number of iterations");

	ht_ss_insert(ht, "0x1010101", "0x1010101");
	ht_ss_insert(ht, "0x2020202", "0x2020202");
	ht_ss_insert(ht, "0x3030303", "0x3030303");
	ht_ss_insert(ht, "0x4040404", "0x4040404");
	ht_ss_insert(ht, "0x5050505", "0x5050505");
	icnt = 0;
	ht_foreach(ss, ht, it) {
		icnt++;
		mu_assert_true(
			RZ_STR_EQ(it.kv->value, "0x1010101") ||
				RZ_STR_EQ(it.kv->value, "0x2020202") ||
				RZ_STR_EQ(it.kv->value, "0x3030303") ||
				RZ_STR_EQ(it.kv->value, "0x4040404") ||
				RZ_STR_EQ(it.kv->value, "0x5050505"),
			"Value mismtach");
	}
	mu_assert_eq(icnt, 5, "Wrong number of iterations");
	icnt = 0;
	// Test write of value
	ht_foreach(ss, ht, it) {
		icnt++;
		if (RZ_STR_EQ(it.kv->value, "0x1010101")) {
			it.kv->value = "0x0";
		}
	}
	mu_assert_eq(icnt, 5, "Wrong number of iterations");
	bool found = false;
	const char *v = ht_ss_find(ht, "0x1010101", &found);
	mu_assert_true(found, "Key not in hash map");
	mu_assert_streq(v, "0x0", "Value didn't change.");
	ht_ss_free(ht);
	mu_end;
}

int all_tests() {
	mu_run_test(test_ht_insert_lookup);
	mu_run_test(test_ht_update_lookup);
	mu_run_test(test_ht_delete);
	mu_run_test(test_ht_insert_kvp);
	mu_run_test(test_ht_insert_collision);
	mu_run_test(test_ht_grow);
	mu_run_test(test_ht_kvp);
	mu_run_test(test_ht_general);
	mu_run_test(test_empty_ht);
	mu_run_test(test_insert);
	mu_run_test(test_update);
	mu_run_test(test_delete);
	mu_run_test(test_grow_1);
	mu_run_test(test_grow_2);
	mu_run_test(test_grow_3);
	mu_run_test(test_grow_4);
	mu_run_test(test_foreach_delete);
	mu_run_test(test_update_key);
	mu_run_test(test_ht_pu_ops);
	mu_run_test(test_insert_update_ex);
	mu_run_test(test_ht_size);
	mu_run_test(test_ht_uu_foreach);
	mu_run_test(test_ht_ss_foreach);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
