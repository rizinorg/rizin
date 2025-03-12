	#include <rz_util.h>
#include "theft.h"
#include "minunit.h"

/* Structure to hold our test environment */
struct test_num_env {
    RzNum *num;
};

/* Allocate a random 64-bit unsigned integer */
static enum theft_alloc_res
alloc_ut64(struct theft *t, void *env, void **instance) {
    ut64 *n = malloc(sizeof(ut64));
    if (!n) {
        return THEFT_ALLOC_ERROR;
    }

    /* Generate a random 64-bit value */
    *n = theft_random_bits(t, 64);
    *instance = n;
    return THEFT_ALLOC_OK;
}

/* Free the allocated integer */
static void
free_ut64(void *instance, void *env) {
    free(instance);
}

/* Hash function for ut64 values */
static theft_hash
hash_ut64(const void *instance, void *env) {
    const ut64 *n = instance;
    return theft_hash_onepass((const uint8_t *)n, sizeof(*n));
}

/* Print function for ut64 values */
static void
print_ut64(FILE *f, const void *instance, void *env) {
    const ut64 *n = instance;
    fprintf(f, "0x%"PFMT64x, *n);
}

/* Property: rz_num_abs(x) >= 0 for all x */
static enum theft_trial_res
prop_rz_num_abs_is_non_negative(struct theft *t, void *arg1) {
    st64 *input = (st64 *)arg1;

    ut64 result = rz_num_abs(*input);

    /* The absolute value should always be non-negative */
    if (result >= 0) {
        return THEFT_TRIAL_PASS;
    } else {
        return THEFT_TRIAL_FAIL;
    }
}

/* Property: rz_num_abs(-x) == rz_num_abs(x) for all x != ST64_MIN */
static enum theft_trial_res
prop_rz_num_abs_symmetry(struct theft *t, void *arg1) {
    st64 *input = (st64 *)arg1;

    /* Skip the edge case of ST64_MIN, which has special handling */
    if (*input == ST64_MIN) {
        return THEFT_TRIAL_SKIP;
    }

    ut64 abs_x = rz_num_abs(*input);
    ut64 abs_neg_x = rz_num_abs(-(*input));

    if (abs_x == abs_neg_x) {
        return THEFT_TRIAL_PASS;
    } else {
        return THEFT_TRIAL_FAIL;
    }
}

/* Property: rz_num_bitmask(n) has exactly n bits set for n <= 64 */
static enum theft_trial_res
prop_rz_num_bitmask_bits_set(struct theft *t, void *arg1) {
    ut64 *input = (ut64 *)arg1;

    /* Limit to 0-64 bits */
    ut8 width = (*input) % 65;

    ut64 mask = rz_num_bitmask(width);

    /* Count the number of bits set */
    int bits_set = 0;
    ut64 temp = mask;
    while (temp) {
        bits_set += temp & 1;
        temp >>= 1;
    }

    /* For width 0, expect 0 bits set */
    if (width == 0 && bits_set == 0) {
        return THEFT_TRIAL_PASS;
    }
    /* For width 1-64, expect exactly 'width' bits set */
    else if (width > 0 && width <= 64 && bits_set == width) {
        return THEFT_TRIAL_PASS;
    } else {
        return THEFT_TRIAL_FAIL;
    }
}

/* Property: rz_num_align_delta(x, a) + x is divisible by a for a > 0 */
static enum theft_trial_res
prop_rz_num_align_delta_alignment(struct theft *t, void *arg1, void *arg2) {
    ut64 *x = (ut64 *)arg1;
    ut64 *a_raw = (ut64 *)arg2;

    /* Ensure alignment is positive and not too large */
    ut64 a = (*a_raw % 1024) + 1;

    ut64 delta = rz_num_align_delta(*x, a);

    /* Check if x + delta is divisible by a */
    if ((*x + delta) % a == 0) {
        return THEFT_TRIAL_PASS;
    } else {
        return THEFT_TRIAL_FAIL;
    }
}

bool test_rz_num_properties(void) {
    struct test_num_env env = { 
        .num = rz_num_new(NULL, NULL, NULL) 
    };

    /* Get a seed based on the current time */
    theft_seed seed = theft_seed_of_time();

    /* Define type info for ut64 */
    struct theft_type_info ut64_info = {
        .alloc = alloc_ut64,
        .free = free_ut64,
        .hash = hash_ut64,
        .print = print_ut64
    };

    /* Test configuration for the absolute value property */
    struct theft_run_config config_abs_non_negative = {
        .name = "rz_num_abs is non-negative",
        .prop1 = prop_rz_num_abs_is_non_negative,
        .type_info = { &ut64_info },
        .seed = seed,
        .trials = 1000,
        .hooks = {
            .env = &env
        }
    };

    /* Test configuration for the absolute value symmetry property */
    struct theft_run_config config_abs_symmetry = {
        .name = "rz_num_abs(-x) == rz_num_abs(x)",
        .prop1 = prop_rz_num_abs_symmetry,
        .type_info = { &ut64_info },
        .seed = seed + 1,
        .trials = 1000,
        .hooks = {
            .env = &env
        }
    };

    /* Test configuration for the bitmask property */
    struct theft_run_config config_bitmask = {
        .name = "rz_num_bitmask sets correct number of bits",
        .prop1 = prop_rz_num_bitmask_bits_set,
        .type_info = { &ut64_info },
        .seed = seed + 2,
        .trials = 1000,
        .hooks = {
            .env = &env
        }
    };

    /* Test configuration for the align_delta property */
    struct theft_run_config config_align_delta = {
        .name = "rz_num_align_delta produces aligned values",
        .prop2 = prop_rz_num_align_delta_alignment,
        .type_info = { &ut64_info, &ut64_info },
        .seed = seed + 3,
        .trials = 1000,
        .hooks = {
            .env = &env
        }
    };

    /* Run the property tests */
    enum theft_run_res res1 = theft_run(&config_abs_non_negative);
    enum theft_run_res res2 = theft_run(&config_abs_symmetry);
    enum theft_run_res res3 = theft_run(&config_bitmask);
    enum theft_run_res res4 = theft_run(&config_align_delta);

    /* Free resources */
    rz_num_free(env.num);

    /* Return true if all tests passed */
    return (res1 == THEFT_RUN_PASS) && 
           (res2 == THEFT_RUN_PASS) && 
           (res3 == THEFT_RUN_PASS) &&
           (res4 == THEFT_RUN_PASS);
}

int main(int argc, char **argv) {
    bool result = test_rz_num_properties();
    return result ? 0 : 1;
}
