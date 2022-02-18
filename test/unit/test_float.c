#include <rz_util.h>
#include "minunit.h"

bool internal_float_main(void) {
    test_internal_in_develop();
    return true;
}

bool all_tests() {
    internal_float_main();
    mu_end;
}

mu_main(all_tests)
