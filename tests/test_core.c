#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "betanet.h"

static void test_init_cleanup(void **state) {
    (void) state; // unused

    assert_int_equal(betanet_init(NULL), 0);
    betanet_cleanup();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_init_cleanup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
