#include "configuration.h"
#include "worker.h"
#include <assert.h>
#include <stdio.h>

int main() {
    Configuration *cfg = configuration_load_from_file("examples/example_ALIKE.conf");
    assert(cfg != NULL);

    Worker *w = worker_create(cfg);
    assert(w != NULL);

    worker_run(w);

    /* Ensure at least one result was produced */
    assert(worker_results_count(w) > 0);

    worker_free(w);
    configuration_free(cfg);

    printf("Main integration test passed.\n");
    return 0;
}
