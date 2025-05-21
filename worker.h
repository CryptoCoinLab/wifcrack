#ifndef WORKER_H
#define WORKER_H

#include "configuration.h"
#include <stddef.h>

typedef struct {
    Configuration *config;
    char **results;
    size_t result_count;
    size_t result_capacity;
    unsigned long time_id;
} Worker;

Worker *worker_create(Configuration *config);
void worker_free(Worker *worker);

void worker_add_result(Worker *worker, const char *data);
void worker_result_to_file(Worker *worker);
void worker_result_to_file_partial(Worker *worker, const char *data);

void worker_run(Worker *worker);
size_t worker_results_count(const Worker *worker);

#endif /* WORKER_H */
