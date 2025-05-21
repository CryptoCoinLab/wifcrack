#include "configuration.h"
#include "worker.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void show_file(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror(filename);
        return;
    }
    char buf[256];
    while (fgets(buf, sizeof(buf), f)) {
        char *p = buf;
        while (*p == ' ' || *p == '\t') p++;
        size_t len = strlen(p);
        while (len > 0 && (p[len-1] == '\n' || p[len-1] == '\r'))
            p[--len] = '\0';
        printf("%s\n", p);
    }
    fclose(f);
}

static void read_email_configuration(Configuration *config, const char *file) {
    FILE *f = fopen(file, "r");
    if (!f) {
        fprintf(stderr, "not found: %s\n", file);
        exit(-1);
    }
    char line[512];
    int line_number = 0;
    char *email = NULL;
    /* For this simplified port we only care about the first line (email address) */
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';
        if (line_number == 0) {
            email = strdup(line);
            break;
        }
        line_number++;
    }
    fclose(f);
    if (email) {
        configuration_set_email(config, email, NULL);
        printf("Email configured (to: '%s')\n", email);
        free(email);
    }
}

int main(int argc, char **argv) {
    if (argc < 2 || (strcmp(argv[1], "--help") == 0)) {
        show_file("help.txt");
        show_file("footer.txt");
        return 0;
    }

    const char *config_file = argv[1];
    Configuration *cfg = configuration_load_from_file(config_file);
    if (!cfg) {
        fprintf(stderr, "Failed to load configuration: %s\n", config_file);
        return 1;
    }

    if (argc > 2) {
        read_email_configuration(cfg, argv[2]);
    }

    Worker *worker = worker_create(cfg);
    worker_run(worker);

    worker_free(worker);
    configuration_free(cfg);

    show_file("footer.txt");
    return 0;
}

