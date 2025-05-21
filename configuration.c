#include "configuration.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static unsigned char *compute_simple_hash(const char *str) {
    if (!str) return NULL;
    size_t len = strlen(str);
    unsigned char *hash = malloc(20);
    if (!hash) return NULL;
    for (size_t i = 0; i < 20; ++i) {
        hash[i] = (unsigned char)(i < len ? str[i] : i);
    }
    return hash;
}

Configuration *configuration_create(const char *targetAddress,
                                    const char *wif,
                                    const char *wifStatus,
                                    WORK work,
                                    guess_entry *guess) {
    Configuration *config = calloc(1, sizeof(Configuration));
    if (!config) return NULL;
    config->work = work;
    if (targetAddress) {
        config->target_address = strdup(targetAddress);
        if (targetAddress[0] == '3') {
            config->compressed = 1;
            config->is_p2sh = 1;
        } else {
            config->address = strdup(targetAddress);
            config->address_hash = compute_simple_hash(targetAddress);
        }
    }
    if (wif) config->wif = strdup(wif);
    if (wifStatus) config->wif_status = strdup(wifStatus);
    config->compressed = (config->compressed || (wif && strlen(wif) == COMPRESSED_WIF_LENGTH) || (work == WORK_END && wif && (wif[0] == 'L' || wif[0] == 'K')));
    config->guess = guess;
    return config;
}

void configuration_free(Configuration *config) {
    if (!config) return;
    free(config->target_address);
    free(config->wif);
    free(config->wif_status);
    free(config->address);
    free(config->address_hash);
    guess_entry_free(config->guess);
    if (config->email_config) {
        free(config->email_config->email_from);
        free(config->email_config->email_to);
        free(config->email_config);
    }
    free(config);
}

int configuration_get_checksum_chars(int compressed) {
    return compressed ? CHECKSUM_CHARS_COMPRESSED : CHECKSUM_CHARS;
}

const char *configuration_get_target_address(const Configuration *config) {
    return config ? config->target_address : NULL;
}

const char *configuration_get_wif(const Configuration *config) {
    return config ? config->wif : NULL;
}

WORK configuration_get_work(const Configuration *config) {
    return config ? config->work : WORK_START;
}

const char *configuration_get_wif_status(const Configuration *config) {
    return config ? config->wif_status : NULL;
}

int configuration_is_compressed(const Configuration *config) {
    return config ? config->compressed : 0;
}

void configuration_set_email(Configuration *config,
                             const char *email_from,
                             void *mail_session) {
    if (!config || !email_from) return;
    EmailConfiguration *email = calloc(1, sizeof(EmailConfiguration));
    if (!email) return;
    email->email_from = strdup(email_from);
    email->email_to = strdup(email_from);
    email->mail_session = mail_session;
    config->email_config = email;
}

EmailConfiguration *configuration_get_email(const Configuration *config) {
    return config ? config->email_config : NULL;
}

int *configuration_get_force_threads(const Configuration *config) {
    return config ? config->force_threads : NULL;
}

void configuration_set_force_threads(Configuration *config, int *threads) {
    if (config) config->force_threads = threads;
}

void guess_entry_free(guess_entry *g) {
    while (g) {
        guess_entry *next = g->next;
        free(g->chars);
        free(g);
        g = next;
    }
}

static char *trim(char *str) {
    while (*str == ' ' || *str == '\t') str++;
    char *end = str + strlen(str);
    while (end > str && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' ' || end[-1] == '\t'))
        *--end = '\0';
    return str;
}

Configuration *configuration_load_from_file(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return NULL;

    char line[256];
    char *target = NULL, *wif = NULL, *status = NULL;
    WORK work = WORK_START;
    guess_entry *guess_head = NULL, *guess_tail = NULL;

    while (fgets(line, sizeof(line), f)) {
        char *trimmed = trim(line);
        if (trimmed[0] == '\0' || trimmed[0] == '#')
            continue;

        char *eq = strchr(trimmed, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(trimmed);
        char *val = trim(eq + 1);

        if (strcmp(key, "targetAddress") == 0) {
            free(target);
            target = strdup(val);
        } else if (strcmp(key, "wif") == 0) {
            free(wif);
            wif = strdup(val);
        } else if (strcmp(key, "wifStatus") == 0) {
            free(status);
            status = strdup(val);
        } else if (strcmp(key, "work") == 0) {
            if (strcmp(val, "END") == 0)
                work = WORK_END;
            else
                work = WORK_START;
        } else if (strncmp(key, "guess", 5) == 0) {
            int index = atoi(key + 5);
            guess_entry *g = calloc(1, sizeof(guess_entry));
            if (!g) continue;
            g->index = index;
            g->chars = strdup(val);
            if (!guess_head)
                guess_head = g;
            else
                guess_tail->next = g;
            guess_tail = g;
        }
    }

    fclose(f);

    Configuration *cfg = configuration_create(target, wif, status, work, guess_head);

    free(target);
    free(wif);
    free(status);

    return cfg;
}

