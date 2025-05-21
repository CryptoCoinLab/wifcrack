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
        unsigned char c = 0;
        if (i < len)
            c = (unsigned char)str[i];
        else
            c = (unsigned char)i;
        hash[i] = c;
    }
    return hash;
}



static WORK parse_work(const char *str) {
    if (!str) return WORK_START;
    if (strcmp(str, "END") == 0) return WORK_END;
    if (strcmp(str, "JUMP") == 0) return WORK_JUMP;
    if (strcmp(str, "ROTATE") == 0) return WORK_ROTATE;
    if (strcmp(str, "SEARCH") == 0) return WORK_SEARCH;
    if (strcmp(str, "ALIKE") == 0) return WORK_ALIKE;
    return WORK_START;
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


Configuration *configuration_load_from_file(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) return NULL;

    char buf[256];
    char *work_s = NULL;
    char *wif = NULL;
    char *wif_status = NULL;
    char *address = NULL;
    char *target_wif = NULL;
    guess_entry *head = NULL, *tail = NULL;

    while (fgets(buf, sizeof(buf), f)) {
        char *p = buf;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#') {
            if (!target_wif && strncasecmp(p, "#target:", 8) == 0) {
                char *q = p + 8;
                while (*q == ' ' || *q == '\t') q++;
                size_t len = strlen(q);
                while (len > 0 && (q[len-1] == '\n' || q[len-1] == '\r'))
                    q[--len] = '\0';
                target_wif = strdup(q);
            }
            continue;
        }
        if (*p == '\n' || *p == '\r' || *p == '\0')
            continue;
        size_t len = strlen(p);
        while (len > 0 && (p[len-1] == '\n' || p[len-1] == '\r'))
            p[--len] = '\0';
        if (!work_s) {
            work_s = strdup(p);
        } else if (!wif) {
            char *comma = strchr(p, ',');
            if (comma) {
                *comma = '\0';
                wif = strdup(p);
                char *s = comma + 1;
                while (*s == ' ' || *s == '\t') s++;
                if (*s)
                    wif_status = strdup(s);
            } else {
                wif = strdup(p);
            }
        } else if (!address) {
            address = strdup(p);
        } else {
            guess_entry *ge = calloc(1, sizeof(guess_entry));
            if (!ge) break;
            ge->index = tail ? tail->index + 1 : 0;
            ge->chars = strdup(p);
            if (tail) tail->next = ge; else head = ge;
            tail = ge;
        }
    }
    fclose(f);

    WORK work = parse_work(work_s);
    const char *status_arg = wif_status ? wif_status : (target_wif ? target_wif : "");
    Configuration *cfg = configuration_create(address, wif, status_arg,
                                              work, head);
    free(work_s);
    free(wif);
    free(wif_status);
    free(address);
    free(target_wif);
    return cfg;
}


void configuration_free(Configuration *config) {
    if (!config) return;
    free(config->target_address);
    free(config->wif);
    free(config->wif_status);
    free(config->address);
    free(config->address_hash);

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

