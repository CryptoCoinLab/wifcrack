#include "configuration.h"
#include <stdlib.h>
#include <string.h>

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

