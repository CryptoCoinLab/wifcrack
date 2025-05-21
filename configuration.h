#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <stddef.h>

#define UNKNOWN_CHAR '_'
#define COMMENT_CHAR "#"
#define COMPRESSED_WIF_LENGTH 52

#define STATUS_PERIOD (60 * 1000)
#define CHECKSUM_CHARS 5
#define CHECKSUM_CHARS_COMPRESSED 6

typedef enum {
    WORK_START,
    WORK_END,
    WORK_JUMP,
    WORK_ROTATE,
    WORK_SEARCH,
    WORK_ALIKE
} WORK;

typedef struct guess_entry {
    int index;
    char *chars;
    struct guess_entry *next;
} guess_entry;

typedef struct {
    void *mail_session;
    char *email_to;
    char *email_from;
} EmailConfiguration;

typedef struct {
    int is_p2sh;
    char *target_address;
    char *wif;
    char *wif_status;
    WORK work;
    guess_entry *guess;
    char *address;
    unsigned char *address_hash;
    int compressed;
    int *force_threads;
    EmailConfiguration *email_config;
} Configuration;

Configuration *configuration_create(const char *targetAddress,
                                    const char *wif,
                                    const char *wifStatus,
                                    WORK work,
                                    guess_entry *guess);
Configuration *configuration_load_from_file(const char *filename);
void configuration_free(Configuration *config);

int configuration_get_checksum_chars(int compressed);

const char *configuration_get_target_address(const Configuration *config);
const char *configuration_get_wif(const Configuration *config);
WORK configuration_get_work(const Configuration *config);
const char *configuration_get_wif_status(const Configuration *config);
int configuration_is_compressed(const Configuration *config);

void configuration_set_email(Configuration *config,
                             const char *email_from,
                             void *mail_session);
EmailConfiguration *configuration_get_email(const Configuration *config);

int *configuration_get_force_threads(const Configuration *config);
void configuration_set_force_threads(Configuration *config, int *threads);

#endif /* CONFIGURATION_H */
