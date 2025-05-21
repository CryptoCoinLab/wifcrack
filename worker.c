#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include "bitcoin.h"
#include "worker.h"

static const char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int BASE58_ALPHABET_LEN = 58;

static const char *work_to_string(WORK work) {
    switch (work) {
        case WORK_END: return "END";
        case WORK_JUMP: return "JUMP";
        case WORK_ROTATE: return "ROTATE";
        case WORK_SEARCH: return "SEARCH";
        case WORK_ALIKE: return "ALIKE";
        case WORK_START:
        default: return "START";
    }
}

static void send_email(Worker *worker, const char *subject, const char *body) {
    EmailConfiguration *email = configuration_get_email(worker->config);
    if (!email) return;
    (void)email; /* unused in this simplified implementation */
    printf("[email] %s\n%s\n", subject, body ? body : "");
}

Worker *worker_create(Configuration *config) {
    if (!config) return NULL;
    Worker *w = calloc(1, sizeof(Worker));
    if (!w) return NULL;
    w->config = config;
    w->time_id = (unsigned long)time(NULL);
    return w;
}

void worker_free(Worker *w) {
    if (!w) return;
    for (size_t i = 0; i < w->result_count; ++i) {
        free(w->results[i]);
    }
    free(w->results);
    free(w);
}

void worker_add_result(Worker *w, const char *data) {
    if (!w || !data) return;
    if (w->result_count >= w->result_capacity) {
        size_t newcap = w->result_capacity ? w->result_capacity * 2 : 4;
        char **tmp = realloc(w->results, newcap * sizeof(char *));
        if (!tmp) return;
        w->results = tmp;
        w->result_capacity = newcap;
    }
    w->results[w->result_count++] = strdup(data);
}

void worker_result_to_file(Worker *w) {
    if (!w || w->result_count == 0) return;
    char filename[64];
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(filename, sizeof(filename), "result_%Y%m%d_%H%M%S.txt", tm);
    FILE *f = fopen(filename, "w");
    if (!f) {
        perror("fopen");
        return;
    }
    for (size_t i = 0; i < w->result_count; ++i) {
        fprintf(f, "%s\n", w->results[i]);
    }
    fclose(f);
}

void worker_result_to_file_partial(Worker *w, const char *data) {
    if (!w || !data) return;
    char filename[64];
    snprintf(filename, sizeof(filename), "resultPartial_%lu.txt", w->time_id);
    FILE *f = fopen(filename, "a");
    if (!f) {
        perror("fopen");
        return;
    }
    fprintf(f, "%s\n", data);
    fclose(f);
}

size_t worker_results_count(const Worker *w) {
    return w ? w->result_count : 0;
}

typedef struct {
    int index;        /* position in WIF */
    const char *chars; /* possible replacements */
} GuessPos;

static char *work_thread(Worker *w, const char *suspect) {
    const char *target_addr = configuration_get_target_address(w->config);
    if (!target_addr)
        return NULL;

    unsigned char target_hash[20];
    if (!base58_decode_bitcoin_address(target_addr, target_hash))
        return NULL;

    unsigned char priv_key[32];
    int compressed = 0;
    if (!decode_wif(suspect, priv_key, &compressed))
        return NULL;

    unsigned char suspect_hash[20];
    if (!generate_pubkey_hash_from_privkey(priv_key, suspect_hash))
        return NULL;

    if (memcmp(target_hash, suspect_hash, 20) == 0) {
        worker_add_result(w, suspect);
        //worker_result_to_file_partial(w, suspect);
        return strdup(suspect);
    }

    return NULL;
}

static void set_loop(Worker *w, char *wif_buf, GuessPos *pos, int count,
                     int ix, char **result, time_t *alive_time) {
    if (*result)
        return;
    if (ix == count) {
        *result = work_thread(w, wif_buf);
        return;
    }

    int position = pos[ix].index;
    time_t now = time(NULL);
    if (now - *alive_time > STATUS_PERIOD / 1000) {
        printf("Alive! %s %s", wif_buf, ctime(&now));
        *alive_time = now;
    }

    for (const char *p = pos[ix].chars; *p && !*result; ++p) {
        wif_buf[position] = *p;
        set_loop(w, wif_buf, pos, count, ix + 1, result, alive_time);
    }
}

static void perform_work_alike(Worker *w) {
    const char *orig_wif = configuration_get_wif(w->config);
    if (!orig_wif)
        return;

    int len = (int)strlen(orig_wif);
    char *buf = strdup(orig_wif);
    if (!buf)
        return;

    GuessPos positions[128];
    int count = 0;

    for (int i = 0; i < len && count < 128; ++i) {
        for (guess_entry *ge = w->config->guess; ge; ge = ge->next) {
            if (strchr(ge->chars, orig_wif[i])) {
                positions[count].index = i;
                positions[count].chars = ge->chars;
                count++;
                break;
            }
        }
    }

    time_t alive = time(NULL);
    char *result = NULL;
    set_loop(w, buf, positions, count, 0, &result, &alive);
    free(buf);
    if (result)
        free(result);
}

static void perform_work_search(Worker *w) {
    const char *orig_wif = configuration_get_wif(w->config);
    if (!orig_wif)
        return;

    int len = (int)strlen(orig_wif);
    char *buf = strdup(orig_wif);
    if (!buf)
        return;

    GuessPos positions[128];
    int count = 0;
    guess_entry *ge = w->config->guess;
    for (int i = 0; i < len && count < 128; ++i) {
        if (buf[i] == UNKNOWN_CHAR) {
            positions[count].index = i;
            if (ge) {
                if (strcmp(ge->chars, "*") == 0)
                    positions[count].chars = BASE58_ALPHABET;
                else
                    positions[count].chars = ge->chars;
                ge = ge->next;
            } else {
                positions[count].chars = BASE58_ALPHABET;
            }
            count++;
        }
    }

    time_t alive = time(NULL);
    char *result = NULL;
    set_loop(w, buf, positions, count, 0, &result, &alive);
    free(buf);
    if (result)
        free(result);
}

static void perform_work_end(Worker *w) {
    const char *orig_wif = configuration_get_wif(w->config);
    if (!orig_wif)
        return;

    int len_base = (int)strlen(orig_wif);
    int expected_len = configuration_is_compressed(w->config) ? COMPRESSED_WIF_LENGTH : 51;
    int missing = expected_len - len_base;
    if (missing <= 0) {
        work_thread(w, orig_wif);
        return;
    }
    char *buf = malloc(expected_len + 1);
    if (!buf)
        return;
    memcpy(buf, orig_wif, len_base);
    buf[expected_len] = '\0';

    GuessPos positions[16];
    guess_entry *ge = w->config->guess;
    for (int i = 0; i < missing && i < 16; ++i) {
        positions[i].index = len_base + i;
        if (ge) {
            positions[i].chars = ge->chars;
            ge = ge->next;
        } else {
            positions[i].chars = BASE58_ALPHABET;
        }
        buf[len_base + i] = positions[i].chars[0];
    }

    time_t alive = time(NULL);
    char *result = NULL;
    set_loop(w, buf, positions, missing, 0, &result, &alive);
    free(buf);
    if (result)
        free(result);
}

static void perform_work_rotate(Worker *w) {
    const char *orig_wif = configuration_get_wif(w->config);
    if (!orig_wif)
        return;
    int len = (int)strlen(orig_wif);
    char *buf = strdup(orig_wif);
    if (!buf)
        return;
    for (int i = 0; i < len; ++i) {
        char orig = buf[i];
        for (int j = 0; j < BASE58_ALPHABET_LEN; ++j) {
            char c = BASE58_ALPHABET[j];
            if (c == orig)
                continue;
            buf[i] = c;
            work_thread(w, buf);
        }
        buf[i] = orig;
    }
    free(buf);
}

static void perform_work_jump(Worker *w) {
    /* simplified: treat as SEARCH */
    perform_work_search(w);
}

static void perform_work(Worker *w) {
    WORK work = configuration_get_work(w->config);
    const char *work_str = work_to_string(work);
    printf("Performing work: %s\n", work_str);

    switch (work) {
    case WORK_ALIKE:
        perform_work_alike(w);
        break;
    case WORK_SEARCH:
        perform_work_search(w);
        break;
    case WORK_END:
        perform_work_end(w);
        break;
    case WORK_ROTATE:
        perform_work_rotate(w);
        break;
    case WORK_JUMP:
        perform_work_jump(w);
        break;
    default: {
        char buf[128];
        snprintf(buf, sizeof(buf), "Dummy result for %s", work_str);
        worker_add_result(w, buf);
        //worker_result_to_file_partial(w, buf);
        break;
    }
   }

}

void worker_run(Worker *w) {
    if (!w) return;
    const char *work_str = work_to_string(configuration_get_work(w->config));
    printf("--- Starting worker ---\n");
    char subject[128];
    snprintf(subject, sizeof(subject), "Starting worker '%s'", work_str);
    send_email(w, subject, configuration_get_wif(w->config));

    perform_work(w);

    printf("--- Work finished ---\n");
    printf("Worker '%s' ended, %zu result(s)\n", work_str, w->result_count);
    for (size_t i = 0; i < w->result_count; ++i) {
        printf("%s\n", w->results[i]);
    }
    if (w->result_count > 0) {
        //worker_result_to_file(w);
    }
    snprintf(subject, sizeof(subject), "Worker '%s' ended, %zu result(s)", work_str, w->result_count);
    if (w->result_count > 0) {
        send_email(w, subject, w->results[0]);
    } else {
        send_email(w, subject, "");
    }
}

