#include "configuration.h"

#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>

int main() {
    // Test creating configuration with non-P2SH address
    Configuration *cfg = configuration_create("1BitcoinAddress", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", WORK_START, NULL);
    assert(cfg != NULL);
    assert(configuration_is_compressed(cfg));
    assert(cfg->is_p2sh == 0);
    assert(configuration_get_work(cfg) == WORK_START);
    assert(configuration_get_checksum_chars(0) == CHECKSUM_CHARS);
    configuration_set_force_threads(cfg, NULL);
    assert(configuration_get_force_threads(cfg) == NULL);
    configuration_set_email(cfg, "test@example.com", NULL);
    EmailConfiguration *email = configuration_get_email(cfg);
    assert(email != NULL);
    assert(strcmp(email->email_from, "test@example.com") == 0);
    configuration_free(cfg);

    // Test P2SH address handling
    cfg = configuration_create("3abcdef", "Labcdef", "", WORK_END, NULL);
    assert(cfg != NULL);
    assert(cfg->is_p2sh == 1);
    assert(configuration_is_compressed(cfg));
    configuration_free(cfg);


    DIR *dir = opendir("examples");
    assert(dir != NULL);
    struct dirent *ent;
    int parsed = 0;
    while ((ent = readdir(dir)) != NULL) {

        if (!strstr(ent->d_name, ".conf"))
            continue;
        char path[512];
        snprintf(path, sizeof(path), "examples/%s", ent->d_name);

        cfg = configuration_load_from_file(path);
        assert(cfg != NULL);
        assert(configuration_get_wif(cfg) != NULL);

        /* Print configuration details */
        const char *work_str = "START";
        switch (configuration_get_work(cfg)) {
            case WORK_END: work_str = "END"; break;
            case WORK_JUMP: work_str = "JUMP"; break;
            case WORK_ROTATE: work_str = "ROTATE"; break;
            case WORK_SEARCH: work_str = "SEARCH"; break;
            case WORK_ALIKE: work_str = "ALIKE"; break;
            default: break;
        }

        printf("Configuration from %s:\n", path);
        printf("  Work: %s\n", work_str);
        printf("  WIF: %s\n", configuration_get_wif(cfg));
        printf("  Target Address: %s\n",
               configuration_get_target_address(cfg)
                   ? configuration_get_target_address(cfg)
                   : "(none)");
        printf("  WIF Status: %s\n",
               configuration_get_wif_status(cfg)
                   ? configuration_get_wif_status(cfg)
                   : "(none)");
        printf("  Compressed: %d\n", configuration_is_compressed(cfg));
        printf("  is_p2sh: %d\n", cfg->is_p2sh);
        for (guess_entry *ge = cfg->guess; ge; ge = ge->next) {
            printf("  Guess %d: %s\n", ge->index, ge->chars);
        }

        configuration_free(cfg);
        parsed++;
    }
    closedir(dir);
    printf("Parsed %d example configuration files.\n", parsed);

    printf("All tests passed.\n");

    return 0;
}
