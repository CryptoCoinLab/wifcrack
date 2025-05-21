#include "configuration.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>

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
        char path[256];
        snprintf(path, sizeof(path), "examples/%s", ent->d_name);
        cfg = configuration_load_from_file(path);
        assert(cfg != NULL);
        assert(configuration_get_wif(cfg) != NULL);
        configuration_free(cfg);
        parsed++;
    }
    closedir(dir);
    printf("Parsed %d example configuration files.\n", parsed);

    printf("All tests passed.\n");
    return 0;
}
