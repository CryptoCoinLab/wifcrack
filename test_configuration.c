#include "configuration.h"
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    DIR *dir = opendir("examples");
    assert(dir && "examples directory missing");
    struct dirent *ent;
    int count = 0;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_type != DT_REG && ent->d_type != DT_LNK)
            continue;
        if (!strstr(ent->d_name, ".conf"))
            continue;
        char path[256];
        snprintf(path, sizeof(path), "examples/%s", ent->d_name);
        Configuration *cfg = configuration_load_from_file(path);
        assert(cfg && "failed to load configuration");
        assert(configuration_get_wif(cfg) != NULL);
        configuration_free(cfg);
        count++;
    }
    closedir(dir);
    printf("Parsed %d example files. All tests passed.\n", count);
    return 0;
}
