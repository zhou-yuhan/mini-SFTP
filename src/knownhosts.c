#include "libsftp/knownhosts.h"

#include <string.h>

#include "libsftp/util.h"

char *ssh_get_known_hosts(void) {
    char *file = "/.ssh/known_hosts";
    char *dir = ssh_get_home_dir();
    char *s = calloc(strlen(file) + strlen(dir) + 1, sizeof(char));
    if (s == NULL) return NULL;
    strcpy(s, dir);
    strcat(s, file);
    return s;
}