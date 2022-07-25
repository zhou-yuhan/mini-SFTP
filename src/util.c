
#include "libsftp/util.h"

#include <pwd.h>
#include <string.h>

char *ssh_get_local_username(void) {
    struct passwd *pw;
    uid_t uid;
    int c;

    uid = geteuid();
    pw = getpwuid(uid);
    if (pw) {
        return strdup(pw->pw_name);
    } else {
        return NULL;
    }
}

char *ssh_get_home_dir(void) {
    struct passwd *pw;
    uid_t uid;
    int c;

    uid = geteuid();
    pw = getpwuid(uid);
    if (pw) {
        return strdup(pw->pw_dir);
    } else {
        return NULL;
    }
}