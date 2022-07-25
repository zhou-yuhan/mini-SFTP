#include "libsftp/libsftp.h"
#include "libsftp/buffer.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    ssh_buffer buf = ssh_buffer_new();
    ssh_string str = ssh_string_from_char("haha this is string");
    ssh_buffer_pack(buf, "dSd", 1, str, 2);
    ssh_string s = ssh_string_new(30);
    int a, b;
    ssh_buffer_unpack(buf, "dSd", &a, &s, &b);
    printf("%d %s %d", a, ssh_string_get_char(s), b);
    printf("%s", ssh_get_local_username());
}