#ifndef STRING_H
#define STRING_H

#include <sys/types.h>

struct ssh_string_struct {
    uint32_t size;
    unsigned char data[1];
} __attribute__((packed));

#endif /* STRING_H */
