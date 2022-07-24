#ifndef KEX_H
#define KEX_H

#define SSH_KEX_METHODS 10

struct ssh_kex_struct {
    unsigned char cookie[16];
    char *methods[SSH_KEX_METHODS];
};

#endif /* KEX_H */