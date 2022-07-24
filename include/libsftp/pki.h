#ifndef PKI_H
#define PKI_H

#include "libcrypto.h"

enum ssh_keytypes_e {
    SSH_KEYTYPE_UNKNOWN = 0,
    SSH_KEYTYPE_DSS = 1,
    SSH_KEYTYPE_RSA,
    /* 
    SSH_KEYTYPE_RSA1,
    SSH_KEYTYPE_ECDSA,
    SSH_KEYTYPE_ED25519,
    SSH_KEYTYPE_DSS_CERT01,
    SSH_KEYTYPE_RSA_CERT01,
    SSH_KEYTYPE_ECDSA_P256,
    SSH_KEYTYPE_ECDSA_P384,
    SSH_KEYTYPE_ECDSA_P521,
    SSH_KEYTYPE_ECDSA_P256_CERT01,
    SSH_KEYTYPE_ECDSA_P384_CERT01,
    SSH_KEYTYPE_ECDSA_P521_CERT01,
    SSH_KEYTYPE_ED25519_CERT01,
    */
};

struct ssh_key_struct {
    enum ssh_keytypes_e type;
    int flags;
    const char *type_c; /* Don't free it ! it is static */
    int ecdsa_nid;

    DSA *dsa;
    RSA *rsa;

    void *cert;
    enum ssh_keytypes_e cert_type;
};

typedef struct ssh_key_struct* ssh_key;

#endif /* PKI_H */