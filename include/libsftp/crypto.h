#ifndef CRYPTO_H
#define CRYPTO_H

#include "kex.h"
#include "libcrypto.h"
#include "libssh.h"
#include "pki.h"

#define DIGEST_MAX_LEN 64

enum ssh_hmac_e {
    SSH_HMAC_SHA1 = 1,
    /*
    SSH_HMAC_SHA256,
    SSH_HMAC_SHA512,
    SSH_HMAC_MD5,
    SSH_HMAC_AEAD_POLY1305,
    SSH_HMAC_AEAD_GCM
    */
};

enum ssh_digest_e {
    SSH_DIGEST_AUTO=0,
    SSH_DIGEST_SHA1=1,
    SSH_DIGEST_SHA256,
    SSH_DIGEST_SHA384,
    SSH_DIGEST_SHA512,
};

enum ssh_key_exchange_e {
    /* diffie-hellman-group1-sha1 */
    SSH_KEX_DH_GROUP1_SHA1 = 1,
    /*
    SSH_KEX_DH_GROUP14_SHA1,
    SSH_KEX_ECDH_SHA2_NISTP256,
    SSH_KEX_ECDH_SHA2_NISTP384,
    SSH_KEX_ECDH_SHA2_NISTP521,
    SSH_KEX_CURVE25519_SHA256_LIBSSH_ORG,
    SSH_KEX_CURVE25519_SHA256,
    SSH_KEX_DH_GROUP16_SHA512,
    SSH_KEX_DH_GROUP18_SHA512,
    SSH_KEX_DH_GROUP14_SHA256,
    */
};

enum ssh_cipher_e {
    /*
    SSH_NO_CIPHER=0,
    SSH_3DES_CBC,
    */
    SSH_AES128_CBC = 0,
    /*
    SSH_AES192_CBC,
    SSH_AES256_CBC,
    SSH_AES128_CTR,
    SSH_AES192_CTR,
    SSH_AES256_CTR,
    SSH_AEAD_AES128_GCM,
    SSH_AEAD_AES256_GCM,
    SSH_AEAD_CHACHA20_POLY1305
    */
};

enum ssh_kdf_digest {
    SSH_KDF_SHA1 = 1,
    SSH_KDF_SHA256,
    SSH_KDF_SHA384,
    SSH_KDF_SHA512
};

struct ssh_crypto_struct {
    bignum shared_secret;
    struct dh_ctx *dh_ctx;
    ssh_string dh_server_signature; /* information used by dh_handshake. */
    size_t session_id_len;
    unsigned char *session_id;
    size_t digest_len; /* len of the secret hash */
    unsigned char
        *secret_hash; /* Secret hash is same as session id until re-kex */
    unsigned char *encryptIV;
    unsigned char *decryptIV;
    unsigned char *decryptkey;
    unsigned char *encryptkey;
    unsigned char *encryptMAC;
    unsigned char *decryptMAC;
    unsigned char hmacbuf[DIGEST_MAX_LEN];
    struct ssh_cipher_struct *in_cipher,
        *out_cipher;                   /* the cipher structures/objects */
    enum ssh_hmac_e in_hmac, out_hmac; /* the MAC algorithms used */

    ssh_key server_pubkey;
    /* kex sent by server, client, and mutually elected methods */
    struct ssh_kex_struct server_kex;
    struct ssh_kex_struct client_kex;
    char *kex_methods[SSH_KEX_METHODS];
    enum ssh_key_exchange_e kex_type;
    enum ssh_kdf_digest
        digest_type; /* Digest type for session keys derivation */
};

struct ssh_cipher_struct {
    const char *name;       /* ssh name of the algorithm */
    unsigned int blocksize; /* blocksize of the algo */
    enum ssh_cipher_e ciphertype;
    uint32_t lenfield_blocksize; /* blocksize of the packet length field */
    size_t keylen;               /* length of the key structure */

    struct ssh_aes_key_schedule *aes_key;
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *ctx;

    unsigned int keysize; /* bytes of key used. != keylen */
    size_t tag_size;      /* overhead required for tag */
    /* Counters for rekeying initialization */
    uint32_t packets;
    uint64_t blocks;
    /* Rekeying limit for the cipher or manually enforced */
    uint64_t max_blocks;
    /* sets the new key for immediate use */
    int (*set_encrypt_key)(struct ssh_cipher_struct *cipher, void *key,
                           void *IV);
    int (*set_decrypt_key)(struct ssh_cipher_struct *cipher, void *key,
                           void *IV);
    void (*encrypt)(struct ssh_cipher_struct *cipher, void *in, void *out,
                    size_t len);
    void (*decrypt)(struct ssh_cipher_struct *cipher, void *in, void *out,
                    size_t len);
    void (*cleanup)(struct ssh_cipher_struct *cipher);
};

struct ssh_crypto_struct* crypto_new(void);

#endif /* CRYPTO_H */