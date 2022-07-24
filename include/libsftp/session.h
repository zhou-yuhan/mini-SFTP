#ifndef SESSION_H
#define SESSION_H

#include <stdbool.h>
#include "libssh.h"
#include "socket.h"
#include "string.h"
#include "buffer.h"
#include "pki.h"
#include "crypto.h"
#include "channel.h"

struct ssh_session_struct {
    ssh_socket socket;
    char *server_id_str;
    char *client_id_str;
    int protoversion;
    int server;
    int client;
    int openssh;
    uint32_t send_seq;
    uint32_t recv_seq;

    int connected;
    /* !=0 when the user got a session handle */
    int alive;
    /* two previous are deprecated */
    /* int auth_service_asked; */

    /* session flags (SSH_SESSION_FLAG_*) */
    int flags;

    /* Extensions negotiated using RFC 8308 */
    uint32_t extensions;

    ssh_string banner; /* that's the issue banner from
                       the server */
    char *discon_msg; /* disconnect message from
                         the remote host */
    ssh_buffer in_buffer;
    ssh_buffer out_buffer;

    struct {
        uint32_t supported_methods;
        uint32_t current_method;
    } auth;

    /*
     * RFC 4253, 7.1: if the first_kex_packet_follows flag was set in
     * the received SSH_MSG_KEXINIT, but the guess was wrong, this
     * field will be set such that the following guessed packet will
     * be ignored.  Once that packet has been received and ignored,
     * this field is cleared.
     */
    int first_kex_follows_guess_wrong;

    ssh_buffer in_hashbuf;
    ssh_buffer out_hashbuf;
    struct ssh_crypto_struct *current_crypto;
    struct ssh_crypto_struct *next_crypto;  /* next_crypto is going to be used after a SSH2_MSG_NEWKEYS */

    ssh_channel channel;

    struct {
        char *username;
        char *host;
        char *bindaddr; /* bind the client to an ip addr */
        char *sshdir;
        char *knownhosts;
        char *global_knownhosts;
        char *wanted_methods[SSH_KEX_METHODS];
        char *pubkey_accepted_types;
        char *ProxyCommand;
        char *custombanner;
        unsigned long timeout; /* seconds */
        unsigned long timeout_usec;
        unsigned int port;
        int fd;
        int StrictHostKeyChecking;
        char compressionlevel;
        char *gss_server_identity;
        char *gss_client_identity;
        int gss_delegate_creds;
        int flags;
        int nodelay;
        bool config_processed;
    } opts;
};




#endif /* SESSION_H */