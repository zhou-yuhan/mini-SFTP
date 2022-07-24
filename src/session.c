#include "libsftp/session.h"

ssh_session ssh_new(void) {
    ssh_session session;
    char *id = NULL;
    int rc;

    session = calloc(1, sizeof (struct ssh_session_struct));
    if (session == NULL) {
        return NULL;
    }

    session->next_crypto = crypto_new();
    if (session->next_crypto == NULL) {
        goto err;
    }

    session->socket = ssh_socket_new(session);
    if (session->socket == NULL) {
        goto err;
    }

    session->out_buffer = ssh_buffer_new();
    if (session->out_buffer == NULL) {
        goto err;
    }

    session->in_buffer = ssh_buffer_new();
    if (session->in_buffer == NULL) {
        goto err;
    }

    session->alive = 0;
    session->auth.supported_methods = 0;

    /* OPTIONS */
    session->opts.StrictHostKeyChecking = 1;
    session->opts.port = 0;
    session->opts.fd = -1;
    session->opts.compressionlevel = 7;
    session->opts.nodelay = 0;

    return session;

err:
    free(id);
    ssh_free(session);
    return NULL;
}

