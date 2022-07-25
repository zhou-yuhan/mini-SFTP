
#include "libsftp/session.h"

#include <string.h>

#include "libsftp/error.h"
#include "libsftp/knownhosts.h"

ssh_session ssh_new(void) {
    ssh_session session;
    int rc;

    session = calloc(1, sizeof(struct ssh_session_struct));
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
    session->opts.username = ssh_get_local_username();
    session->opts.port = 22;
    session->opts.sshdir = ssh_get_home_dir();
    session->opts.knownhosts = ssh_get_known_hosts();

    return session;

err:
    ssh_free(session);
    return NULL;
}

int ssh_options_set(ssh_session session, enum ssh_options_e type,
                    const void *value) {
    const char *v;
    char *p, *q;

    if (session == NULL) return SSH_ERROR;

    switch (type) {
        case SSH_OPTIONS_HOST:
            v = value;
            if (v == NULL || v[0] == '\0') {
                return SSH_ERROR;
            } else {
                q = strdup(value);
                if (q == NULL) {
                    return SSH_ERROR;
                }
                p = strchr(q, '@');

                SAFE_FREE(session->opts.host);

                if (p) {
                    *p = '\0';
                    session->opts.host = strdup(p + 1);
                    if (session->opts.host == NULL) {
                        SAFE_FREE(q);
                        return SSH_ERROR;
                    }

                    SAFE_FREE(session->opts.username);
                    session->opts.username = strdup(q);
                    SAFE_FREE(q);
                    if (session->opts.username == NULL) {
                        ssh_set_error_oom(session);
                        return -1;
                    }
                } else {
                    session->opts.host = q;
                }
            }
            break;
        case SSH_OPTIONS_PORT:
            if (value == NULL) {
                return SSH_ERROR;
            } else {
                int *x = (int *)value;
                if (*x <= 0) {
                    SSH_ERROR;
                }
                session->opts.port = *x & 0xffffU;
            }
            break;
        case SSH_OPTIONS_USER:
            v = value;
            if (v == NULL || v[0] == '\0') {
                return SSH_ERROR;
            } else { /* username provided */
                SAFE_FREE(session->opts.username);
                session->opts.username = strdup(value);
                if (session->opts.username == NULL) {
                    return SSH_ERROR;
                }
            }
            break;
        default:
            ssh_set_error(SSH_REQUEST_DENIED, "unknown option %d", type);
            return SSH_ERROR;
            break;
    }

    return SSH_OK;
}

int ssh_connect(ssh_session session) {
    int rc;

    if(session == NULL) return SSH_ERROR;
    if(session->opts.host == NULL) {
        ssh_set_error(SSH_FATAL, "host name required");
        return SSH_ERROR;
    }

    rc = ssh_socket_connect(session->socket, session->opts.host, session->opts.port, NULL);
    if(rc == SSH_ERROR) {
        ssh_set_error(SSH_REQUEST_DENIED, "socket error, can not connect to server");
        return SSH_ERROR;
    }
}