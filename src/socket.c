#include "libsftp/socket.h"
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include "libsftp/error.h"
#include "libsftp/libssh.h"
#include "libsftp/util.h"

static int getai(const char *host, int port, struct addrinfo **ai) {
    const char *service = NULL;
    struct addrinfo hints;
    char s_port[10];

    ZERO_STRUCT(hints);

    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (port == 0) {
        hints.ai_flags = AI_PASSIVE;
    } else {
        snprintf(s_port, sizeof(s_port), "%hu", (unsigned short)port);
        service = s_port;
    }

    return getaddrinfo(host, service, &hints, ai);
}

int ssh_socket_connect(ssh_socket s, const char *host, uint16_t port,
                       const char *bind_addr) {
    int fd;
    int rc;

    struct addrinfo *ai = NULL;
    struct addrinfo *itr = NULL;

    rc = getai(host, port, &ai);
    if(rc != 0) {
        ssh_set_error(SSH_FATAL, "failed to resolve hostname %s", host);
        return SSH_ERROR;
    }

    for(itr = ai; itr != NULL; itr = itr->ai_next) {
        fd = socket(itr->ai_family, itr->ai_socktype, itr->ai_protocol);
        if(fd < 0) continue;

        rc = connect(fd, itr->ai_addr, itr->ai_addrlen);
        if(rc < 0) {
            ssh_set_error(SSH_REQUEST_DENIED, "failed to connect: %s", strerror(errno));
            close(fd);
            continue;
        }
        break;
    }
    freeaddrinfo(ai);

    ssh_socket_set_fd(s, fd);
    return SSH_OK;
}

void ssh_socket_set_fd(ssh_socket s, int fd) { s->fd = fd; }