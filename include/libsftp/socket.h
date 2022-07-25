#ifndef SOCKET_H
#define SOCKET_H

#include <sys/socket.h>

struct ssh_socket_struct {
    int fd;
};
typedef struct ssh_socket_struct *ssh_socket;

int ssh_socket_connect(ssh_socket s, const char *host, uint16_t port,
                       const char *bind_addr);
void ssh_socket_set_fd(ssh_socket s, int fd);

#endif /* SOCKET_H */