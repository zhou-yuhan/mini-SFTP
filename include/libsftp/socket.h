#ifndef SOCKET_H
#define SOCKET_H

#include <sys/socket.h>

struct ssh_socket_struct {
    int fd;

};
typedef struct ssh_socket_struct* ssh_socket;

#endif /* SOCKET_H */