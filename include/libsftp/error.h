#include <sys/types.h>
#define ERR_BUF_MAX 1024

enum ssh_error_types_e {
    SSH_NO_ERROR = 0,
    SSH_REQUEST_DENIED,
    SSH_FATAL,
    SSH_EINTR
};

void ssh_set_error(uint8_t code, char* format, ...);