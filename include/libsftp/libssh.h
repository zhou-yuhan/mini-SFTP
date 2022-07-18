#ifndef LIBSSH_H
#define LIBSSH_H

#include <sys/types.h>

#define API  // TODO

/* Error return codes */
#define SSH_OK 0     /* No error */
#define SSH_ERROR -1 /* Error of some kind */
#define SSH_AGAIN -2 /* The nonblocking call must be repeated */
#define SSH_EOF -127 /* We have already a eof */

/* ssh API */
typedef struct ssh_session_struct *ssh_session;

/* buffer API */
typedef struct ssh_buffer_struct *ssh_buffer;
API ssh_buffer ssh_buffer_new(void);
API void ssh_buffer_free(ssh_buffer buffer);
API int ssh_buffer_reinit(ssh_buffer buffer);
API int ssh_buffer_add_data(ssh_buffer buffer, const void *data, uint32_t len);
API uint32_t ssh_buffer_get_data(ssh_buffer buffer, void *data,
                                 uint32_t requestedlen);
API void *ssh_buffer_get(ssh_buffer buffer);
API uint32_t ssh_buffer_get_len(ssh_buffer buffer);

/* error API */
API char *ssh_get_error(void);
API char *sftp_get_error(void);

/* string API */
typedef struct ssh_string_struct *ssh_string;
API void ssh_string_burn(ssh_string str);
API ssh_string ssh_string_copy(ssh_string str);
API void *ssh_string_data(ssh_string str);
API int ssh_string_fill(ssh_string str, const void *data, size_t len);
#define SSH_STRING_FREE(x)      \
    do {                        \
        if ((x) != NULL) {      \
            ssh_string_free(x); \
            x = NULL;           \
        }                       \
    } while (0)
API void ssh_string_free(ssh_string str);
API ssh_string ssh_string_from_char(const char *what);
API size_t ssh_string_len(ssh_string str);
API ssh_string ssh_string_new(size_t size);
API const char *ssh_string_get_char(ssh_string str);
API char *ssh_string_to_char(ssh_string str);
#define SSH_STRING_FREE_CHAR(x)      \
    do {                             \
        if ((x) != NULL) {           \
            ssh_string_free_char(x); \
            x = NULL;                \
        }                            \
    } while (0)
API void ssh_string_free_char(char *s);

#endif /* LIBSSH_H */