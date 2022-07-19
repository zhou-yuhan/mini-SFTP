/**
 * @file stfp.c
 * @author Zhou Yuhan (zhouyuhan_@outlook.com)
 * @brief Implementaiton of SFTP functions, including APIs and helpers.
 * Only open, close, read, write of regular files are supported
 * @version 0.1
 * @date 2022-07-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include <fcntl.h>
#include <stddef.h>

#include "libsftp/buffer.h"
#include "libsftp/error.h"
#include "libsftp/logger.h"
#include "libsftp/sftp.h"
#include "libsftp/util.h"

struct sftp_session_struct {
    ssh_session ssh;
    uint32_t id_counter;
    uint32_t version;
    // TODO
};

struct sftp_packet_struct {
    sftp_session sftp;
    uint8_t type;
    uint32_t id;
    ssh_buffer payload;
};

/* file handler */
struct sftp_file_struct {
    sftp_session sftp;
    uint64_t offset;
    ssh_string handle;
    uint8_t eof;
};

/* SSH_FXP_MESSAGE described into .7 page 26 */
struct sftp_status_struct {
    uint32_t id;
    uint32_t status;
    char *errormsg;
    char *langtag;
};

struct sftp_attributes_struct {
    char *name;
    char *longname; /* ls -l output on openssh, not reliable else */
    uint32_t flags;
    uint8_t type;
    uint64_t size;
    uint32_t uid;
    uint32_t gid;
    char *owner; /* set if openssh and version 4 */
    char *group; /* set if openssh and version 4 */
    uint32_t permissions;
    uint64_t atime64;
    uint32_t atime;
    uint32_t atime_nseconds;
    uint64_t createtime;
    uint32_t createtime_nseconds;
    uint64_t mtime64;
    uint32_t mtime;
    uint32_t mtime_nseconds;
    ssh_string acl;
    uint32_t extended_count;
    ssh_string extended_type;
    ssh_string extended_data;
};

static sftp_attributes sftp_stat(sftp_session session, const char *path);
static void sftp_status_free(sftp_status status);
static void sftp_packet_free(sftp_packet packet);
static void sftp_file_free(sftp_file file);
static sftp_status sftp_parse_status(sftp_packet packet);
static sftp_file sftp_parse_handle(sftp_packet packet);
static sftp_packet sftp_packet_read(sftp_session sftp, uint32_t id);
static ssize_t sftp_packet_write(sftp_session sftp, uint8_t type,
                                 ssh_buffer payload);

static uint32_t sftp_get_new_id(sftp_session sftp) {
    return ++sftp->id_counter;
}

int sftp_init(sftp_session sftp) {
    sftp_packet response = NULL;
    ssh_buffer buffer = NULL;
    uint32_t version;
    int rc;

    sftp->version = LIBSFTP_VERSION;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        LOG_CRITICAL("can not create ssh buffer");
        ssh_set_error(SSH_FATAL, "buffer error");
        return NULL;
    }

    if ((rc = ssh_buffer_pack(buffer, "d", sftp->version)) != SSH_OK) {
        LOG_CRITICAL("can not pack buffer");
        ssh_set_error(SSH_FATAL, "buffer error");
        ssh_buffer_free(buffer);
        return NULL;
    }

    if (sftp_packet_write(sftp, SSH_FXP_INIT, buffer) < 0) {
        LOG_CRITICAL("can not send init request");
        ssh_set_error(SSH_FATAL, "init request error");
        ssh_buffer_free(buffer);
    }
    ssh_buffer_free(buffer);

    while (response == NULL) {
        response = sftp_packet_read(sftp, 0);
    }

    if (response->type != SSH_FXP_VERSION) {
        LOG_ERROR("unexpected server response");
        ssh_set_error(SSH_FATAL, "received code %d during init",
                      response->type);
        sftp_packet_free(response);
        return SSH_ERROR;
    }

    rc = ssh_buffer_unpack(response->payload, "d", &version);
    if (rc != SSH_OK) {
        LOG_ERROR("can not parse server response");
        ssh_set_error(SSH_FATAL, "buffer error");
        sftp_packet_free(response);
        return SSH_ERROR;
    }

    if(version != sftp->version) {
        LOG_ERROR("sftp server version %d does not match client version %d", version, sftp->version);
        ssh_set_error(SSH_REQUEST_DENIED, "version mismatch (server: %d client: %d)", version, sftp->version);
        sftp_packet_free(response);
        return SSH_ERROR;
    }

    return SSH_OK;
}

sftp_file sftp_open(sftp_session sftp, const char *filename, int flags,
                    mode_t mode) {
    sftp_packet response = NULL;
    sftp_status status = NULL;
    sftp_file handle = NULL;
    ssh_buffer buffer = NULL;
    uint32_t perm_flags = 0;
    uint32_t attr_flags =
        SSH_FILEXFER_ATTR_PERMISSIONS; /* only specify permission flags when
                                          opening a file */

    uint32_t id;
    int rc;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        LOG_CRITICAL("can not create ssh buffer");
        ssh_set_error(SSH_FATAL, "buffer error");
        return NULL;
    }

    if ((flags & O_RDWR) == O_RDWR) {
        perm_flags |= (SSH_FXF_WRITE | SSH_FXF_READ);
    } else if ((flags & O_WRONLY) == O_WRONLY) {
        perm_flags |= SSH_FXF_WRITE;
    } else {
        perm_flags |= SSH_FXF_READ;
    }
    if ((flags & O_CREAT) == O_CREAT) perm_flags |= SSH_FXF_CREAT;
    if ((flags & O_TRUNC) == O_TRUNC) perm_flags |= SSH_FXF_TRUNC;
    if ((flags & O_EXCL) == O_EXCL) perm_flags |= SSH_FXF_EXCL;
    if ((flags & O_APPEND) == O_APPEND) {
        perm_flags |= SSH_FXF_APPEND;
    }

    id = sftp_get_new_id(sftp);

    if ((rc = ssh_buffer_pack(buffer, "dsddw", id, filename, perm_flags,
                              attr_flags, mode)) != SSH_OK) {
        LOG_CRITICAL("can not pack buffer");
        ssh_set_error(SSH_FATAL, "buffer error");
        ssh_buffer_free(buffer);
        return NULL;
    }

    if (sftp_packet_write(sftp, SSH_FXP_OPEN, buffer) < 0) {
        LOG_CRITICAL("can not send open request");
        ssh_set_error(SSH_FATAL, "open request error");
        ssh_buffer_free(buffer);
    }
    ssh_buffer_free(buffer);

    while (response == NULL) {
        response = sftp_packet_read(sftp, id);
    }

    switch (response->type) {
        case SSH_FXP_STATUS:
            status = sftp_parse_status(response);
            sftp_packet_free(response);
            if (status == NULL) {
                LOG_ERROR("can not parse server status");
                return NULL;
            }
            ssh_set_error(SSH_REQUEST_DENIED, "status code: %d, message: %s",
                          status->status, status->errormsg);
            sftp_status_free(status);
            return NULL;
        case SSH_FXP_HANDLE:
            handle = sftp_parse_handle(response);
            sftp_packet_free(response);
            if (handle == NULL) {
                LOG_ERROR("can not parse server handle");
                return NULL;
            }
            if ((flags & O_APPEND) == O_APPEND) {
                /**
                 * Must get the size of file if we want to append
                 * not implemented
                 *
                 */
                return NULL;
            }
            return handle;
        default:
            LOG_ERROR("unexpected server response");
            ssh_set_error(SSH_FATAL, "received code %d during open",
                          response->type);
            sftp_packet_free(response);
    }
    return NULL;
}

int sftp_close(sftp_file file) {
    sftp_session sftp = file->sftp;
    ssh_string handle = file->handle;
    sftp_packet response = NULL;
    sftp_status status = NULL;
    ssh_buffer buffer = NULL;
    uint32_t id;
    int rc;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        LOG_CRITICAL("can not create ssh buffer");
        ssh_set_error(SSH_FATAL, "buffer error");
        return SSH_ERROR;
    }

    id = sftp_get_new_id(sftp);

    if ((rc == ssh_buffer_pack(buffer, "dS", id, handle)) != SSH_OK) {
        LOG_CRITICAL("can not pack buffer");
        ssh_set_error(SSH_FATAL, "buffer error");
        ssh_buffer_free(buffer);
        return SSH_ERROR;
    }

    if (sftp_packet_write(sftp, SSH_FXP_CLOSE, buffer) < 0) {
        LOG_CRITICAL("can not send close request");
        ssh_set_error(SSH_FATAL, "close request error");
        ssh_buffer_free(buffer);
        return SSH_ERROR;
    }
    ssh_buffer_free(buffer);

    while (response == NULL) {
        response = sftp_packet_read(sftp, id);
    }

    switch (response->type) {
        case SSH_FXP_STATUS:
            status = sftp_parse_status(response);
            sftp_packet_free(response);
            if (status == NULL) {
                LOG_ERROR("can not parse server status");
                return SSH_ERROR;
            }
            if (status->status == SSH_FX_OK) {
                sftp_status_free(status);
                sftp_file_free(file);
                return SSH_OK;
            } else {
                LOG_ERROR("can not close file");
                ssh_set_error(SSH_REQUEST_DENIED, "status code %d, message %s",
                              status->status, status->errormsg);
                sftp_status_free(status);
                return SSH_ERROR;
            }
        default:
            LOG_ERROR("unexpected server response");
            ssh_set_error(SSH_FATAL, "receive %d during close", response->type);
            sftp_packet_free(response);
            return SSH_ERROR;
    }
}

ssize_t sftp_read(sftp_file file, void *buf, size_t count) {
    sftp_session sftp = file->sftp;
    sftp_packet response = NULL;
    sftp_status status = NULL;
    ssh_string data = NULL;
    size_t recvlen;
    ssh_buffer buffer = NULL;
    uint32_t id;
    int rc;

    if (file->eof) return 0;

    buffer = ssh_buffer_new();
    if (buffer == NULL) {
        LOG_CRITICAL("can not create ssh buffer");
        ssh_set_error(SSH_FATAL, "buffer error");
        return SSH_ERROR;
    }

    id = sftp_get_new_id(sftp);

    rc = ssh_buffer_pack(buffer, "dSqq", id, file->handle, file->offset, count);
    if (rc != SSH_OK) {
        LOG_CRITICAL("can not pack buffer");
        ssh_set_error(SSH_FATAL, "buffer error");
        ssh_buffer_free(buffer);
        return SSH_ERROR;
    }

    if (sftp_packet_write(sftp, SSH_FXP_READ, buffer) < 0) {
        LOG_CRITICAL("can not send read request");
        ssh_set_error(SSH_FATAL, "read request error");
        ssh_buffer_free(buffer);
        return SSH_ERROR;
    }
    ssh_buffer_free(buffer);

    while (response == NULL) {
        response = sftp_packet_read(sftp, id);
    }

    switch (response->type) {
        case SSH_FXP_STATUS:
            status = sftp_parse_status(response);
            sftp_packet_free(response);
            if (status == NULL) {
                LOG_ERROR("can not parse server status");
                return SSH_ERROR;
            }
            ssh_set_error(SSH_REQUEST_DENIED, "status code %d, message %s",
                          status->status, status->errormsg);

            if (status->status == SSH_FX_EOF) {
                file->eof = 1;
                sftp_status_free(status);
                return 0;
            } else {
                LOG_ERROR("read error");
                sftp_status_free(status);
                return SSH_ERROR;
            }
        case SSH_FXP_DATA:
            data = ssh_buffer_get_ssh_string(response->payload);
            sftp_packet_free(response);
            if (data == NULL) {
                LOG_ERROR("can not extract data from server response");
                ssh_set_error(SSH_FATAL, "invalid server DATA packet");
                return SSH_ERROR;
            }

            recvlen = ssh_string_len(data);
            if (recvlen > count) {
                LOG_ERROR("too much data received");
                ssh_set_error(SSH_FATAL,
                              "received a too big DATA packet from server, "
                              "received %d, asked for %d",
                              recvlen, count);
                return SSH_ERROR;
            }
            file->offset += recvlen;
            memcpy(buf, ssh_string_data(data), recvlen);
            ssh_string_free(data);
            return recvlen;
        default:
            LOG_ERROR("unexpected server response");
            ssh_set_error(SSH_FATAL, "receive %d during read", response->type);
            sftp_packet_free(response);
            return SSH_ERROR;
    }
    return SSH_ERROR;
}

ssize_t sftp_write(sftp_file file, const void *buf, size_t count) {
    sftp_session sftp = file->sftp;
    sftp_packet response = NULL;
    sftp_status status = NULL;
    ssh_string data = NULL;
    size_t nleft = count;
    size_t nwrite;
    size_t nsend;
    ssh_buffer buffer = NULL;
    uint32_t id;
    int rc;

    while (nleft > 0) {
        buffer = ssh_buffer_new();
        if (buffer == NULL) {
            LOG_CRITICAL("can not create ssh buffer");
            ssh_set_error(SSH_FATAL, "buffer error");
            return SSH_ERROR;
        }

        id = sftp_get_new_id(sftp);

        nwrite = MIN(nleft, SSH_FXP_MAXLEN);

        rc = ssh_buffer_pack(buffer, "dSqqP", id, file->handle, file->offset,
                             nwrite, (size_t)nwrite,
                             (char *)buf + (count - nleft));
        if (rc != SSH_OK) {
            LOG_CRITICAL("can not pack buffer");
            ssh_set_error(SSH_FATAL, "buffer error");
            ssh_buffer_free(buffer);
            return SSH_ERROR;
        }

        nsend = sftp_packet_write(sftp, SSH_FXP_WRITE, buffer);
        if (nsend != ssh_buffer_get_len(buffer)) {
            LOG_ERROR("can not send write request");
            ssh_set_error(SSH_FATAL, "write request error");
            ssh_buffer_free(buffer);
            return SSH_ERROR;
        }
        ssh_buffer_free(buffer);

        while (response == NULL) {
            response = sftp_packet_read(sftp, id);
        }

        switch (response->type) {
            case SSH_FXP_STATUS:
                status = sftp_parse_status(response);
                sftp_packet_free(response);
                if (status == NULL) {
                    LOG_ERROR("can not parse server status");
                    return SSH_ERROR;
                }
                if (status->status == SSH_FX_OK) {
                    file->offset += nwrite;
                    nleft -= nwrite;
                    sftp_status_free(status);
                } else {
                    LOG_ERROR("can not write data");
                    ssh_set_error(SSH_REQUEST_DENIED,
                                  "status code %d, message %s", status->status,
                                  status->errormsg);
                    sftp_status_free(status);
                    return SSH_ERROR;
                }
            default:
                LOG_ERROR("unexpected server response");
                ssh_set_error(SSH_FATAL, "received %d during write",
                              response->type);
                sftp_packet_free(response);
                return SSH_ERROR;
        }
    }
    return count - nleft;
}

sftp_packet sftp_packet_read(sftp_session sftp, uint32_t id) {}

ssize_t sftp_packet_write(sftp_session sftp, uint8_t type, ssh_buffer payload) {

}

static void sftp_status_free(sftp_status status) {
    if (status == NULL) return;
    SAFE_FREE(status->errormsg);
    SAFE_FREE(status->langtag);
    SAFE_FREE(status);
}

static void sftp_packet_free(sftp_packet packet) {
    if (packet == NULL) return;
    ssh_buffer_free(packet->payload);
    SAFE_FREE(packet);
}

static void sftp_file_free(sftp_file file) {
    if (file == NULL) return;
    ssh_string_free(file->handle);
    SAFE_FREE(file);
}

static sftp_file sftp_parse_handle(sftp_packet packet) {
    sftp_file file;

    if (packet->type != SSH_FXP_HANDLE) return NULL;

    file = calloc(1, sizeof(struct sftp_file_struct));
    if (file == NULL) return NULL;

    file->handle = ssh_buffer_get_ssh_string(packet->payload);
    if (file->handle == NULL) {
        SAFE_FREE(file);
        return NULL;
    }

    file->sftp = packet->sftp;
    file->offset = 0;
    file->eof = 0;

    return file;
}

static sftp_status sftp_parse_status(sftp_packet packet) {
    sftp_status status;
    int rc;

    if (packet->type != SSH_FXP_STATUS) return NULL;

    status = calloc(1, sizeof(struct sftp_status_struct));
    if (status == NULL) return NULL;

    status->id = packet->id;
    rc = ssh_buffer_unpack(packet->payload, "d", &status->status);
    if (rc != SSH_OK) {
        SAFE_FREE(status);
        return NULL;
    }
    rc = ssh_buffer_unpack(packet->payload, "ss", &status->errormsg,
                           &status->langtag);

    if (rc != SSH_OK) {
        SAFE_FREE(status);
        return NULL;
    }

    return status;
}

/**
 * @brief Get file attributes from the server.
 * Not implemented since we only want to read and write (excluding append)
 *
 * @param session
 * @param path
 * @return sftp_attributes
 */
static sftp_attributes sftp_stat(sftp_session session, const char *path) {}