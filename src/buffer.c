/**
 * @file buffer.c
 * @author Zhou Yuhan
 * @brief Buffer implementation, mostly copied from libssh 0.9.6 buffer.c
 * @version 0.1
 * @date 2022-07-14
 *
 * @copyright Copyright (c) 2022
 *
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

#include "mini-libssh/libssh.h"
#include "mini-libssh/util.h"

/*
 * Describes a buffer state
 * [XXXXXXXXXXXXDATA PAYLOAD       XXXXXXXXXXXXXXXXXXXXXXXX]
 * ^            ^                  ^                       ^]
 * \_data points\_pos points here  \_used points here |    /
 *   here                                          Allocated
 */
struct ssh_buffer_struct {
    size_t used;
    size_t allocated;
    size_t pos;
    uint8_t *data;
};

/* Buffer size maximum is 256M */
#define BUFFER_SIZE_MAX 0x10000000

/**
 * @brief Create a new SSH buffer.
 *
 * @return A newly initialized SSH buffer, NULL on error.
 */
struct ssh_buffer_struct *ssh_buffer_new(void) {
    struct ssh_buffer_struct *buf = NULL;
    int rc;

    buf = calloc(1, sizeof(struct ssh_buffer_struct));
    if (buf == NULL) {
        return NULL;
    }

    /*
     * Always preallocate 64 bytes.
     *
     * -1 for ralloc_buffer magic.
     */
    rc = buffer_allocate_size(buf, 64 - 1);
    if (rc != 0) {
        SAFE_FREE(buf);
        return NULL;
    }

    return buf;
}

static int buffer_allocate_size(struct ssh_buffer_struct *buffer, uint32_t len) {
    if (buffer->allocated < len) {
        if (buffer->pos > 0) {
            buffer_shift(buffer);
        }
        if (realloc_buffer(buffer, len) < 0) {
            return -1;
        }
    }

    return 0;
}

static int realloc_buffer(struct ssh_buffer_struct *buffer, size_t needed) {
    size_t smallest = 1;
    uint8_t *new = NULL;

    /* Find the smallest power of two which is greater or equal to needed */
    while (smallest <= needed) {
        if (smallest == 0) {
            return -1;
        }
        smallest <<= 1;
    }
    needed = smallest;

    if (needed > BUFFER_SIZE_MAX) {
        return -1;
    }

    new = realloc(buffer->data, needed);
    if (new == NULL) {
        return -1;
    }

    buffer->data = new;
    buffer->allocated = needed;

    return 0;
}

/** @internal
 * @brief shifts a buffer to remove unused data in the beginning
 * @param buffer SSH buffer
 */
static void buffer_shift(ssh_buffer buffer) {
    size_t burn_pos = buffer->pos;

    if (buffer->pos == 0) {
        return;
    }
    memmove(buffer->data, buffer->data + buffer->pos,
            buffer->used - buffer->pos);
    buffer->used -= buffer->pos;
    buffer->pos = 0;
}

/**
 * @brief Deallocate a SSH buffer.
 *
 * @param[in]  buffer   The buffer to free.
 */
void ssh_buffer_free(struct ssh_buffer_struct *buffer) {
    if (buffer == NULL) {
        return;
    }

    SAFE_FREE(buffer->data);
    SAFE_FREE(buffer);
}

/**
 * @brief Reinitialize a SSH buffer.
 *
 * In case the buffer has exceeded 64K in size, the buffer will be reallocated
 * to 64K.
 *
 * @param[in]  buffer   The buffer to reinitialize.
 *
 * @return              0 on success, < 0 on error.
 */
int ssh_buffer_reinit(struct ssh_buffer_struct *buffer) {
    if (buffer == NULL) {
        return -1;
    }

    buffer->used = 0;
    buffer->pos = 0;

    /* If the buffer is bigger then 64K, reset it to 64K */
    if (buffer->allocated > 65536) {
        int rc;

        /* -1 for realloc_buffer magic */
        rc = realloc_buffer(buffer, 65536 - 1);
        if (rc != 0) {
            return -1;
        }
    }

    return 0;
}

/**
 * @brief Add data at the tail of a buffer.
 *
 * @param[in]  buffer   The buffer to add the data.
 *
 * @param[in]  data     A pointer to the data to add.
 *
 * @param[in]  len      The length of the data to add.
 *
 * @return              0 on success, < 0 on error.
 */
int ssh_buffer_add_data(struct ssh_buffer_struct *buffer, const void *data,
                        uint32_t len) {
    if (buffer == NULL) {
        return -1;
    }

    if (data == NULL) {
        return -1;
    }

    if (buffer->used + len < len) {
        return -1;
    }

    if (buffer->allocated < (buffer->used + len)) {
        if (buffer->pos > 0) {
            buffer_shift(buffer);
        }
        if (realloc_buffer(buffer, buffer->used + len) < 0) {
            return -1;
        }
    }

    memcpy(buffer->data + buffer->used, data, len);
    buffer->used += len;
    return 0;
}

/**
 * @brief Get the remaining data out of the buffer and adjust the read pointer.
 *
 * @param[in]  buffer   The buffer to read.
 *
 * @param[in]  data     The data buffer where to store the data.
 *
 * @param[in]  len      The length to read from the buffer.
 *
 * @returns             0 if there is not enough data in buffer, len otherwise.
 */
uint32_t ssh_buffer_get_data(struct ssh_buffer_struct *buffer, void *data,
                             uint32_t len) {
    int rc;

    /*
     * Check for a integer overflow first, then check if not enough data is in
     * the buffer.
     */
    rc = ssh_buffer_validate_length(buffer, len);
    if (rc != SSH_OK) {
        return 0;
    }
    memcpy(data, buffer->data + buffer->pos, len);
    buffer->pos += len;
    return len; /* no yet support for partial reads (is it really needed ?? ) */
}

/**
 * @brief Valdiates that the given length can be obtained from the buffer.
 *
 * @param[in]  buffer  The buffer to read from.
 *
 * @param[in]  len     The length to be checked.
 *
 * @return             SSH_OK if the length is valid, SSH_ERROR otherwise.
 */
int ssh_buffer_validate_length(struct ssh_buffer_struct *buffer, size_t len) {
    if (buffer->pos + len < len || buffer->pos + len > buffer->used) {
        return SSH_ERROR;
    }

    return SSH_OK;
}

/**
 * @brief Get a pointer to the head of a buffer at the current position.
 *
 * @param[in]  buffer   The buffer to get the head pointer.
 *
 * @return              A pointer to the data from current position.
 *
 * @see ssh_buffer_get_len()
 */
void *ssh_buffer_get(struct ssh_buffer_struct *buffer) {
    return buffer->data + buffer->pos;
}

/**
 * @brief Get the length of the buffer from the current position.
 *
 * @param[in]  buffer   The buffer to get the length from.
 *
 * @return              The length of the buffer.
 *
 * @see ssh_buffer_get()
 */
uint32_t ssh_buffer_get_len(struct ssh_buffer_struct *buffer) {
    return buffer->used - buffer->pos;
}