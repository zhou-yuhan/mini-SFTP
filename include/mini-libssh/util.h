#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <string.h>

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

/** Free memory space */
#define SAFE_FREE(x)       \
    do {                   \
        if ((x) != NULL) { \
            free(x);       \
            x = NULL;      \
        }                  \
    } while (0)

/** Zero a structure */
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

/** Zero a structure given a pointer to the structure */
#define ZERO_STRUCTP(x)                                        \
    do {                                                       \
        if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); \
    } while (0)

/** Get the size of an array */
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

/** Zero memory */
#define ZERO(p, n) memset((char*)(p), 0, n)

#endif /* UTIL_H */