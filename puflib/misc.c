// PUFlib miscellaneous functions
//
// (C) Copyright 2016 Assured Information Security, Inc.
//

#include "misc.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

char * puflib_duplicate_string(char const * src)
{
    // Count the length once, then use it as a bound for the data copy. This
    // avoids writing past the end of dest if src is modified by a thread while
    // this function is running.

    if (!src) {
        return NULL;
    }

    size_t len = strlen(src);
    char * dest = malloc(len + 1);

    if (!dest) {
        return NULL;
    }

    strncpy(dest, src, len);
    dest[len] = 0;
    return dest;
}


#define PUFLIB_VASPRINTF_BUFLEN 200
int puflib_vasprintf(char **strp, const char *fmt, va_list ap)
{
    va_list ap2;

    char * buf = malloc(PUFLIB_VASPRINTF_BUFLEN);
    if (!buf) {
        goto err;
    }

    va_copy(ap2, ap);
    int size = vsnprintf(buf, PUFLIB_VASPRINTF_BUFLEN, fmt, ap);

    if (size >= PUFLIB_VASPRINTF_BUFLEN) {
        char * newbuf = realloc(buf, (size_t) size + 1);
        if (!newbuf) {
            goto err;
        } else {
            buf = newbuf;
        }
        int rtn = vsnprintf(buf, size + 1, fmt, ap2);
        if (rtn >= 0) {
            *strp = buf;
            return rtn;
        } else {
            goto err;
        }
    } else if (size >= 0) {
        va_end(ap2);
        *strp = buf;
        return size;
    } else {
        va_end(ap2);
        goto err;
    }

err:
    if (buf) {
        int errno_hold = errno;
        free(buf);
        errno = errno_hold;
    }
    return -1;
}


int puflib_asprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    return puflib_vasprintf(strp, fmt, ap);
}


char * puflib_concat(char const * first, ...)
{
    va_list ap, ap2;
    size_t len;
    char const * each;
    char * head, * tail;

    if (!first) return puflib_concat("", NULL);

    len = 0;
    va_start(ap, first);
    va_copy(ap2, ap);
    each = first;
    do {
        len += strlen(each);
    } while ((each = va_arg(ap, char const *)));
    va_end(ap);

    head = malloc(len + 1);
    if (!head) {
        return NULL;
    }
    tail = head;

    while ((each = va_arg(ap2, char const *))) {
        size_t each_len = strlen(each);
        strncpy(tail, each, each_len);
        len -= each_len;
        tail += each_len;
    }
    va_end(ap2);

    *tail = 0;

    return head;
}
