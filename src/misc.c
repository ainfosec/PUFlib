// PUFlib miscellaneous functions
//
// (C) Copyright 2016 Assured Information Security, Inc.
//

#include "misc.h"
#include <string.h>
#include <stdlib.h>

char * puflib_duplicate_string(char const * src)
{
    // Count the length once, then use it as a bound for the data copy. This
    // avoids writing past the end of dest if src is modified by a thread while
    // this function is running.

    size_t len = strlen(src);
    char * dest = malloc(len + 1);

    if (!dest) {
        return NULL;
    }

    strncpy(dest, src, len);
    dest[len] = 0;
    return dest;
}
