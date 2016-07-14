// PUFlib miscellaneous functions
//
// (C) Copyright 2016 Assured Information Security, Inc.
//
// Internal header, not to be installed with library.
//

#ifndef _PUFLIB_MISC_H_
#define _PUFLIB_MISC_H_

#include <stdarg.h>

/**
 * Duplicate a string. This is equivalent to strdup() (which is not available
 * on all platforms).
 *
 * @return new string, or NULL on error.
 */
char * puflib_duplicate_string(char const * src);

/**
 * Print to allocated string (see asprintf(3)). Internal implementation not
 * depending on GNU.
 *
 * @return number of bytes printed, or -1 on failure.
 */
int puflib_vasprintf(char **strp, const char *fmt, va_list ap)
    __attribute__((format (printf, 2, 0)));

/**
 * Print to allocated string (see asprintf(3)). Internal implementation not
 * depending on GNU.
 *
 * @return number of bytes printed, or -1 on failure.
 */
int puflib_asprintf(char **strp, const char *fmt, ...)
    __attribute__((format (printf, 2, 3)));

/**
 * Concatenate multiple strings into a single string allocated on the heap.
 * Returns NULL if the memory could not be allocated. The list of strings
 * must be terminated with a NULL sentinel.
 *
 * @return concatenated string, or NULL on failure.
 */
char * puflib_concat(char const * first, ...)
    __attribute__((sentinel));

#endif // _PUFLIB_MISC_H_
