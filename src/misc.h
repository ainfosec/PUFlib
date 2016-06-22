// PUFlib miscellaneous functions
//
// (C) Copyright 2016 Assured Information Security, Inc.
//
// Internal header, not to be installed with library.
//

#ifndef _PUFLIB_MISC_H_
#define _PUFLIB_MISC_H_

/**
 * Duplicate a string. This is equivalent to strdup() (which is not available
 * on all platforms).
 *
 * @return new string, or NULL on error.
 */
char * puflib_duplicate_string(char const * src);

#endif // _PUFLIB_MISC_H_
