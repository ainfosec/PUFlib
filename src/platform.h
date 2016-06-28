// PUFlib platform-dependent functions
//
// (C) Copyright 2016 Assured Information Security, Inc.
//
// Internal header, not to be installed with library.
//
// These are functions used by puflib and its modules that are platform-
// dependent. The corresponding sources are at src/platform-*.c, one per
// supported platform.

#ifndef _PUFLIB_PLATFORM_H_
#define _PUFLIB_PLATFORM_H_

#include <stdio.h>

/**
 * Return the path separator on this platform.
 */
char const * puflib_get_path_sep();

/**
 * Return the preferred path for nonvolatile stores. This will be an absolute
 * path into a place where the calling process should have read and write
 * permission, but this function neither verifies this nor creates the
 * directory.
 *
 * @return path to directory on success, NULL on error (with errno set)
 */
char const * puflib_get_nv_store_path();

/**
 * Create a directory and all parent directories that don't already exist. This
 * is equivalent to 'mkdir -p'.
 *
 * @return zero on success, nonzero on error (with errno set)
 */
int puflib_create_directory_tree(char const * path);

/**
 * Create and open a new file, but fail if it already exists. This should be
 * implemented atomically wherever possible.
 *
 * @param path - path to the file
 * @param mode - mode string, compatible with fopen()
 * @return open file, or NULL on error (with errno set)
 */
FILE * puflib_create_and_open(char const * path, char const * mode);

/**
 * Open an existing file, but fail without creating it if it does not exist.
 * This should be implemented atomically wherever possible.
 *
 * @param path - path to the file
 * @param mode - mode string, compatible with fopen()
 * @return open file, or NULL on error (with errno set)
 */
FILE * puflib_open_existing(char const * path, char const * mode);

/**
 * Create a directory.
 * @param path - path to directory
 * @return zero on success, nonzero on failure
 */
int puflib_mkdir(char const * path);

/**
 * Check whether the running process can access a path.
 *
 * Warning: using this to gate access creates a possible security hole, as the
 * time between checking access and actually opening the file can be exploited.
 * Only use this for basic status reporting and similar.
 *
 * @param path - path
 * @param isdirectory - if true, test as a directory rather than as a file.
 * @return zero if the running process can access a path.
 */
int puflib_check_access(char const * path, int isdirectory);

/**
 * Delete an entire directory tree.
 *
 * @param path - tree to delete
 * @return zero on success, nonzero on error (with errno set)
 */
int puflib_delete_tree(char const * path);

#endif // _PUFLIB_PLATFORM_H
