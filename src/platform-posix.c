// PUFlib platform-dependent functions, POSIX implementation
//
// (C) Copyright 2016 Assured Information Security, Inc.
//
//

#define _XOPEN_SOURCE 700

#include "platform.h"
#include "misc.h"
#include <puflib.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <ftw.h>


char const * puflib_get_path_sep()
{
    return "/";
}


char * puflib_get_nv_store_path(char const * module_name, enum puflib_storage_type type)
{
    if (getuid() == 0) {
        char const * basepath = "/var/lib/puflib/";
        switch (type) {
        case STORAGE_TEMP_FILE:
        case STORAGE_TEMP_DIR:
            return puflib_concat(basepath, "temp/", module_name, NULL);
        
        case STORAGE_FINAL_FILE:
        case STORAGE_FINAL_DIR:
            return puflib_concat(basepath, "final/", module_name, NULL);
        default:
            return NULL;
        }
    } else {
        char const * home = getenv("HOME");
        char const * subdir = "/.local/lib/puflib/";
        if (!home) {
            errno = ENOENT;
            return NULL;
        }
        switch(type) {
        case STORAGE_TEMP_FILE:
        case STORAGE_TEMP_DIR:
            return puflib_concat(home, subdir, "temp/", module_name, NULL);

        case STORAGE_FINAL_FILE:
        case STORAGE_FINAL_DIR:
            return puflib_concat(home, subdir, "final/", module_name, NULL);
        default:
            return NULL;
        }
    }
}


bool puflib_create_directory_tree(char const * path, bool skip_last)
{
    char * path_buf = puflib_duplicate_string(path);
    if (!path_buf) {
        return true;
    }

    // Move through the string one path separator at a time, blanking out that
    // separator and creating the path.
    char * path_sep = path_buf;

    while (path_sep && *path_sep) {
        path_sep = strchr(path_sep, '/');

        if (path_sep) {
            *path_sep = 0;
        }

        if (!(skip_last && !path_sep)) {
            if (*path_buf && mkdir(path_buf, 0777)) {
                if (errno != EEXIST) {
                    int errno_hold = errno;
                    free(path_buf);
                    errno = errno_hold;
                    return true;
                }
            }
        }

        if (path_sep) {
            *path_sep = '/';
            ++path_sep;
        }
    }

    free(path_buf);
    return false;
}


FILE * puflib_create_and_open(char const * path, char const * mode)
{
    int fd = open(path, O_CREAT | O_RDWR | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return NULL;
    } else {
        return fdopen(fd, mode);
    }
}


FILE * puflib_open_existing(char const * path, char const * mode)
{
    int fd = open(path, O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return NULL;
    } else {
        return fdopen(fd, mode);
    }
}


bool puflib_mkdir(char const * path)
{
    return mkdir(path, 0700) != 0;
}


bool puflib_check_access(char const * path, bool isdirectory)
{
    return access(path, isdirectory ? (R_OK | W_OK | X_OK) : (R_OK | W_OK)) != 0;
}


static int delete_tree_callback(char const * fpath, struct stat const * sb,
        int typeflag, struct FTW * ftwbuf)
{
    (void) sb;
    (void) typeflag;
    (void) ftwbuf;

    if (remove(fpath)) {
        return errno;
    } else {
        return 0;
    }
}


bool puflib_delete_tree(char const * path)
{
    int rv = nftw(path, &delete_tree_callback, 10, FTW_DEPTH | FTW_PHYS);

    if (rv < 0) {
        // nftw itself failed, and there is an error in errno
        return true;
    } else if (rv > 0) {
        // the callback passed an errno error in the return value
        errno = rv;
        return true;
    } else {
        return false;
    }
}
