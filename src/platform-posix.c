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


char const * puflib_get_nv_store_path()
{
    static char nvstore[PATH_MAX + 1] = {0};

    if (getuid() == 0) {
        return "/var/lib/puflib/nvstores";
    } else if (nvstore[0] != 0) {
        return &nvstore[0];
    } else {
        char const *home = getenv("HOME");
        if (!home) {
            errno = ENOENT;
            return NULL;
        }

        size_t homelen = strlen(home);

        strncpy(nvstore, home, PATH_MAX);
        strncpy(nvstore + homelen, "/.local/lib/puflib/nvstores", PATH_MAX - homelen);
        nvstore[sizeof(nvstore) - 1] = 0;
        return &nvstore[0];
    }
}


int puflib_create_directory_tree(char const * path)
{
    char * path_buf = puflib_duplicate_string(path);
    if (!path_buf) {
        return -1;
    }

    // Move through the string one path separator at a time, blanking out that
    // separator and creating the path.
    char * path_sep = path_buf;

    while (path_sep && *path_sep) {
        path_sep = strchr(path_sep, '/');

        if (path_sep) {
            *path_sep = 0;
        }

        if (*path_buf && mkdir(path_buf, 0777)) {
            if (errno != EEXIST) {
                int errno_hold = errno;
                free(path_buf);
                errno = errno_hold;
                return -1;
            }
        }

        if (path_sep) {
            *path_sep = '/';
            ++path_sep;
        }
    }

    free(path_buf);
    return 0;
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


int puflib_mkdir(char const * path)
{
    return mkdir(path, 0700);
}


int puflib_check_access(char const * path, int isdirectory)
{
    return access(path, isdirectory ? (R_OK | W_OK | X_OK) : (R_OK | W_OK));
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


int puflib_delete_tree(char const * path)
{
    int rv = nftw(path, &delete_tree_callback, 10, FTW_DEPTH | FTW_PHYS);

    if (rv < 0) {
        // nftw itself failed, and there is an error in errno
        return -1;
    } else if (rv > 0) {
        // the callback passed an errno error in the return value
        errno = rv;
        return -1;
    } else {
        return 0;
    }
}
