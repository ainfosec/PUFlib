// PUFlib central library
//
// (C) Copyright 2016 Assured Information Security, Inc.
//
//

#include <puflib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

extern module_info const * const PUFLIB_MODULES[];
static void (*STATUS_CALLBACK)(char const * message) = NULL;

#define PUFLIB_MODULE_SANITIZED_MAX (PUFLIB_MODULE_NAME_MAX * 2)

#define NV_STORE_MAX (200 + LOGIN_NAME_MAX + PUFLIB_MODULE_SANITIZED_MAX)
#define REPORT_MAX 500

static char const * get_nv_store_dir();
static char * get_nv_filename(module_info const * module);
static char * strnthchr(char *s, int c, size_t n);
static int create_nv_store_dir();


/**
 * @internal
 * Return the preferred directory to contain a nonvolatile store for a module.
 * Can return NULL if not root and $HOME is not set (errno will be ENOENT).
 */
static char const * get_nv_store_dir()
{
    static char nvstore[NV_STORE_MAX + 1] = {0};

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

        strncpy(nvstore, getenv("HOME"), NV_STORE_MAX);
        strncpy(nvstore + homelen, "/.local/lib/puflib/nvstores", NV_STORE_MAX - homelen);
        nvstore[NV_STORE_MAX] = 0;
        return &nvstore[0];
    }
}


/**
 * @internal
 * Locate the nth character c in a string
 */
static char * strnthchr(char *s, int c, size_t n)
{
    if (n == 0) {
        n = 1;
    }

    for (size_t i = 0; s[i]; ++i) {
        if (s[i] == c) {
            if (n == 1) {
                return &s[i];
            } else {
                --n;
            }
        }
    }

    return NULL;
}


/**
 * @internal
 * Try to create the NV store directory if it doesn't exist.
 * @return zero on success, nonzero with errno set on error
 */
static int create_nv_store_dir()
{
    char const * nvstore = get_nv_store_dir();
    char * path = malloc(strlen(nvstore));
    if (!path) {
        return -1;
    }
    strcpy(path, nvstore);

    // Create path components until there aren't any more
    char * pathsep;
    size_t n_components = 2;
    do {
        pathsep = strnthchr(path, '/', n_components);
        ++n_components;
        if (pathsep) {
            *pathsep = 0;
        }
        if (mkdir(path, 0777)) {
            if (errno != EEXIST) {
                int errno_temp = errno;
                free(path);
                errno = errno_temp;
                return -1;
            }
        }
        if (pathsep) {
            *pathsep = '/';
        }
    } while (pathsep);
    return 0;
}


/**
 * @internal
 * Return the filename for a module's nonvolatile store. This is allocated on
 * the heap and must be freed by the caller.
 *
 * Returns NULL on OOM with errno == ENOMEM.
 */
static char * get_nv_filename(module_info const * module)
{
    char const *nvstore = get_nv_store_dir();
    char * buf = malloc(strlen(nvstore) + strlen(module->name) + 2);

    if (!buf) {
        return NULL;
    }

    strcpy(buf, nvstore);
    strcat(buf, "/");
    strcat(buf, module->name);
    return buf;
}


module_info const * const * puflib_get_modules()
{
    return PUFLIB_MODULES;
}


void puflib_set_status_handler(void (*callback)(char const * message))
{
    STATUS_CALLBACK = callback;
}


/**
 * @internal
 * Open the NV store with given mode flags (see open(2)).
 */
FILE * open_nv_store(module_info const * module, int flags)
{
    char *filename = get_nv_filename(module);
    if (!filename) {
        return NULL;
    }

    // Using open(2) is the only way to make sure we atomically create the file
    // if it doesn't exist, but fail if it does.
    int fd = open(filename, flags, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        int errno_temp = errno;
        free(filename);
        errno = errno_temp;
        return NULL;
    } else {
        free(filename);
    }

    return fdopen(fd, "r+");
}


FILE * puflib_create_nv_store(module_info const * module)
{
    if (create_nv_store_dir()) {
        return NULL;
    }
    return open_nv_store(module, O_CREAT | O_RDWR | O_EXCL);
}


FILE * puflib_get_nv_store(module_info const * module)
{
    return open_nv_store(module, O_RDWR);
}


int puflib_delete_nv_store(module_info const * module)
{
    char *filename = get_nv_filename(module);
    if (!filename) {
        return -1;
    }

    if (remove(filename)) {
        int errno_temp = errno;
        free(filename);
        errno = errno_temp;
        return -1;
    } else {
        free(filename);
        return 0;
    }
}


void puflib_report(module_info const * module, enum puflib_status_level level,
        char const * message)
{
    char buf[REPORT_MAX + 1];

    char const * level_as_string;
    switch (level) {
    case STATUS_INFO:
        level_as_string = "info";
        break;
    case STATUS_WARN:
        level_as_string = "warn";
        break;
    case STATUS_ERROR:
    default:
        level_as_string = "error";
        break;
    }

    snprintf(buf, REPORT_MAX + 1, "%s (%s): %s", level_as_string, module->name, message);
    if (STATUS_CALLBACK) {
        STATUS_CALLBACK(buf);
    }
}

