// PUFlib central library
//
// (C) Copyright 2016 Assured Information Security, Inc.
//
//

#include <puflib.h>
#include "platform.h"

#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

extern module_info const * const PUFLIB_MODULES[];
static void (*STATUS_CALLBACK)(char const * message) = NULL;

#define REPORT_MAX 500

static char * get_nv_filename(module_info const * module);


/**
 * @internal
 * Return the filename for a module's nonvolatile store. This is allocated on
 * the heap and must be freed by the caller.
 *
 * Returns NULL on OOM with errno == ENOMEM.
 */
static char * get_nv_filename(module_info const * module)
{
    char path_sep[2] = {puflib_get_path_sep(), 0};
    char const *nvstore = puflib_get_nv_store_path();
    char * buf = malloc(strlen(nvstore) + strlen(module->name) + 2);

    if (!buf) {
        return NULL;
    }

    strcpy(buf, nvstore);
    strcat(buf, path_sep);
    strcat(buf, module->name);
    return buf;
}


module_info const * const * puflib_get_modules()
{
    return PUFLIB_MODULES;
}


module_info const * puflib_get_module( char const * name )
{
    for (size_t i = 0; PUFLIB_MODULES[i]; ++i) {
        if (!strcmp(PUFLIB_MODULES[i]->name, name)) {
            return PUFLIB_MODULES[i];
        }
    }
    return NULL;
}


void puflib_set_status_handler(void (*callback)(char const * message))
{
    STATUS_CALLBACK = callback;
}


FILE * puflib_create_nv_store(module_info const * module)
{
    char * filename = get_nv_filename(module);
    if (!filename) {
        return NULL;
    }

    if (puflib_create_directory_tree(puflib_get_nv_store_path())) {
        free(filename);
        return NULL;
    }

    FILE *f = puflib_create_and_open(filename, "r+");

    int errno_hold = errno;
    free(filename);
    errno = errno_hold;
    return f;
}


FILE * puflib_get_nv_store(module_info const * module)
{
    char * filename = get_nv_filename(module);
    if (!filename) {
        return NULL;
    }

    FILE *f = puflib_open_existing(filename, "r+");

    int errno_hold = errno;
    free(filename);
    errno = errno_hold;
    return f;
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

