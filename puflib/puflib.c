// PUFlib central library
//
// (C) Copyright 2016 Assured Information Security, Inc.
//
//

#include <puflib.h>
#include <puflib_internal.h>
#include "misc.h"

#include <string.h>
#include <errno.h>

extern module_info const * const PUFLIB_MODULES[];
static puflib_status_handler_p volatile STATUS_CALLBACK = NULL;
static puflib_query_handler_p volatile QUERY_CALLBACK = NULL;

static bool storage_type_is_dir(enum puflib_storage_type type)
{
    return type == STORAGE_TEMP_DIR || type == STORAGE_FINAL_DIR;
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


void puflib_set_status_handler(puflib_status_handler_p callback)
{
    STATUS_CALLBACK = callback;
}


void puflib_set_query_handler(puflib_query_handler_p callback)
{
    QUERY_CALLBACK = callback;
}


char * puflib_create_nv_store(module_info const * module, enum puflib_storage_type type)
{
    char * path = puflib_get_nv_store_path(module->name, type);
    if (!path) {
        return NULL;
    }

    if (storage_type_is_dir(type)) {
        if (!puflib_check_access(path, true)) {
            free(path);
            errno = EEXIST;
            return NULL;
        }
    }

    if (puflib_create_directory_tree(path, !storage_type_is_dir(type))) {
        goto err;
    }

    if (!storage_type_is_dir(type)) {
        FILE *f = puflib_create_and_open(path, "r+");
        if (!f) goto err;
        fclose(f);
    }

    return path;

err:
    if (path) {
        free(path);
    }
    return NULL;
}


char * puflib_get_nv_store(module_info const * module, enum puflib_storage_type type)
{
    char * path = puflib_get_nv_store_path(module->name, type);
    if (!path) {
        return NULL;
    }

    if (puflib_check_access(path, storage_type_is_dir(type))) {
        free(path);
        errno = EACCES;
        return NULL;
    } else {
        return path;
    }
}


bool puflib_delete_nv_store(module_info const * module, enum puflib_storage_type type)
{
    char * path = puflib_get_nv_store_path(module->name, type);
    if (!path) {
        return true;
    }

    bool err;

    if (storage_type_is_dir(type)) {
        err = puflib_delete_tree(path);
    } else {
        err = remove(path);
    }

    if (err) {
        int errno_temp = errno;
        free(path);
        errno = errno_temp;
        return true;
    } else {
        free(path);
        return false;
    }
}


void puflib_report(module_info const * module, enum puflib_status_level level,
        char const * message)
{
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

    char *formatted = NULL;
    if (puflib_asprintf(&formatted, "%s (%s): %s", level_as_string, module->name, message) < 0) {
        if (formatted) free(formatted);
        STATUS_CALLBACK("error (puflib): internal error formatting message");
    } else {
        STATUS_CALLBACK(formatted);
        free(formatted);
    }
}


void puflib_report_fmt(module_info const * module, enum puflib_status_level level,
        char const * fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    char *formatted = NULL;
    if (puflib_vasprintf(&formatted, fmt, ap) < 0) {
        if (formatted) free(formatted);
        STATUS_CALLBACK("error (puflib): internal error formatting message");
    } else {
        puflib_report(module, level, formatted);
        free(formatted);
    }
}


void puflib_perror(module_info const * module)
{
    puflib_report(module, STATUS_ERROR, strerror(errno));
}


bool puflib_query(module_info const * module, char const * key, char const * prompt,
        char * buffer, size_t buflen)
{
    if (QUERY_CALLBACK) {
        return QUERY_CALLBACK(module, key, prompt, buffer, buflen);
    } else {
        errno = 0;
        return true;
    }
}
