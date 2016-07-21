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
#include <assert.h>

extern module_info const * const PUFLIB_MODULES[];
static puflib_status_handler_p volatile STATUS_CALLBACK = NULL;
static puflib_query_handler_p volatile QUERY_CALLBACK = NULL;

static bool storage_type_is_dir(enum puflib_storage_type type)
{
    return type == STORAGE_TEMP_DIR
        || type == STORAGE_FINAL_DIR
        || type == STORAGE_DISABLED_DIR;
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


enum module_status puflib_module_status(module_info const * module)
{
    enum module_status status = 0;
    char * path_f = NULL;
    char * path_d = NULL;
    char * path_dis_f = NULL;
    char * path_dis_d = NULL;

    path_f = puflib_get_nv_store_path(module->name, STORAGE_FINAL_FILE);
    if (!path_f) goto err;
    path_d = puflib_get_nv_store_path(module->name, STORAGE_FINAL_DIR);
    if (!path_d) goto err;
    path_dis_f = puflib_get_nv_store_path(module->name, STORAGE_DISABLED_FILE);
    if (!path_dis_f) goto err;
    path_dis_d = puflib_get_nv_store_path(module->name, STORAGE_DISABLED_DIR);
    if (!path_dis_d) goto err;

    bool access_f = !puflib_check_access(path_f, false);
    bool access_d = !puflib_check_access(path_d, true);
    bool access_dis_f = !puflib_check_access(path_dis_f, false);
    bool access_dis_d = !puflib_check_access(path_dis_d, true);

    if (access_dis_f || access_dis_d) {
        status |= MODULE_PROVISIONED | MODULE_DISABLED;
    }

    if (access_f || access_d) {
        status |= MODULE_PROVISIONED;
    }

    free(path_f);
    free(path_d);
    free(path_dis_f);
    free(path_dis_d);

    return status;

err:
    if (path_f) free(path_f);
    if (path_d) free(path_d);
    if (path_dis_f) free(path_dis_f);
    if (path_dis_d) free(path_dis_d);
    return MODULE_STATUS_ERROR;
}


bool puflib_deprovision(module_info const * module)
{
    char * store_file_path = NULL;
    char * store_dir_path = NULL;

    store_file_path = puflib_get_nv_store_path(module->name, STORAGE_FINAL_FILE);
    if (!store_file_path) {
        goto err;
    }

    store_dir_path = puflib_get_nv_store_path(module->name, STORAGE_FINAL_DIR);
    if (!store_dir_path) {
        goto err;
    }

    if (!puflib_check_access(store_file_path, false)) {
        if (remove(store_file_path)) {
            goto err;
        }
    }

    if (!puflib_check_access(store_dir_path, true)) {
        if (puflib_delete_tree(store_dir_path)) {
            goto err;
        }
    }

    if (store_file_path)    free(store_file_path);
    if (store_dir_path)     free(store_dir_path);
    return false;

err:
    {
        int errno_hold = errno;
        if (store_file_path)    free(store_file_path);
        if (store_dir_path)     free(store_dir_path);
        errno = errno_hold;
        return true;
    }
}


static bool puflib_en_dis(module_info const * module, bool enable)
{
    char * store_file_en_path = NULL;
    char * store_dir_en_path = NULL;
    char * store_file_dis_path = NULL;
    char * store_dir_dis_path = NULL;

    store_file_en_path = puflib_get_nv_store_path(module->name, STORAGE_FINAL_FILE);
    if (!store_file_en_path) goto err;

    store_dir_en_path = puflib_get_nv_store_path(module->name, STORAGE_FINAL_DIR);
    if (!store_dir_en_path) goto err;

    store_file_dis_path = puflib_get_nv_store_path(module->name, STORAGE_DISABLED_FILE);
    if (!store_file_dis_path) goto err;

    store_dir_dis_path = puflib_get_nv_store_path(module->name, STORAGE_DISABLED_DIR);
    if (!store_dir_dis_path) goto err;

    char * file_old     = enable ? store_file_dis_path : store_file_en_path;
    char * dir_old      = enable ? store_dir_dis_path : store_dir_en_path;
    char * file_new     = enable ? store_file_en_path : store_file_dis_path;
    char * dir_new      = enable ? store_dir_en_path : store_dir_dis_path;

    bool acc_file_old   = !puflib_check_access(file_old, false);
    bool acc_dir_old    = !puflib_check_access(dir_old, true);
    bool acc_file_new   = !puflib_check_access(file_new, false);
    bool acc_dir_new    = !puflib_check_access(dir_new, true);

    // Create partial paths first, if they don't exist
    if (acc_file_old) {
        if (puflib_create_directory_tree(file_new, true)) {
            goto err;
        }
    }
    if (acc_dir_old) {
        if (puflib_create_directory_tree(dir_new, true)) {
            goto err;
        }
    }

    if ((acc_file_new || acc_dir_new) && (acc_file_old || acc_dir_old)) {
        puflib_report_fmt(module, STATUS_ERROR,
                "cannot %s module - both enabled and disabled stores exist",
                enable ? "enable" : "disable");
        goto err;
    }

    if (acc_file_new || acc_dir_new) {
        goto nop;
    }

    if (acc_file_old) {
        if (rename(file_old, file_new)) {
            goto err;
        }
    }

    if (acc_dir_old && strcmp(file_old, dir_old)) {
        if (rename(dir_old, dir_new)) {
            goto err;
        }
    }
nop:
    assert(store_file_en_path);     free(store_file_en_path);
    assert(store_dir_en_path);      free(store_dir_en_path);
    assert(store_file_dis_path);    free(store_file_dis_path);
    assert(store_dir_dis_path);     free(store_dir_dis_path);
    return false;

err:
    if(store_file_en_path)      free(store_file_en_path);
    if(store_dir_en_path)       free(store_dir_en_path);
    if(store_file_dis_path)     free(store_file_dis_path);
    if(store_dir_dis_path)      free(store_dir_dis_path);
    return true;
}


bool puflib_enable(module_info const * module)
{
    return puflib_en_dis(module, true);
}


bool puflib_disable(module_info const * module)
{
    return puflib_en_dis(module, false);
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
