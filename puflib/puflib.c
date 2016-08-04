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
#include <stddef.h>

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
    static const struct {
        enum puflib_storage_type stype;
        bool is_dir;
        enum module_status mask;
    } paths[] = {
        { STORAGE_TEMP_FILE,     false, MODULE_IN_PROGRESS },
        { STORAGE_TEMP_DIR,      true,  MODULE_IN_PROGRESS },
        { STORAGE_FINAL_FILE,    false, MODULE_PROVISIONED },
        { STORAGE_FINAL_DIR,     true,  MODULE_PROVISIONED },
        { STORAGE_DISABLED_FILE, false, MODULE_PROVISIONED | MODULE_DISABLED },
        { STORAGE_DISABLED_DIR,  true,  MODULE_PROVISIONED | MODULE_DISABLED },
    };

    enum module_status status = 0;

    for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {

        char * path = puflib_get_nv_store_path(module->name, paths[i].stype);
        if (!path) {
            goto err;
        }

        bool access_path = !puflib_check_access(path, paths[i].is_dir);

        if (access_path) {
            status |= paths[i].mask;
        }

        free(path);
    }

    return status;

err:
    return MODULE_STATUS_ERROR;
}


bool puflib_seal(module_info const * module,
        uint8_t const * data_in, size_t data_in_len,
        uint8_t ** data_out, size_t * data_out_len)
{
    char * header = NULL;
    uint8_t * rawbuffer = NULL;
    uint8_t * header_buffer = NULL;
    size_t rawbuflen;

    if (!module) {
        return true;
    }

    header = puflib_concat(PUFLIB_HEADER, module->name, "\n", NULL);
    if (!header) {
        goto err;
    }

    if (module->seal(data_in, data_in_len, &rawbuffer, &rawbuflen)) {
        goto err;
    }

    size_t header_len = strlen(header);
    size_t header_buflen = rawbuflen + header_len;

    header_buffer = malloc(header_buflen);
    if (!header_buffer) {
        goto err;
    }

    memcpy(header_buffer, header, header_len);
    memcpy(header_buffer + header_len, rawbuffer, rawbuflen);
    free(header);
    free(rawbuffer);

    *data_out = header_buffer;
    *data_out_len = header_buflen;

    return false;
err:
    free(header);
    free(rawbuffer);
    free(header_buffer);
    return true;
}


bool puflib_unseal(
        uint8_t const * data_in, size_t data_in_len,
        uint8_t ** data_out, size_t * data_out_len)
{
    char * module_name = NULL;

    if (data_in_len < strlen(PUFLIB_HEADER)) {
        puflib_report(NULL, STATUS_ERROR,
                "malformed header: too short for puflib magic prefix");
        goto err;
    }

    if (memcmp(data_in, PUFLIB_HEADER, strlen(PUFLIB_HEADER))) {
        puflib_report(NULL, STATUS_ERROR,
                "malformed header: no puflib magic prefix");
        goto err;
    }

    ptrdiff_t datalen_without_magic = data_in_len - strlen(PUFLIB_HEADER);
    if (datalen_without_magic <= 0) {
        puflib_report(NULL, STATUS_ERROR,
                "malformed header: too short for module name");
        goto err;
    }

    void const * module_name_start = (data_in + strlen(PUFLIB_HEADER));
    void const * module_name_end =
        memchr(module_name_start, '\n', datalen_without_magic);

    if (!module_name_end) {
        puflib_report(NULL, STATUS_ERROR, "malformed header: no module name");
        goto err;
    }

    module_name = malloc(module_name_end - module_name_start + 1);
    if (!module_name) {
        goto err;
    }

    memcpy(module_name, module_name_start, module_name_end - module_name_start);
    module_name[module_name_end - module_name_start] = 0;

    module_info const * module = puflib_get_module(module_name);
    if (!module) {
        puflib_report_fmt(NULL, STATUS_ERROR,
                "cannot unseal blob; requested module not found: %s\n",
                module_name);
        goto err;
    }

    size_t header_len = strlen(PUFLIB_HEADER) + strlen(module_name);
    uint8_t const * data_raw = data_in + header_len + 1;
    size_t data_raw_len = data_in_len - header_len - 1;
    free(module_name);

    return module->unseal(data_raw, data_raw_len, data_out, data_out_len);

err:
    free(module_name);
    return true;
}


bool puflib_chal_resp(module_info const * module,
        void const * data_in, size_t data_in_len,
        void ** data_out, size_t * data_out_len)
{
    if (module) {
        return module->chal_resp(data_in, data_in_len, data_out, data_out_len);
    } else {
        return true;
    }
}


bool puflib_deprovision(module_info const * module)
{
    static const struct {
        enum puflib_storage_type stype;
        bool is_dir;
    } paths[] = {
        { STORAGE_FINAL_FILE, false },
        { STORAGE_FINAL_DIR, true },
        { STORAGE_DISABLED_FILE, false },
        { STORAGE_DISABLED_DIR, true },
        { STORAGE_TEMP_FILE, false },
        { STORAGE_TEMP_DIR, true },
    };

    for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
        char * path = puflib_get_nv_store_path(module->name, paths[i].stype);
        if (!path) {
            return true;
        }

        if (!puflib_check_access(path, paths[i].is_dir)) {
            if (paths[i].is_dir ? puflib_delete_tree(path) : remove(path)) {
                goto err;
            }
        }

        free(path);
        continue;
err:
        free(path);
        return true;
    }

    return false;
}


static bool puflib_en_dis(module_info const * module, bool enable)
{
    static const struct {
        enum puflib_storage_type stype_en;
        enum puflib_storage_type stype_dis;
        bool is_dir;
    } paths[] = {
        { STORAGE_FINAL_FILE, STORAGE_DISABLED_FILE, false },
        { STORAGE_FINAL_DIR,  STORAGE_DISABLED_DIR,  true },
    };

    for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {

        char * en_path = NULL, * dis_path = NULL;

        en_path  = puflib_get_nv_store_path(module->name, paths[i].stype_en);
        dis_path = puflib_get_nv_store_path(module->name, paths[i].stype_dis);

        if (!en_path)  goto err;
        if (!dis_path) goto err;

        char * old_path = enable ? dis_path : en_path;
        char * new_path = enable ? en_path : dis_path;

        bool acc_old = !puflib_check_access(old_path, paths[i].is_dir);
        bool acc_new = !puflib_check_access(new_path, paths[i].is_dir);

        if (acc_old) {
            if (puflib_create_directory_tree(new_path, true)) {
                goto err;
            }
        }

        if (acc_old && acc_new) {
            puflib_report_fmt(module, STATUS_ERROR,
                    "cannot %s module - both enabled and disabled stores exist",
                    enable ? "enable" : "disable");
            goto err;
        }

        if (acc_new) {
            goto nop;
        }

        if (acc_old) {
            if (rename(old_path, new_path)) {
                goto err;
            }
        }

nop:
        free(en_path);
        free(dis_path);
        continue;

err:
        if (en_path)  free(en_path);
        if (dis_path) free(dis_path);
        return true;
    }

    return false;
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
    case STATUS_DEBUG:
        level_as_string = "debug";
        break;
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

#ifdef NDEBUG
    if (level == STATUS_DEBUG) {
        return;
    }
#endif

    char *formatted = NULL;
    char const * name = module ? module->name : "puflib";

    if (puflib_asprintf(&formatted, "%s (%s): %s", level_as_string, name, message) < 0) {
        if (formatted) free(formatted);
        STATUS_CALLBACK(NULL, STATUS_ERROR,
                "error (puflib): internal error formatting message");
    } else {
        STATUS_CALLBACK(module, level, formatted);
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
        STATUS_CALLBACK(NULL, STATUS_ERROR,
                "error (puflib): internal error formatting message");
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
