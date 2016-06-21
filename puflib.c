// PUFlib central library
//
// (C) Copyright 2016 Assured Information Security, Inc.
//
//

#include <puflib.h>
#include <string.h>

extern module_info const * const PUFLIB_MODULES[];
static void (*STATUS_CALLBACK)(char const * message) = NULL;

#define PUFLIB_MODULE_SANITIZED_MAX (PUFLIB_MODULE_NAME_MAX * 2)

/**
 * @internal
 * Return the preferred directory to contain a nonvolatile store for a module.
 */
char const * get_nv_store_dir()
{
    // if (root) {
    //      return "/var/lib/puflib/nvstores";
    // } else {
    //      return $HOME/.local/lib/puflib/nvstores/${sanitized_module_name}
    // }
    // TODO
    return "/var/lib/puflib/nvstores";
}


/**
 * @internal
 * Sanitize a module name to be used in a filename.
 * @param name - buffer of at least PUFLIB_MODULE_SANITIZED_MAX+1 to hold the
 * @param module
 * name
 */
void sanitize_module_name(char * name, module_info const * module)
{
    // Module names can be sanitized any number of ways... Technically all that
    // is absolutely necessary is to escape '/' and '\0' and an escape
    // character. Perhaps cleaning up other specials would also be a good idea,
    // though.
    // TODO
    strncpy(name, module->name, PUFLIB_MODULE_SANITIZED_MAX);
    name[PUFLIB_MODULE_SANITIZED_MAX] = 0;
}


module_info const * const * puflib_get_modules()
{
    return PUFLIB_MODULES;
}


void puflib_set_status_handler(void (*callback)(char const * message))
{
    STATUS_CALLBACK = callback;
}


FILE * puflib_create_nv_store(module_info const * module)
{
    // Get file name: get_nv_store_dir() + "/" + sanitize_module_name()
    // Create and open file. Be sure to throw EEXIST if it already exists.
    // Return open file object.
    // TODO
    return NULL;
}


FILE * puflib_get_nv_store(module_info const * module)
{
    // Get file name: get_nv_store_dir() + "/" + sanitize_module_name()
    // Open file. Be sure to throw ENOENT if it doesn't exist rather than
    // creating it.
    // Return open file object.
    // TODO
    return NULL;
}


int puflib_delete_nv_store(module_info const * module)
{
    // Get file name: get_nv_store_dir() + "/" + sanitize_module_name()
    // Unlink file.
    // TODO
    return 1;
}


void puflib_report(module_info const * module, enum puflib_status_level level,
        char const * message)
{
    // sprintf(temp, "%s (%s): %s", level_as_string, module->name, message);
    // callback(temp)
    // TODO
}

