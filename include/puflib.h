/**
 * @file
 * Main PUFlib header file.
 *
 * (C) Copyright 2016 Assured Information Security, Inc.
 */

#ifndef _PUFLIB_H_
#define _PUFLIB_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum provisioning_status {
    PROVISION_NOT_SUPPORTED,
    PROVISION_INCOMPLETE,
    PROVISION_COMPLETE,
    PROVISION_ERROR,
};

/**
 * Module status flags - bitwise OR'd
 */
enum module_status {
    MODULE_DISABLED = 0x01,
    MODULE_PROVISIONED = 0x02,
    MODULE_STATUS_ERROR = 0x8000,
};

struct module_info_s {
  char * name;
  char * author;
  char * desc;
  bool (*is_hw_supported)();
  enum provisioning_status (*provision)();
  int8_t * (*chal_resp)();
};
typedef struct module_info_s module_info;

typedef void (*puflib_status_handler_p)(char const * message);
typedef bool (*puflib_query_handler_p)(
        module_info const * module,
        char const * key,
        char const * prompt,
        char * buffer,
        size_t buflen);

/**
 * Return a list of all registered modules. Note that this may include modules
 * supporting hardware that is not present, so ->is_hw_supported() must be
 * called on any module before using it.
 *
 * List ends with a sentinel NULL pointer.
 */
module_info const * const * puflib_get_modules();

/**
 * Return a module by name, or NULL if it doesn't exist. Note that a module
 * being returned does not imply that the running system is supported by it, so
 * ->is_hw_supported() must be called on any module before using it.
 */
module_info const * puflib_get_module(char const * name);

/**
 * Query the status of a module.
 * @param module - module to check
 * @return bitwise OR of status flags, or MODULE_STATUS_ERROR on error (with
 *  errno set).
 */
enum module_status puflib_module_status(module_info const * module);

/**
 * Deprovision the module. No-op if the module is not provisioned.
 * @param module - module to deprovision
 * @return true on error
 */
bool puflib_deprovision(module_info const * module);

/**
 * Set a callback function to receive status messages. This defaults to NULL,
 * so any messages generated before this is called will be dropped!
 *
 * @param - callback, or NULL to ignore messages.
 */
void puflib_set_status_handler(puflib_status_handler_p callback);

/**
 * Set a callback function to receive queries. This defaults to NULL. If any
 * module tries to query before this has been set, it will have the option of
 * using a default value; modules are not required to allow this, however, so
 * configuring it prior to provisioning is recommended.
 *
 * Callback function parameters:
 *  - module - the calling module
 *  - key - a unique key identifying the data being requested
 *  - prompt - a human-readable prompt
 *  - buffer - a buffer to receive the data
 *  - bufsz - the length of the buffer
 *  - (return) - false on success, true on error (including user cancel)
 *
 * The unique key is provided to allow data to be provided by non-interactive
 * means, by using a callback that looks up data by key and returns it
 * directly.
 *
 * @param - callback, or NULL to clear (but see warning above)
 */
void puflib_set_query_handler(puflib_query_handler_p callback);

#endif // _PUFLIB_H_
