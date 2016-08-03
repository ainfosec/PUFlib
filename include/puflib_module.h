/**
 * @file
 * Internal PUFlib header for modules.
 *
 * (C) Copyright 2016 Assured Information Security, Inc.
 */

#ifndef _PUFLIB_MODULE_H_
#define _PUFLIB_MODULE_H_

#include <puflib.h>

/**
 * @name Nonvolatile storage
 * These functions provide nonvolatile storage to modules, both for temporary
 * use during provisioning, and for permanent storage of the results of
 * provisioning.
 */
/// @{

/// Storage types
enum puflib_storage_type
{
    STORAGE_TEMP_FILE,  ///< temporary file, to be deleted after provisioning
    STORAGE_TEMP_DIR,   ///< temporary directory, to be deleted after provisioning
    STORAGE_FINAL_FILE, ///< final file, to hold the result of provisioning
    STORAGE_FINAL_DIR,  ///< final directory, to hold the result of provisioning

    STORAGE_DISABLED_FILE,  ///< disabled final file - for internal use
    STORAGE_DISABLED_DIR,   ///< disabled final directory - for internal use
};

/**
 * Create a nonvolatile storage area. This can be used to track status during
 * provisioning or to save the result of provisioning. An error may occur if
 * there is nowhere available to create it (due to read-only file system,
 * insufficient permissions for the running process, etc); in this case the
 * return value will be NULL and an error code will be present in errno.
 *
 * In particular, this could fail with EEXIST if a previous run never concluded
 * or the module has already been provisioned. In this case, aborting the
 * previous run with puflib_delete_nv_store() or continuing it with
 * puflib_get_nv_store() should resolve this.
 *
 * The module is responsible for freeing the returned path string. For
 * temporary stores, the module is also responsible for deleting the store
 * with puflib_delete_nv_store() when totally done.
 *
 * @param module - the calling module, for tracking ownership
 * @param type - type of storage requested
 * @return path or NULL on error; caller is responsible for calling free().
 */
char * puflib_create_nv_store(module_info const * module, enum puflib_storage_type type);

/**
 * Return the path to an existing nonvolatile store that was created by
 * puflib_create_nv_store(). An error may occur if the path does not exist, or
 * if the returning process has insufficient permissions to access it. In this
 * case the return value will be NULL and an error code will be present in
 * errno.
 *
 * @param module - the calling module, for tracking ownership
 * @param type - type of storage requested
 * @return path or NULL on error; caller is responsible for calling free().
 */
char * puflib_get_nv_store(module_info const * module, enum puflib_storage_type type);

/**
 * Delete a nonvolatile store that was created by puflib_create_nv_store().
 * An error may occur if it does not exist, or if the running process has
 * insufficient permissions to access it. In this case the return value will
 * be true and an error code will be present in errno.
 *
 * @param module - the calling module, for tracking ownership
 * @param type - type of storage requested
 * @return false on success, true on error
 */
bool puflib_delete_nv_store(module_info const * module, enum puflib_storage_type type);

/// @}

/**
 * Severity levels for status messages.
 */
enum puflib_status_level {
    STATUS_INFO,
    STATUS_WARN,
    STATUS_ERROR,
};

/**
 * Report a status message. The message should be unformatted and raw, like
 * "hardware caught fire"; formatting like "error (eeprom): hardware caught fire"
 * will be added later.
 *
 * @param module - the calling module
 * @param level - status level
 * @param message - message
 */
void puflib_report(module_info const * module, enum puflib_status_level level,
        char const * message);

/**
 * Report a formatted status message. The message should be otherwise
 * unformatted and raw (do not prepend the message type and module name);
 * as with puflib_report, formatting like "error (eeprom): hardware caught fire"
 * will be added later.
 *
 * @param module - the calling module
 * @param level - the status level
 * @param fmt - printf format string
 * @param ... - printf arguments
 */
void puflib_report_fmt(module_info const * module, enum puflib_status_level level,
        char const * fmt, ...)
#ifndef DOXYGEN
    __attribute__((format (printf, 3, 4)))
#endif
    ;

/**
 * Print an error message through the report mechanism.
 * This is equivalent to puflib_report(module, STATUS_ERROR, strerror(errno)).
 *
 * @param module - the calling module
 */
void puflib_perror(module_info const * module);

/**
 * Query for data. This should only be run during provisioning, and can be used
 * to gather any required information from the user.
 *
 * The module must provide a unique key for every data item being requested.
 * This allows callers to provide data non-interactively by looking it up
 * based on this key.
 *
 * Note that this function can "fail" because the user cancelled the request.
 * In this case, it will return true to indicate error, but errno will be set
 * to zero.
 *
 * Also note that implementations may provide totally unvalidated data,
 * including data that is not NUL-terminated.
 *
 * @param module - the calling module
 * @param key - a unique key identifying the data being requested
 * @param prompt - a human-readable prompt
 * @param buffer - a buffer to receive the data
 * @param buflen - the length of the buffer
 * @return zero on success, nonzero on error (including user cancel)
 */
bool puflib_query(module_info const * module, char const * key, char const * prompt,
        char * buffer, size_t buflen);


#endif // _PUFLIB_MODULE_H_
