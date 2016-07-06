// PUFlib Main Header File
//
// (C) Copyright 2016 Assured Information Security, Inc.
//
//

#ifndef _PUFLIB_H_
#define _PUFLIB_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define PUFLIB_MODULE_NAME_MAX 100

enum provisioning_status {
  PROVISION_NOT_SUPPORTED,
  PROVISION_INCOMPLETE,
  PROVISION_COMPLETE,
  PROVISION_ERROR,
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
module_info const * puflib_get_module( char const * name );

/**
 * Set a callback function to receive status messages. This defaults to NULL,
 * so any messages generated before this is called will be dropped!
 *
 * @param - callback, or NULL to ignore messages.
 */
void puflib_set_status_handler(void (*callback)(char const * message));

/**************************************************************************//**
 * @section
 * Internal documentation; used for implementing modules.
 *****************************************************************************/

/**
 * @internal
 * Create a file for saving nonvolatile state. This can be used to track status
 * during provisioning. An error may occur if there is nowhere available to
 * create a file (due to read-only file system, insufficient permissions for
 * the running process, etc); in this case the return value will be NULL and
 * an error code will be present in errno.
 *
 * The module is responsible for closing the file with fclose() when finished
 * writing, and for deleting it with puflib_delete_nv_store() when totally
 * done.
 *
 * The module developer is responsible for consistently using either
 * nonvolatile files or nonvolatile directories. The two cannot be mixed.
 *
 * In particular, this could fail with EEXIST if a previous run never
 * concluded. In this case, aborting the previous run with
 * puflib_delete_nv_store() or continuing it with puflig_get_nv_store() should
 * resolve this.
 *
 * @param module - the calling module, for tracking ownership
 * @return opened file or NULL on error; caller is responsible for calling fclose()
 */
FILE * puflib_create_nv_store(module_info const * module);

/**
 * @internal
 * Open an existing nonvolatile store that was created by
 * puflib_create_nv_store(). An error may occur if the file does not exist, or
 * if the running process has insufficient permissions to access the file. In
 * this case the return value will be NULL and an error code will be present in
 * errno.
 *
 * @param module - the calling module, for tracking ownership
 * @return opened file or NULL on error; caller is responsible for calling fclose()
 */
FILE * puflib_get_nv_store(module_info const * module);

/**
 * @internal
 * Delete a nonvolatile store that was created by puflib_create_nv_store(). An
 * error may occur if the file does not exist, or if the running process has
 * insufficient permissions to access the file. In this case the return value
 * will be true and an error code will be present in errno.
 *
 * @param module - the calling module, for tracking ownership
 * @return false on success, true on error
 */
bool puflib_delete_nv_store(module_info const * module);

/**
 * @internal
 * Create a directory for saving nonvolatile state. This can be used to track
 * status during provisioning. An error may occur if there is nowhere available
 * to create a directory (due to read-only file system, insufficient permissions
 * for the running process, etc); in this case the return value will be NULL and
 * an error code will be present in errno.
 *
 * The module is responsible for freeing the returned path string, and for
 * deleting the directory with puflib_delete_nv_store_dir() when totally done.
 *
 * The module developer is responsible for consistently using either
 * nonvolatile files or nonvolatile directories. The two cannot be mixed.
 *
 * In particular, this could fail with EEXIST if a previous run never
 * concluded. In this case, aborting the previous run with
 * puflib_delete_nv_store_dir() or continuing it with puflib_get_nv_store_dir()
 * should resolve this.
 *
 * @param module - the calling module, for tracking ownership
 * @return path to directory or NULL on error; caller is responsible for
 *  calling free()
 */
char * puflib_create_nv_store_dir(module_info const * module);

/**
 * @internal
 * Return the path to an existing nonvolatile store that was created by
 * puflib_create_nv_store_dir(). An error may occur if the directory does not
 * exist, or if the running process has insufficient permissions to access it.
 * In this case the return value will be NULL and an error code will be present
 * in errno.
 *
 * @param module - the calling module, for tracking ownership
 * @return path to directory or NULL on error; caller is responsible for
 *  calling free()
 */
char * puflib_get_nv_store_dir(module_info const * module);

/**
 * @internal
 * Delete a nonvolatile store that was created by puflib_create_nv_store_dir().
 * An error may occur if the directory does not exist, or if the running
 * process has insufficient permissions to access it. In this case the return
 * value will be true and an error code will be present in errno.
 *
 * @param module - the calling module, for tracking ownership
 * @return false on success, true on error
 */
bool puflib_delete_nv_store_dir(module_info const * module);

/**
 * @internal
 * Severity levels for status messages.
 */
enum puflib_status_level {
    STATUS_INFO,
    STATUS_WARN,
    STATUS_ERROR,
};

/**
 * @internal
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
 * @internal
 * Print an error message through the report mechanism.
 * This is equivalent to puflib_report(module, STATUS_ERROR, strerror(errno)).
 *
 * @param module - the calling module
 */
void puflib_perror(module_info const * module);

#endif // _PUFLIB_H_
