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

/**
 * Module status flags - bitwise OR'd
 */
enum module_status {
    MODULE_DISABLED = 0x01,         ///< Module has been provisioned, but is not available for use
    MODULE_PROVISIONED = 0x02,      ///< Module has been provisioned and is ready
    MODULE_IN_PROGRESS = 0x04,      ///< Module provisioning has started, but not finished
    MODULE_STATUS_ERROR = 0x8000,   ///< There was an error retrieving module status
};

/**
 * Severity levels for status messages.
 */
enum puflib_status_level {
    STATUS_DEBUG,   ///< Messages that only need to be seen while debugging.
                    ///< Will be silently dropped when compiling with NDEBUG
                    ///< defined.
    STATUS_INFO,    ///< Simple informative/progress messages for the user
    STATUS_WARN,    ///< Messages indicating something may be wrong
    STATUS_ERROR,   ///< Messages indicating failure
};

/**
 * Structure containing the information and functions belonging to a puflib
 * module. Every module must provide this.
 */
typedef struct module_info_s {
  char * name;          ///< Short name of the module, used to identify it
  char * author;        ///< Author string. May contain authors, email addresses, etc.
  char * desc;          ///< Longer (but still brief) description of the module
  bool (*is_hw_supported)();                ///< Return true if the platform present is supported
  enum provisioning_status (*provision)();  ///< Provision the module on this hardware

  /**
   * Seal (encrypt) the provided data.
   * @param data_in - data to be sealed
   * @param data_in_len - length of the data to be sealed, in bytes
   * @param data_out - outparam for the encrypted data. Will be allocated by
   *    seal(); caller is reponsible for freeing.
   * @param data_out_len - outparam for the length of the encrypted data,
   *    in bytes.
   * @return false on success, true on error
   */
  bool (*seal  )(
          uint8_t const * data_in,  size_t   data_in_len,
          uint8_t **      data_out, size_t * data_out_len );

  /**
   * Unseal (decrypt) the provided data.
   * @param data_in - data to be unsealed
   * @param data_in_len - length of the data to be unsealed, in bytes
   * @param data_out - outparam for the decrypted data. Will be allocated by
   *    unseal(); caller is reponsible for freeing.
   * @param data_out_len - outparam for the length of the decrypted data,
   *    in bytes.
   * @return false on success, true on error
   */
  bool (*unseal)(
          uint8_t const * data_in,  size_t   data_in_len,
          uint8_t **      data_out, size_t * data_out_len );

  /**
   * Low-level challenge/response call. Should return each module's rough
   * equivalent of puf(hash(i)).
   *
   * Note that the input handling will vary between modules. While the generic
   * chal_resp() function must accept arbitrary data, the module may impose its
   * own restrictions and reject data that does not fit. Many modules will take
   * a simple integer.
   *
   * @param data_in - challenge input data
   * @param data_in_len - challenge input length in bytes
   * @param data_out - outparam for the response. Will be allocated by
   *    chal_resp(); caller is responsible for freeing.
   * @param data_out_len - outparam for the length of the data, in bytes.
   * @return false on success, true on error
   */
  bool (*chal_resp)(
          void const * data_in,  size_t   data_in_len,
          void **      data_out, size_t * data_out_len );

} module_info;

/**
 * Status returned by each module's provision().
 */
enum provisioning_status {
    PROVISION_NOT_SUPPORTED,    ///< The platform present is not supported by this module
    PROVISION_INCOMPLETE,       ///< Some provisioning was performed, but needs to be continued
    PROVISION_COMPLETE,         ///< Provisioning is complete
    PROVISION_ERROR,            ///< An error occurred
};


/**
 * Callback to handle info and error messages from modules.
 * Generally, parameters module and level may be ignored; the message is
 * passed to the callback totally formatted and ready to be displayed.
 * These parameters may be used by a handler that wants to do something more
 * advanced (e.g. colorized output).
 *
 * @param module - the calling module. This may be NULL for messages coming from
 *  puflib internals!
 * @param level - status level
 * @param message - the fully formatted string message
 */
typedef void (*puflib_status_handler_p)(module_info const * module,
        enum puflib_status_level level, char const * message);

/**
 * Callback to handle queries from modules.
 * @param module - the calling module
 * @param key - a unique key identifying the data being requested
 * @param prompt - a human-readable prompt
 * @param buffer - a buffer to receive the data
 * @param bufsz - the length of the buffer
 * @return false on success, true on error (including user cancel)
 *
 * The unique key is provided to allow data to be provided by non-interactive
 * means, by using a callback that looks up data by key and returns it
 * directly.
 */
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
 * Seal a secret. The input data will be encrypted by the PUF module, and the
 * output data will be passed as a newly allocated block through data_out and
 * data_out_len. Caller is responsible for freeing data_out.
 *
 * @param module - module to use
 * @param data_in - data to be sealed
 * @param data_in_len - length of data_in, in bytes
 * @param data_out - pointer to a (uint8_t *) to receive the data.
 *  Caller is responsible for freeing.
 * @param data_out_len - pointer to a size_t to receive the output data's
 *  length, in bytes.
 *
 * @return true on error
 */
bool puflib_seal(module_info const * module,
        uint8_t const * data_in, size_t data_in_len,
        uint8_t ** data_out, size_t * data_out_len);

/**
 * Unseal a secret. The input data will be decrypted by the PUF module, and the
 * output data will be passed as a newly allocated block through data_out and
 * data_out_len. Caller is responsible for freeing data_out.
 *
 * @param module - module to use
 * @param data_in - data to be unsealed
 * @param data_in_len - length of data_in, in bytes
 * @param data_out - pointer to a (uint8_t *) to receive the data.
 *  Caller is responsible for freeing.
 * @param data_out_len - pointer to a size_t to receive the output data's
 *  length, in bytes.
 *
 * @return true on error, including if the data cannot be decrypted.
 */
bool puflib_unseal(module_info const * module,
        uint8_t const * data_in, size_t data_in_len,
        uint8_t ** data_out, size_t * data_out_len);

/**
 * Perform a low-level challenge-response call. Should return each module's
 * rough equivalent of puf(hash(i)).
 *
 * Note that the input handling will vary between modules. While the generic
 * puflib_chal_resp() function accepts arbitrary data, the module may impose
 * its own restrictions and reject data that does not fit. Many modules will
 * take a simple integer.
 *
 * @param module - module to use
 * @param data_in - challenge input data
 * @param data_in_len - challenge input length in bytes
 * @param data_out - outparam for the response. Will be allocated by
 *  puflib_chal_resp(); caller is reponsible for freeing.
 * @param data_out_len - outparam for the length of the data, in bytes.
 * @return false on success, true on error.
 */
bool puflib_chal_resp(module_info const * module,
        void const * data_in, size_t data_in_len,
        void ** data_out, size_t * data_out_len);

/**
 * Deprovision the module. No-op if the module is not provisioned. If the
 * module is partially provisioned, it will be reset to non-provisioned.
 * @param module - module to deprovision
 * @return true on error
 */
bool puflib_deprovision(module_info const * module);

/**
 * Enable the module if disabled. No-op if the module is not disabled or not
 * provisioned.
 * @param module - module to enable
 * @return true on error
 */
bool puflib_enable(module_info const * module);

/**
 * Disable the module if enabled. No-op if the module is not enabled or not
 * provisionsed.
 * @param module - module to enable
 * @return true on error
 */
bool puflib_disable(module_info const * module);

/**
 * Set a callback function to receive status messages. This defaults to NULL,
 * so any messages generated before this is called will be dropped!
 *
 * @param callback - callback, or NULL to ignore messages.
 */
void puflib_set_status_handler(puflib_status_handler_p callback);

/**
 * Set a callback function to receive queries. This defaults to NULL. If any
 * module tries to query before this has been set, it will have the option of
 * using a default value; modules are not required to allow this, however, so
 * configuring it prior to provisioning is recommended.
 *
 * @param callback - callback, or NULL to clear (but see warning above)
 */
void puflib_set_query_handler(puflib_query_handler_p callback);

#endif // _PUFLIB_H_
