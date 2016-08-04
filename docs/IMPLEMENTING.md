# Implementing PUFlib modules

Note that there is a small test module, puflibtest, which can also be used as a starting point.

## Directory structure

First, create the following directory structure (where _modulename_ is the name of your module):

* modules/
    * _modulename_/
        * Source files.
        * `Makefile`: Makefile to build the module. A standard include makes this simple; see below.
        * `test_supported`: optional script to check whether the module can be built. If the module cannot be built, this script can exit nonzero, and then the build system will skip over it.
        Any error messages from this script will be printed to the console. Try to only emit messages if there are _errors_; if every script that simply doesn't support the current build target emits a message, the build will be very noisy.

## Minimal code skeleton

    #include <puflib.h>

    int8_t is_hw_supported();
    enum provisioning_status provision();
    bool seal(uint8_t const * data_in, size_t data_in_len, uint8_t ** data_out, size_t * data_out_len);
    bool unseal(uint8_t const * data_in, size_t data_in_len, uint8_t ** data_out, size_t * data_out_len);
    bool chal_resp(void const * data_in, size_t data_in_len, void ** data_out, size_t * data_out_len);

    module_info const MODULE_INFO =
    {
        .name = "modulename",
        .author = "First Last <email@domain.tld>",
        .desc = "Description",
        .is_hw_supported = &is_hw_supported,
        .provision = &provision,
        .seal = &seal,
        .unseal = &unseal,
        .chal_resp = &chal_resp,        // optional
    };

    // Test whether the running hardware is supported by this module.
    // This function should return 0 if not supported, or nonzero if supported.
    int8_t is_hw_supported()
    {
        return 1;
    }

    // Provision the PUF. See function documentation in puflib_module.h for more
    // information; the bulk of the provisioning code will go here.
    enum provisioning_status provision()
    {
        return PROVISION_COMPLETE;
    }

    // Seal data_in, placing a raw, sealed blob into data_out. puflib will then
    // prepend a header identifying the source module before passing the data
    // to the original caller.
    bool seal()
    {
        return true;
    }

    // Unseal a raw blob as produced by seal().
    bool unseal()
    {
        return true;
    }

    // OPTIONAL: raw challenge/response interface. This is
    // module/implementation-specific, and should write the module's closest
    // equivalent to puf(hash(data_in)) to data_out.
    bool chal_resp()
    {
        return true;
    }

## Makefile

The most basic module Makefile looks like this:

    SOURCES = ...
    include ${PUFLIB_MF}

The following extra variables can be defined in this module Makefile:

    MODCFLAGS = ...
    MODLDFLAGS = ...

Additionally, if a very custom build is required, the double-colon `all` and
`clean` targets can be expanded to include build commands, the `%.o` rule can
be overridden, and the `OBJECTS` variable can be redefined to list all object
files that should be included in the modules.
