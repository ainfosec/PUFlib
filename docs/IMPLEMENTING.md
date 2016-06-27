# Implementing PUFlib modules

Note that there is a small test module, puflibtest, which can also be used as a starting point.

## Directory structure

First, create the following directory structure (where _modulename_ is the name of your module):

* modules/
    * _modulename_/
        * Source files. These are any files with the standard `.c` extension; the build system will compile all that it finds.
        * `test_supported`: optional script to check whether the module can be built. If the module cannot be built, this script can exit nonzero, and then the build system will skip over it.
        Any error messages from this script will be printed to the console. Try to only emit messages if there are _errors_; if every script that simply doesn't support the current build target emits a message, the build will be very noisy.
        * `Makefile.inc`: optional per-module Makefile include; see below.

## Minimal code skeleton

    #include <puflib.h>

    static int8_t is_hw_supported();
    static enum provisioning_status provision();
    static int8_t * chal_resp();

    // "modulename" below must be replaced by the actual module name
    module_info const MODULE_INFO__modulename =
    {
        .name = "modulename",
        .author = "First Last <email@domain.tld>",
        .desc = "Description",
        .is_hw_supported = &is_hw_supported,
        .provision = &provision,
        .chal_resp = &chal_resp,
    };

    // Test whether the running hardware is supported by this module.
    // This function should return 0 if not supported, or nonzero if supported.
    static int8_t is_hw_supported()
    {
        return 1;
    }

    // Provision the PUF. See function documentation in puflib.h for more
    // information; the bulk of the provisioning code will go here.
    static enum provisioning_status provision()
    {
        return COMPLETED;
    }

    // Raw challenge/response interface
    // TODO: document this properly
    static int8_t * chal_resp()
    {
        return NULL;
    }

## `Makefile.inc`

It is possible that a module may need to change build or link settings. In this
case, a `Makefile.inc` can be created in the module subdirectory, to be included
at build time. Note that includes for modules that fail `test_supported` will
not be loaded.

Two useful lines in this file are:

    CFLAGS-modulename = ...
    LDFLAGS += ...

It is not recommended to use `CFLAGS +=` as this modifies flags for the entire build.
