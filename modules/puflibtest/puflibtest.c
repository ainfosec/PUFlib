// PUFlib test module
//
// (C) Copyright 2016 Assured Information Security, Inc.
//
//

#include <puflib.h>
#include <stdio.h>

static int8_t is_hw_supported();
static enum provisioning_status provision();
static int8_t * chal_resp();


module_info const MODULE_INFO__puflibtest =
{
    .name = "puflibtest",
    .author = "Chris Pavlina <pavlinac@ainfosec.com>",
    .desc = "puflib test module",
    .is_hw_supported = &is_hw_supported,
    .provision = &provision,
    .chal_resp = &chal_resp,
};


static int8_t is_hw_supported()
{
    return 1;
}


static enum provisioning_status provision()
{
    puts("puflibtest provisioned!");
    return COMPLETED;
}

static int8_t* chal_resp()
{
    return NULL;
}
