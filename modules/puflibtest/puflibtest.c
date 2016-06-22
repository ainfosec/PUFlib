// PUFlib test module
//
// (C) Copyright 2016 Assured Information Security, Inc.
//
//

#include <puflib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

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


static module_info const * const this = &MODULE_INFO__puflibtest;


static int8_t is_hw_supported()
{
    return 1;
}


static enum provisioning_status provision_start(FILE *f);
static enum provisioning_status provision_continue(FILE *f);


static enum provisioning_status provision()
{
    FILE *f;

    f = puflib_create_nv_store(this);
    if (f) {
        puflib_report(this, STATUS_INFO, "creating NV store");
        return provision_start(f);
    } else {
        puflib_report(this, STATUS_INFO, "could not create or NV store exists, continuing provision");
        f = puflib_get_nv_store(this);
        if (!f) {
            puflib_report(this, STATUS_ERROR, strerror(errno));
            return PROVISION_ERROR;
        } else {
            return provision_continue(f);
        }
    }
}


static enum provisioning_status provision_start(FILE *f)
{
    puflib_report(this, STATUS_INFO, "writing to NV store");
    fprintf(f, "%d\n", 1);

    puflib_report(this, STATUS_INFO, "provisioning will continue after the next invocation");
    fclose(f);
    return INCOMPLETE;
}


static enum provisioning_status provision_continue(FILE *f)
{
    int step = 0;

    puflib_report(this, STATUS_INFO, "reading from NV store");
    fscanf(f, "%d", &step);

    switch(step) {
    case 1:
        puflib_report(this, STATUS_INFO, "writing to NV store again");
        puflib_report(this, STATUS_INFO, "provisioning will continue after the next invocation");
        rewind(f);
        fprintf(f, "%d\n", 2);
        fclose(f);
        return INCOMPLETE;

    case 2:
        fclose(f);
        puflib_report(this, STATUS_INFO, "complete");
        puflib_report(this, STATUS_INFO, "deleting NV store");
        if (puflib_delete_nv_store(this)) {
            puflib_report(this, STATUS_ERROR, strerror(errno));
            return PROVISION_ERROR;
        } else {
            return COMPLETED;
        }

    default:
        fclose(f);
        puflib_report(this, STATUS_WARN, "NV store corrupted");
        return PROVISION_ERROR;
    }

}


static int8_t* chal_resp()
{
    return NULL;
}
