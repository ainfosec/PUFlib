// PUFlib directory test module
//
// (C) Copyright 2016 Assured Information Security, Inc.
//
//

#include <puflib_module.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

bool is_hw_supported();
enum provisioning_status provision();
int8_t * chal_resp();


module_info const MODULE_INFO =
{
    .name = "puflibdirtest",
    .author = "Chris Pavlina <pavlinac@ainfosec.com>",
    .desc = "puflib directory test module",
    .is_hw_supported = &is_hw_supported,
    .provision = &provision,
    .chal_resp = &chal_resp,
};


bool is_hw_supported()
{
    return true;
}


int8_t* chal_resp()
{
    return NULL;
}

static enum provisioning_status provision_start(FILE *f);
static enum provisioning_status provision_continue(FILE *f);

enum provisioning_status provision()
{
    char *path;
    FILE *f;

    path = puflib_create_nv_store(&MODULE_INFO, STORAGE_TEMP_DIR);
    if (path) {
        puflib_report(&MODULE_INFO, STATUS_INFO, "creating NV store");
        chdir(path);
        free(path);
        f = fopen("file", "w+");
        return provision_start(f);
    } else {
        puflib_report(&MODULE_INFO, STATUS_INFO, "could not create or NV store exists, continuing provision");
        path = puflib_get_nv_store(&MODULE_INFO, STORAGE_TEMP_DIR);
        if (!path) {
            puflib_report(&MODULE_INFO, STATUS_ERROR, strerror(errno));
            return PROVISION_ERROR;
        } else {
            chdir(path);
            free(path);
            f = fopen("file", "r+");
            return provision_continue(f);
        }
    }
}


static enum provisioning_status provision_start(FILE *f)
{
    puflib_report(&MODULE_INFO, STATUS_INFO, "writing to NV store");
    fprintf(f, "%d\n", 1);

    puflib_report(&MODULE_INFO, STATUS_INFO, "provisioning will continue after the next invocation");
    fclose(f);
    return PROVISION_INCOMPLETE;
}


static enum provisioning_status provision_continue(FILE *f)
{
    int step = 0;

    puflib_report(&MODULE_INFO, STATUS_INFO, "reading from NV store");
    fscanf(f, "%d", &step);

    switch(step) {
    case 1:
        puflib_report(&MODULE_INFO, STATUS_INFO, "writing to NV store again");
        puflib_report(&MODULE_INFO, STATUS_INFO, "provisioning will continue after the next invocation");
        rewind(f);
        fprintf(f, "%d\n", 2);
        fclose(f);
        return PROVISION_INCOMPLETE;

    case 2:
        fclose(f);
        puflib_report(&MODULE_INFO, STATUS_INFO, "complete");
        puflib_report(&MODULE_INFO, STATUS_INFO, "deleting NV store");
        if (puflib_delete_nv_store(&MODULE_INFO, STORAGE_TEMP_DIR)) {
            puflib_report(&MODULE_INFO, STATUS_ERROR, strerror(errno));
            return PROVISION_ERROR;
        } else {
            return PROVISION_COMPLETE;
        }

    default:
        fclose(f);
        puflib_report(&MODULE_INFO, STATUS_WARN, "NV store corrupted");
        return PROVISION_ERROR;
    }

}


