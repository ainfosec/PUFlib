// PUFlib test module
//
// (C) Copyright 2016 Assured Information Security, Inc.
//
//

#include <puflib_module.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

bool is_hw_supported();
enum provisioning_status provision();
bool seal(uint8_t const * data_in, size_t data_in_len, uint8_t ** data_out, size_t * data_out_len);
bool unseal(uint8_t const * data_in, size_t data_in_len, uint8_t ** data_out, size_t * data_out_len);
bool chal_resp(void const * data_in, size_t data_in_len, void ** data_out, size_t * data_out_len);

module_info const MODULE_INFO =
{
    .name = "puflibtest",
    .author = "Chris Pavlina <pavlinac@ainfosec.com>",
    .desc = "puflib test module",
    .is_hw_supported = &is_hw_supported,
    .provision = &provision,
    .chal_resp = &chal_resp,
    .seal = &seal,
    .unseal = &unseal,
};


bool is_hw_supported()
{
    return true;
}


bool chal_resp(void const * data_in, size_t data_in_len, void ** data_out, size_t * data_out_len)
{
    void * buf = malloc(data_in_len);

    if (!buf) {
        puflib_perror(&MODULE_INFO);
        return true;
    }

    memcpy(buf, data_in, data_in_len);
    *data_out = buf;
    *data_out_len = data_in_len;
    return false;
}


bool seal(uint8_t const * data_in, size_t data_in_len, uint8_t ** data_out, size_t * data_out_len)
{
    uint8_t *data_out_buf = malloc(data_in_len);

    if (!data_out_buf) {
        puflib_perror(&MODULE_INFO);
        return true;
    }

    memcpy(data_out_buf, data_in, data_in_len);
    *data_out = data_out_buf;
    *data_out_len = data_in_len;

    return false;
}


bool unseal(uint8_t const * data_in, size_t data_in_len, uint8_t ** data_out, size_t * data_out_len)
{
    // Hey, it's a no-op anyway...
    return seal(data_in, data_in_len, data_out, data_out_len);
}


static enum provisioning_status provision_start(FILE *f);
static enum provisioning_status provision_continue(FILE *f);

enum provisioning_status provision()
{
    char *path;
    FILE *f;

    path = puflib_create_nv_store(&MODULE_INFO, STORAGE_TEMP_FILE);
    if (path) {
        f = fopen(path, "r+");
        if (!f) {
            puflib_perror(&MODULE_INFO);
            free(path);
            return PROVISION_ERROR;
        }
        puflib_report(&MODULE_INFO, STATUS_INFO, "creating NV store");
        free(path);
        return provision_start(f);
    } else {
        puflib_report(&MODULE_INFO, STATUS_INFO, "could not create or NV store exists, continuing provision");
        free(path);
        path = puflib_get_nv_store(&MODULE_INFO, STORAGE_TEMP_FILE);
        if (!path) {
            puflib_perror(&MODULE_INFO);
            return PROVISION_ERROR;
        } else {
            f = fopen(path, "r+");
            if (!f) {
                puflib_perror(&MODULE_INFO);
                free(path);
                return PROVISION_ERROR;
            }
            free(path);
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

    char querybuf[500];
    puflib_query(&MODULE_INFO, "testquery", "Enter any data: ", &querybuf[0], sizeof(querybuf));
    querybuf[sizeof(querybuf) - 1] = 0;
    puflib_report_fmt(&MODULE_INFO, STATUS_INFO, "query input was: %s", querybuf);

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
        if (puflib_delete_nv_store(&MODULE_INFO, STORAGE_TEMP_FILE)) {
            puflib_report(&MODULE_INFO, STATUS_ERROR, strerror(errno));
            return PROVISION_ERROR;
        }

        {
            char * final = puflib_create_nv_store(&MODULE_INFO, STORAGE_FINAL_FILE);
            if (!final) {
                puflib_perror(&MODULE_INFO);
                return PROVISION_ERROR;
            }
            FILE * f = fopen(final, "w");
            if (!f) {
                int errno_hold = errno;
                free(final);
                errno = errno_hold;
                puflib_perror(&MODULE_INFO);
                return PROVISION_ERROR;
            }
            free(final);
            if (fputs("provisioned", f) == EOF) {
                int errno_hold = errno;
                fclose(f);
                errno = errno_hold;
                puflib_perror(&MODULE_INFO);
                return PROVISION_ERROR;
            }
            fclose(f);
            return PROVISION_COMPLETE;
        }

    default:
        fclose(f);
        puflib_report(&MODULE_INFO, STATUS_WARN, "NV store corrupted");
        return PROVISION_ERROR;
    }

}


