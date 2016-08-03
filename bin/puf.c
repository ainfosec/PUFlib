// puf - seal and unseal secrets using PUFlib PUFs
//
// Copyright (C) 2016 Assured Information Security, Inc.

#include <puflib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <alloca.h>
#include <ctype.h>
#include <readline/readline.h>
#include "optparse.h"
#include "base64.h"

struct opts {
    bool help;
    bool input_base64;
    bool output_base64;
    char * output;
    int argc;
    char ** argv;
};


static void usage(void)
{
    printf("puf [OPTIONS] COMMAND [...]\n");
    printf("seal and unseal secrets using PUFlib PUFs. Use pufctl to discover\n");
    printf("available modules.\n");
    printf("\n");
    printf("options:\n");
    printf("  -I, --input-base64    input is base64-encoded\n");
    printf("  -O, --output-base64   output is base64-encoded\n");
    printf("  -o OUT, --output=OUT  output to OUT instead of stdout\n");
    printf("\n");
    printf("commands:\n");
    printf("  seal MOD IN       Seal IN using MOD\n");
    printf("  unseal MOD IN     Unseal IN using MOD\n");
    printf("  chal MOD IN       Use MOD's raw challenge-response interface\n");
}


static void status_handler(module_info const * module,
        enum puflib_status_level level, char const * message)
{
    (void) module;
    (void) level;
    printf("%s\n", message);
}


static bool query_handler(module_info const * module, char const * key,
        char const * prompt, char * buffer, size_t buflen)
{
    char * input;

    printf("Query from module \"%s\", key \"%s\"\n", module->name, key);
    input = readline(prompt);
    if (!input) {
        return true;
    } else {
        strncpy(buffer, input, buflen);
        buffer[buflen - 1] = 0;
        free(input);
        return false;
    }
}


#define MAX_BUFFER_LEN (8 * 1024 * 1024)
#define INIT_BUFFER_LEN 1024


static uint8_t * read_input_buffer(FILE * f, size_t * len)
{
    size_t bufsz = INIT_BUFFER_LEN;
    size_t bytes_read = 0;
    uint8_t * buf = NULL;

    buf = malloc(bufsz);
    if (!buf) {
        goto err;
    }

    bytes_read = fread(buf, 1, bufsz/2, f);

    while (!feof(f)) {
        size_t this_bytes_read = fread(buf + bytes_read, 1, bufsz/2, f);
        bytes_read += this_bytes_read;

        if (ferror(f)) {
            goto err;
        }

        if (this_bytes_read) {
            bufsz *= 2;
            if (bufsz > MAX_BUFFER_LEN) {
                errno = EFBIG;
                goto err;
            }

            uint8_t * newbuf = realloc(buf, bufsz);
            if (!newbuf) {
                goto err;
            }
            buf = newbuf;
        }
    }

    *len = bytes_read;
    return buf;

err:
    {
        int errno_hold = errno;
        if (buf) {
            free(buf);
        }
        errno = errno_hold;
        return NULL;
    }
}


/**
 * Replace a buffer with a base64-encoded copy of itself. The original buffer
 * will be freed.
 * @return true on error - on error, the old buffer will be untouched.
 */
bool replace_with_b64_encoded(uint8_t ** buffer, size_t * bufsz)
{
    size_t new_sz = BASE64_SIZE(*bufsz) + 1;
    uint8_t * newbuf = malloc(new_sz);
    if (!newbuf) {
        return true;
    }

    base64_encode((char *) newbuf, new_sz, *buffer, *bufsz);

    size_t len = strlen((char *) newbuf);
    newbuf[len] = '\n';
    *bufsz = len + 1;
    *buffer = newbuf;

    return false;
}


/**
 * Decode a buffer from base64 and replace it with the raw data. The original
 * buffer will be freed.
 * @return true on error - on error, the old buffer will be untouched.
 */
bool replace_with_b64_decoded(uint8_t ** buffer, size_t * bufsz)
{
    size_t new_sz = *bufsz;
    uint8_t * newbuf = malloc(new_sz);
    if (!newbuf) {
        return true;
    }

    // Trim any whitespace from the right
    for (size_t i = *bufsz - 1; i > 0; --i) {
        if (isspace((char) (*buffer)[i])) {
            (*buffer)[i] = 0;
        } else {
            break;
        }
    }

    int n = base64_decode(newbuf, (char const *) *buffer, new_sz);

    if (n < 0) {
        free(newbuf);
        return true;
    } else {
        *bufsz = (size_t) n;
        free(*buffer);
        *buffer = newbuf;
        return false;
    }
}


int do_action(struct opts opts)
{
    int argc = opts.argc;
    char ** argv = opts.argv;

    if (argc != 3) {
        fprintf(stderr, "pufctl: expected two arguments to command \"%s\". Try --help\n", argv[0]);
        return 1;
    }

    FILE * f_in  = NULL;
    FILE * f_out = NULL;
    size_t in_buf_len = 0;
    size_t out_buf_len = 0;
    uint8_t * in_buf = NULL;
    uint8_t * out_buf = NULL;

    // Load and check the module
    module_info const * mod = puflib_get_module(argv[1]);
    if (!mod) {
        fprintf(stderr, "puf: cannot use module \"%s\": does not exist\n", argv[1]);
        goto err;
    }

    enum module_status status = puflib_module_status(mod);
    if (status == MODULE_STATUS_ERROR) {
        goto perr;
    }
    if (status & MODULE_DISABLED) {
        fprintf(stderr, "puf: cannot use module \"%s\": module is disabled\n", mod->name);
        goto err;
    }
    if (!(status & MODULE_PROVISIONED)) {
        fprintf(stderr, "puf: cannot use module \"%s\": module has not been provisioned\n",
                mod->name);
        goto err;
    }

    // Read data
    if (!strcmp(argv[2], "-")) {
        f_in = stdin;
    } else {
        f_in = fopen(argv[2], "r");
        if (!f_in) {
            goto perr;
        }
    }

    in_buf = read_input_buffer(f_in, &in_buf_len);
    if (!in_buf) {
        goto perr;
    }

    if (opts.input_base64) {
        if (replace_with_b64_decoded(&in_buf, &in_buf_len)) {
            fprintf(stderr, "puf: error decoding base64 data\n");
            goto err;
        }
    }

    // Seal or unseal
    bool rc = false;
    if (!strcmp(argv[0], "seal")) {
        rc = puflib_seal(mod, in_buf, in_buf_len, &out_buf, &out_buf_len);
    } else if (!strcmp(argv[0], "unseal")) {
        rc = puflib_unseal(mod, in_buf, in_buf_len, &out_buf, &out_buf_len);
    } else if (!strcmp(argv[0], "chal")) {
        rc = puflib_chal_resp(mod, (void const *) in_buf, in_buf_len,
                (void **) &out_buf, &out_buf_len);
    } else {
        assert(false && "expected 'seal' or 'unseal'");
        goto err;
    }

    if (rc) {
        goto perr;
    } else {
        assert(out_buf);
    }

    // Write data
    if (opts.output) {
        f_out = fopen(opts.output, "w");
        if (!f_out) {
            goto perr;
        }
    } else {
        f_out = stdout;
    }

    if (opts.output_base64) {
        if (replace_with_b64_encoded(&out_buf, &out_buf_len)) {
            fprintf(stderr, "puf: error encoding base64 data\n");
            goto err;
        }
    }

    size_t write_i = 0;
    while (!feof(f_out) && (out_buf_len - write_i)) {
        if (ferror(f_out)) {
            goto err;
        }

        size_t n = fwrite(out_buf + write_i, 1, out_buf_len - write_i, f_out);
        write_i += n;
        if (!n) {
            break;
        }
    }

    fclose(f_in);
    fclose(f_out);
    free(in_buf);
    free(out_buf);

    return 0;

perr:
    perror("puf");
err:
    if (f_in) {
        fclose(f_in);
    }
    if (f_out) {
        fclose(f_out);
    }
    if (in_buf) {
        free(in_buf);
    }
    if (out_buf) {
        free(out_buf);
    }
    return 1;
}


int main(int argc, char ** argv)
{
    struct opts opts = {0};

    puflib_set_status_handler(&status_handler);
    puflib_set_query_handler(&query_handler);

    struct optparse options;
    optparse_init(&options, argv);
    struct optparse_long longopts[] = {
        {"help",            'h',    OPTPARSE_NONE},
        {"input-base64",    'I',    OPTPARSE_NONE},
        {"output-base64",   'O',    OPTPARSE_NONE},
        {"output",          'o',    OPTPARSE_REQUIRED},
        {0}
    };

    int option;
    while ((option = optparse_long(&options, longopts, NULL)) != -1) {
        switch (option) {
        case 'h':
            opts.help = true;
            break;
        case 'I':
            opts.input_base64 = true;
            break;
        case 'O':
            opts.output_base64 = true;
            break;
        case 'o':
            opts.output = options.optarg;
            break;
        case '?':
            fprintf(stderr, "%s: %s\n", argv[0], options.errmsg);
            return 1;
        }
    }

    char *argv_final[argc];
    char *arg;
    while ((arg = optparse_arg(&options))) {
        argv_final[opts.argc++] = arg;
    }
    opts.argv = &argv_final[0];

    if (opts.help) {
        usage();
        return 0;
    }

    if (opts.argc == 0) {
        fprintf(stderr, "puf: expected a command. Try --help\n");
        return 1;
    } else if (!strcmp(opts.argv[0], "seal") ||
               !strcmp(opts.argv[0], "unseal") ||
               !strcmp(opts.argv[0], "chal")) {
        return do_action(opts);
    } else {
        fprintf(stderr, "pufctl: unrecognized command '%s'\n", opts.argv[0]);
        return 1;
    }
}
