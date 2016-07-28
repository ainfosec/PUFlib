// puf - seal and unseal secrets using PUFlib PUFs
//
// Copyright (C) 2016 Assured Information Security, Inc.

#include <puflib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <readline/readline.h>

struct opts {
    bool help;
    bool input_base64;
    bool output_base64;
    int argc;
    char ** argv;
};


/**
 * Check whether an argument is a short option (-asdf is a short option,
 * equivalent to -a -s -d -f; --asdf is not and neither is asdf).
 */
static bool is_short(char const * arg)
{
    assert(arg);
    if (arg[0] == '-') {
        return arg[1] != '-';
    } else {
        return false;
    }
}


/**
 * Parse the command-line arguments into 'opts'. If anything remains, it will
 * be placed in opts->argc and opts->argv, otherwise opts->argc will be 0 and
 * opts->argv will be NULL.
 *
 * @param opts - structure to receive options
 * @param argc - number of arguments to parse, not including the command name
 * @param argv - arguments to parse, not including the command name
 *
 * @return true on error
 */
static bool parse_args(struct opts * opts, int argc, char ** argv)
{
    for (int i = 0; i < argc; ++i) {
        if (is_short(argv[i])) {
            for (int ishort = 1; argv[i][ishort]; ++ishort) {
                char arg = argv[i][ishort];
                switch (arg) {
                    case 'h':
                        opts->help = true;
                        break;
                    default:
                        fprintf(stderr, "puf: invalid option -- '%c'\n", arg);
                        return true;
                }
            }
        } else if (!strcmp(argv[i], "--help")) {
            opts->help = true;
        } else if (!strcmp(argv[i], "--input-base64")) {
            opts->input_base64 = true;
        } else if (!strcmp(argv[i], "--output-base64")) {
            opts->output_base64 = true;
        } else if (argv[i][0] != '-') {
            // This is the end of the arguments
            opts->argc = argc - i;
            opts->argv = argv + i;
            return false;
        } else if (!strcmp(argv[i], "--")) {
            // Forced stop - next argument is the end
            opts->argc = argc - i - 1;
            opts->argv = argv + i + 1;
            return false;
        } else {
            fprintf(stderr, "puf: unrecognized option '%s'\n", argv[i]);
            return true;
        }
    }

    // Reached the end - no further items
    opts->argc = 0;
    opts->argv = NULL;
    return false;
}


static void usage(void)
{
    printf("puf [OPTIONS] COMMAND [...]\n");
    printf("seal and unseal secrets using PUFlib PUFs. Use pufctl to discover\n");
    printf("available modules.\n");
    printf("\n");
    printf("commands:\n");
    printf("  seal MOD IN [OUT]     Seal IN using MOD, to OUT\n");
    printf("  unseal MOD IN [OUT]   Unseal IN using MOD, to OUT\n");
}


static void status_handler(char const * message)
{
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


int do_seal_unseal(int argc, char ** argv)
{
    if (argc != 3 && argc != 4) {
        fprintf(stderr, "pufctl: expected two or three arguments to command \"%s\". Try --help\n", argv[0]);
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

    // Seal or unseal
    bool rc = false;
    if (!strcmp(argv[0], "seal")) {
        rc = puflib_seal(mod, in_buf, in_buf_len, &out_buf, &out_buf_len);
    } else if (!strcmp(argv[0], "unseal")) {
        rc = puflib_unseal(mod, in_buf, in_buf_len, &out_buf, &out_buf_len);
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
    if (argc < 4 || !strcmp(argv[3], "-")) {
        f_out = stdout;
    } else {
        f_out = fopen(argv[3], "w");
        if (!f_out) {
            goto perr;
        }
    }

    size_t write_i = 0;
    while (!ferror(f_out) && !feof(f_out) && (out_buf_len - write_i)) {
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

    if (parse_args(&opts, argc - 1, argv + 1)) {
        return 1;
    }

    if (opts.help) {
        usage();
        return 0;
    }

    if (opts.argc == 0) {
        fprintf(stderr, "puf: expected a command. Try --help\n");
        return 1;
    } else if (!strcmp(opts.argv[0], "seal") || !strcmp(opts.argv[0], "unseal")) {
        return do_seal_unseal(opts.argc, opts.argv);
    } else if (!strcmp(opts.argv[0], "unseal")) {
        return do_seal_unseal(opts.argc, opts.argv);
    } else {
        fprintf(stderr, "pufctl: unrecognized command '%s'\n", opts.argv[0]);
        return 1;
    }
}
