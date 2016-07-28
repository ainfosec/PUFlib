// puf - seal and unseal secrets using PUFlib PUFs
//
// Copyright (C) 2016 Assured Information Security, Inc.

#include <puflib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
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
    } else if (!strcmp(opts.argv[0], "seal")) {
        puts("seal");
        return 0;
    } else if (!strcmp(opts.argv[0], "unseal")) {
        puts("unseal");
        return 0;
    } else {
        fprintf(stderr, "pufctl: unrecognized command '%s'\n", opts.argv[0]);
        return 1;
    }
}
