// pufctl - manage and provision PUFlib PUFs
//
// Copyright (C) 2016 Assured Information Security, Inc.

//#include <puflib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

struct opts {
    bool help;
    bool noninteractive;
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
                        fprintf(stderr, "pufctl: invalid option -- '%c'\n", arg);
                        return true;
                }
            }
        } else if (!strcmp(argv[i], "--help")) {
            opts->help = true;
        } else if (!strcmp(argv[i], "--non-interactive")) {
            opts->noninteractive = true;
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
            fprintf(stderr, "pufctl: unrecognized option '%s'\n", argv[i]);
            return true;
        }
    }

    // Reached the end - no further items
    opts->argc = 0;
    opts->argv = NULL;
    return false;
}


int main(int argc, char ** argv)
{
    struct opts opts = {0};

    if (parse_args(&opts, argc - 1, argv + 1)) {
        return 1;
    }

    if (opts.help) {
        puts("help");
    }

    if (opts.noninteractive) {
        puts("noninteractive");
    }

    puts("Extra arguments:");
    for (int i = 0; i < opts.argc; ++i) {
        puts(opts.argv[i]);
    }

    return 0;
}
