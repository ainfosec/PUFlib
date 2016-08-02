// pufctl - manage and provision PUFlib PUFs
//
// Copyright (C) 2016 Assured Information Security, Inc.

#include <puflib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <readline/readline.h>
#include "optparse.h"

struct opts {
    bool help;
    bool noninteractive;
    int argc;
    char ** argv;
};


static void usage(void)
{
    printf("pufctl [OPTIONS] COMMAND [...]\n");
    printf("manage and provision PUFlib PUFs.\n");
    printf("\n");
    printf("commands:\n");
    printf("  list                  List all PUF modules\n");
    printf("  provisioned           List all provisioned PUF modules\n");
    printf("  provision MOD         Provision MOD. May be interactive.\n");
    printf("  continue MOD          Continue provisioning MOD.\n");
    printf("  deprovision MOD...    Deprovision modules.\n");
    printf("  disable MOD...        Temporarily disable modules.\n");
    printf("  enable MOD...         Re-enable modules.\n");
}


/**
 * Command to emit a list of modules.
 * @param include_all - list all compiled modules. If false, only list
 *  provisioned modules.
 * @return exit code
 */
static int do_list(bool include_all)
{
    char const * fmt = "%-20s %-15s %-15s %-15s\n";
    printf(fmt, "MODULE", "HWSUPPORT", "PROVISIONED", "ENABLED");

    module_info const * const * modules = puflib_get_modules();

    for (size_t i = 0; modules[i]; ++i) {
        bool hwsupp = modules[i]->is_hw_supported();
        enum module_status status = puflib_module_status(modules[i]);
        bool provisioned = (status & MODULE_PROVISIONED);
        bool enabled = !(status & MODULE_DISABLED);

        if (include_all || (provisioned && enabled)) {
            printf(fmt, modules[i]->name,
                    hwsupp ? "supported" : "not-supp",
                    provisioned ? "provisioned" : "not-prov",
                    enabled ? "enabled" : "disabled");
        }
    }

    return 0;
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


static int do_provision(char const * modname, bool noninteractive)
{
    module_info const * module = puflib_get_module(modname);

    if (module) {
        enum module_status status = puflib_module_status(module);
        if (status == MODULE_STATUS_ERROR) {
            perror("puflib_module_status");
            return 1;
        }
        if (status & MODULE_PROVISIONED) {
            fprintf(stderr, "pufctl: cannot provision module \"%s\": already provisioned\n",
                    modname);
            return 1;
        } else if (status & MODULE_IN_PROGRESS) {
            fprintf(stderr, "pufctl: cannot provision module \"%s\": already started provisioning. Try \"continue\"\n",
                    modname);
            return 1;
        }
        if (module->is_hw_supported()) {
            module->provision();
            return 0;
        } else {
            fprintf(stderr, "pufctl: module \"%s\" does not support this hardware\n",
                    modname);
            return 1;
        }
    } else {
        fprintf(stderr, "pufctl: module \"%s\" not found\n", modname);
        return 1;
    }
}


static int do_continue(char const * modname, bool noninteractive)
{
    module_info const * module = puflib_get_module(modname);

    if (module) {
        enum module_status status = puflib_module_status(module);
        if (status == MODULE_STATUS_ERROR) {
            perror("puflib_module_status");
            return 1;
        }
        if (status & MODULE_PROVISIONED) {
            fprintf(stderr, "pufctl: cannot provision module \"%s\": already provisioned\n",
                    modname);
            return 1;
        } else if (!(status & MODULE_IN_PROGRESS)) {
            fprintf(stderr, "pufctl: cannot continue provisioning module \"%s\": haven't started yet. Try \"provision\"\n",
                    modname);
            return 1;
        }
        if (module->is_hw_supported()) {
            module->provision();
            return 0;
        } else {
            fprintf(stderr, "pufctl: module \"%s\" does not support this hardware\n",
                    modname);
            return 1;
        }
    } else {
        fprintf(stderr, "pufctl: module \"%s\" not found\n", modname);
        return 1;
    }
}


enum module_simple_actions { DEPROVISION, ENABLE, DISABLE };


static int do_simple(int argc, char ** argv, enum module_simple_actions action)
{
    char * action_name = NULL;

    switch (action) {
    case DEPROVISION:
        action_name = "deprovision";
        break;
    case ENABLE:
        action_name = "enable";
        break;
    case DISABLE:
        action_name = "disable";
        break;
    default:
        fprintf(stderr, "pufctl: internal error: unknown simple action\n");
        return 1;
    }

    // First check that all modules exist, and abort before doing anything if
    // not.
    for (int i = 0; i < argc; ++i) {
        if (!puflib_get_module(argv[i])) {
            fprintf(stderr, "pufctl: cannot %s module \"%s\": does not exist\n",
                    action_name, argv[i]);
            return 1;
        }
    }

    for (int i = 0; i < argc; ++i) {
        module_info const * mod = puflib_get_module(argv[i]);
        assert(mod);
        enum module_status status = puflib_module_status(mod);
        if (status == MODULE_STATUS_ERROR) {
            perror("puflib_module_status");
            return 1;
        }
        switch (action) {
        case DEPROVISION:
            if (puflib_deprovision(mod)) {
                perror("puflib_deprovision");
                return 1;
            }
            break;
        case ENABLE:
            if (puflib_enable(mod)) {
                perror("puflib_enable");
                return 1;
            }
            break;
        case DISABLE:
            if (puflib_disable(mod)) {
                perror("puflib_disable");
                return 1;
            }
            break;
        }
    }

    return 0;
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
        {"non-interactive", 'n', OPTPARSE_NONE},
        {0}
    };

    int option;
    while ((option = optparse_long(&options, longopts, NULL)) != -1) {
        switch (option) {
        case 'h':
            opts.help = true;
            break;
        case 'n':
            opts.noninteractive = true;
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

    if (opts.argc == 0 || !strcmp(opts.argv[0], "list")) {
        return do_list(true);
    } else if (!strcmp(opts.argv[0], "provisioned")) {
        return do_list(false);
    } else if (!strcmp(opts.argv[0], "provision")) {
        if (opts.argc != 2) {
            fprintf(stderr, "pufctl: expected one argument to command \"provision\". Try --help\n");
            return 1;
        } else {
            return do_provision(opts.argv[1], opts.noninteractive);
        }
    } else if (!strcmp(opts.argv[0], "continue")) {
        if (opts.argc != 2) {
            fprintf(stderr, "pufctl: expected one argument to command \"continue\". Try --help\n");
            return 1;
        } else {
            return do_continue(opts.argv[1], opts.noninteractive);
        }
    } else if (!strcmp(opts.argv[0], "deprovision")) {
        if (opts.argc < 2) {
            fprintf(stderr, "pufctl: expected at least one argument to command \"deprovision\". Try --help\n");
            return 1;
        } else {
            return do_simple(opts.argc - 1, opts.argv + 1, DEPROVISION);
        }
    } else if (!strcmp(opts.argv[0], "enable")) {
        if (opts.argc < 2) {
            fprintf(stderr, "pufctl: expected at least one argument to command \"enable\". Try --help\n");
            return 1;
        } else {
            return do_simple(opts.argc - 1, opts.argv + 1, ENABLE);
        }
    } else if (!strcmp(opts.argv[0], "disable")) {
        if (opts.argc < 2) {
            fprintf(stderr, "pufctl: expected at least one argument to command \"disable\". Try --help\n");
            return 1;
        } else {
            return do_simple(opts.argc - 1, opts.argv + 1, DISABLE);
        }
    } else {
        fprintf(stderr, "pufctl: unrecognized command '%s'\n", opts.argv[0]);
        return 1;
    }
}
