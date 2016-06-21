// PUFlib test
//
// (C) Copyright 2016 Assured Information Security, Inc.
//
//

// If called with no arguments, list modules.
// If called with an argument, provision it.

#include <puflib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc == 1)
    {
        module_info const * const * modules = puflib_get_modules();

        for (size_t i = 0; modules[i]; ++i) {
            printf("%s\n", modules[i]->name);
            printf("Desc: %s\n", modules[i]->desc);
            printf("Auth: %s\n", modules[i]->author);
            printf("\n");
        }

        return 0;

    } else {
        module_info const * const * modules = puflib_get_modules();
        module_info const * module = NULL;

        for (size_t i = 0; modules[i]; ++i) {
            if (!strcmp(modules[i]->name, argv[1])) {
                module = modules[i];
            }
        }

        if (module) {
            module->provision();
            return 0;
        } else {
            printf("no module found with name: %s\n", argv[1]);
            return 1;
        }
    }
}
