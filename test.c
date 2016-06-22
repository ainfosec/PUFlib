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


static void status_handler(char const * message)
{
    puts(message);
}


int main(int argc, char **argv)
{
    puflib_set_status_handler(&status_handler);

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
        module_info const * module = puflib_get_module(argv[1]);

        if (module) {
            if (module->is_hw_supported()) {
                module->provision();
                return 0;
            } else {
                printf("module does not support this hardware\n");
                return 1;
            }
        } else {
            printf("no module found with name: %s\n", argv[1]);
            return 1;
        }
    }
}
