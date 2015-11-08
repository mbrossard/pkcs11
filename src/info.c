/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "common.h"
#include "pkcs11_display.h"

static char *app_name = "pkcs11-util info";
static const char *option_help[] = {
    "Print this help and exit",
    "Specify the module to load",
    "Specify the directory for NSS database",
};
static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "module",             1, 0,           'm' },
    { "directory",          1, 0,           'd' },
    { 0, 0, 0, 0 }
};

int info(int argc, char **argv)
{
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_INFO           info;
    CK_RV             rc;
    char *opt_module = NULL, *opt_dir = NULL;
    int  long_optind = 0;

    while (1) {
        char c = getopt_long(argc, argv, "d:hm:",
                             options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'd':
                opt_dir = optarg;
                break;
            case 'm':
                opt_module = optarg;
                break;
            case 'h':
            default:
                print_usage_and_die(app_name, options, option_help);
        }
    }

    funcs = pkcs11_get_function_list(opt_module);
    if (!funcs) {
        fprintf(stdout, "Could not get function list.\n");
        return -1;
    }

    if(opt_dir) {
        fprintf(stderr, "Using %s directory\n", opt_dir);
    }

    rc = pkcs11_initialize_nss(funcs, opt_dir);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Initialize", rc);
        return rc;
    }

    rc = funcs->C_GetInfo(&info);
    if (rc != CKR_OK) {
        show_error(stdout, "C_GetInfo", rc);
        return rc;
    } else {
        print_ck_info(stdout, &info);
    }

    return rc;
}
