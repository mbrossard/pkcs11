/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"

#ifdef HAVE_OPENSSL

#include "common.h"

static const char *app_name = "pkcs11-util import";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
};

int import(int argc, char **argv)
{
    CK_RV             rc = 0;
    int long_optind = 0;
    char c;

    while (1) {
        c = getopt_long(argc, argv, "h",
                        options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'h':
            default:
                print_usage_and_die(app_name, options, option_help);
        }
    }

    print_usage_and_die(app_name, options, option_help);

    return rc;
}

#endif
