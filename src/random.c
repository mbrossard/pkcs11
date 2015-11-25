/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "crypto.h"
#include "common.h"
#include "pkcs11_display.h"

#include <string.h>

static char *app_name = "pkcs11-util random";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "directory",          1, 0,           'd' },
    { "length",             1, 0,           'l' },
    { "module",             1, 0,           'm' },
    { "slot",               1, 0,           's' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Specify the directory for NSS database",
    "Specify the length of random string to generate",
    "Specify the module to load",
    "Specify number of the slot to use",
};

int random_p11(int argc, char **argv)
{
    CK_ULONG          nslots, opt_length;
    CK_SLOT_ID        *pslots = NULL, opt_slot;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_RV             rc;
    char *opt_module = NULL, *opt_dir = NULL;
    int long_optind = 0;

    while (1) {
        char c = getopt_long(argc, argv, "d:hl:m:s:",
                             options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'd':
                opt_dir = optarg;
                break;
            case 'l':
                opt_length = atoi(optarg);
                break;
            case 'm':
                opt_module = optarg;
                break;
            case 's':
                opt_slot = (CK_SLOT_ID) atoi(optarg);
                break;
            case 'h':
            default:
                print_usage_and_die(app_name, options, option_help);
        }
    }

    rc = pkcs11_load_init(opt_module, opt_dir, stderr, &funcs);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = pkcs11_get_slots(funcs, stderr, &pslots, &nslots);
    if (rc != CKR_OK) {
        return rc;
    }
    
    if(opt_slot != -1) {
        /* TODO: Look in pslots */
        pslots = &opt_slot;
        nslots = 1;
    }

    if(nslots == 1) {
        CK_SESSION_HANDLE h_session;
        CK_FLAGS flags = CKF_SERIAL_SESSION;

        rc = funcs->C_OpenSession(pslots[0], flags, NULL, NULL, &h_session);
        if (rc != CKR_OK) {
            show_error(stderr, "C_OpenSession", rc);
            return rc;
        }

        do {
            CK_BYTE buffer[256];
            CK_ULONG l = opt_length;
            l = (l > sizeof(buffer) ? sizeof(buffer) : l);
            rc = funcs->C_GenerateRandom(h_session, buffer, l);
            fwrite(buffer, l, 1, stdout);
            opt_length -= l;
        } while (opt_length);
    }

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        show_error(stderr, "C_Finalize", rc);
        return rc;
    }

    return rc;
}
