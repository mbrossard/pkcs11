/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "crypto.h"
#include "common.h"
#include "pkcs11_display.h"

#include <string.h>

int do_GetSlotInfo(CK_FUNCTION_LIST *funcs,
                   CK_SLOT_ID slot_id)
{
    CK_SLOT_INFO  info;
    CK_RV         rc;

    rc = funcs->C_GetSlotInfo(slot_id, &info);
    if (rc != CKR_OK) {
        show_error(stdout, "   C_GetTokenInfo", rc);
        return FALSE;
    }

    fprintf(stdout, "CK_SLOT_INFO for slot #%ld:  \n", slot_id);
    print_slot_info(stdout, &info);
    fprintf(stdout, "\n\n");

    return TRUE;
}

int do_GetTokenInfo(CK_FUNCTION_LIST *funcs,
                    CK_SLOT_ID slot_id)
{
    CK_TOKEN_INFO  info;
    CK_RV          rc;

    rc = funcs->C_GetTokenInfo(slot_id, &info);
    if (rc != CKR_OK) {
        show_error(stdout, "   C_GetTokenInfo", rc);
        return FALSE;
    }

    fprintf(stdout, "CK_TOKEN_INFO for slot #%ld:  \n", slot_id);
    print_token_info(stdout, &info);
    fprintf(stdout, "\n\n");

    return TRUE;
}

static char *app_name = "pkcs11-util list-slots";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "module",             1, 0,           'm' },
    { "directory",          1, 0,           'd' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Specify the module to load",
    "Specify the directory for NSS database",
};

int slots(int argc, char **argv)
{
    CK_ULONG          nslots, islot;
    CK_SLOT_ID        *pslots = NULL;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_RV             rc;
    char *opt_module = NULL, *opt_dir = NULL;
    int long_optind = 0;

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

    rc = pkcs11_load_init(opt_module, opt_dir, stdout, &funcs);
    if (rc != CKR_OK) {
        return rc;
    }

    rc = pkcs11_get_slots(funcs, stdout, &pslots, &nslots);
    if (rc != CKR_OK) {
        return rc;
    }
    
    for (islot = 0; islot < nslots; islot++) {
        do_GetSlotInfo(funcs, pslots[islot]);
        do_GetTokenInfo(funcs, pslots[islot]);
    }

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Finalize", rc);
        return rc;
    }

    return rc;
}
