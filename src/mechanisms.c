/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "crypto.h"
#include "common.h"
#include "pkcs11_display.h"

int do_GetTokenMech(CK_FUNCTION_LIST *funcs,
                    CK_SLOT_ID slot_id)
{
    CK_RV             rc;
    CK_MECHANISM_INFO minfo;
    CK_MECHANISM_TYPE_PTR pMechanismList;
    CK_ULONG          imech, ulMechCount;

    rc = funcs->C_GetMechanismList(slot_id, NULL, &ulMechCount);

    pMechanismList = (CK_MECHANISM_TYPE *) malloc(ulMechCount * sizeof(CK_MECHANISM_TYPE));
    if (!pMechanismList) {
        fprintf(stderr, "Failed on line %d\n", __LINE__);
        return CKR_HOST_MEMORY;
    }

    rc = funcs->C_GetMechanismList(slot_id, pMechanismList, &ulMechCount);
    if (rc != CKR_OK) {
        show_error(stdout, "C_GetMechanismList", rc);
        return rc;
    }

    for (imech = 0; imech < ulMechCount; imech++) {
        rc = funcs->C_GetMechanismInfo(slot_id, pMechanismList[imech], &minfo);
        print_mech_info(stdout, pMechanismList[imech], &minfo);
    }

    free(pMechanismList);
    return rc;
}

static char *app_name = "pkcs11-util list-mechanisms";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { "directory",          1, 0,           'd' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Specify number of the slot to use",
    "Specify the module to load",
    "Specify the directory for NSS database",
};

int mechanisms(int argc, char **argv)
{
    CK_ULONG          nslots, islot;
    CK_SLOT_ID        *pslots = NULL;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_RV             rc;
    CK_ULONG          opt_slot = -1;
    char *opt_module = NULL, *opt_dir = NULL;
    int long_optind = 0;

    while (1) {
        char c = getopt_long(argc, argv, "d:hs:m:",
                             options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'd':
                opt_dir = optarg;
                break;
            case 's':
                opt_slot = (CK_SLOT_ID) atoi(optarg);
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

    if(opt_slot != -1) {
        /* TODO: Look in pslots */
        pslots = &opt_slot;
        nslots = 1;
    }

    for (islot = 0; islot < nslots; islot++) {
            do_GetTokenMech(funcs, pslots[islot]);
    }

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Finalize", rc);
        return rc;
    }

    return rc;
}
