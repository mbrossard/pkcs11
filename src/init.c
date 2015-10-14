/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include <string.h>
#include <getopt.h>
#include <stdio.h>

#include "common.h"
#include "pkcs11_display.h"

static char *app_name = "pkcs11-util init";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "label",              1, 0,           'l' },
    { "module",             1, 0,           'm' },
    { "directory",          1, 0,           'd' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Supply PIN on the command line",
    "Specify number of the slot to use",
    "Token label",
    "Specify the module to load",
    "Specify the directory for NSS database",
};

CK_RV pkcs11_initialize_db(CK_FUNCTION_LIST_PTR funcs, const char *path)
{
    CK_RV rc = CKR_HOST_MEMORY;
    static const char *nss_init_string = "configdir='sql:%s' certPrefix='' keyPrefix='' secmod='secmod.db'";
    char buffer[256];
    CK_C_INITIALIZE_ARGS *iap = NULL;
    struct {
        CK_CREATEMUTEX CreateMutex;
        CK_DESTROYMUTEX DestroyMutex;
        CK_LOCKMUTEX LockMutex;
        CK_UNLOCKMUTEX UnlockMutex;
        CK_FLAGS flags;
        CK_CHAR_PTR LibraryParameters;
        CK_VOID_PTR pReserved;
    } ia;
    
    iap = (CK_C_INITIALIZE_ARGS *)&ia;
    ia.flags = CKF_OS_LOCKING_OK;
    ia.LibraryParameters = (CK_CHAR_PTR)buffer;
    ia.pReserved = NULL_PTR;
    snprintf(buffer, 256, nss_init_string, path);
    rc = funcs->C_Initialize( (CK_VOID_PTR)iap );

    return rc;
}

/* init is a reserved symbol */
int init_token( int argc, char **argv )
{
    CK_FUNCTION_LIST *funcs = NULL;
    /* CK_UTF8CHAR       label[32]; */
    CK_BYTE           opt_pin[32] = "";
    CK_ULONG          opt_pin_len = 0;
    CK_RV             rc;
    CK_ULONG          opt_slot = -1;
    CK_SESSION_HANDLE h_session;
    char *opt_module = NULL, *opt_dir = NULL, *opt_label = NULL;
    int long_optind = 0, kid = 0;
    char c;

    while (1) {
        c = getopt_long(argc, argv, "hrd:p:s:m:", options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'd':
                opt_dir = optarg;
                break;
            case 'p':
                opt_pin_len = strlen(optarg);
                opt_pin_len = (opt_pin_len < sizeof(opt_pin)) ?
                    opt_pin_len : sizeof(opt_pin) - 1;
                memcpy( opt_pin, optarg, opt_pin_len );
                break;
            case 's':
                opt_slot = (CK_SLOT_ID) atoi(optarg);
                break;
            case 'l':
                opt_label = optarg;
                break;
            case 'm':
                opt_module = optarg;
                break;
            case 'k':
                kid = atoi(optarg);
                break;
            case 'h':
            default:
                print_usage_and_die(app_name, options, option_help);
        }
    }

    funcs = pkcs11_get_function_list( opt_module );
    if (!funcs) {
        printf("Could not get function list (%s).\n", opt_module);
        return -1;
    }

    rc = pkcs11_initialize_db(funcs, opt_dir);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Initialize", rc );
        return rc;
    }

    if(*opt_pin != '\0') {
        /* memset(label, 0, sizeof(label)); */
        rc = funcs->C_InitToken(opt_slot, opt_pin, opt_pin_len,
                                (CK_UTF8CHAR_PTR) opt_label);
        if (rc != CKR_OK) {
            show_error(stdout, "C_InitToken", rc );
            return rc;
        }

        rc = funcs->C_OpenSession(opt_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                  NULL_PTR, NULL_PTR, &h_session);
        if (rc != CKR_OK) {
            show_error(stdout, "C_OpenSession", rc );
            return rc;
        }

        // rc = funcs->C_Login(h_session, CKU_SO, opt_pin, opt_pin_len );
        rc = funcs->C_Login(h_session, CKU_SO, NULL, 0 );
        // rc = funcs->C_Login(h_session, CKU_SO, "", 0 );
        if (rc != CKR_OK) {
            show_error(stdout, "C_Login", rc );
            return rc;
        }

        rc = funcs->C_InitPIN(h_session, opt_pin, opt_pin_len);
        if (rc != CKR_OK) {
            show_error(stdout, "C_InitPin", rc );
            return rc;
        }

        rc = funcs->C_Logout(h_session);
        if (rc != CKR_OK) {
            show_error(stdout, "C_Logout", rc );
            return rc;
        }

        rc = funcs->C_CloseSession(h_session);
        if (rc != CKR_OK) {
            show_error(stdout, "C_CloseSession", rc );
            return rc;
        }
    }

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Finalize", rc );
        return rc;
    }

    rc = funcs->C_Finalize( NULL );
    return rc;
}
