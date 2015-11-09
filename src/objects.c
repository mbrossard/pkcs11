/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "crypto.h"
#include "common.h"
#include "pkcs11_display.h"

#include <string.h>

int do_list_token_objects(CK_FUNCTION_LIST *funcs,
                          CK_SLOT_ID        SLOT_ID,
                          CK_BYTE          *user_pin,
                          CK_ULONG          user_pin_len)
{
    CK_RV             rc;
    CK_ULONG          i, j, k, l;
    CK_SESSION_HANDLE h_session;
    CK_OBJECT_HANDLE  obj;

    rc = pkcs11_login_session(funcs, stdout, SLOT_ID, &h_session,
                              CK_FALSE, CKU_USER, user_pin, user_pin_len);
    if (rc != CKR_OK) {
        goto done;
    }

    rc = funcs->C_FindObjectsInit(h_session, NULL, 0);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsInit", rc);
        rc = FALSE;
        goto done;
    }

    j = 0;

    do {
        rc = funcs->C_FindObjects(h_session, &obj, 1, &i);
        if (rc != CKR_OK) {
            show_error(stdout, "C_FindObjects", rc);
            rc = FALSE;
            goto done;
        }
        if(i) {
            CK_ATTRIBUTE attribute;

            rc = funcs->C_GetObjectSize(h_session, obj, &k);
            if (rc != CKR_OK) {
                fprintf(stdout, "----------------\nObject %ld\n", j);
            } else {
                fprintf(stdout, "----------------\nObject %ld has size %ld\n", j, k);
            }

            j++;

            for(k = 0, l = 0; k < ck_attribute_num; k++) {
                attribute.type = ck_attribute_specs[k].type;
                attribute.pValue = NULL;
                attribute.ulValueLen = 0;

                rc = funcs->C_GetAttributeValue(h_session, obj, &attribute, 1);
                if ((rc == CKR_OK) && ((CK_LONG)attribute.ulValueLen != -1)) {
                    attribute.pValue = (CK_VOID_PTR) malloc(attribute.ulValueLen);

                    rc = funcs->C_GetAttributeValue(h_session, obj, &attribute, 1);
                    if (rc == CKR_OK) {
                        fprintf(stdout, "(%02ld) %s ", l++, ck_attribute_specs[k].name);

                        ck_attribute_specs[k].display
                            (stdout, attribute.type, attribute.pValue,
                             attribute.ulValueLen, ck_attribute_specs[k].arg);
                    }
                    free(attribute.pValue);
                } else if(rc == CKR_ATTRIBUTE_SENSITIVE) {
                    fprintf(stdout, "(%02ld) %s is sensitive\n", l++,
                           ck_attribute_specs[k].name);
                } else if((rc != CKR_ATTRIBUTE_TYPE_INVALID) &&
                          (rc != CKR_TEMPLATE_INCONSISTENT)) {
                    show_error(stdout, "C_GetAttributeValue", rc);
                    rc = FALSE;
                    goto done;
                }
            }
        }
    } while (i);

    rc = funcs->C_FindObjectsFinal(h_session);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsFinal", rc);
        rc = FALSE;
        goto done;
    }

    fprintf(stdout, "Found: %ld objects\n", j);
    rc = TRUE;

 done:
    if(user_pin) {
        funcs->C_CloseAllSessions(SLOT_ID);
    }
    return rc;
}

static char *app_name = "pkcs11-util list-objects";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { "directory",          1, 0,           'd' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Supply PIN on the command line",
    "Specify number of the slot to use",
    "Specify the module to load",
    "Specify the directory for NSS database",
};

int objects(int argc, char **argv)
{
    CK_ULONG          nslots, islot;
    CK_SLOT_ID        *pslots = NULL;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_UTF8CHAR_PTR   opt_pin = NULL;
    CK_ULONG          opt_pin_len = 0;
    CK_RV             rc;
    CK_ULONG          opt_slot = -1;
    char *opt_module = NULL, *opt_dir = NULL;
    int long_optind = 0;

    init_crypto();

    while (1) {
        char c = getopt_long(argc, argv, "d:hp:s:m:",
                             options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'd':
                opt_dir = optarg;
                break;
            case 'p':
                opt_pin = (CK_UTF8CHAR_PTR) strdup(optarg);
                if(opt_pin) {
                    opt_pin_len = strlen(optarg);
                }
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
        do_list_token_objects(funcs, pslots[islot], opt_pin, opt_pin_len);
    }

    free(opt_pin);

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Finalize", rc);
        return rc;
    }

    return rc;
}
