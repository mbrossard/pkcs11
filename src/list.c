/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include <string.h>
#include <getopt.h>

#include "config.h"

#include "crypto.h"
#include "common.h"
#include "pkcs11_display.h"

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
        rc = funcs->C_FindObjects( h_session, &obj, 1, &i);
        if (rc != CKR_OK) {
            show_error(stdout, "C_FindObjects", rc);
            rc = FALSE;
            goto done;
        }
        if(i) {
            CK_ATTRIBUTE attribute;

            rc = funcs->C_GetObjectSize(h_session, obj, &k);
            if (rc != CKR_OK) {
                printf("----------------\nObject %ld\n", j);
            } else {
                printf("----------------\nObject %ld has size %ld\n", j, k);
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
                        printf("(%02ld) %s ", l++, ck_attribute_specs[k].name);

                        ck_attribute_specs[k].display
                            (stdout, attribute.type, attribute.pValue,
                             attribute.ulValueLen, ck_attribute_specs[k].arg);
                    }
                    free(attribute.pValue);
                } else if(rc == CKR_ATTRIBUTE_SENSITIVE) {
                    printf("(%02ld) %s is sensitive\n", l++,
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

    printf("Found: %ld objects\n", j);
    rc = TRUE;

 done:
    if(user_pin) {
        funcs->C_CloseAllSessions(SLOT_ID);
    }
    return rc;
}

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

    printf("CK_SLOT_INFO for slot #%ld:  \n", slot_id);
    print_slot_info(stdout, &info);
    printf("\n\n");

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

    printf("CK_TOKEN_INFO for slot #%ld:  \n", slot_id);
    print_token_info(stdout, &info);
    printf("\n\n");

    return TRUE;
}

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

static char *app_name = "pkcs11-util list";

static const struct option options[] = {
    { "show-info",          0, 0,           'I' },
    { "list-slots",         0, 0,           'L' },
    { "list-mechanisms",    0, 0,           'M' },
    { "list-objects",       0, 0,           'O' },
    { "help",               0, 0,           'h' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { "directory",          1, 0,           'd' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Show global token information",
    "List slots available on the token",
    "List mechanisms supported by the token",
    "List objects contained in the token",
    "Print this help and exit",
    "Supply PIN on the command line",
    "Specify number of the slot to use",
    "Specify the module to load",
    "Specify the directory for NSS database",
};

int list(int argc, char **argv)
{
    CK_ULONG          nslots, islot;
    CK_SLOT_ID        *pslots = NULL;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_UTF8CHAR_PTR   opt_pin = NULL;
    CK_ULONG          opt_pin_len = 0;
    CK_INFO           info;
    CK_RV             rc;
    CK_ULONG          opt_slot = -1;
    char *opt_module = NULL, *opt_dir = NULL;
    int long_optind = 0;
    int do_show_info = 0;
    int do_list_slots = 0;
    int do_list_mechs = 0;
    int do_list_objects = 0;
    int action_count = 0;

    char c;

    init_crypto();

    while (1) {
        c = getopt_long(argc, argv, "ILMOd:hp:s:m:",
                        options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'd':
                opt_dir = optarg;
                break;
            case 'I':
                do_show_info = 1;
                action_count++;
                break;
            case 'L':
                do_list_slots = 1;
                action_count++;
                break;
            case 'M':
                do_list_mechs = 1;
                action_count++;
                break;
            case 'O':
                do_list_objects = 1;
                action_count++;
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
        printf("Could not get function list.\n");
        if(!opt_module) {
            print_usage_and_die(app_name, options, option_help);
        }
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

    if(do_show_info) {
        rc = funcs->C_GetInfo(&info);
        if (rc != CKR_OK) {
            show_error(stdout, "C_GetInfo", rc);
            return rc;
        } else {
            print_ck_info(stdout,&info);
        }
    }

    rc = pkcs11_get_slots(funcs, stdout, &pslots, &nslots);
    if (rc != CKR_OK) {
        return rc;
    }
    
    if(opt_slot != -1) {
        /* TODO: Look in pslots */
        pslots = &opt_slot;
        nslots = 1;
    } else {
        if(opt_pin_len) {
            printf("No slot specified, the '--pin' parameter will be ignored\n");
        }
    }

    for (islot = 0; islot < nslots; islot++) {
        if (do_list_slots) {
            do_GetSlotInfo(funcs, pslots[islot]);
            do_GetTokenInfo(funcs, pslots[islot]);
        }
        if(do_list_mechs) {
            do_GetTokenMech(funcs, pslots[islot]);
        }

        if(do_list_objects) {
            do_list_token_objects(funcs, pslots[islot], opt_pin, opt_pin_len);
        }
    }

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Finalize", rc);
        return rc;
    }

    return rc;
}
