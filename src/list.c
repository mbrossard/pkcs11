/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "config.h"

#include "crypto.h"
#include "common.h"
#include "keypair.h"
#include "pkcs11_display.h"

int do_list_token_objects(CK_FUNCTION_LIST *funcs,
                          CK_SLOT_ID        SLOT_ID,
                          CK_BYTE          *user_pin,
                          CK_ULONG          user_pin_len)
{
    CK_RV             rc;
    CK_FLAGS          flags;
    CK_ULONG          i, j, k, l;
    CK_SESSION_HANDLE h_session;
    CK_OBJECT_HANDLE  obj;

    if(user_pin && user_pin_len) {
        /* create a USER/SO R/W session */
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        rc = funcs->C_OpenSession( SLOT_ID, flags, NULL, NULL, &h_session );
        if (rc != CKR_OK) {
            show_error(stdout, "C_OpenSession", rc );
            rc = FALSE;
            goto done;
        }

        rc = funcs->C_Login( h_session, CKU_USER, user_pin, user_pin_len );
        if (rc != CKR_OK) {
            show_error(stdout, "C_Login", rc );
            rc = FALSE;
            goto done;
        }
    } else {
        /* create a Public R/W session */
        flags = CKF_SERIAL_SESSION;
        rc = funcs->C_OpenSession( SLOT_ID, flags, NULL, NULL, &h_session );
        if (rc != CKR_OK) {
            show_error(stdout, "C_OpenSession", rc );
            rc = FALSE;
            goto done;
        }
    }

    rc = funcs->C_FindObjectsInit( h_session, NULL, 0 );
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsInit", rc );
        rc = FALSE;
        goto done;
    }

    j = 0;

    do {
        rc = funcs->C_FindObjects( h_session, &obj, 1, &i );
        if (rc != CKR_OK) {
            show_error(stdout, "C_FindObjects", rc );
            rc = FALSE;
            goto done;
        }
        if(i) {
            CK_ATTRIBUTE attribute;

            rc = funcs->C_GetObjectSize( h_session, obj, &k );
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

                rc = funcs->C_GetAttributeValue( h_session, obj, &attribute, 1);
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
                    show_error(stdout, "C_GetAttributeValue", rc );
                    rc = FALSE;
                    goto done;
                }
            }
        }
    } while (i);

    rc = funcs->C_FindObjectsFinal( h_session );
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsFinal", rc );
        rc = FALSE;
        goto done;
    }

    printf("Found: %ld objects\n", j);
    rc = TRUE;

 done:
    if(user_pin) {
        funcs->C_CloseAllSessions( SLOT_ID );
    }
    return rc;
}

int do_GetSlotInfo(CK_FUNCTION_LIST *funcs,
                   CK_SLOT_ID slot_id)
{
    CK_SLOT_INFO  info;
    CK_RV         rc;

    rc = funcs->C_GetSlotInfo( slot_id, &info );
    if (rc != CKR_OK) {
        show_error(stdout, "   C_GetTokenInfo", rc );
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

    rc = funcs->C_GetTokenInfo( slot_id, &info );
    if (rc != CKR_OK) {
        show_error(stdout, "   C_GetTokenInfo", rc );
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
        show_error(stdout, "C_GetMechanismList", rc );
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
    { "genkey",             1, 0,           'g' },
    { "label",              1, 0,           'l' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Show global token information",
    "List slots available on the token",
    "List mechanisms supported by the token",
    "List objects contained in the token",
    "Print this help and exit",
    "Supply PIN on the command line (if used in scripts: careful!)",
    "Specify number of the slot to use",
    "Specify the module to load",
    "Specify the directory for NSS database",
    "Generate key",
    "Set label on generated keys",
};


#define NEED_SESSION_RO 0x01
#define NEED_SESSION_RW 0x02

int list( int argc, char **argv )
{
    CK_ULONG          nslots, islot;
    CK_SLOT_ID        *pslots = NULL;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_BYTE           opt_pin[20] = "";
    CK_BYTE_PTR       opt_label = NULL;
    CK_INFO           info;
    CK_ULONG          opt_pin_len = 0;
    CK_RV             rc;
    CK_ULONG          opt_slot = -1;
    char *opt_module = NULL, *opt_dir = NULL;
    char *gen_param = NULL;
    int long_optind = 0;
    int do_show_info = 0;
    int do_list_slots = 0;
    int do_list_mechs = 0;
    int do_list_objects = 0;
    int need_session = 0;
    int action_count = 0;
    int genkey = 0;

    char c;

    init_crypto();

    while (1) {
        c = getopt_long(argc, argv, "ILMOd:hl:p:s:g:m:",
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
            case 'l':
                opt_label = (CK_BYTE_PTR)optarg;
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
                need_session |= NEED_SESSION_RO;
                do_list_objects = 1;
                action_count++;
                break;
            case 'p':
                need_session |= NEED_SESSION_RW;
                opt_pin_len = strlen(optarg);
                opt_pin_len = (opt_pin_len < 20) ? opt_pin_len : 19;
                memcpy( opt_pin, optarg, opt_pin_len );
                break;
            case 's':
                opt_slot = (CK_SLOT_ID) atoi(optarg);
                break;
            case 'm':
                opt_module = optarg;
                break;
            case 'g':
                need_session |= NEED_SESSION_RW;
                gen_param = optarg;
                genkey = 1;
                break;
            case 'h':
            default:
                print_usage_and_die(app_name, options, option_help);
        }
    }

    funcs = pkcs11_get_function_list( opt_module );
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
        show_error(stdout, "C_Initialize", rc );
        return rc;
    }

    if(do_show_info) {
        rc = funcs->C_GetInfo(&info);
        if (rc != CKR_OK) {
            show_error(stdout, "C_GetInfo", rc );
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

    if(genkey) {

        if(opt_slot == -1) {
            rc = funcs->C_GetSlotList(0, NULL_PTR, &nslots);
            if (rc != CKR_OK) {
                show_error(stdout, "C_GetSlotList", rc );
                return rc;
            }

            if(nslots == 1) {
                rc = funcs->C_GetSlotList(0, &opt_slot, &nslots);
                if (rc != CKR_OK) {
                    show_error(stdout, "C_GetSlotList", rc );
                    return rc;
                } else {
                    printf("Using slot %ld\n", opt_slot);
                }
            }
        }

        if(opt_slot != -1) {
            char             *tmp;
            long              keysize;
            CK_SESSION_HANDLE h_session;
            CK_FLAGS          flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
            rc = funcs->C_OpenSession( opt_slot, flags, NULL, NULL, &h_session );
            if(opt_pin_len) {
                rc = funcs->C_Login( h_session, CKU_USER, opt_pin, opt_pin_len );
                if (rc != CKR_OK) {
                    show_error(stdout, "C_Login", rc );
                }
            } else {
                CK_TOKEN_INFO  info;

                rc = funcs->C_GetTokenInfo( opt_slot, &info );
                if (rc != CKR_OK) {
                    show_error(stdout, "C_GetTokenInfo", rc );
                    return FALSE;
                }

                if(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
                    rc = funcs->C_Login( h_session, CKU_USER, NULL, 0 );
                    if (rc != CKR_OK) {
                        show_error(stdout, "C_Login", rc );
                        return rc;
                    }
                }
            }
            fprintf(stdout, "Generating key with param '%s'\n", gen_param);
            keysize = strtol(gen_param, &tmp, 10);
            if(gen_param != tmp) {
                fprintf(stdout, "Generating RSA key with size %ld\n", keysize);
                rc = generateRsaKeyPair(funcs, h_session, keysize, opt_label);
            } else if(strncmp(gen_param, "gost", 4) == 0) {
                fprintf(stdout, "Generating GOST R34.10-2001 key (%s) in slot %ld\n",
                        gen_param, opt_slot);
                rc = generateGostKeyPair(funcs, h_session, gen_param, opt_label);
            } else {
                CK_BBOOL full;
                rc = ecdsaNeedsEcParams(funcs, opt_slot, &full);
                if(rc == CKR_OK) {
                    fprintf(stdout, "Generating ECDSA key with curve '%s' "
                            "in slot %ld with %s\n", gen_param, opt_slot,
                            full ? "EC Parameters" : "Named Curve");
                    rc = generateEcdsaKeyPair(funcs, h_session, gen_param, full, opt_label);
                }
            }
        } else {
            printf("The key generation function requires the '--slot' parameter\n");
        }
    }

    rc = funcs->C_Finalize( NULL );
    return rc;
}
