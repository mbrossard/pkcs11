/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include <string.h>
#include <stdio.h>

#include "common.h"
#include "pkcs11_display.h"

static char *app_name = "pkcs11-util clean";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { "directory",          1, 0,           'd' },
    { "read-write",         0, 0,           'r' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Supply PIN on the command line",
    "Specify number of the slot to use",
    "Specify the module to load",
    "Specify the directory for NSS database",
    "Actually delete objects"
};

static CK_FUNCTION_LIST *funcs = NULL;

int clean( int argc, char **argv )
{
    CK_BYTE           opt_pin[32] = "";
    CK_ULONG          opt_pin_len = -1;
    CK_RV             rc;
    CK_ULONG          nslots, opt_slot = -1;
    CK_SESSION_HANDLE h_session;
    char *opt_module = NULL, *opt_dir = NULL;
    int long_optind = 0, rw = 0, destroy = 0, i;
    char c;

    if(argc <= 1) {
        print_usage_and_die(app_name, options, option_help);
    }

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
            case 'm':
                opt_module = optarg;
                break;
            case 'r':
                rw = 1;
                break;
            case 'h':
            default:
                print_usage_and_die(app_name, options, option_help);
        }
    }

    funcs = pkcs11_get_function_list( opt_module );
    if (!funcs) {
        printf("Could not get function list.\n");
        return -1;
    }

    rc = pkcs11_initialize_nss(funcs, opt_dir);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Initialize", rc );
        return rc;
    }

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
        } else {
            printf("Found %ld slots, use --slot parameter to choose.\n", nslots);
        }
    }

    rc = funcs->C_OpenSession(opt_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL_PTR, NULL_PTR, &h_session);
    if (rc != CKR_OK) {
        show_error(stdout, "C_OpenSession", rc );
        return rc;
    }

    if(opt_pin_len != -1) {
        rc = funcs->C_Login(h_session, CKU_USER, opt_pin, opt_pin_len );
        if (rc != CKR_OK) {
            show_error(stdout, "C_Login", rc );
            return rc;
        }
    } else {
        CK_TOKEN_INFO  info;
        
        rc = funcs->C_GetTokenInfo( opt_slot, &info );
        if (rc != CKR_OK) {
            show_error(stdout, "C_GetTokenInfo", rc );
            return rc;
        }

        if(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
            rc = funcs->C_Login( h_session, CKU_USER, NULL, 0 );
            if (rc != CKR_OK) {
                show_error(stdout, "C_Login", rc );
                return rc;
            }
        } else {
            printf("No PIN provided and no protected authentication path.\n");
            return -1;
        }
    }

    CK_OBJECT_CLASS pkey = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE search_all[] =
    {
        { CKA_CLASS, &pkey, sizeof(pkey)}
    };
    CK_OBJECT_HANDLE all_keys[65536];
    CK_ULONG key_count = 65536;

    rc = funcs->C_FindObjectsInit(h_session, search_all, 1);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsInit", rc );
        return rc;
    }

    rc = funcs->C_FindObjects(h_session, all_keys, key_count, &key_count);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjects", rc );
        return rc;
    }

    rc = funcs->C_FindObjectsFinal(h_session);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsFinal", rc );
        return rc;
    }

    printf("Found %lu private keys\n", key_count);

    for(i = 0; i < key_count; i++) {
        CK_BYTE id[32];
        CK_OBJECT_CLASS crt = CKO_CERTIFICATE;
        CK_ATTRIBUTE search_crt[] = {
            { CKA_ID, &id, 32 },
            { CKA_CLASS, &crt, sizeof(crt)}
        };
        CK_OBJECT_HANDLE h_crt;
        CK_ULONG crt_count = 1;

        rc = funcs->C_GetAttributeValue(h_session, all_keys[i], search_crt, 1);
        if (rc != CKR_OK) {
            show_error(stdout, "C_GetAttributeValue", rc );
            return rc;
        }

        printf("Handling key #%d with handle 0x%lx\n", i, all_keys[i]);
        dump_generic(stdout, "Key ID", id, search_crt[0].ulValueLen);

        rc = funcs->C_FindObjectsInit(h_session, search_crt, 2);
        if (rc != CKR_OK) {
            show_error(stdout, "C_FindObjectsInit", rc );
            return rc;
        }

        rc = funcs->C_FindObjects(h_session, &h_crt, 1, &crt_count);
        if (rc != CKR_OK) {
            show_error(stdout, "C_FindObjects", rc );
            return rc;
        }

        rc = funcs->C_FindObjectsFinal(h_session);
        if (rc != CKR_OK) {
            show_error(stdout, "C_FindObjectsFinal", rc );
            return rc;
        }

        if(crt_count == 0) {
            CK_OBJECT_CLASS pub = CKO_PUBLIC_KEY;
            CK_ATTRIBUTE search_pub[] = {
                { CKA_ID, &id, search_crt[0].ulValueLen },
                { CKA_CLASS, &pub, sizeof(pub)}
            };
            CK_OBJECT_HANDLE h_pub;
            CK_ULONG pub_count = 1;
            
            printf("Didn't find matching certificate. Now looking for public key.\n");

            rc = funcs->C_FindObjectsInit(h_session, search_pub, 2);
            if (rc != CKR_OK) {
                show_error(stdout, "C_FindObjectsInit", rc );
                return rc;
            }

            rc = funcs->C_FindObjects(h_session, &h_pub, 1, &pub_count);
            if (rc != CKR_OK) {
                show_error(stdout, "C_FindObjects", rc );
                return rc;
            }

            rc = funcs->C_FindObjectsFinal(h_session);
            if (rc != CKR_OK) {
                show_error(stdout, "C_FindObjectsFinal", rc );
                return rc;
            }

            if(pub_count == 0) {
                printf("Didn't find matching public key. Skipping\n");
            } else {
                if(!rw) {
                    printf("Read-only mode: Found candidate private key and public key with handles 0x%lx 0x%lx\n",
                           all_keys[i], h_pub);
                } else {
                    printf("Deleting private key and public key with handles 0x%lx 0x%lx\n", all_keys[i], h_pub);
                    
                    rc = funcs->C_DestroyObject(h_session, all_keys[i]);
                    if (rc != CKR_OK) {
                        show_error(stdout, "C_DestroyObject", rc );
                        return rc;
                    }

                    rc = funcs->C_DestroyObject(h_session, h_pub);
                    if (rc != CKR_OK) {
                        show_error(stdout, "C_DestroyObject", rc );
                        return rc;
                    }
                    destroy += 2;
                }
            }
        } else {
            printf("Found matching certificate\n");
        }

    }

    if(*opt_pin != '\0') {
        rc = funcs->C_Logout(h_session);
        if (rc != CKR_OK) {
            show_error(stdout, "C_Logout", rc );
            return rc;
        }
    }

    rc = funcs->C_CloseSession(h_session);
    if (rc != CKR_OK) {
        show_error(stdout, "C_CloseSession", rc );
        return rc;
    }

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Finalize", rc );
        return rc;
    }

    if(destroy > 0) {
        printf("\nDeleted %d objects\n", destroy);
    }

    rc = funcs->C_Finalize( NULL );
    return rc;
}
