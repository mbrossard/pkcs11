/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "common.h"
#include "pkcs11_display.h"

#include <string.h>

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

int clean(int argc, char **argv)
{
    CK_UTF8CHAR_PTR   opt_pin = NULL;
    CK_ULONG          opt_pin_len = 0;
    CK_RV             rc;
    CK_ULONG          nslots, opt_slot = -1;
    CK_SLOT_ID        *pslots = NULL;
    CK_SESSION_HANDLE h_session;
    char *opt_module = NULL, *opt_dir = NULL;
    int long_optind = 0, rw = 0, destroy = 0, i;
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
            case 'r':
                rw = 1;
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
    } else {
        if(nslots == 1) {
            opt_slot = pslots[0];
        } else {
            fprintf(stdout, "Found %ld slots, use --slot parameter to choose.\n", nslots);
            exit(-1);
        }
    }

    rc = pkcs11_login_session(funcs, stdout, opt_slot, &h_session,
                              CK_TRUE, CKU_USER, opt_pin, opt_pin_len);
    free(opt_pin);
    if (rc != CKR_OK) {
        return rc;
    }

    CK_OBJECT_CLASS pkey = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE search_all[] =
    {
        { CKA_CLASS, &pkey, sizeof(pkey)}
    };
    CK_OBJECT_HANDLE all_keys[65536];
    CK_ULONG key_count = sizeof(all_keys) / sizeof(CK_OBJECT_HANDLE);

    rc = funcs->C_FindObjectsInit(h_session, search_all, 1);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsInit", rc);
        return rc;
    }

    rc = funcs->C_FindObjects(h_session, all_keys, key_count, &key_count);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjects", rc);
        return rc;
    }

    rc = funcs->C_FindObjectsFinal(h_session);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsFinal", rc);
        return rc;
    }

    fprintf(stdout, "Found %lu private keys\n", key_count);

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
            show_error(stdout, "C_GetAttributeValue", rc);
            return rc;
        }

        fprintf(stdout, "Handling key #%d with handle 0x%lx\n", i, all_keys[i]);
        dump_generic(stdout, "Key ID", id, search_crt[0].ulValueLen);

        rc = funcs->C_FindObjectsInit(h_session, search_crt, 2);
        if (rc != CKR_OK) {
            show_error(stdout, "C_FindObjectsInit", rc);
            return rc;
        }

        rc = funcs->C_FindObjects(h_session, &h_crt, 1, &crt_count);
        if (rc != CKR_OK) {
            show_error(stdout, "C_FindObjects", rc);
            return rc;
        }

        rc = funcs->C_FindObjectsFinal(h_session);
        if (rc != CKR_OK) {
            show_error(stdout, "C_FindObjectsFinal", rc);
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

            fprintf(stdout, "Didn't find matching certificate. Now looking for public key.\n");

            rc = funcs->C_FindObjectsInit(h_session, search_pub, 2);
            if (rc != CKR_OK) {
                show_error(stdout, "C_FindObjectsInit", rc);
                return rc;
            }

            rc = funcs->C_FindObjects(h_session, &h_pub, 1, &pub_count);
            if (rc != CKR_OK) {
                show_error(stdout, "C_FindObjects", rc);
                return rc;
            }

            rc = funcs->C_FindObjectsFinal(h_session);
            if (rc != CKR_OK) {
                show_error(stdout, "C_FindObjectsFinal", rc);
                return rc;
            }

            if(pub_count == 0) {
                fprintf(stdout, "Didn't find matching public key. Skipping\n");
            } else {
                if(!rw) {
                    fprintf(stdout, "Read-only mode: Found candidate private key and public key with handles 0x%lx 0x%lx\n",
                           all_keys[i], h_pub);
                } else {
                    fprintf(stdout, "Deleting private key and public key with handles 0x%lx 0x%lx\n", all_keys[i], h_pub);

                    rc = funcs->C_DestroyObject(h_session, all_keys[i]);
                    if (rc != CKR_OK) {
                        show_error(stdout, "C_DestroyObject", rc);
                    }

                    rc = funcs->C_DestroyObject(h_session, h_pub);
                    if (rc != CKR_OK) {
                        show_error(stdout, "C_DestroyObject", rc);
                    }
                    destroy += 2;
                }
            }
        } else {
            fprintf(stdout, "Found matching certificate\n");
        }

    }

    pkey = CKO_SECRET_KEY;
    rc = funcs->C_FindObjectsInit(h_session, search_all, 1);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsInit", rc);
        return rc;
    }

    key_count = sizeof(all_keys) / sizeof(CK_OBJECT_HANDLE);
    rc = funcs->C_FindObjects(h_session, all_keys, key_count, &key_count);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjects", rc);
        return rc;
    }

    rc = funcs->C_FindObjectsFinal(h_session);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsFinal", rc);
        return rc;
    }

    fprintf(stdout, "Found %lu secret keys\n", key_count);

    for(i = 0; i < key_count; i++) {
        rc = funcs->C_DestroyObject(h_session, all_keys[i]);
        if (rc != CKR_OK) {
            show_error(stdout, "C_DestroyObject", rc);
        }
        destroy += 1;
    }

    if(destroy > 0) {
        fprintf(stdout, "\nDeleted %d objects\n", destroy);
    }

    rc = pkcs11_close(stdout, funcs, h_session);
    return rc;
}
