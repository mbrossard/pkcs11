/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "pkcs11-util.h"

#ifdef HAVE_OPENSSL

#include "common.h"
#include "pkcs11_display.h"

#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <openssl/evp.h>

static char *app_name = "pkcs11-util wrap";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { "directory",          1, 0,           'd' },
    { "key",                1, 0,           'k' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Supply PIN on the command line",
    "Specify number of the slot to use",
    "Specify the module to load",
    "Specify the directory for NSS database",
    "ID of the key to wrap",
};

int wrap( int argc, char **argv )
{
    CK_FUNCTION_LIST *funcs = NULL;
    CK_BYTE           opt_pin[32] = "";
    CK_ULONG          opt_pin_len = 0;
    CK_RV             rc;
    CK_ULONG          opt_slot = -1;
    CK_SESSION_HANDLE h_session;
    char *opt_module = NULL, *opt_dir = NULL;
    int long_optind = 0, i;
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
            case 'm':
                opt_module = optarg;
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

    rc = pkcs11_initialize_nss(funcs, opt_dir);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Initialize", rc );
        return rc;
    }

    rc = funcs->C_OpenSession(opt_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                              NULL_PTR, NULL_PTR, &h_session);
    if (rc != CKR_OK) {
        show_error(stdout, "C_OpenSession", rc );
        return rc;
    }

    if(*opt_pin != '\0') {
        rc = funcs->C_Login(h_session, CKU_USER, opt_pin, opt_pin_len );
        if (rc != CKR_OK) {
            show_error(stdout, "C_Login", rc );
            return rc;
        }
    }

    CK_BBOOL true = CK_TRUE;
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt = CKK_AES;
    unsigned char aes[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    CK_OBJECT_HANDLE aes_key;
    CK_ATTRIBUTE import_aes[] =
    {
        { CKA_CLASS,       &cls,  sizeof(cls)  },
        { CKA_KEY_TYPE,    &kt,   sizeof(kt)   },
        { CKA_ENCRYPT,     &true, sizeof(true) },
        { CKA_DECRYPT,     &true, sizeof(true) },
        { CKA_WRAP,        &true, sizeof(true) },
        { CKA_UNWRAP,      &true, sizeof(true) },
        { CKA_EXTRACTABLE, &true, sizeof(true) },
        { CKA_VALUE,       &aes,  sizeof(aes)  }
    };

    rc = funcs->C_CreateObject(h_session, import_aes, 8, &aes_key);
    if (rc != CKR_OK) {
        show_error(stdout, "C_CreateObject", rc );
        return rc;
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

    fprintf(stderr, "Found %ld private keys\n", key_count);

    for(i = 0; i < key_count; i++) {
        CK_BYTE wrapped_key[65536];
        /* CK_ULONG wl = 0; */
        CK_ULONG wl = sizeof(wrapped_key);

        CK_BYTE iv[16] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
                           0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
        CK_MECHANISM mech = {
            CKM_AES_CBC_PAD, iv, sizeof(iv),
        };

        fprintf(stderr, "Handling key #%d with handle 0x%lx\n", i, all_keys[i]);
        rc = funcs->C_WrapKey(h_session, &mech, aes_key, all_keys[i], wrapped_key, &wl);
        if (rc != CKR_OK) {
            show_error(stdout, "C_WrapKey", rc );
            return rc;
        }

        fprintf(stderr, "Wrapped size is %ld bytes\n", wl);

        dump_generic(stderr, "Wrapped key", wrapped_key, wl);
        
        if(1) {
            CK_BYTE unwrapped[65536];
            EVP_CIPHER_CTX ctx;
            int len, tmp;

            EVP_CIPHER_CTX_init(&ctx);
            switch (sizeof(aes)) {
                case 16:
                    EVP_DecryptInit (&ctx, EVP_aes_128_cbc (), aes, iv);
                    break;
                case 24:
                    EVP_DecryptInit (&ctx, EVP_aes_192_cbc (), aes, iv);
                    break;
                case 32:
                    EVP_DecryptInit (&ctx, EVP_aes_256_cbc (), aes, iv);
                    break;
            };

            if(EVP_DecryptUpdate(&ctx, unwrapped, &len, wrapped_key, wl)) {
                if(EVP_DecryptFinal(&ctx, unwrapped + len, &tmp)) {
                    char b[256];
                    FILE *f;
                    len += tmp;
                    dump_generic(stderr, "Unwrapped key", unwrapped, len);
                    sprintf(b, "key-%04d.key", i);
                    if((f = fopen(b, "wb"))) {
                        fwrite(unwrapped, len, 1, f);
                        fclose(f);
                    }
                } else {
                    fprintf(stderr, "Error decrypting final\n");
                }
            } else {
                fprintf(stderr, "Error decrypting\n");
            }

            EVP_CIPHER_CTX_cleanup(&ctx);
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

    rc = funcs->C_Finalize( NULL );
    return rc;
}
#endif
