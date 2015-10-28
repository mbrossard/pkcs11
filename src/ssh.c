/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include <string.h>
#include <getopt.h>

#include "config.h"

#ifdef HAVE_OPENSSL
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#endif

#include "crypto.h"
#include "pkcs11_display.h"

#include "base64.h"

unsigned int ssh_dump(CK_BYTE *output, CK_BYTE *input, unsigned int size)
{
    unsigned int k = 0;

    /* Pad with a 0 if first byte MSB is set */
    if(input[0] & 0x80) {
        output[4] = 0x0;
        k = 1;
    }

    memcpy(output + 4 + k, input, size);
    for(int i = 0, j = size + k; i < 4; i++) {
        output[3-i] = (char)(j & 0xFF);
        j >>= 8;
    }

    return size + 4 + k;
}

int do_list_ssh_keys(CK_FUNCTION_LIST *funcs,
                     CK_SLOT_ID        SLOT_ID,
                     CK_BYTE          *user_pin,
                     CK_ULONG          user_pin_len)
{
    CK_RV             rc;
    CK_FLAGS          flags;
    CK_ULONG          i, j;
    CK_SESSION_HANDLE h_session;
    CK_OBJECT_HANDLE  obj[1024];
    CK_OBJECT_CLASS   class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE      search[2];
    CK_ULONG          kt;

    printf("Slot ID: %lx\n", SLOT_ID);

    if(user_pin) {
        flags = CKF_SERIAL_SESSION;
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
        flags = CKF_SERIAL_SESSION;
        rc = funcs->C_OpenSession( SLOT_ID, flags, NULL, NULL, &h_session );
        if (rc != CKR_OK) {
            show_error(stdout, "C_OpenSession", rc );
            rc = FALSE;
            goto done;
        }
    }

    fillAttribute(&(search[0]), CKA_CLASS, &class, sizeof(class));
    fillAttribute(&(search[1]), CKA_KEY_TYPE, &kt, sizeof(kt));
    kt = CKK_RSA;

    rc = pkcs11_find_object(funcs, stdout, h_session, search, 1, obj,
                            sizeof(obj)/sizeof(CK_OBJECT_HANDLE), &i);
    if (rc != CKR_OK) {
        return rc;
    }

    printf("Found: %ld RSA keys\n", i);

    if(i) {
        CK_ATTRIBUTE      aid[3];
        CK_BYTE           id[256], e[256], n[1024];
        CK_BYTE           raw[2048], b64[2048], crt[16384];
        unsigned int      rawl, b64l;
        CK_OBJECT_HANDLE  crto[2];
        CK_OBJECT_CLASS   crtc = CKO_CERTIFICATE;
        CK_ATTRIBUTE      crt_search[2];
        CK_ATTRIBUTE      crt_get;
        
        for(j = 0; j < i; j++) {
            CK_ULONG k = 0;

            fillAttribute(&(aid[0]), CKA_ID, id, sizeof(id));
            fillAttribute(&(aid[1]), CKA_PUBLIC_EXPONENT, e, sizeof(e));
            fillAttribute(&(aid[2]), CKA_MODULUS, n, sizeof(n));

            rc = funcs->C_GetAttributeValue( h_session, obj[j], aid, 3);
            if (rc != CKR_OK) {
                continue;
                show_error(stdout, "C_GetAttributeValue", rc );
                rc = FALSE;
                goto done;
            }

            rawl = ssh_dump(raw, (CK_BYTE *)"ssh-rsa", 7);
            rawl += ssh_dump(raw + rawl, e, aid[1].ulValueLen);
            rawl += ssh_dump(raw + rawl, n, aid[2].ulValueLen);
            
            b64l = encode_base64(raw, rawl, b64, 0);
            b64[b64l] = '\0';
            printf("ssh-rsa %s\n", b64);

            fillAttribute(&(crt_search[0]), CKA_ID, id, aid[0].ulValueLen);
            fillAttribute(&(crt_search[1]), CKA_CLASS, &crtc, sizeof(crtc));

            rc = funcs->C_FindObjectsInit( h_session, crt_search, 2 );
            if (rc != CKR_OK) {
                show_error(stdout, "C_FindObjectsInit", rc );
                rc = FALSE;
                goto done;
            }
            
            rc = funcs->C_FindObjects( h_session, crto, 2, &k );
            if (rc != CKR_OK) {
                show_error(stdout, "C_FindObjects", rc );
                rc = FALSE;
                goto done;
            }
            
            rc = funcs->C_FindObjectsFinal( h_session );
            if (rc != CKR_OK) {
                show_error(stdout, "C_FindObjectsFinal", rc );
                rc = FALSE;
                goto done;
            }

            if(k == 1) {
                fillAttribute(&crt_get, CKA_VALUE, crt, sizeof(crt));
                rc = funcs->C_GetAttributeValue( h_session, crto[0], &crt_get, 1);
                if (rc != CKR_OK) {
                    show_error(stdout, "C_GetAttributeValue", rc );
                    rc = FALSE;
                    goto done;
                }

#ifdef HAVE_OPENSSL
                X509 *x509;
                unsigned char *p = crt;
                x509 = d2i_X509(NULL, (const unsigned char **)&p, crt_get.ulValueLen);
                if(x509) {
                    int flags =  XN_FLAG_RFC2253;
                        BIO *bio = BIO_new(BIO_s_file());
                        X509_EXTENSION *ext; 
                        BIO_set_fp(bio, stdout, BIO_NOCLOSE);
                        fprintf(stdout, "Subject: ");
                        X509_NAME_print_ex(bio, X509_get_subject_name(x509), 0, flags);
                        fprintf(stdout, "\nIssuer: ");
                        X509_NAME_print_ex(bio, X509_get_issuer_name(x509), 0, flags);
                        fprintf(stdout, "\nSerial Number: ");
                        BIGNUM *bn = ASN1_INTEGER_to_BN(X509_get_serialNumber(x509), NULL);
                        BN_print(bio, bn);
                        BN_free(bn);
                        fprintf(stdout, "\nValidity: ");
                        ASN1_TIME_print(bio, X509_get_notBefore(x509));
                        fprintf(stdout, " to ");
                        ASN1_TIME_print(bio, X509_get_notAfter(x509));

                        ext = X509_get_ext(x509, X509_get_ext_by_NID(x509, NID_key_usage, 0));
                        if(ext) {
                            fprintf(stdout, "\nKey Usage: ");
                            X509V3_EXT_print(bio, ext, 0, 0);
                        }
                        ext = X509_get_ext(x509, X509_get_ext_by_NID(x509, NID_ext_key_usage, 0));
                        if(ext) {
                            fprintf(stdout, "\nExtended Key Usage: ");
                            X509V3_EXT_print(bio, ext, 0, 0);
                        }

                        fprintf(stdout, "\n");
                        BIO_free(bio);
                }
#endif

                
            } else if(k == 0) {
                printf("Certificate not found\n");
            } else {
                printf("Found more than one certificate\n");
            }

            printf("---------------------------\n");
        }
    }
    rc = TRUE;

 done:
    if(user_pin) {
        funcs->C_CloseAllSessions( SLOT_ID );
    }
    return rc;
}

static char *app_name = "pkcs11-util ssh";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "pin",                1, 0,           'p' },
    { "slot",               1, 0,           's' },
    { "module",             1, 0,           'm' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Supply PIN on the command line",
    "Specify number of the slot to use",
    "Specify the module to load",
};

int ssh(int argc, char **argv)
{
    CK_ULONG          nslots, islot;
    CK_SLOT_ID        *pslots = NULL;
    CK_FUNCTION_LIST  *funcs = NULL;
    CK_BYTE           opt_pin[20] = "";
    CK_ULONG          opt_pin_len = 0;
    CK_RV             rc;
    CK_ULONG          opt_slot = -1;
    char *opt_module = NULL, *opt_dir = NULL;
    int long_optind = 0;

    char c;

    init_crypto();

    while (1) {
        c = getopt_long(argc, argv, "d:hp:s:m:",
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
            case 'p':
                opt_pin_len = strlen(optarg);
                opt_pin_len = (opt_pin_len < 20) ? opt_pin_len : 19;
                memcpy( opt_pin, optarg, opt_pin_len );
                break;
            case 's':
                opt_slot = (CK_SLOT_ID) atoi(optarg);
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

    rc = pkcs11_get_slots(funcs, stdout, &pslots, &nslots);
    if (rc != CKR_OK) {
        return rc;
    }
    
    if(opt_slot != -1) {
        pslots[0] = opt_slot;
        nslots = 1;
    }

    for (islot = 0; islot < nslots; islot++) {
        do_list_ssh_keys(funcs, pslots[islot], opt_pin, opt_pin_len);
    }

    rc = funcs->C_Finalize( NULL );
    return rc;
}
