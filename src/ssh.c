/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "crypto.h"
#include "pkcs11_display.h"
#include "base64.h"

#include <string.h>

#ifdef HAVE_OPENSSL
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

void dump_x509(unsigned char *crt, unsigned int len)
{
    X509 *x509;
    unsigned char *p = crt;
    x509 = d2i_X509(NULL, (const unsigned char **)&p, len);
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
}

void find_x509(CK_FUNCTION_LIST *funcs, CK_SESSION_HANDLE h_session,
               CK_BYTE_PTR id, CK_ULONG len)
{
    CK_OBJECT_HANDLE  crto;
    CK_OBJECT_CLASS   crtc = CKO_CERTIFICATE;
    CK_ATTRIBUTE      crt_search[2];
    CK_ATTRIBUTE      crt_get;
    CK_BYTE           crt[16384];
    CK_RV             rc;
    CK_ULONG          k = 0;

    fillAttribute(&(crt_search[0]), CKA_ID, id, len);
    fillAttribute(&(crt_search[1]), CKA_CLASS, &crtc, sizeof(crtc));

    rc = funcs->C_FindObjectsInit(h_session, crt_search, 2);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsInit", rc);
        goto done;
    }
        
    rc = funcs->C_FindObjects(h_session, &crto, 1, &k);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjects", rc);
        goto done;
    }

    rc = funcs->C_FindObjectsFinal(h_session);
    if (rc != CKR_OK) {
        show_error(stdout, "C_FindObjectsFinal", rc);
        goto done;
    }

    if(k == 1) {
        fillAttribute(&crt_get, CKA_VALUE, crt, sizeof(crt));
        rc = funcs->C_GetAttributeValue( h_session, crto, &crt_get, 1);
        if (rc != CKR_OK) {
            show_error(stdout, "C_GetAttributeValue", rc);
            goto done;
        }
        dump_x509(crt, crt_get.ulValueLen);
    }

 done:
    return;
}
#endif

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

int do_list_rsa_ssh_keys(CK_FUNCTION_LIST *funcs,
                         CK_SESSION_HANDLE h_session)
{
    CK_RV             rc;
    CK_ULONG          i, j, kt = CKK_RSA;
    CK_OBJECT_HANDLE  obj[1024];
    CK_OBJECT_CLASS   class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE      search[2];

    fillAttribute(&(search[0]), CKA_CLASS, &class, sizeof(class));
    fillAttribute(&(search[1]), CKA_KEY_TYPE, &kt, sizeof(kt));
    kt = CKK_RSA;

    rc = pkcs11_find_object(funcs, stdout, h_session, search, 2, obj,
                            sizeof(obj)/sizeof(CK_OBJECT_HANDLE), &i);
    if (rc != CKR_OK) {
        return rc;
    }

    fprintf(stdout, "Found: %ld RSA keys\n", i);

    if(i) {
        CK_ATTRIBUTE      aid[3];
        CK_BYTE           id[256], e[256], n[4096];
        CK_BYTE           raw[2048], b64[2048];
        unsigned int      rawl, b64l;
        
        for(j = 0; j < i; j++) {
            fillAttribute(&(aid[0]), CKA_ID, id, sizeof(id));
            fillAttribute(&(aid[1]), CKA_PUBLIC_EXPONENT, e, sizeof(e));
            fillAttribute(&(aid[2]), CKA_MODULUS, n, sizeof(n));

            rc = funcs->C_GetAttributeValue( h_session, obj[j], aid, 3);
            if (rc != CKR_OK) {
                continue;
                show_error(stdout, "C_GetAttributeValue", rc);
                rc = FALSE;
                goto done;
            }

            rawl = ssh_dump(raw, (CK_BYTE *)"ssh-rsa", 7);
            rawl += ssh_dump(raw + rawl, e, aid[1].ulValueLen);
            rawl += ssh_dump(raw + rawl, n, aid[2].ulValueLen);
            
            b64l = encode_base64(raw, rawl, b64, 0);
            b64[b64l] = '\0';
            fprintf(stdout, "ssh-rsa %s\n", b64);

#ifdef HAVE_OPENSSL
            find_x509(funcs, h_session, id, aid[0].ulValueLen);
#endif
        }
    }

 done:
    return rc;
}

static unsigned char prime256v1_oid[] = { 0x06, 0x08, 0x2a, 0x86, 0x48,
                                          0xce, 0x3d, 0x03, 0x01, 0x07 };
static unsigned char secp384r1_oid[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
static unsigned char secp521r1_oid[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };

int do_list_ecdsa_ssh_keys(CK_FUNCTION_LIST *funcs,
                           CK_SESSION_HANDLE h_session)
{
    CK_RV             rc;
    CK_ULONG          i = 0, j, k, kt = CKK_EC;
    CK_OBJECT_HANDLE  obj[1024];
    CK_OBJECT_HANDLE  pubkey;
    CK_OBJECT_CLASS   private = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS   public = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE      search[2];
    CK_ATTRIBUTE      aid[4];
    CK_BYTE           id[256], ecparams[1024], ecpoint[1024], raw[2048], b64[2048];
    unsigned int      rawl, b64l;
 
    fillAttribute(&(search[0]), CKA_CLASS, &private, sizeof(private));
    fillAttribute(&(search[1]), CKA_KEY_TYPE, &kt, sizeof(kt));

    rc = pkcs11_find_object(funcs, stdout, h_session, search, 2, obj,
                            sizeof(obj)/sizeof(CK_OBJECT_HANDLE), &i);
    if (rc != CKR_OK) {
        goto done;
    }
    if(i == 0) {
        goto done;
    }

    fprintf(stdout, "Found: %ld EC keys\n", i);
    
    for(j = 0; j < i; j++) {
        CK_ATTRIBUTE point;
        char *ktlabel = NULL;
        char *curve = NULL;
        unsigned int ecpsize = 0, offset = 0;
        fillAttribute(&(aid[0]), CKA_ID, id, sizeof(id));
        fillAttribute(&(aid[1]), CKA_EC_PARAMS, ecparams, sizeof(ecparams));

        rc = funcs->C_GetAttributeValue(h_session, obj[j], aid, 2);
        if (rc != CKR_OK) {
            continue;
        }

        if(aid[1].ulValueLen == sizeof(prime256v1_oid) &&
           memcmp(ecparams, prime256v1_oid, sizeof(prime256v1_oid)) == 0) {
            ktlabel = "ecdsa-sha2-nistp256";
            curve = "nistp256";
            ecpsize = 65;
        } else if(aid[1].ulValueLen == sizeof(secp384r1_oid) &&
                  memcmp(ecparams, secp384r1_oid, sizeof(secp384r1_oid)) == 0) {
            ktlabel = "ecdsa-sha2-nistp384";
            curve = "nistp384";
            ecpsize = 97;
        } else if(aid[1].ulValueLen == sizeof(secp521r1_oid) &&
                  memcmp(ecparams, secp521r1_oid, sizeof(secp521r1_oid)) == 0) {
            ktlabel = "ecdsa-sha2-nistp521";
            curve = "nistp521";
            ecpsize = 133;
        } else {
            fprintf(stdout, "Unknown EC key parameters\n");
        }

        fillAttribute(&(aid[1]), CKA_KEY_TYPE, &kt, sizeof(kt));
        fillAttribute(&(aid[2]), CKA_CLASS, &public, sizeof(public));
        rc = pkcs11_find_object(funcs, stdout, h_session, aid, 3, &pubkey, 1, &k);
        if (rc != CKR_OK) {
            return rc;
        }

        if(k == 0) {
            fprintf(stderr, "Missing public key\n");
            continue;
        }

        fillAttribute(&point, CKA_EC_POINT, ecpoint, sizeof(ecpoint));
        rc = funcs->C_GetAttributeValue(h_session, pubkey, &point, 1);
        if (rc != CKR_OK) {
            continue;
        }

        if(point.ulValueLen > ecpsize) {
            offset = point.ulValueLen - ecpsize;
        }

        rawl = ssh_dump(raw, (CK_BYTE *)ktlabel, strlen(ktlabel));
        rawl += ssh_dump(raw + rawl, (CK_BYTE *)curve, strlen(curve));
        rawl += ssh_dump(raw + rawl, ecpoint + offset, point.ulValueLen - offset);

        b64l = encode_base64(raw, rawl, b64, 0);
        b64[b64l] = '\0';
        fprintf(stdout, "%s %s\n", ktlabel, b64);
        
#ifdef HAVE_OPENSSL
        find_x509(funcs, h_session, id, aid[0].ulValueLen);
#endif
    }

 done:
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
    CK_UTF8CHAR_PTR   opt_pin = NULL;
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
                opt_pin = (CK_UTF8CHAR_PTR) strdup(optarg);
                if(opt_pin) {
                    opt_pin_len = strlen(optarg);
                }
                break;
            case 's':
                opt_slot = (CK_SLOT_ID) atoi(optarg);
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
        fprintf(stdout, "Using %s directory\n", opt_dir);
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
        pslots[0] = opt_slot;
        nslots = 1;
    }

    for (islot = 0; islot < nslots; islot++) {
        CK_SESSION_HANDLE h_session;
        fprintf(stdout, "Slot ID: %lx\n", pslots[islot]);

        rc = pkcs11_login_session(funcs, stdout, pslots[islot], &h_session,
                                  CK_FALSE, CKU_USER, opt_pin, opt_pin_len);
        if (rc != CKR_OK) {
            continue;
        }

        do_list_rsa_ssh_keys(funcs, h_session);
        do_list_ecdsa_ssh_keys(funcs, h_session);

        if(opt_pin) {
            rc = funcs->C_Logout(h_session);
            if (rc != CKR_OK) {
                show_error(stdout, "C_Logout", rc);
                continue;
            }
        }
    
        rc = funcs->C_CloseSession(h_session);
        if (rc != CKR_OK) {
            show_error(stdout, "C_CloseSession", rc);
            continue;
        }
    }
    
    free(opt_pin);

    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK) {
        show_error(stdout, "C_Finalize", rc);
    }

    return rc;
}
